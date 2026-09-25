"""El trabajador: reclama de la cola, valida lo pendiente y ordena.

Si el presupuesto se agota o el proveedor cae, conserva lo validado y devuelve
el resto a la cola.
"""

import logging
from dataclasses import dataclass, field
from uuid import UUID

from ....domain.entities.execution import Execution
from ....domain.repositories.repositories import (
    CodeContextRepository,
    ExecutionRepository,
    FindingRepository,
    VerdictRepository,
)
from ....domain.services.budget_guard import BudgetExhausted, BudgetGuard
from ....domain.services.priority_calculator import PriorityCalculator
from .validate_finding_command_service import ValidateFindingCommandService

logger = logging.getLogger(__name__)

# Umbral de la red de seguridad del lote. Tres es suficiente para
# distinguir un archivo que se movio de un repositorio que no esta.
FALLOS_DE_CONTEXTO_SEGUIDOS = 3


def _sin_contexto(cuantos: int, ultimo: str | None) -> str:
    """La explicación que se guarda y que la pantalla muestra tal cual."""
    cuenta = (
        "El único hallazgo que se intentó se quedó"
        if cuantos == 1
        else f"{cuantos} hallazgos seguidos se quedaron"
    )
    return (
        f"{cuenta} sin contexto recuperable, y ninguno se validó. El "
        f"repositorio no parece estar donde este trabajador lo busca, así que "
        f"la ejecución vuelve a la cola sin consumirse. {ultimo or ''}"
    ).strip()


@dataclass
class RunReport:
    execution_id: UUID
    validated: int = 0
    failed: int = 0
    interrupted: bool = False
    interruption_reason: str | None = None
    traces: list[str] = field(default_factory=list)

    def describe(self) -> str:
        base = f"{self.validated} hallazgos validados"
        if self.failed:
            # No siempre es el contexto: desde que una consulta fallida
            # deja de llevarse el lote, aqui tambien cae la respuesta
            # que el proveedor no entrego o entrego fuera de contrato.
            base += f", {self.failed} sin validar por fallo"
        if self.interrupted:
            base += f". Interrumpida: {self.interruption_reason}"
        return base


class RunExecutionCommandService:
    def __init__(
        self,
        execution_repository: ExecutionRepository,
        finding_repository: FindingRepository,
        context_repository: CodeContextRepository,
        verdict_repository: VerdictRepository,
        validator: ValidateFindingCommandService,
        budget: BudgetGuard,
        priority_calculator: PriorityCalculator | None = None,
        prompt_version: str | None = None,
    ) -> None:
        self._executions = execution_repository
        self._findings = finding_repository
        self._contexts = context_repository
        self._verdicts = verdict_repository
        self._validator = validator
        self._budget = budget
        self._priority = priority_calculator or PriorityCalculator()
        self._prompt_version = prompt_version

    async def claim_and_run(
        self,
        worker: str,
        batch_size: int | None = None,
        project_id: UUID | None = None,
    ) -> RunReport | None:
        """Toma la siguiente ejecución pendiente y la procesa. None si no hay.

        Con `project_id`, solo toma trabajo de ese proyecto. Un trabajador lee
        el código de su propio disco, de modo que reclamar el de otro
        repositorio no falla a medias: consume el lote entero.
        """
        execution = await self._executions.claim_next_pending(worker, project_id)
        if execution is None:
            return None
        return await self.run(execution, batch_size)

    async def run(
        self,
        execution: Execution,
        batch_size: int | None = None,
        worker: str = "api",
    ) -> RunReport:
        report = RunReport(execution_id=execution.id)

        # Quien entra por la API no pasó por la cola. Se reclama aquí para que
        # dos peticiones simultáneas no procesen la misma ejecución dos veces.
        if execution.is_claimable:
            execution.claim(worker)
            await self._executions.save(execution)

        # Solo lo que falta: reanudar no vuelve a pagar por lo ya validado.
        pending = await self._findings.list_pending_validation(execution.id, batch_size)
        logger.info(
            "Ejecución %s: %d hallazgos por validar", execution.id, len(pending)
        )

        # Cuantos fallos de contexto seguidos, sin ninguno validado, bastan
        # para dar por hecho que el problema es la configuracion y no el
        # hallazgo. Ver el aborto mas abajo.
        seguidos = 0
        ultimo_fallo_de_contexto: str | None = None

        for finding in pending:
            try:
                outcome = await self._validator.execute(finding)
            except BudgetExhausted as exc:
                report.interrupted = True
                report.interruption_reason = str(exc)
                break

            report.traces.extend(outcome.trace)

            if not outcome.succeeded:
                if outcome.error and "límite" in outcome.error:
                    report.interrupted = True
                    report.interruption_reason = outcome.error
                    break

                report.failed += 1

                # Red de seguridad. Si el contexto falla de entrada y varias
                # veces seguidas, lo que falla no es el hallazgo sino la ruta
                # del repositorio: este trabajador no ve ese codigo. Sin esto
                # se comia el lote entero marcandolo todo como fallo, y el
                # trabajador que si tenia el codigo ya no lo encontraba, porque
                # la ejecucion habia dejado de estar pendiente. Se devuelve a la
                # cola en vez de consumirla.
                if outcome.context_failed and report.validated == 0:
                    seguidos += 1
                    ultimo_fallo_de_contexto = outcome.error
                    if seguidos >= FALLOS_DE_CONTEXTO_SEGUIDOS:
                        report.interrupted = True
                        report.interruption_reason = _sin_contexto(
                            seguidos, ultimo_fallo_de_contexto
                        )
                        logger.error(report.interruption_reason)
                        break
                continue

            seguidos = 0

            if outcome.context is not None:
                await self._contexts.save(outcome.context)
            await self._verdicts.save(outcome.verdict, self._prompt_version)
            report.validated += 1

        await self._rank(execution)

        # Un lote más corto que el umbral no llega a disparar la red de arriba.
        # Sin esto, cargar un SARIF de dos hallazgos contra un repositorio que
        # este trabajador no tiene dejaba la corrida reclamada para siempre:
        # todo falló por contexto, nada se validó, y nadie lo decía.
        if (
            not report.interrupted
            and report.validated == 0
            and report.failed
            and seguidos == report.failed
        ):
            report.interrupted = True
            report.interruption_reason = _sin_contexto(
                seguidos, ultimo_fallo_de_contexto
            )

        if report.interrupted:
            # Se devuelve a la cola en vez de marcarla fallida: lo validado se
            # conserva y otro intento retoma donde quedó.
            #
            # La razón se anota antes de devolverla. Volver a la cola borra
            # `failure_reason`, de modo que sin esta nota la corrida quedaba
            # igual que una recién cargada y quien la subió no tenía cómo saber
            # que ya se intentó, ni qué ruta se buscó.
            execution.note_attempt(report.interruption_reason or "Sin causa registrada")
            execution.resume()
            await self._executions.save(execution)
            logger.warning("Ejecución %s interrumpida: %s", execution.id, report.interruption_reason)
            return report

        # Este intento sí avanzó, de modo que lo que dijera el anterior ya no
        # describe la corrida.
        if report.validated:
            execution.clear_attempt_note()

        # Se comprueba el estado y no solo el pendiente: volver a correr una
        # ejecucion ya terminada es legitimo desde la linea de comandos, y sin
        # esta guarda terminaba en un error de dominio en vez de no hacer nada.
        if execution.pending_findings == 0 and execution.is_running:
            execution.complete()
        await self._executions.save(execution)
        return report

    async def _rank(self, execution: Execution) -> None:
        """Calcula el orden sobre todo lo que ya tiene veredicto.

        Se recalcula completo y no de forma incremental: el orden es relativo, y
        un veredicto nuevo puede desplazar a los anteriores.
        """
        findings = {f.id: f for f in await self._findings.list_by_execution(execution.id)}
        verdicts = await self._verdicts.list_by_execution(execution.id)

        # Ante varios veredictos por hallazgo, manda el de mayor repetición: es
        # el más reciente bajo la misma condición.
        latest: dict[UUID, object] = {}
        for v in verdicts:
            actual = latest.get(v.finding_id)
            if actual is None or v.repetition >= actual.repetition:  # type: ignore[attr-defined]
                latest[v.finding_id] = v

        # El avance se deriva de lo que hay guardado y no se lleva sumando.
        # Sumando se desfasa en cuanto una corrida termina sin guardar la
        # ejecucion, y entonces el porcentaje miente y la ejecucion no se da
        # por completa aunque no quede nada pendiente.
        execution.validated_findings = len(latest)

        pairs = [
            (findings[fid], v)  # type: ignore[arg-type]
            for fid, v in latest.items()
            if fid in findings
        ]
        if not pairs:
            return

        for finding, _verdict, priority in self._priority.rank(pairs):  # type: ignore[arg-type]
            await self._findings.set_priority(finding.id, priority.score, priority.reason)
