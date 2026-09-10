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
            base += f", {self.failed} con fallo de contexto"
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

    async def claim_and_run(self, worker: str, batch_size: int | None = None) -> RunReport | None:
        """Toma la siguiente ejecución pendiente y la procesa. None si no hay."""
        execution = await self._executions.claim_next_pending(worker)
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
                continue

            if outcome.context is not None:
                await self._contexts.save(outcome.context)
            await self._verdicts.save(outcome.verdict, self._prompt_version)
            report.validated += 1
            execution.validated_findings += 1

        await self._rank(execution)

        if report.interrupted:
            # Se devuelve a la cola en vez de marcarla fallida: lo validado se
            # conserva y otro intento retoma donde quedó.
            execution.resume()
            await self._executions.save(execution)
            logger.warning("Ejecución %s interrumpida: %s", execution.id, report.interruption_reason)
            return report

        if execution.pending_findings == 0:
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

        pairs = [
            (findings[fid], v)  # type: ignore[arg-type]
            for fid, v in latest.items()
            if fid in findings
        ]
        if not pairs:
            return

        for finding, _verdict, priority in self._priority.rank(pairs):  # type: ignore[arg-type]
            await self._findings.set_priority(finding.id, priority.score, priority.reason)
