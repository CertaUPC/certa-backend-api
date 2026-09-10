"""Prepara el lote antes de una sesión con participantes.

Los veredictos se piden aquí y no durante la sesión: si no, el cronómetro
mediría la latencia del proveedor en vez de la decisión de la persona.

Reparte además los hallazgos en los dos lotes del diseño intra-sujeto, disjuntos,
para que nadie se reencuentre en la segunda condición con uno ya resuelto.
"""

import logging
from dataclasses import dataclass, field
from uuid import UUID

from .....shared.tracing import Stage, correlate, emit
from ....domain.entities.execution import Execution
from ....domain.repositories.repositories import (
    CodeContextRepository,
    FindingRepository,
    VerdictRepository,
)
from ....domain.services.budget_guard import BudgetGuard
from .validate_finding_command_service import ValidateFindingCommandService

logger = logging.getLogger(__name__)


class SessionNotReady(RuntimeError):
    """El lote no está listo para exponerse a un participante."""


@dataclass
class BatchPlan:
    """Reparto de los hallazgos entre las dos condiciones."""

    batch_a: list[UUID] = field(default_factory=list)
    batch_b: list[UUID] = field(default_factory=list)

    @property
    def are_disjoint(self) -> bool:
        return not (set(self.batch_a) & set(self.batch_b))

    @property
    def total(self) -> int:
        return len(self.batch_a) + len(self.batch_b)


@dataclass
class PreparationReport:
    execution_id: UUID
    precomputed: int = 0
    already_ready: int = 0
    failed: int = 0
    plan: BatchPlan = field(default_factory=BatchPlan)
    blocking: list[str] = field(default_factory=list)

    @property
    def is_ready(self) -> bool:
        return not self.blocking

    def describe(self) -> str:
        if not self.is_ready:
            return "El lote no está listo: " + "; ".join(self.blocking)
        return (
            f"{self.plan.total} hallazgos listos, {self.precomputed} calculados "
            f"ahora y {self.already_ready} que ya lo estaban. Lote A con "
            f"{len(self.plan.batch_a)} y lote B con {len(self.plan.batch_b)}."
        )


class PrepareSessionCommandService:
    def __init__(
        self,
        finding_repository: FindingRepository,
        verdict_repository: VerdictRepository,
        context_repository: CodeContextRepository,
        validator: ValidateFindingCommandService,
        budget: BudgetGuard,
    ) -> None:
        self._findings = finding_repository
        self._verdicts = verdict_repository
        self._contexts = context_repository
        self._validator = validator
        self._budget = budget

    async def prepare(
        self, execution: Execution, batch_size: int | None = None
    ) -> PreparationReport:
        report = PreparationReport(execution_id=execution.id)

        findings = await self._findings.list_by_execution(execution.id)
        if batch_size:
            findings = findings[:batch_size]
        if not findings:
            report.blocking.append("la ejecución no tiene hallazgos")
            return report

        for finding in findings:
            existentes = await self._verdicts.get_by_finding(finding.id)
            if existentes:
                report.already_ready += 1
                continue

            with correlate() as cid:
                emit(Stage.INGEST, "precomputo", hallazgo=str(finding.id), correlacion=cid)
                outcome = await self._validator.execute(finding)

            if not outcome.succeeded:
                report.failed += 1
                logger.warning(
                    "No se pudo precomputar el hallazgo %s: %s",
                    finding.id, outcome.error,
                )
                continue

            if outcome.context is not None:
                await self._contexts.save(outcome.context)
            await self._verdicts.save(outcome.verdict)
            report.precomputed += 1

        report.plan = self._split(findings)

        # Un lote donde falte el veredicto de algún hallazgo no puede exponerse:
        # el participante encontraría una pantalla en blanco donde debería haber
        # un juicio, y esa alerta quedaría fuera de la comparación.
        listos = report.precomputed + report.already_ready
        if listos < len(findings):
            report.blocking.append(
                f"{len(findings) - listos} de {len(findings)} hallazgos siguen "
                f"sin veredicto"
            )
        if not report.plan.are_disjoint:
            report.blocking.append("los dos lotes comparten hallazgos")

        return report

    @staticmethod
    def _split(findings: list) -> BatchPlan:
        """Alterna por huella y no por posición: así la misma ejecución da
        siempre los mismos dos lotes."""
        ordenados = sorted(findings, key=lambda f: f.fingerprint.value)
        plan = BatchPlan()
        for i, f in enumerate(ordenados):
            (plan.batch_a if i % 2 == 0 else plan.batch_b).append(f.id)
        return plan
