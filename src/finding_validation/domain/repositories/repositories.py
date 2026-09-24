"""Puertos de persistencia. El dominio dice qué guardar; no sabe si detrás hay
PostgreSQL, memoria o un archivo."""

from typing import Protocol
from uuid import UUID

from ..entities.decision import Decision
from ..entities.code_context import CodeContext
from ..entities.execution import Execution
from ..entities.finding import Finding
from ..entities.verdict import Verdict
from ..value_objects.fingerprint import Fingerprint


class ExecutionRepository(Protocol):
    """Guarda ejecuciones y hace además de cola de trabajos."""

    async def save(self, execution: Execution) -> None: ...

    async def get(self, execution_id: UUID) -> Execution | None: ...

    async def claim_next_pending(
        self, worker: str, project_id: UUID | None = None
    ) -> Execution | None:
        """La pendiente más antigua, o None. Dos trabajadores nunca pueden
        reclamar la misma; cómo se consiga es cosa de la implementación."""
        ...

    async def list_by_project(self, project_id: UUID) -> list[Execution]: ...


class FindingRepository(Protocol):
    async def save_all(self, findings: list[Finding], execution_id: UUID) -> None: ...

    async def get(self, finding_id: UUID) -> Finding | None: ...

    async def list_by_execution(self, execution_id: UUID) -> list[Finding]: ...

    async def list_pending_validation(
        self, execution_id: UUID, limit: int | None = None
    ) -> list[Finding]:
        """Los que aún no tienen veredicto. Permite retomar sin volver a pagar
        lo ya hecho."""
        ...

    async def set_priority(self, finding_id: UUID, score: float, reason: str) -> None: ...


class CodeContextRepository(Protocol):
    async def save(self, context: CodeContext) -> None: ...

    async def get_by_finding(self, finding_id: UUID) -> CodeContext | None: ...

    async def purge_by_execution(self, execution_id: UUID) -> int:
        """Borra el texto y conserva las métricas. Devuelve cuántos purgó."""
        ...


class DecisionRepository(Protocol):
    """Las decisiones sobre hallazgos, las del producto y las del estudio."""

    async def save(self, decision: Decision) -> None:
        """Guarda la nueva y retira la vigencia de la anterior, si la habia."""
        ...

    async def list_by_finding(self, finding_id: UUID) -> list[Decision]:
        """El historial completo, de la mas reciente a la mas antigua."""
        ...


class VerdictRepository(Protocol):
    async def save(self, verdict: Verdict) -> None: ...

    async def get_by_finding(self, finding_id: UUID) -> list[Verdict]: ...

    async def get_for_run(
        self, finding_id: UUID, model: str, model_version: str, repetition: int
    ) -> Verdict | None:
        """El veredicto de esa corrida exacta, si ya se obtuvo."""
        ...

    async def find_reusable(
        self, fingerprint: Fingerprint, model: str, model_version: str
    ) -> Verdict | None:
        """Las tres condiciones son necesarias: otro modelo, u otra versión del
        mismo, no responde por este."""
        ...

    async def list_by_execution(self, execution_id: UUID) -> list[Verdict]: ...
