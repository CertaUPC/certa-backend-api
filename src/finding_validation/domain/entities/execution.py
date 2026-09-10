from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

from ..value_objects.scope_filter import ScopeFilter


class ExecutionStatus(str, Enum):
    """Estado de una corrida del analizador sobre un proyecto.

    Este mismo estado cumple la función de cola: el trabajador reclama las
    pendientes. Que la cola viva en el propio motor relacional elimina un
    componente del despliegue, porque para el volumen previsto no hace falta un
    intermediario de mensajería dedicado.
    """

    PENDING = "pendiente"
    IN_PROGRESS = "en_proceso"
    COMPLETED = "completada"
    FAILED = "fallida"


@dataclass
class Execution:
    """Raíz de agregado de una corrida. Agrupa los hallazgos que produjo."""

    project_id: UUID
    ruleset_version: str
    tool_name: str = "semgrep-oss"
    status: ExecutionStatus = ExecutionStatus.PENDING
    total_findings: int = 0
    validated_findings: int = 0
    scope: ScopeFilter = field(default_factory=ScopeFilter.unrestricted)
    claimed_by: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    failure_reason: str | None = None
    context_purged: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not self.ruleset_version:
            raise ValueError(
                "Sin la versión del conjunto de reglas, comparar dos ejecuciones "
                "carece de sentido"
            )

    # -- transiciones -----------------------------------------------------
    def claim(self, worker: str, now: datetime | None = None) -> None:
        if self.status is not ExecutionStatus.PENDING:
            raise ValueError(
                f"Solo se reclama una ejecución pendiente, esta está {self.status.value}"
            )
        self.status = ExecutionStatus.IN_PROGRESS
        self.claimed_by = worker
        self.started_at = now or datetime.now(timezone.utc)

    def complete(self, now: datetime | None = None) -> None:
        if self.status is not ExecutionStatus.IN_PROGRESS:
            raise ValueError("Solo se completa una ejecución en proceso")
        self.status = ExecutionStatus.COMPLETED
        self.finished_at = now or datetime.now(timezone.utc)

    def fail(self, reason: str, now: datetime | None = None) -> None:
        if not reason:
            raise ValueError("Un fallo sin causa no se puede diagnosticar después")
        self.status = ExecutionStatus.FAILED
        self.failure_reason = reason
        self.finished_at = now or datetime.now(timezone.utc)

    def resume(self) -> None:
        """Devuelve una ejecución interrumpida a la cola.

        Lo ya validado se conserva: al retomarla, el trabajador salta los
        hallazgos que ya tienen veredicto y no vuelve a pagar por ellos.
        """
        if self.status not in (ExecutionStatus.FAILED, ExecutionStatus.IN_PROGRESS):
            raise ValueError(
                f"No se reanuda una ejecución {self.status.value}"
            )
        self.status = ExecutionStatus.PENDING
        self.claimed_by = None
        self.failure_reason = None
        self.finished_at = None

    # -- consultas ---------------------------------------------------------
    @property
    def is_claimable(self) -> bool:
        return self.status is ExecutionStatus.PENDING

    @property
    def pending_findings(self) -> int:
        return max(0, self.total_findings - self.validated_findings)

    @property
    def progress(self) -> float:
        if not self.total_findings:
            return 0.0
        return round(self.validated_findings / self.total_findings, 4)

    @property
    def is_closed(self) -> bool:
        return self.status in (ExecutionStatus.COMPLETED, ExecutionStatus.FAILED)

    def describe_progress(self) -> str:
        if not self.total_findings:
            return "La ejecución no produjo hallazgos"
        return (
            f"{self.validated_findings} de {self.total_findings} hallazgos "
            f"validados ({self.progress:.0%}), {self.pending_findings} pendientes"
        )
