"""La decisión que toma quien audita un hallazgo.

Existe aparte de `Decision`, que vive en el contexto de experimentación, porque
responden a preguntas distintas. Esta es un registro de auditoría del producto:
quién revisó qué y qué resolvió. La otra es una medición: qué decidió un
participante bajo una condición asignada, con su tiempo, para contrastarla con
la condición contraria.

Juntarlas obligaba a inventar un participante y una condición cada vez que
alguien usara la herramienta fuera del estudio, que es justo lo que impedía
retirar la instrumentación al terminar la tesis.

Una rectificación no sobrescribe: se guarda otra y la anterior deja de ser la
vigente. Sin ese historial no se puede distinguir una primera impresión de una
conclusión, y esa distinción es la que hace auditable el registro.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4


class AuditValue(str, Enum):
    """Lo que el evaluador resuelve sobre el hallazgo.

    DOUBTFUL no es una negativa a decidir: es una decisión de que el hallazgo
    necesita a alguien más. Se registra como tal y no se cuenta como descarte.
    """

    CONFIRMED = "confirmado"
    DISMISSED = "descartado"
    DOUBTFUL = "dudoso"


@dataclass
class Audit:
    """Registro de auditoría de un hallazgo por una persona."""

    finding_id: UUID
    value: AuditValue
    seconds: float
    user_id: UUID | None = None
    comment: str | None = None
    is_current: bool = True
    id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        if self.seconds <= 0:
            raise ValueError(
                "El tiempo empleado debe ser mayor que cero: un registro sin "
                "duración no permite analizar el esfuerzo de la revisión"
            )

    def supersede(self) -> None:
        """Deja de ser la vigente porque llegó una rectificación."""
        self.is_current = False
