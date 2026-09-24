"""Alguien decidió algo sobre un hallazgo, en un tiempo.

Antes eran dos entidades, `Audit` aquí y `Decision` en experimentación, con la
lógica de rectificación escrita dos veces. El acto es el mismo, así que lo
propio del estudio admite ausencia y una decisión del producto no carga ni uno
de esos campos. Vive en validación porque el acto pertenece al producto: el
estudio lo usa, no lo posee.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

# Se declara como texto y no importando el objeto de valor de experimentación,
# porque el producto no depende del experimento.
CONDICIONES = ("con_asistente", "sin_asistente")


class DecisionValue(str, Enum):
    """DOUBTFUL no es negarse a decidir: es decidir que el hallazgo necesita a
    alguien más. No se cuenta como descarte, porque la duda es un dato."""

    CONFIRMED = "confirmado"
    DISMISSED = "descartado"
    DOUBTFUL = "dudoso"


@dataclass
class Decision:
    """`seconds` va desde que el hallazgo se muestra hasta que la persona
    decide. En el estudio, los veredictos se calculan antes de la sesión, de
    modo que ahí no hay latencia del proveedor dentro de la medida."""

    finding_id: UUID
    value: DecisionValue
    seconds: float

    # Exactamente uno de los dos. Una cuenta cuando es uso del producto, un
    # participante cuando es el estudio.
    user_id: UUID | None = None
    participant_id: UUID | None = None

    # Propios del estudio. Ausentes en el producto.
    session_id: UUID | None = None
    worklist_id: UUID | None = None
    condition: str | None = None

    is_current: bool = True
    comment: str | None = None
    id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        if self.seconds <= 0:
            raise ValueError(
                f"El tiempo por hallazgo debe ser positivo, llegó {self.seconds}"
            )
        if (self.user_id is None) == (self.participant_id is None):
            # El motor también lo impide, pero fallar aquí da el error donde se
            # comete y no al confirmar la transacción.
            raise ValueError(
                "Una decisión la toma una cuenta o un participante, y "
                "exactamente uno de los dos: sin autor no se puede atribuir, y "
                "con dos no se sabe a cuál"
            )
        if self.condition is not None and self.condition not in CONDICIONES:
            raise ValueError(
                f"Condición desconocida: {self.condition!r}. Se admiten "
                f"{' y '.join(CONDICIONES)}, o ninguna fuera del estudio"
            )

    @property
    def is_from_study(self) -> bool:
        return self.participant_id is not None

    def supersede(self) -> None:
        """La reemplaza sin borrarla: un cambio de opinión no es un dato
        ausente, y distinguirlos es lo que hace auditable el registro."""
        self.is_current = False

    def is_correct_against(self, known_truth: bool | None) -> bool | None:
        """None si no hay verdad conocida o si marcó dudoso: en ninguno de los
        dos casos hay acierto que medir."""
        if known_truth is None or self.value is DecisionValue.DOUBTFUL:
            return None
        decidio_real = self.value is DecisionValue.CONFIRMED
        return decidio_real == known_truth
