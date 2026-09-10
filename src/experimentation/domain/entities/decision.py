from dataclasses import dataclass, field
from uuid import UUID, uuid4

from ..value_objects.condition import Condition, DecisionValue


@dataclass
class Decision:
    """Lo que se mide.

    `seconds` va desde que el hallazgo se muestra hasta que la persona decide.
    Los veredictos se calculan antes de la sesión, así que ahí no hay latencia
    del proveedor.
    """

    finding_id: UUID
    participant_id: UUID
    value: DecisionValue
    seconds: float
    condition: Condition
    is_current: bool = True
    comment: str | None = None
    id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if self.seconds <= 0:
            raise ValueError(
                f"El tiempo por hallazgo debe ser positivo, llegó {self.seconds}"
            )

    def supersede(self) -> None:
        """La reemplaza sin borrarla: un cambio de opinión no es un dato ausente."""
        self.is_current = False

    def is_correct_against(self, known_truth: bool | None) -> bool | None:
        """None si no hay verdad conocida o si marcó dudoso: en ninguno de los
        dos casos hay acierto que medir."""
        if known_truth is None or self.value is DecisionValue.DOUBTFUL:
            return None
        decidio_real = self.value is DecisionValue.CONFIRMED
        return decidio_real == known_truth
