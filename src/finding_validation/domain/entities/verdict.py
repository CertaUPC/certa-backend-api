from dataclasses import dataclass, field
from enum import Enum
from uuid import UUID, uuid4

from ..value_objects.justification import Justification

_MAX_ATTEMPTS = 2


class VerdictValue(str, Enum):
    """NOT_VERIFIABLE juzga la respuesta, no el código: el modelo no logró
    sostener su conclusión con líneas que existan."""

    EXPLOITABLE = "explotable"
    NOT_EXPLOITABLE = "no_explotable"
    UNDETERMINED = "indeterminado"
    NOT_VERIFIABLE = "no_verificable"


@dataclass
class Verdict:
    """Juicio ya verificado. `model_version` entra en la identidad de la
    condición: un cambio de versión a media medición tiene que verse."""

    finding_id: UUID
    model: str
    model_version: str
    value: VerdictValue
    justification: Justification
    anchor_verified: bool
    confidence: float | None = None
    temperature: float = 0.0
    repetition: int = 1
    attempts: int = 1
    reused_from: UUID | None = None
    latency_ms: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not self.model or not self.model_version:
            raise ValueError("Sin modelo y versión el veredicto no es reproducible")
        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"La confianza vive en [0, 1], llegó {self.confidence}")
        if not 1 <= self.attempts <= _MAX_ATTEMPTS:
            raise ValueError(
                f"La política admite un único reintento, llegaron {self.attempts} intentos"
            )
        if self.repetition < 1:
            raise ValueError("Las repeticiones se numeran desde 1")

    @property
    def needed_retry(self) -> bool:
        return self.attempts > 1

    @property
    def was_reused(self) -> bool:
        """Se resolvió por huella, sin consultar al modelo."""
        return self.reused_from is not None

    @property
    def condition_key(self) -> tuple[UUID, str, str, int]:
        return (self.finding_id, self.model, self.model_version, self.repetition)
