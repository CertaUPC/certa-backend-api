from dataclasses import dataclass, field
from uuid import UUID, uuid4

from ..value_objects.code_location import CodeLocation
from ..value_objects.fingerprint import Fingerprint


@dataclass
class Finding:
    """Alerta que emitió el analizador. Raíz del agregado."""

    rule_id: str
    severity: str
    location: CodeLocation
    fingerprint: Fingerprint
    cwe: str | None = None
    message: str | None = None
    known_truth: bool | None = None
    id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not self.rule_id:
            raise ValueError("Un hallazgo sin regla no es un hallazgo")
        if not self.severity:
            raise ValueError("El hallazgo exige la severidad declarada por la regla")

    def is_same_as(self, other: "Finding") -> bool:
        return self.fingerprint == other.fingerprint

    @property
    def has_known_truth(self) -> bool:
        """Solo los conjuntos de referencia traen etiqueta."""
        return self.known_truth is not None
