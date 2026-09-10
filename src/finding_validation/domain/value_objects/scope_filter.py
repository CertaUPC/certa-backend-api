from collections.abc import Iterable
from dataclasses import dataclass, field

from ..entities.finding import Finding

# Orden de severidad tal como SARIF la declara, de mayor a menor.
SEVERITY_ORDER = ("error", "warning", "note")
_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}


@dataclass(frozen=True)
class ScopeFilter:
    """Acota qué se procesa antes de gastar presupuesto. Sin criterios pasa
    todo, no nada."""

    cwes: frozenset[str] = field(default_factory=frozenset)
    min_severity: str | None = None

    def __post_init__(self) -> None:
        if self.min_severity is not None and self.min_severity not in _RANK:
            raise ValueError(
                f"Severidad desconocida {self.min_severity!r}. "
                f"Se admiten: {', '.join(SEVERITY_ORDER)}"
            )
        normalized = frozenset(c.strip().upper() for c in self.cwes if c and c.strip())
        object.__setattr__(self, "cwes", normalized)

    @classmethod
    def unrestricted(cls) -> "ScopeFilter":
        return cls()

    @property
    def is_unrestricted(self) -> bool:
        return not self.cwes and self.min_severity is None

    def admits(self, finding: Finding) -> bool:
        if self.cwes and (finding.cwe or "").upper() not in self.cwes:
            return False
        if self.min_severity is not None:
            rank = _RANK.get(finding.severity.lower())
            if rank is None or rank > _RANK[self.min_severity]:
                return False
        return True

    def apply(self, findings: Iterable[Finding]) -> list[Finding]:
        return [f for f in findings if self.admits(f)]

    def describe(self) -> str:
        """Se guarda con la ejecución, para saber después con qué alcance corrió."""
        if self.is_unrestricted:
            return "sin restricción de alcance"
        partes = []
        if self.cwes:
            partes.append("CWE " + ", ".join(sorted(self.cwes)))
        if self.min_severity:
            partes.append(f"severidad {self.min_severity} o superior")
        return "; ".join(partes)
