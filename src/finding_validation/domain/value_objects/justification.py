from collections.abc import Iterable
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Justification:
    """Lo que el modelo afirma y las líneas en que lo apoya.

    Inmutable, para que lo que se audita después sea lo que se verificó.
    """

    text: str
    cited_lines: frozenset[int] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.text or not self.text.strip():
            raise ValueError("Una justificación sin texto no justifica nada")
        if any(n < 1 for n in self.cited_lines):
            raise ValueError("Las líneas citadas se numeran desde 1")

    @classmethod
    def from_model_output(cls, text: str, lines: Iterable[int] | None) -> "Justification":
        """Las líneas llegan como lista y se guardan como conjunto: el orden
        y las repeticiones no cambian lo que se citó."""
        if lines is None:
            raw: tuple[object, ...] = ()
        elif isinstance(lines, (str, bytes)):
            raise TypeError("Las líneas citadas deben llegar como lista de enteros")
        else:
            raw = tuple(lines)
        try:
            normalized = frozenset(int(n) for n in raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Línea citada no numérica: {exc}") from exc
        return cls(text=text.strip(), cited_lines=normalized)

    @property
    def cites_anything(self) -> bool:
        return bool(self.cited_lines)

    def __str__(self) -> str:
        if not self.cited_lines:
            return "sin líneas citadas"
        return "líneas " + ", ".join(str(n) for n in sorted(self.cited_lines))
