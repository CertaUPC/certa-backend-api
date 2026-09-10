from dataclasses import dataclass, field
from uuid import UUID, uuid4


@dataclass
class CodeContext:
    """El código que se le entregó al modelo.

    `text` es el envío literal y `available_lines` las líneas reales que cubre.
    Son lo único contra lo que se puede comprobar el anclaje después.
    """

    finding_id: UUID
    enclosing_function: str
    text: str
    available_lines: frozenset[int]
    callers: tuple[str, ...] = ()
    sanitizers: tuple[str, ...] = ()
    source_expression: str | None = None
    caller_depth: int = 2
    degraded_to_file: bool = False
    id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not self.text or not self.text.strip():
            raise ValueError("Un contexto vacío no permite juzgar nada")
        if not self.available_lines:
            raise ValueError("Sin el rango de líneas no se puede verificar el anclaje")

    def contains_line(self, line: int) -> bool:
        return line in self.available_lines

    @property
    def recovered_line_count(self) -> int:
        return len(self.available_lines)

    @property
    def has_sanitizers(self) -> bool:
        return bool(self.sanitizers)
