from dataclasses import dataclass


@dataclass(frozen=True)
class CodeLocation:
    """Región que señala el hallazgo. Rango cerrado y líneas desde 1, como en
    SARIF."""

    file_path: str
    start_line: int
    end_line: int

    def __post_init__(self) -> None:
        if not self.file_path:
            raise ValueError("La ubicación exige un archivo")
        if self.start_line < 1:
            raise ValueError(f"Las líneas se numeran desde 1, llegó {self.start_line}")
        if self.end_line < self.start_line:
            raise ValueError(
                f"La línea final {self.end_line} precede a la inicial {self.start_line}"
            )

    @property
    def lines(self) -> frozenset[int]:
        return frozenset(range(self.start_line, self.end_line + 1))

    @property
    def height(self) -> int:
        return self.end_line - self.start_line + 1

    def __str__(self) -> str:
        if self.start_line == self.end_line:
            return f"{self.file_path}:{self.start_line}"
        return f"{self.file_path}:{self.start_line}-{self.end_line}"
