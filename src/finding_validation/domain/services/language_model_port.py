from dataclasses import dataclass
from typing import Protocol

from ..entities.code_context import CodeContext
from ..entities.finding import Finding


@dataclass(frozen=True)
class ModelJudgement:
    """La respuesta cruda del proveedor. No es un `Verdict`: el veredicto solo
    existe después de verificar el anclaje."""

    value: str
    justification_text: str
    cited_lines: tuple[int, ...]
    confidence: float | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0


class LanguageModelPort(Protocol):
    """Proveedor de modelo de lenguaje. Cambiarlo toca un adaptador y ninguna
    regla, que es lo que hace comparables los modelos entre sí."""

    async def judge(
        self, finding: Finding, context: CodeContext, retry_hint: str | None = None
    ) -> ModelJudgement:
        """Emite un juicio. `retry_hint` señala el defecto del intento previo."""
        ...

    @property
    def model_name(self) -> str:
        ...

    @property
    def model_version(self) -> str:
        """Versión exacta. Sin ella el resultado no se reproduce."""
        ...
