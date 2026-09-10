"""Modelo guionado para probar la cadena sin proveedor.

No simula: devuelve respuestas escritas de antemano, en orden. Con eso se
ejercitan el orquestador, el reintento y la cascada de forma determinista, y se
reproduce a voluntad el caso que motiva el trabajo: descartar un hallazgo
citando una línea que no existe.
"""

from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field

from ...domain.entities.code_context import CodeContext
from ...domain.entities.finding import Finding
from ...domain.services.language_model_port import ModelJudgement


@dataclass
class ScriptedLanguageModel:
    """Implementa `LanguageModelPort` devolviendo respuestas en orden."""

    script: deque[ModelJudgement]
    model_name: str = "modelo-guionado"
    model_version: str = "2026-09-10"
    calls: list[tuple[Finding, CodeContext, str | None]] = field(default_factory=list)

    def __init__(
        self,
        judgements: Iterable[ModelJudgement],
        model_name: str = "modelo-guionado",
        model_version: str = "2026-09-10",
    ) -> None:
        self.script = deque(judgements)
        self.model_name = model_name
        self.model_version = model_version
        self.calls = []

    async def judge(
        self, finding: Finding, context: CodeContext, retry_hint: str | None = None
    ) -> ModelJudgement:
        self.calls.append((finding, context, retry_hint))
        if not self.script:
            raise AssertionError(
                "El guion se agotó: la cadena consultó al modelo más veces de las "
                "previstas por la prueba"
            )
        return self.script.popleft()

    @property
    def call_count(self) -> int:
        return len(self.calls)

    @property
    def last_hint(self) -> str | None:
        return self.calls[-1][2] if self.calls else None


def exploitable(lines: Iterable[int], confidence: float = 0.9) -> ModelJudgement:
    return ModelJudgement(
        value="explotable",
        justification_text="El dato llega al punto sensible sin saneamiento",
        cited_lines=tuple(lines),
        confidence=confidence,
        input_tokens=3_500,
        output_tokens=450,
        latency_ms=1_200,
    )


def not_exploitable(lines: Iterable[int], confidence: float = 0.85) -> ModelJudgement:
    return ModelJudgement(
        value="no_explotable",
        justification_text="El dato se sanea antes de alcanzar el punto sensible",
        cited_lines=tuple(lines),
        confidence=confidence,
        input_tokens=3_400,
        output_tokens=420,
        latency_ms=1_100,
    )


def hallucinated_dismissal(fake_line: int) -> ModelJudgement:
    """Descarta el hallazgo citando una línea que no existe.

    Es el caso que el verificador de anclaje debe atrapar, y la razón por la que
    el mecanismo existe.
    """
    return ModelJudgement(
        value="no_explotable",
        justification_text=f"La entrada se valida en la línea {fake_line}",
        cited_lines=(fake_line,),
        confidence=0.95,
        input_tokens=3_500,
        output_tokens=300,
        latency_ms=900,
    )
