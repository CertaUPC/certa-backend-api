from dataclasses import dataclass
from enum import Enum

from ..entities.code_context import CodeContext
from ..entities.finding import Finding


class PrefilterOutcome(str, Enum):
    """Qué hacer con el hallazgo antes de gastar una consulta."""

    ESCALATE_TO_MODEL = "escalar_al_modelo"
    RESOLVED_BY_RULE = "resuelto_por_regla"


@dataclass(frozen=True)
class PrefilterDecision:
    outcome: PrefilterOutcome
    reason: str

    @property
    def spends_budget(self) -> bool:
        return self.outcome is PrefilterOutcome.ESCALATE_TO_MODEL


class DeterministicPrefilter:
    """Resuelve sin consultar al modelo cuando la traza basta por sí sola.

    No es un clasificador: ante la duda escala. Resolver de más produce falsos
    negativos silenciosos; escalar de más solo cuesta dinero.
    """

    def __init__(self, require_sanitizer_before_sink: bool = True) -> None:
        self._require_before_sink = require_sanitizer_before_sink

    def decide(self, finding: Finding, context: CodeContext) -> PrefilterDecision:
        if context.degraded_to_file:
            return PrefilterDecision(
                PrefilterOutcome.ESCALATE_TO_MODEL,
                "El contexto se recuperó degradado: no hay traza suficiente para "
                "resolver por regla",
            )

        if not context.has_sanitizers:
            return PrefilterDecision(
                PrefilterOutcome.ESCALATE_TO_MODEL,
                "La traza no presenta saneador reconocido",
            )

        if self._require_before_sink and not self._sanitizer_precedes_sink(
            finding, context
        ):
            return PrefilterDecision(
                PrefilterOutcome.ESCALATE_TO_MODEL,
                "Hay saneador en la función, pero no se puede establecer que "
                "actúe antes del punto sensible",
            )

        nombres = ", ".join(context.sanitizers)
        return PrefilterDecision(
            PrefilterOutcome.RESOLVED_BY_RULE,
            f"La ruta atraviesa saneamiento acreditado ({nombres}) antes del "
            f"punto sensible",
        )

    def _sanitizer_precedes_sink(
        self, finding: Finding, context: CodeContext
    ) -> bool:
        """Condición necesaria, no suficiente: no sustituye al seguimiento de
        contaminación. Por eso lo resuelto aquí se marca aparte en la base."""
        sink_line = finding.location.start_line
        for line in context.text.splitlines():
            numero, _, contenido = line.partition(":")
            try:
                actual = int(numero.strip())
            except ValueError:
                continue
            if actual >= sink_line:
                break
            if any(s in contenido for s in context.sanitizers):
                return True
        return False
