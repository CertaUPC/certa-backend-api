"""Señal previa a la consulta: qué dice la traza por sí sola.

Este filtro resolvía. Cuando reconocía un saneador antes del punto sensible,
daba el hallazgo por no explotable y no lo consultaba, con lo que se ahorraba
una llamada al modelo.

La prueba de concepto sobre el conjunto con verdad conocida mostró el precio de
ese ahorro: de las cien alertas resolvió ocho sin consultar, y las ocho eran
vulnerabilidades reales. La causa es que reconocer un saneador por su nombre y
comprobar que aparece antes en el texto no demuestra que el dato contaminado lo
atraviese. En cuatro casos el saneador actuaba sobre otra variable; en el resto
la debilidad no depende de un flujo de datos, como el uso de un generador de
números débil, de modo que la pregunta por el saneamiento no aplicaba.

Un error así no se ve en ninguna métrica del modelo, porque el hallazgo nunca
llega al modelo y no hay veredicto que contrastar. En una herramienta de triaje
de seguridad, una optimización que introduce falsos negativos silenciosos no se
sostiene, así que la etapa deja de decidir.

Lo que queda es la señal: el filtro sigue mirando la traza y declara lo que
encuentra, y esa declaración se guarda en el rastro de la validación para que
sea auditable. Todos los hallazgos pasan por el modelo. Cuando el proyecto
disponga de seguimiento de contaminación suficiente para demostrar que el dato
atraviesa el saneador, la etapa podrá volver a decidir, y entonces será una
afirmación sobre el flujo y no sobre la coincidencia de un nombre.
"""

from dataclasses import dataclass
from enum import Enum

from ..entities.code_context import CodeContext
from ..entities.finding import Finding


class PrefilterOutcome(str, Enum):
    """Qué se sabe de la traza antes de consultar. Ninguno resuelve."""

    ESCALATE_TO_MODEL = "escalar_al_modelo"
    ESCALATE_WITH_SIGNAL = "escalar_con_senal"


@dataclass(frozen=True)
class PrefilterDecision:
    outcome: PrefilterOutcome
    reason: str

    @property
    def spends_budget(self) -> bool:
        """Siempre. La etapa ya no evita consultas, solo las acompaña."""
        return True

    @property
    def has_sanitizer_signal(self) -> bool:
        return self.outcome is PrefilterOutcome.ESCALATE_WITH_SIGNAL


class DeterministicPrefilter:
    """Observa la traza y declara lo que encuentra. No emite veredicto.

    La asimetría que gobernaba esta etapa sigue vigente y ahora es absoluta:
    resolver de más produce falsos negativos silenciosos, escalar de más solo
    cuesta dinero, de modo que se escala siempre.
    """

    def __init__(self, require_sanitizer_before_sink: bool = True) -> None:
        self._require_before_sink = require_sanitizer_before_sink

    def decide(self, finding: Finding, context: CodeContext) -> PrefilterDecision:
        if context.degraded_to_file:
            return PrefilterDecision(
                PrefilterOutcome.ESCALATE_TO_MODEL,
                "El contexto se recuperó degradado: la traza no alcanza ni para "
                "una señal",
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
                "Hay saneador en la función, pero no aparece antes del punto "
                "sensible",
            )

        nombres = ", ".join(context.sanitizers)
        return PrefilterDecision(
            PrefilterOutcome.ESCALATE_WITH_SIGNAL,
            f"Señal: la función presenta saneamiento acreditado ({nombres}) "
            f"antes del punto sensible. No se da por saneado: que el nombre "
            f"aparezca antes no demuestra que el dato lo atraviese, de modo que "
            f"el hallazgo se consulta igual",
        )

    def _sanitizer_precedes_sink(
        self, finding: Finding, context: CodeContext
    ) -> bool:
        """Condición necesaria y no suficiente, que es justamente el motivo por
        el que esta etapa ya no decide: no sustituye al seguimiento de la
        contaminación."""
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
