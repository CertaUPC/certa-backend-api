from enum import Enum


class Condition(str, Enum):
    """Bajo qué condición se resuelve un lote.

    Misma interfaz en las dos. La de control oculta veredicto, confianza,
    justificación y sello, y no reordena. Así la diferencia que se mide es el
    asistente y no el aspecto de la pantalla.
    """

    WITH_ASSISTANT = "con_asistente"
    CONTROL = "sin_asistente"

    @property
    def shows_verdict(self) -> bool:
        return self is Condition.WITH_ASSISTANT

    @property
    def orders_by_priority(self) -> bool:
        return self is Condition.WITH_ASSISTANT

    @property
    def opposite(self) -> "Condition":
        return (
            Condition.CONTROL
            if self is Condition.WITH_ASSISTANT
            else Condition.WITH_ASSISTANT
        )


class DecisionValue(str, Enum):
    """DOUBTFUL existe porque forzar el binario produce respuestas inventadas.
    La duda es un dato, no ruido."""

    CONFIRMED = "confirmado"
    DISMISSED = "descartado"
    DOUBTFUL = "dudoso"
