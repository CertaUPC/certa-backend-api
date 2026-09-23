"""Seguimiento del veredicto equivocado.

La variable principal del estudio es la exactitud de la decisión del
participante frente a la verdad conocida. Esa cifra puede subir por dos motivos
opuestos que producen el mismo número: porque la justificación anclada permite a
la persona juzgar mejor, o porque la persona deja de juzgar y adopta un
veredicto que acierta la mayoría de las veces. Solo el primero sostiene la
afirmación del trabajo.

Lo que los separa es qué hace el participante cuando la herramienta se equivoca.
Esos hallazgos no se fabrican: son los errores que el modelo cometió de verdad
sobre el conjunto de referencia, de modo que representan el error real del
sistema y no un escenario construido para la ocasión.

Un aumento de la exactitud acompañado de un seguimiento alto del veredicto
equivocado no es evidencia a favor de la herramienta, sino de que induce
confianza injustificada.
"""

from dataclasses import dataclass

EXPLOITABLE = "explotable"
NOT_EXPLOITABLE = "no_explotable"
CONFIRMED = "confirmado"
DISMISSED = "descartado"

# Los dos valores en que el modelo se moja. La abstención no afirma nada, de
# modo que no hay veredicto que seguir ni que rectificar.
_COMMITTED = (EXPLOITABLE, NOT_EXPLOITABLE)


@dataclass(frozen=True)
class MisleadingCase:
    """Un hallazgo en que la herramienta se equivocó, y lo que hizo la persona."""

    finding_id: str
    model_verdict: str
    known_truth: bool
    participant_decision: str

    def __post_init__(self) -> None:
        if self.model_said_exploitable == self.known_truth:
            raise ValueError(
                f"El veredicto {self.model_verdict!r} no contradice la verdad "
                f"conocida: este hallazgo no mide seguimiento de nada"
            )

    @property
    def model_said_exploitable(self) -> bool:
        return self.model_verdict == EXPLOITABLE

    @property
    def truth_is_exploitable(self) -> bool:
        return self.known_truth

    @property
    def was_followed(self) -> bool:
        """La persona adoptó la afirmación equivocada del modelo.

        La duda no cuenta como seguimiento: quien duda no ha dado por bueno el
        veredicto, que es precisamente lo que aquí se mide.
        """
        if self.participant_decision == CONFIRMED:
            return self.model_said_exploitable
        if self.participant_decision == DISMISSED:
            return not self.model_said_exploitable
        return False


def misleading_cases(findings: list[dict]) -> list[dict]:
    """Los hallazgos del lote en que el veredicto contradice la verdad conocida.

    Recibe diccionarios con `finding_id`, `verdict` y `known_truth` para no
    atar el dominio a la forma en que la persistencia los devuelva.
    """
    return [
        f
        for f in findings
        if f.get("known_truth") is not None
        and f.get("verdict") in _COMMITTED
        and (f["verdict"] == EXPLOITABLE) != bool(f["known_truth"])
    ]


def follow_rate(cases: list[MisleadingCase]) -> float | None:
    """Proporción de veredictos equivocados que el participante adoptó.

    None cuando no hubo ninguno: devolver cero afirmaría que nadie siguió al
    modelo, y lo cierto sería que no hubo ocasión de hacerlo.
    """
    if not cases:
        return None
    return sum(1 for c in cases if c.was_followed) / len(cases)


__all__ = ["MisleadingCase", "follow_rate", "misleading_cases"]
