"""Seguimiento del veredicto equivocado, la medida que separa mejor juicio de
obediencia.

La variable principal del estudio es la exactitud de la decisión del
participante frente a la verdad conocida. Esa cifra puede subir por dos motivos
opuestos que producen el mismo número: porque la justificación anclada permite a
la persona juzgar mejor, o porque la persona deja de juzgar y adopta un
veredicto que acierta la mayoría de las veces.

Solo el primero sostiene la afirmación del trabajo. Para separarlos se observa
qué hace el participante en los hallazgos donde la herramienta se equivoca, que
no hay que fabricar: son los errores que el modelo cometió de verdad sobre el
conjunto de referencia.

Un aumento de la exactitud acompañado de un seguimiento alto del veredicto
equivocado no es evidencia a favor de la herramienta, sino de que induce
confianza injustificada.
"""

import pytest

from src.experimentation.domain.services.misleading_follow import (
    MisleadingCase,
    follow_rate,
    misleading_cases,
)

E, N, I = "explotable", "no_explotable", "indeterminado"
CONF, DESC, DUDA = "confirmado", "descartado", "dudoso"


def caso(veredicto, verdad, decision):
    return MisleadingCase(
        finding_id="f",
        model_verdict=veredicto,
        known_truth=verdad,
        participant_decision=decision,
    )


class TestQueHallazgosCuentan:
    def test_el_veredicto_que_contradice_la_verdad_es_engañoso(self):
        """El modelo dice no explotable sobre una vulnerabilidad real."""
        hallazgos = [
            {"finding_id": "a", "verdict": N, "known_truth": True},
            {"finding_id": "b", "verdict": E, "known_truth": True},
        ]
        assert [c["finding_id"] for c in misleading_cases(hallazgos)] == ["a"]

    def test_el_falso_positivo_declarado_explotable_tambien_cuenta(self):
        hallazgos = [{"finding_id": "a", "verdict": E, "known_truth": False}]
        assert len(misleading_cases(hallazgos)) == 1

    def test_la_abstencion_no_es_un_veredicto_equivocado(self):
        """Abstenerse no afirma nada, de modo que no hay nada que seguir."""
        hallazgos = [{"finding_id": "a", "verdict": I, "known_truth": True}]
        assert misleading_cases(hallazgos) == []

    def test_sin_verdad_conocida_no_se_puede_saber(self):
        hallazgos = [{"finding_id": "a", "verdict": E, "known_truth": None}]
        assert misleading_cases(hallazgos) == []


class TestTasaDeSeguimiento:
    def test_seguir_al_modelo_equivocado_cuenta(self):
        """El modelo dijo no explotable sobre algo real y la persona lo descartó."""
        assert follow_rate([caso(N, True, DESC)]) == 1.0

    def test_rectificar_no_cuenta(self):
        assert follow_rate([caso(N, True, CONF)]) == 0.0

    def test_dudar_no_es_seguir(self):
        """La duda es el resultado de no dar por bueno el veredicto: cuenta como
        no seguirlo, porque la persona no adoptó la afirmación."""
        assert follow_rate([caso(N, True, DUDA)]) == 0.0

    def test_tasa_sobre_varios(self):
        casos = [
            caso(N, True, DESC),   # sigue
            caso(N, True, CONF),   # rectifica
            caso(E, False, CONF),  # sigue
            caso(E, False, DESC),  # rectifica
        ]
        assert follow_rate(casos) == 0.5

    def test_sin_casos_no_se_inventa_una_tasa(self):
        """Devolver cero diría que nadie siguió al modelo, y lo cierto es que no
        hubo ocasión de hacerlo."""
        assert follow_rate([]) is None


class TestLecturaDelResultado:
    def test_el_caso_declara_si_fue_seguido(self):
        assert caso(N, True, DESC).was_followed is True
        assert caso(N, True, CONF).was_followed is False

    def test_el_caso_declara_que_afirmo_el_modelo(self):
        c = caso(N, True, DESC)
        assert c.model_said_exploitable is False
        assert c.truth_is_exploitable is True

    def test_un_caso_que_no_es_engañoso_se_rechaza(self):
        """Construirlo con un veredicto correcto sería medir otra cosa."""
        with pytest.raises(ValueError, match="no contradice"):
            MisleadingCase(
                finding_id="f",
                model_verdict=E,
                known_truth=True,
                participant_decision=CONF,
            )
