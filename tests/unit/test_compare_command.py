"""La prueba de concepto del objetivo 1, ejercitada sin gastar en proveedor.

Los modelos van guionados. Lo que se comprueba no es lo que responden, sino que
la comparación sepa contrastar esas respuestas contra la verdad conocida y
producir la tabla con la que se elige el modelo.
"""

import csv
from collections import deque
from uuid import uuid4

import pytest

from src.cli import _scorecard
from src.finding_validation.application.internal.commandservices.compare_models_command_service import (
    Comparison,
    ModelRun,
)
from src.finding_validation.domain.entities.verdict import VerdictValue
from src.spoc_export import write_scorecard


def run(nombre, veredictos, repeticion=1, anclados=None, usd=0.0):
    r = ModelRun(model=nombre, model_version=nombre, repetition=repeticion)
    r.verdicts = dict(veredictos)
    r.anchored_first_try = len(veredictos) if anclados is None else anclados
    r.usd = usd
    return r


@pytest.fixture
def lote():
    """Cuatro hallazgos: dos reales y dos falsos positivos."""
    ids = [uuid4() for _ in range(4)]
    verdad = {ids[0]: True, ids[1]: True, ids[2]: False, ids[3]: False}
    return ids, verdad


class TestScorecard:
    def test_perfect_model_scores_one(self, lote):
        ids, verdad = lote
        E, N = VerdictValue.EXPLOITABLE, VerdictValue.NOT_EXPLOITABLE
        c = Comparison(execution_id=uuid4(), runs=[
            run("perfecto", {ids[0]: E, ids[1]: E, ids[2]: N, ids[3]: N})])
        f = _scorecard(c, verdad)[0]
        assert f["f1"] == 1.0
        assert f["verdaderos_positivos"] == 2
        assert f["falsos_positivos"] == 0

    def test_model_that_accepts_everything_is_exposed(self, lote):
        """Declarar explotable a todo da exhaustividad perfecta y precisión de
        0.5. Solo la matriz completa lo delata; la exactitud sola, no."""
        ids, verdad = lote
        E = VerdictValue.EXPLOITABLE
        c = Comparison(execution_id=uuid4(), runs=[
            run("complaciente", {i: E for i in ids})])
        f = _scorecard(c, verdad)[0]
        assert f["exhaustividad"] == 1.0
        assert f["precision"] == 0.5
        assert f["falsos_positivos"] == 2

    def test_model_that_discards_everything(self, lote):
        ids, verdad = lote
        N = VerdictValue.NOT_EXPLOITABLE
        c = Comparison(execution_id=uuid4(), runs=[
            run("severo", {i: N for i in ids})])
        f = _scorecard(c, verdad)[0]
        assert f["falsos_negativos"] == 2
        assert f["exhaustividad"] == 0.0

    def test_verdicts_without_truth_are_left_out(self, lote):
        """Un hallazgo sin etiqueta no se cuenta ni a favor ni en contra."""
        ids, verdad = lote
        ajeno = uuid4()
        E = VerdictValue.EXPLOITABLE
        c = Comparison(execution_id=uuid4(), runs=[
            run("con ruido", {ids[0]: E, ids[1]: E, ajeno: E})])
        f = _scorecard(c, verdad)[0]
        assert f["veredictos"] == 3
        assert f["contrastados"] == 2

    def test_one_row_per_repetition(self, lote):
        ids, verdad = lote
        E, N = VerdictValue.EXPLOITABLE, VerdictValue.NOT_EXPLOITABLE
        c = Comparison(execution_id=uuid4(), runs=[
            run("m", {ids[0]: E, ids[2]: N}, repeticion=1),
            run("m", {ids[0]: E, ids[2]: E}, repeticion=2),
            run("m", {ids[0]: E, ids[2]: N}, repeticion=3),
        ])
        filas = _scorecard(c, verdad)
        assert [f["repeticion"] for f in filas] == [1, 2, 3]
        assert filas[1]["falsos_positivos"] == 1


class TestAbstention:
    """Abstenerse no es afirmar que el hallazgo sea un falso positivo.

    El modelo responde "indeterminado" cuando el fragmento no le alcanza para
    decidir. Contar esa respuesta como "no explotable" le atribuye una
    afirmación que no hizo: infla los falsos negativos, hunde la exhaustividad
    y hace que un modelo prudente puntúe peor que uno que responde al azar.

    Lo que corresponde es medir sobre lo que el modelo sí resolvió, y declarar
    aparte qué proporción del lote dejó sin resolver. Sin ese segundo dato la
    primera cifra engaña, porque un modelo que solo se pronuncia sobre lo fácil
    sacaría una puntuación excelente sin servir para nada.
    """

    def test_abstention_is_not_counted_as_a_negative(self, lote):
        ids, verdad = lote
        E, U = VerdictValue.EXPLOITABLE, VerdictValue.UNDETERMINED
        c = Comparison(execution_id=uuid4(), runs=[
            run("prudente", {ids[0]: E, ids[1]: U, ids[2]: U, ids[3]: U})])
        f = _scorecard(c, verdad)[0]
        assert f["falsos_negativos"] == 0, "abstenerse no es negar"
        assert f["verdaderos_positivos"] == 1
        assert f["exhaustividad"] == 1.0

    def test_coverage_exposes_the_prudent_model(self, lote):
        """La puntuación alta sobre poco lote tiene que verse como tal."""
        ids, verdad = lote
        E, U = VerdictValue.EXPLOITABLE, VerdictValue.UNDETERMINED
        c = Comparison(execution_id=uuid4(), runs=[
            run("prudente", {ids[0]: E, ids[1]: U, ids[2]: U, ids[3]: U})])
        f = _scorecard(c, verdad)[0]
        assert f["f1"] == 1.0
        assert f["cobertura"] == 0.25
        assert f["abstenciones"] == 3
        assert f["resueltos"] == 1
        assert f["contrastados"] == 4

    def test_unverifiable_counts_as_abstention_too(self, lote):
        """Si el anclaje no se pudo comprobar, el veredicto no se usa."""
        ids, verdad = lote
        E, NV = VerdictValue.EXPLOITABLE, VerdictValue.NOT_VERIFIABLE
        c = Comparison(execution_id=uuid4(), runs=[
            run("sin anclar", {ids[0]: E, ids[1]: NV, ids[2]: NV, ids[3]: NV})])
        f = _scorecard(c, verdad)[0]
        assert f["abstenciones"] == 3
        assert f["cobertura"] == 0.25

    def test_a_model_that_never_commits(self, lote):
        ids, verdad = lote
        U = VerdictValue.UNDETERMINED
        c = Comparison(execution_id=uuid4(), runs=[run("mudo", {i: U for i in ids})])
        f = _scorecard(c, verdad)[0]
        assert f["cobertura"] == 0.0
        assert f["f1"] == 0.0
        assert f["resueltos"] == 0


class TestAgreement:
    def test_unstable_model_shows_it(self, lote):
        """La estabilidad es el criterio de fiabilidad: tres corridas idénticas
        que no coinciden invalidan el veredicto aunque acierten de media."""
        ids, _ = lote
        E, N = VerdictValue.EXPLOITABLE, VerdictValue.NOT_EXPLOITABLE
        c = Comparison(execution_id=uuid4(), runs=[
            run("m", {ids[0]: E, ids[1]: E}, repeticion=1),
            run("m", {ids[0]: E, ids[1]: N}, repeticion=2),
        ])
        assert c.agreement() == 0.5
        assert len(c.disagreements()) == 1


class TestCsv:
    def test_written_file_can_be_read_back(self, lote, tmp_path):
        ids, verdad = lote
        E, N = VerdictValue.EXPLOITABLE, VerdictValue.NOT_EXPLOITABLE
        c = Comparison(execution_id=uuid4(), runs=[
            run("uno", {ids[0]: E, ids[2]: N}, usd=1.25),
            run("dos", {ids[0]: N, ids[2]: N}, usd=0.5),
        ])
        destino = tmp_path / "spoc.csv"
        write_scorecard(destino, _scorecard(c, verdad))
        filas = list(csv.DictReader(destino.open(encoding="utf-8")))
        assert [f["modelo"] for f in filas] == ["uno", "dos"]
        assert float(filas[0]["usd"]) == 1.25
        assert "f1" in filas[0]


class TestScriptedModel:
    def test_the_double_answers_in_order(self):
        """Se apoya en el modelo guionado, que devuelve respuestas escritas de
        antemano. Permite ejercitar la cadena sin proveedor ni gasto."""
        from src.finding_validation.domain.services.language_model_port import (
            ModelJudgement,
        )
        from src.finding_validation.infrastructure.external.scripted_language_model import (
            ScriptedLanguageModel,
        )

        guion = [ModelJudgement("explotable", "cita la línea 12", (12,)),
                 ModelJudgement("no_explotable", "está saneado", (14,))]
        modelo = ScriptedLanguageModel(guion, model_name="guionado")
        assert modelo.model_name == "guionado"
        assert len(modelo.script) == 2
        assert modelo.script == deque(guion)


class TestArrayResponse:
    """Un proveedor puede contestar cualquier cosa, y una sola respuesta rara
    no puede costar una corrida entera.

    El 15 de setiembre un modelo devolvió el veredicto envuelto en un arreglo.
    El parser asumía diccionario, la excepción no estaba entre las previstas y
    se llevó por delante la comparación completa tras siete dólares y medio ya
    gastados. Los veredictos se conservaron porque se guardan uno a uno, pero el
    cuadro de resultados se perdió.
    """

    @staticmethod
    def parse(texto):
        from src.finding_validation.infrastructure.external.chat_completions_language_model import (
            parse_judgement,
        )
        return parse_judgement(texto, 10, 10, 5)

    def test_a_single_element_array_is_unwrapped(self):
        crudo = ('[{"value": "explotable", "justification_text": "linea 12", '
                 '"cited_lines": [12], "confidence": 0.9}]')
        assert self.parse(crudo).value == "explotable"

    def test_a_longer_array_is_a_contract_violation_not_a_crash(self):
        import pytest

        from src.finding_validation.infrastructure.external.chat_completions_language_model import (
            ModelContractViolation,
        )
        crudo = '[{"value": "explotable"}, {"value": "no_explotable"}]'
        with pytest.raises(ModelContractViolation):
            self.parse(crudo)

    def test_a_bare_array_is_a_contract_violation(self):
        import pytest

        from src.finding_validation.infrastructure.external.chat_completions_language_model import (
            ModelContractViolation,
        )
        with pytest.raises(ModelContractViolation):
            self.parse('[1, 2, 3]')
