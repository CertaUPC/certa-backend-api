"""El filtro que resuelve sin gastar una consulta.

Su regla de conducta está escrita en el propio módulo y es asimétrica a
propósito: resolver de más produce falsos negativos silenciosos, mientras que
escalar de más solo cuesta dinero. Ante la duda, escala.

Esa asimetría es lo que estas pruebas vigilan. Un filtro que se vuelva
optimista descartaría vulnerabilidades reales sin que ninguna métrica lo
delate, porque el hallazgo ni siquiera llegaría al modelo y no habría veredicto
que contrastar.
"""

import pytest

from src.finding_validation.domain.entities.code_context import CodeContext
from src.finding_validation.domain.entities.finding import Finding
from src.finding_validation.domain.services.deterministic_prefilter import (
    DeterministicPrefilter,
    PrefilterOutcome,
)
from src.finding_validation.domain.value_objects.code_location import CodeLocation
from src.finding_validation.domain.value_objects.fingerprint import Fingerprint

SUMIDERO = 12


def hallazgo(linea: int = SUMIDERO) -> Finding:
    loc = CodeLocation(file_path="UserDao.java", start_line=linea, end_line=linea)
    return Finding(
        rule_id="java.sqli",
        severity="error",
        location=loc,
        fingerprint=Fingerprint.compute("java.sqli", "UserDao.java", "cuerpo"),
        cwe="CWE-89",
    )


def contexto(texto: str, saneadores: tuple[str, ...], degradado: bool = False):
    lineas = frozenset(
        int(l.split(":")[0]) for l in texto.splitlines() if l.split(":")[0].strip().isdigit()
    )
    return CodeContext(
        finding_id=hallazgo().id,
        enclosing_function="buscar",
        text=texto,
        available_lines=lineas or frozenset({SUMIDERO}),
        sanitizers=saneadores,
        degraded_to_file=degradado,
    )


ANTES = """8: String param = req.getParameter("id");
9: String limpio = ESAPI.encoder().encodeForSQL(param);
12: st.execute("SELECT * FROM t WHERE c = '" + limpio + "'");"""

DESPUES = """8: String param = req.getParameter("id");
12: st.execute("SELECT * FROM t WHERE c = '" + param + "'");
14: String tarde = ESAPI.encoder().encodeForSQL(param);"""

SIN_SANEADOR = """8: String param = req.getParameter("id");
12: st.execute("SELECT * FROM t WHERE c = '" + param + "'");"""


@pytest.fixture
def filtro():
    return DeterministicPrefilter()


class TestResuelvePorRegla:
    def test_saneador_antes_del_sumidero(self, filtro):
        d = filtro.decide(hallazgo(), contexto(ANTES, ("encodeForSQL",)))
        assert d.outcome is PrefilterOutcome.RESOLVED_BY_RULE

    def test_lo_resuelto_no_gasta_presupuesto(self, filtro):
        """Es la razón de existir del filtro: el hallazgo no llega al modelo."""
        d = filtro.decide(hallazgo(), contexto(ANTES, ("encodeForSQL",)))
        assert not d.spends_budget

    def test_la_razon_nombra_el_saneador(self, filtro):
        """Quien audite la decisión tiene que poder ver en qué se apoyó."""
        d = filtro.decide(hallazgo(), contexto(ANTES, ("encodeForSQL",)))
        assert "encodeForSQL" in d.reason


class TestEscalaAlModelo:
    def test_sin_saneador_en_la_traza(self, filtro):
        d = filtro.decide(hallazgo(), contexto(SIN_SANEADOR, ()))
        assert d.outcome is PrefilterOutcome.ESCALATE_TO_MODEL
        assert d.spends_budget

    def test_saneador_despues_del_sumidero_no_sirve(self, filtro):
        """Sanear después de usar el dato no sanea nada. Confundir la presencia
        del saneador con su efecto es el error que este filtro no puede cometer."""
        d = filtro.decide(hallazgo(), contexto(DESPUES, ("encodeForSQL",)))
        assert d.outcome is PrefilterOutcome.ESCALATE_TO_MODEL
        assert "antes del punto sensible" in d.reason

    def test_saneador_en_la_misma_linea_del_sumidero_no_basta(self, filtro):
        """La comparación es estricta: en la misma línea no se puede establecer
        el orden, y el criterio del filtro ante la duda es escalar."""
        texto = """8: String param = req.getParameter("id");
12: st.execute(ESAPI.encoder().encodeForSQL(param));"""
        d = filtro.decide(hallazgo(), contexto(texto, ("encodeForSQL",)))
        assert d.outcome is PrefilterOutcome.ESCALATE_TO_MODEL

    def test_contexto_degradado_siempre_escala(self, filtro):
        """Sin función contenedora identificada no hay traza que ordenar,
        aunque el saneador aparezca en el texto."""
        d = filtro.decide(
            hallazgo(), contexto(ANTES, ("encodeForSQL",), degradado=True)
        )
        assert d.outcome is PrefilterOutcome.ESCALATE_TO_MODEL
        assert "degradado" in d.reason


class TestElOrdenSeLeeDeLaNumeracion:
    def test_lineas_sin_numero_no_rompen_el_recorrido(self, filtro):
        """El contexto trae líneas en blanco entre bloques cuando se recuperan
        el método y su llamado."""
        texto = """8: String param = req.getParameter("id");

9: String limpio = ESAPI.encoder().encodeForSQL(param);

12: st.execute("..." + limpio);"""
        d = filtro.decide(hallazgo(), contexto(texto, ("encodeForSQL",)))
        assert d.outcome is PrefilterOutcome.RESOLVED_BY_RULE

    def test_un_sumidero_en_la_primera_linea_no_puede_resolverse(self, filtro):
        d = filtro.decide(hallazgo(linea=8), contexto(ANTES, ("encodeForSQL",)))
        assert d.outcome is PrefilterOutcome.ESCALATE_TO_MODEL


class TestLaReglaSePuedeApagar:
    def test_sin_exigir_orden_basta_la_presencia(self, filtro):
        """La exigencia de orden es configurable, y apagarla vuelve al filtro
        más optimista. Se prueba para que el efecto quede a la vista de quien
        decida apagarla."""
        laxo = DeterministicPrefilter(require_sanitizer_before_sink=False)
        estricto = filtro
        ctx = contexto(DESPUES, ("encodeForSQL",))
        assert laxo.decide(hallazgo(), ctx).outcome is PrefilterOutcome.RESOLVED_BY_RULE
        assert (
            estricto.decide(hallazgo(), ctx).outcome
            is PrefilterOutcome.ESCALATE_TO_MODEL
        )
