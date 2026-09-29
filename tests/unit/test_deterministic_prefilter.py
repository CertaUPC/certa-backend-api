"""La señal que precede a la consulta, y que ya no decide por su cuenta.

Esta etapa resolvía: si reconocía un saneador antes del punto sensible, daba el
hallazgo por no explotable y no lo consultaba. Sobre el conjunto con verdad
conocida resolvió ocho alertas de cien y las ocho eran vulnerabilidades reales,
porque que el nombre de un saneador aparezca antes en el texto no demuestra que
el dato contaminado lo atraviese.

Lo que estas pruebas vigilan ahora es que ningún camino vuelva a producir un
descarte sin consultar. Un falso negativo así no lo delata ninguna métrica del
modelo: el hallazgo no llega al modelo y no hay veredicto que contrastar. La
lectura de la traza se conserva como señal auditable, que es lo que una etapa
con seguimiento de contaminación podrá convertir algún día en decisión.
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


class TestNingunCaminoResuelve:
    """La propiedad que sostiene el cambio: ninguna entrada evita la consulta."""

    def test_el_saneador_antes_del_sumidero_ya_no_resuelve(self, filtro):
        d = filtro.decide(hallazgo(), contexto(ANTES, ("encodeForSQL",)))
        assert d.outcome is PrefilterOutcome.ESCALATE_WITH_SIGNAL
        assert d.has_sanitizer_signal

    def test_todo_hallazgo_gasta_consulta(self, filtro):
        """Se comprueba sobre las cuatro entradas posibles, y no sobre una:
        basta que una sola evite el modelo para que vuelva el falso negativo
        silencioso."""
        entradas = [
            contexto(ANTES, ("encodeForSQL",)),
            contexto(DESPUES, ("encodeForSQL",)),
            contexto(SIN_SANEADOR, ()),
            contexto(ANTES, ("encodeForSQL",), degradado=True),
        ]
        for ctx in entradas:
            assert filtro.decide(hallazgo(), ctx).spends_budget

    def test_la_señal_nombra_el_saneador_y_declara_su_limite(self, filtro):
        """Quien audite la validación tiene que ver en qué se apoyó la señal y
        por qué no alcanza para decidir."""
        d = filtro.decide(hallazgo(), contexto(ANTES, ("encodeForSQL",)))
        assert "encodeForSQL" in d.reason
        assert "no demuestra que el dato lo atraviese" in d.reason


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
        assert d.outcome is PrefilterOutcome.ESCALATE_WITH_SIGNAL

    def test_un_sumidero_en_la_primera_linea_no_deja_señal(self, filtro):
        d = filtro.decide(hallazgo(linea=8), contexto(ANTES, ("encodeForSQL",)))
        assert d.outcome is PrefilterOutcome.ESCALATE_TO_MODEL


class TestLaExigenciaDeOrdenSePuedeApagar:
    def test_sin_exigir_orden_basta_la_presencia_para_la_señal(self, filtro):
        """La exigencia de orden sigue siendo configurable y sigue cambiando la
        señal, pero ya no cambia lo que se consulta: con la exigencia apagada,
        un saneador posterior al sumidero produce señal, y aun así el hallazgo
        va al modelo."""
        laxo = DeterministicPrefilter(require_sanitizer_before_sink=False)
        ctx = contexto(DESPUES, ("encodeForSQL",))
        suelto = laxo.decide(hallazgo(), ctx)
        estricto = filtro.decide(hallazgo(), ctx)
        assert suelto.outcome is PrefilterOutcome.ESCALATE_WITH_SIGNAL
        assert estricto.outcome is PrefilterOutcome.ESCALATE_TO_MODEL
        assert suelto.spends_budget and estricto.spends_budget
