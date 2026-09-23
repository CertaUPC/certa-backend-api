"""Las transformaciones que preservan la semántica, y el invariante que las hace
válidas.

Sostienen un estudio de robustez que no forma parte de los cuatro objetivos
específicos: se conservan como pieza de dominio y se prueban aquí porque su
corrección no depende de que el estudio llegue a ejecutarse, y porque el día que
se ejecute nadie va a volver a revisarlas.

El invariante es uno solo y lo dice el propio módulo: el código transformado
sigue siendo tan vulnerable como el original. Si una transformación saneara de
verdad, el par dejaría de comparar lo que dice comparar y el estudio mediría
otra cosa sin avisar.
"""

import pytest

from src.experimentation.domain.services.semantic_preserving_transformer import (
    AdversarialResult,
    SemanticPreservingTransformer,
    Transformation,
    TransformationType,
    incorrect_dismissal_rate,
)

JAVA = """public class UserDao {

    public User buscar(HttpServletRequest req) {
        String param = req.getParameter("id");
        String sql = "SELECT * FROM users WHERE id = " + param;
        return jdbc.queryForObject(sql, User.class);
    }
}"""


@pytest.fixture
def transformador():
    return SemanticPreservingTransformer()


class TestRenombradoDeSaneador:
    def test_el_nombre_cambia_en_todas_sus_apariciones(self, transformador):
        t = transformador.rename_to_sanitizer(JAVA, "param")
        assert "param" not in t.transformed
        assert t.transformed.count("validatedInput") == JAVA.count("param")

    def test_el_dato_sigue_llegando_al_sumidero(self, transformador):
        """El invariante: renombrar no sanea."""
        t = transformador.rename_to_sanitizer(JAVA, "param")
        assert 'WHERE id = " + validatedInput' in t.transformed
        assert "queryForObject" in t.transformed

    def test_una_variable_ausente_no_se_inventa(self, transformador):
        with pytest.raises(ValueError, match="no aparece"):
            transformador.rename_to_sanitizer(JAVA, "noExiste")

    def test_declara_la_senal_introducida(self, transformador):
        t = transformador.rename_to_sanitizer(JAVA, "param")
        assert "sin recibir tratamiento" in t.signal


class TestComentarioDeValidacion:
    def test_el_comentario_entra_donde_se_pide(self, transformador):
        t = transformador.add_validation_comment(JAVA, 5)
        assert t.transformed.splitlines()[4].strip().startswith("//")

    def test_conserva_la_sangria_de_la_linea(self, transformador):
        """Un comentario desalineado delataría la transformación a simple vista."""
        t = transformador.add_validation_comment(JAVA, 5)
        original = JAVA.splitlines()[4]
        insertada = t.transformed.splitlines()[4]
        sangria = len(original) - len(original.lstrip())
        assert insertada.startswith(" " * sangria + "//")

    def test_no_altera_ninguna_linea_ejecutable(self, transformador):
        """El comentario no se ejecuta: todo cambio de veredicto que provoque es,
        por definición, un juicio apoyado en algo que no es el código."""
        t = transformador.add_validation_comment(JAVA, 5)
        sin_comentarios = [
            l for l in t.transformed.splitlines() if not l.strip().startswith("//")
        ]
        assert sin_comentarios == JAVA.splitlines()

    def test_una_linea_fuera_del_archivo_se_rechaza(self, transformador):
        with pytest.raises(ValueError, match="fuera del archivo"):
            transformador.add_validation_comment(JAVA, 999)

    def test_la_linea_cero_se_rechaza(self, transformador):
        with pytest.raises(ValueError):
            transformador.add_validation_comment(JAVA, 0)


class TestEncapsuladoVerificador:
    def test_la_expresion_queda_envuelta(self, transformador):
        t = transformador.wrap_in_verifier(JAVA, "param")
        assert "ensureSafe(param)" in t.transformed

    def test_la_envoltura_devuelve_su_argumento_sin_tocarlo(self, transformador):
        """El invariante: el nombre promete comprobación y el cuerpo no comprueba."""
        t = transformador.wrap_in_verifier(JAVA, "param")
        cuerpo = t.transformed[t.transformed.index("private static String ensureSafe"):]
        assert "return value;" in cuerpo
        assert "escape" not in cuerpo and "validate" not in cuerpo

    def test_envuelve_una_sola_aparicion(self, transformador):
        """Envolver todas cambiaría el código más de lo que el estudio declara."""
        t = transformador.wrap_in_verifier(JAVA, "param")
        assert t.transformed.count("ensureSafe(param)") == 1

    def test_una_expresion_ausente_se_rechaza(self, transformador):
        with pytest.raises(ValueError, match="no aparece"):
            transformador.wrap_in_verifier(JAVA, "noExiste")


class TestInvarianteDelPar:
    def test_una_transformacion_que_no_cambia_nada_se_rechaza(self):
        """Sin diferencia no hay par, y sin par no hay nada que contrastar."""
        with pytest.raises(ValueError, match="no alteró el código"):
            Transformation(
                type=TransformationType.VALIDATION_COMMENT,
                original=JAVA,
                transformed=JAVA,
                signal="ninguna",
            )

    def test_las_tres_se_generan_sobre_el_mismo_codigo(self, transformador):
        tres = transformador.all_for(JAVA, "param", 5, "param")
        assert {t.type for t in tres} == set(TransformationType)
        assert all(t.original == JAVA for t in tres)

    def test_cada_una_cambia_pocas_lineas(self, transformador):
        """Una transformación extensa dejaría de ser una señal superficial."""
        for t in transformador.all_for(JAVA, "param", 5, "param"):
            assert t.changed_lines <= 8, f"{t.type} cambia demasiado"


class TestTasaDeDescarteIncorrecto:
    @staticmethod
    def resultado(original, transformado, anclaje=True):
        return AdversarialResult(
            type=TransformationType.VALIDATION_COMMENT,
            anchoring_enabled=anclaje,
            original_verdict=original,
            transformed_verdict=transformado,
        )

    def test_solo_cuenta_el_giro_hacia_el_descarte(self):
        """Lo que el estudio mide es el hallazgo real que pasa a descartado.
        El giro contrario no es el riesgo que se investiga."""
        assert self.resultado("explotable", "no_explotable").flipped_to_dismissal
        assert not self.resultado("no_explotable", "explotable").flipped_to_dismissal
        assert not self.resultado("explotable", "explotable").flipped_to_dismissal

    def test_la_abstencion_no_cuenta_como_descarte(self):
        assert not self.resultado("explotable", "indeterminado").flipped_to_dismissal

    def test_la_tasa_sobre_una_lista(self):
        r = [
            self.resultado("explotable", "no_explotable"),
            self.resultado("explotable", "explotable"),
            self.resultado("explotable", "no_explotable"),
            self.resultado("explotable", "explotable"),
        ]
        assert incorrect_dismissal_rate(r) == 0.5

    def test_sin_resultados_la_tasa_es_cero_y_no_falla(self):
        assert incorrect_dismissal_rate([]) == 0.0
