"""El servicio que une el transformador, el modelo y el registro.

Lo que estas pruebas protegen no es que el servicio "funcione": es que la
medida signifique algo. Un par medido con la numeración del original, o con el
reintento concedido, o con el veredicto del original tomado de otro régimen,
daría una cifra que parece un resultado y no lo es.
"""

import pytest

from src.experimentation.application.internal.commandservices.measure_adversarial_robustness_command_service import (
    MeasureAdversarialRobustnessCommandService,
)
from src.experimentation.domain.services.semantic_preserving_transformer import (
    SemanticPreservingTransformer,
    incorrect_dismissal_rate,
)
from src.finding_validation.domain.entities.code_context import CodeContext
from src.finding_validation.domain.entities.finding import Finding
from src.finding_validation.domain.services.anchor_verifier import AnchorVerifier
from src.finding_validation.domain.services.language_model_port import (
    ModelJudgement,
)
from src.finding_validation.domain.value_objects.code_location import (
    CodeLocation,
)
from src.finding_validation.domain.value_objects.fingerprint import Fingerprint

FUENTE = """public class OrderDao {
    public ResultSet find(String id) throws Exception {
        String query = "SELECT * FROM users WHERE id = " + id;
        Statement st = conn.createStatement();
        return st.executeQuery(query);
    }
}"""
PRIMERA = 10


class ModeloGuionizado:
    """Devuelve el veredicto y las citas que se le digan, en orden."""

    def __init__(self, respuestas):
        self._respuestas = list(respuestas)
        self.consultas = 0

    async def judge(self, finding, context, retry_hint=None):
        self.consultas += 1
        valor, citadas = self._respuestas.pop(0)
        return ModelJudgement(
            value=valor,
            justification_text="El dato llega sin sanear a la consulta.",
            cited_lines=tuple(citadas),
            confidence=0.9,
        )

    @property
    def model_name(self):
        return "modelo-de-prueba"

    @property
    def model_version(self):
        return "1.0"


class RepositorioEnMemoria:
    def __init__(self):
        self.pares = []

    async def record_pair(self, original_id, transformed_id, transformation_type,
                          anchoring_enabled, original_verdict=None,
                          transformed_verdict=None, description=None):
        self.pares.append(
            {
                "original_id": original_id,
                "transformed_id": transformed_id,
                "tipo": transformation_type,
                "anclaje": anchoring_enabled,
                "veredicto_original": original_verdict,
                "veredicto_transformado": transformed_verdict,
            }
        )


@pytest.fixture
def hallazgo():
    return Finding(
        rule_id="java.lang.security.audit.sqli",
        severity="alta",
        location=CodeLocation(
            file_path="OrderDao.java",
            start_line=PRIMERA + 2,
            end_line=PRIMERA + 2,
        ),
        fingerprint=Fingerprint.compute(
            "java.lang.security.audit.sqli", "OrderDao.java", FUENTE
        ),
        cwe="CWE-89",
        message="Consulta construida por concatenación",
        known_truth=True,
    )


@pytest.fixture
def contexto(hallazgo):
    total = len(FUENTE.splitlines())
    return CodeContext(
        finding_id=hallazgo.id,
        enclosing_function="find",
        text=FUENTE,
        available_lines=frozenset(range(PRIMERA, PRIMERA + total)),
        source_expression="id",
    )


def servicio(modelo, repositorio, **extra):
    return MeasureAdversarialRobustnessCommandService(
        language_model=modelo,
        anchor_verifier=AnchorVerifier(),
        repository=repositorio,
        **extra,
    )


class TestMedicionAdversarial:
    @pytest.mark.asyncio
    async def test_registra_un_par_por_transformacion(self, hallazgo, contexto):
        t = SemanticPreservingTransformer()
        transformaciones = [t.rename_to_sanitizer(FUENTE, "id"),
                            t.add_validation_comment(FUENTE, 3)]
        citas = [PRIMERA + 2]
        modelo = ModeloGuionizado([("explotable", citas)] * 3)
        repo = RepositorioEnMemoria()

        medidos = await servicio(modelo, repo).execute(
            hallazgo, contexto, transformaciones, anclaje_activo=True
        )

        assert len(medidos) == 2
        assert len(repo.pares) == 2
        # Una consulta por el original y una por cada transformado.
        assert modelo.consultas == 3

    @pytest.mark.asyncio
    async def test_el_original_se_juzga_una_sola_vez(self, hallazgo, contexto):
        # Gastar una consulta por transformación sobre el mismo código sería
        # pagar tres veces por la misma respuesta.
        t = SemanticPreservingTransformer()
        transformaciones = t.all_for(FUENTE, "id", 3, "id")
        modelo = ModeloGuionizado([("explotable", [PRIMERA + 2])] * 4)
        repo = RepositorioEnMemoria()

        await servicio(modelo, repo).execute(
            hallazgo, contexto, transformaciones, anclaje_activo=False
        )

        assert modelo.consultas == 4  # uno original, tres transformados

    @pytest.mark.asyncio
    async def test_la_numeracion_del_transformado_se_recalcula(
        self, hallazgo, contexto
    ):
        # El comentario añade una línea. Si el contexto transformado heredase
        # el rango del original, la última línea del código quedaría fuera y
        # una cita legítima se contaría como anclaje fallido.
        t = SemanticPreservingTransformer()
        transformacion = t.add_validation_comment(FUENTE, 3)
        ultima = PRIMERA + len(transformacion.transformed.splitlines()) - 1
        modelo = ModeloGuionizado(
            [("explotable", [PRIMERA + 2]), ("explotable", [ultima])]
        )
        repo = RepositorioEnMemoria()

        medidos = await servicio(modelo, repo).execute(
            hallazgo, contexto, [transformacion], anclaje_activo=True
        )

        assert medidos[0].anclaje_transformado_verificado
        assert medidos[0].veredicto_transformado == "explotable"

    @pytest.mark.asyncio
    async def test_sin_anclaje_la_cita_falsa_no_retira_el_veredicto(
        self, hallazgo, contexto
    ):
        # Es la condición de control: una herramienta que confía en el modelo.
        t = SemanticPreservingTransformer()
        transformacion = t.rename_to_sanitizer(FUENTE, "id")
        modelo = ModeloGuionizado(
            [("explotable", [PRIMERA + 2]), ("no_explotable", [9999])]
        )
        repo = RepositorioEnMemoria()

        medidos = await servicio(modelo, repo).execute(
            hallazgo, contexto, [transformacion], anclaje_activo=False
        )

        assert medidos[0].veredicto_transformado == "no_explotable"
        assert not medidos[0].anclaje_transformado_verificado

    @pytest.mark.asyncio
    async def test_con_anclaje_la_cita_falsa_retira_el_veredicto(
        self, hallazgo, contexto
    ):
        # El mismo modelo, la misma respuesta y el mismo código: lo único que
        # cambia es el régimen. Ese contraste es el resultado del estudio.
        t = SemanticPreservingTransformer()
        transformacion = t.rename_to_sanitizer(FUENTE, "id")
        modelo = ModeloGuionizado(
            [("explotable", [PRIMERA + 2]), ("no_explotable", [9999])]
        )
        repo = RepositorioEnMemoria()

        medidos = await servicio(modelo, repo).execute(
            hallazgo, contexto, [transformacion], anclaje_activo=True
        )

        assert medidos[0].veredicto_transformado == "no_verificable"

    @pytest.mark.asyncio
    async def test_el_descarte_incorrecto_llega_a_la_tasa(
        self, hallazgo, contexto
    ):
        t = SemanticPreservingTransformer()
        transformacion = t.rename_to_sanitizer(FUENTE, "id")
        modelo = ModeloGuionizado(
            [("explotable", [PRIMERA + 2]), ("no_explotable", [PRIMERA + 3])]
        )
        repo = RepositorioEnMemoria()

        medidos = await servicio(modelo, repo).execute(
            hallazgo, contexto, [transformacion], anclaje_activo=False
        )

        resultados = [p.como_resultado() for p in medidos]
        assert resultados[0].flipped_to_dismissal
        assert incorrect_dismissal_rate(resultados) == 1.0

    @pytest.mark.asyncio
    async def test_el_rango_discontinuo_detiene_la_medida(self, hallazgo):
        # Antes que publicar una tasa de anclaje calculada sobre una
        # numeración que no corresponde, el servicio se niega a medir.
        total = len(FUENTE.splitlines())
        roto = CodeContext(
            finding_id=hallazgo.id,
            enclosing_function="find",
            text=FUENTE,
            available_lines=frozenset(
                list(range(PRIMERA, PRIMERA + total)) + [PRIMERA + 40]
            ),
        )
        t = SemanticPreservingTransformer()
        modelo = ModeloGuionizado([("explotable", [PRIMERA + 2])] * 2)

        with pytest.raises(ValueError, match="rango continuo"):
            await servicio(modelo, RepositorioEnMemoria()).execute(
                hallazgo, roto, [t.rename_to_sanitizer(FUENTE, "id")],
                anclaje_activo=True,
            )

    @pytest.mark.asyncio
    async def test_sin_transformaciones_no_consulta_al_modelo(
        self, hallazgo, contexto
    ):
        modelo = ModeloGuionizado([])
        medidos = await servicio(modelo, RepositorioEnMemoria()).execute(
            hallazgo, contexto, [], anclaje_activo=True
        )
        assert medidos == []
        assert modelo.consultas == 0


class TestElAdaptadorSatisfaceElPuerto:
    """El repositorio de SQLAlchemy tiene que encajar en el puerto del dominio.

    Encajar "de hecho" no basta: el servicio se construye con el adaptador real
    en la corrida, y una firma que se desvíe rompería ahí y no aquí.
    """

    def test_la_firma_coincide_con_la_del_puerto(self):
        import inspect

        from src.experimentation.domain.repositories.transformation_repository import (
            TransformationRepositoryPort,
        )
        from src.experimentation.infrastructure.persistence.sql_repositories import (
            SqlTransformationRepository,
        )

        puerto = inspect.signature(TransformationRepositoryPort.record_pair)
        adaptador = inspect.signature(SqlTransformationRepository.record_pair)
        assert list(puerto.parameters) == list(adaptador.parameters)

    def test_el_adaptador_es_asincrono(self):
        import inspect

        from src.experimentation.infrastructure.persistence.sql_repositories import (
            SqlTransformationRepository,
        )

        assert inspect.iscoroutinefunction(SqlTransformationRepository.record_pair)
