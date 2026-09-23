"""Traza, precómputo de sesión y comparación entre modelos."""

from collections import deque
from pathlib import Path
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import src.shared.database_experiment  # noqa: F401  (registra sus tablas)
from src.finding_validation.application.internal.commandservices.compare_models_command_service import (
    CompareModelsCommandService,
)
from src.finding_validation.application.internal.commandservices.prepare_session_command_service import (
    PrepareSessionCommandService,
)
from src.finding_validation.application.internal.commandservices.run_execution_command_service import (
    RunExecutionCommandService,
)
from src.finding_validation.application.internal.commandservices.validate_finding_command_service import (
    ValidateFindingCommandService,
)
from src.finding_validation.domain.entities.execution import Execution
from src.finding_validation.domain.entities.finding import Finding
from src.finding_validation.domain.entities.verdict import VerdictValue
from src.finding_validation.domain.services.anchor_verifier import AnchorVerifier
from src.finding_validation.domain.services.budget_guard import BudgetGuard
from src.finding_validation.domain.services.deterministic_prefilter import (
    DeterministicPrefilter,
)
from src.finding_validation.domain.services.priority_calculator import (
    PriorityCalculator,
)
from src.finding_validation.domain.value_objects.code_location import CodeLocation
from src.finding_validation.domain.value_objects.fingerprint import Fingerprint
from src.finding_validation.domain.value_objects.prompt_version import (
    OUTPUT_CONTRACT_V1,
    PromptVersion,
)
from src.finding_validation.infrastructure.external.chat_completions_language_model import (
    ModelContractViolation,
)
from src.finding_validation.infrastructure.external.code_reader_registry import (
    CodeReaderRegistry,
)
from src.finding_validation.infrastructure.external.scripted_language_model import (
    ScriptedLanguageModel,
    exploitable,
    not_exploitable,
)
from src.finding_validation.infrastructure.persistence.sql_repositories import (
    SqlCodeContextRepository,
    SqlExecutionRepository,
    SqlFindingRepository,
    SqlVerdictRepository,
)
from src.shared.database import Base, FindingRow, ProjectRow

# Registra la tabla de cuentas, que executions referencia por clave
# foránea. Sin esto el archivo pasa dentro de la suite, porque otro
# módulo la importa, y falla al correrlo solo.
import src.iam.infrastructure.persistence.models  # noqa: F401
from src.shared.tracing import (
    Stage,
    correlate,
    current_correlation_id,
    emit,
    install_memory_sink,
    timed,
)

PROJECT_ID = uuid4()

JAVA = """public class Dao {

    public User find(String id) {
        String q = "SELECT * FROM users WHERE id = " + id;
        return jdbc.queryForObject(q, User.class);
    }

    public User handle(String raw) {
        return find(raw);
    }
}
"""


# ══════════════════════════════════════════════════════ traza de eventos
class TestTracing:
    @pytest.fixture(autouse=True)
    def sink(self):
        s = install_memory_sink()
        s.clear()
        yield s
        s.clear()

    def test_events_share_the_correlation_id(self, sink):
        with correlate("abc123") as cid:
            emit(Stage.CONTEXT, "ok", lineas=42)
            emit(Stage.MODEL, "ok", tokens=100)
        assert cid == "abc123"
        assert len(sink.by_correlation("abc123")) == 2

    def test_correlation_does_not_leak_outside(self):
        with correlate("dentro"):
            assert current_correlation_id() == "dentro"
        assert current_correlation_id() is None

    def test_never_records_code_or_credentials(self, sink):
        with correlate("secreto"):
            emit(
                Stage.MODEL, "ok",
                api_key="sk-no-debe-aparecer",
                texto_contexto="String q = SELECT ...",
                hallazgo="f1",
            )
        evento = sink.by_correlation("secreto")[0]
        assert "api_key" not in evento.data
        assert "texto_contexto" not in evento.data
        assert evento.data["hallazgo"] == "f1"

    def test_long_strings_are_omitted(self, sink):
        with correlate("largo"):
            emit(Stage.CONTEXT, "ok", message="x" * 500)
        assert "omitidos" in sink.by_correlation("largo")[0].data["message"]

    def test_timed_records_duration(self, sink):
        with correlate("medido"), timed(Stage.ANCHOR, hallazgo="f1") as t:
            t["lineas"] = 3
        e = sink.by_correlation("medido")[0]
        assert e.duration_ms is not None
        assert e.data["lineas"] == 3

    def test_timed_records_the_failure_and_reraises(self, sink):
        with correlate("fallo"), pytest.raises(ValueError), timed(Stage.MODEL):
            raise ValueError("el proveedor cayó")
        e = sink.by_correlation("fallo")[0]
        assert e.outcome == "fallo"
        assert "el proveedor cayó" in (e.error or "")


# ═══════════════════════════════════════════════ precómputo y comparación
@pytest_asyncio.fixture
async def env(tmp_path: Path):
    (tmp_path / "Dao.java").write_text(JAVA, encoding="utf-8")
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)

    async with maker() as s:
        s.add(ProjectRow(id=str(PROJECT_ID), name="P", repository_path="/r"))
        await s.commit()

        execution = Execution(project_id=PROJECT_ID, ruleset_version="1.0")
        await SqlExecutionRepository(s).save(execution)

        findings = [
            Finding(
                rule_id="r.sqli",
                severity="error",
                location=CodeLocation("Dao.java", 4, 4),
                fingerprint=Fingerprint.compute("r.sqli", "Dao.java", f"cuerpo {n}"),
            )
            for n in range(4)
        ]
        await SqlFindingRepository(s).save_all(findings, execution.id)

        yield {
            "session": s,
            "execution": execution,
            "findings": findings,
            "root": tmp_path,
        }
    await engine.dispose()


def _validator(env, model, budget):
    return ValidateFindingCommandService(
        code_reader=CodeReaderRegistry(env["root"]),
        language_model=model,
        anchor_verifier=AnchorVerifier(),
        prefilter=DeterministicPrefilter(),
        budget=budget,
        prompt_version=PromptVersion.of("v1", "Juzga...", OUTPUT_CONTRACT_V1),
        verdict_cache={},
    )


class TestPrepareSession:
    async def test_precomputes_every_finding(self, env):
        model = ScriptedLanguageModel(deque([exploitable([4, 5]) for _ in range(10)]))
        budget = BudgetGuard(max_queries=50)
        service = PrepareSessionCommandService(
            SqlFindingRepository(env["session"]),
            SqlVerdictRepository(env["session"]),
            SqlCodeContextRepository(env["session"]),
            _validator(env, model, budget),
            budget,
        )
        report = await service.prepare(env["execution"])
        assert report.is_ready
        assert report.precomputed == 4

    async def test_batches_are_disjoint(self, env):
        model = ScriptedLanguageModel(deque([exploitable([4]) for _ in range(10)]))
        budget = BudgetGuard(max_queries=50)
        service = PrepareSessionCommandService(
            SqlFindingRepository(env["session"]),
            SqlVerdictRepository(env["session"]),
            SqlCodeContextRepository(env["session"]),
            _validator(env, model, budget),
            budget,
        )
        report = await service.prepare(env["execution"])
        assert report.plan.are_disjoint
        assert report.plan.total == 4

    async def test_split_is_deterministic(self, env):
        """El mismo lote produce siempre el mismo reparto."""
        model = ScriptedLanguageModel(deque([exploitable([4]) for _ in range(20)]))
        budget = BudgetGuard(max_queries=50)
        service = PrepareSessionCommandService(
            SqlFindingRepository(env["session"]),
            SqlVerdictRepository(env["session"]),
            SqlCodeContextRepository(env["session"]),
            _validator(env, model, budget),
            budget,
        )
        uno = await service.prepare(env["execution"])
        dos = await service.prepare(env["execution"])
        assert uno.plan.batch_a == dos.plan.batch_a

    async def test_second_run_reports_already_ready(self, env):
        model = ScriptedLanguageModel(deque([exploitable([4]) for _ in range(20)]))
        budget = BudgetGuard(max_queries=50)
        service = PrepareSessionCommandService(
            SqlFindingRepository(env["session"]),
            SqlVerdictRepository(env["session"]),
            SqlCodeContextRepository(env["session"]),
            _validator(env, model, budget),
            budget,
        )
        await service.prepare(env["execution"])
        segundo = await service.prepare(env["execution"])
        assert segundo.already_ready == 4
        assert segundo.precomputed == 0

    async def test_incomplete_batch_is_not_ready(self, env):
        """Un lote con huecos no se puede exponer a un participante."""
        model = ScriptedLanguageModel(deque([exploitable([4])]))
        budget = BudgetGuard(max_queries=1)
        service = PrepareSessionCommandService(
            SqlFindingRepository(env["session"]),
            SqlVerdictRepository(env["session"]),
            SqlCodeContextRepository(env["session"]),
            _validator(env, model, budget),
            budget,
        )
        report = await service.prepare(env["execution"])
        assert not report.is_ready
        assert "sin veredicto" in report.describe()


class TestCompareModels:
    def _service(self, env):
        return CompareModelsCommandService(
            SqlFindingRepository(env["session"]),
            SqlVerdictRepository(env["session"]),
            CodeReaderRegistry(env["root"]),
            AnchorVerifier(),
            DeterministicPrefilter(),
            PromptVersion.of("v1", "Juzga...", OUTPUT_CONTRACT_V1),
        )

    async def test_requires_two_models(self, env):
        model = ScriptedLanguageModel(deque([exploitable([4])]), "m1", "v1")
        with pytest.raises(ValueError, match="al menos dos"):
            await self._service(env).compare(env["execution"], [model])

    async def test_runs_every_model_on_the_same_batch(self, env):
        a = ScriptedLanguageModel(deque([exploitable([4]) for _ in range(8)]), "m1", "v1")
        b = ScriptedLanguageModel(deque([exploitable([4]) for _ in range(8)]), "m2", "v1")
        c = await self._service(env).compare(env["execution"], [a, b])
        assert len(c.runs) == 2
        assert {r.model for r in c.runs} == {"m1", "m2"}
        assert all(len(r.verdicts) == 4 for r in c.runs)

    async def test_only_the_given_batch_is_queried(self, env):
        """El lote que se paga tiene que ser el lote que se eligió.

        Si el servicio vuelve a leer todos los hallazgos de la ejecución, se
        consulta a un conjunto y se informan las etiquetas de otro: el gasto se
        va en hallazgos que no entran en la medición y el cuadro de resultados
        describe una muestra que nunca se corrió.
        """
        todos = await SqlFindingRepository(env["session"]).list_by_execution(
            env["execution"].id
        )
        assert len(todos) == 4, "la ejecución de prueba trae cuatro hallazgos"
        elegidos = todos[:2]

        a = ScriptedLanguageModel(deque([exploitable([4]) for _ in range(8)]), "m1", "v1")
        b = ScriptedLanguageModel(deque([exploitable([4]) for _ in range(8)]), "m2", "v1")
        c = await self._service(env).compare(
            env["execution"], [a, b], findings=elegidos
        )

        esperados = {f.id for f in elegidos}
        for r in c.runs:
            assert set(r.verdicts) == esperados
        assert a.call_count == 2

    async def test_empty_batch_is_refused(self, env):
        a = ScriptedLanguageModel(deque([exploitable([4])]), "m1", "v1")
        b = ScriptedLanguageModel(deque([exploitable([4])]), "m2", "v1")
        with pytest.raises(ValueError, match="vacío"):
            await self._service(env).compare(env["execution"], [a, b], findings=[])

    async def test_full_agreement(self, env):
        a = ScriptedLanguageModel(deque([exploitable([4]) for _ in range(8)]), "m1", "v1")
        b = ScriptedLanguageModel(deque([exploitable([4]) for _ in range(8)]), "m2", "v1")
        c = await self._service(env).compare(env["execution"], [a, b])
        assert c.agreement() == 1.0
        assert c.disagreements() == []

    async def test_disagreement_is_detected_and_listed(self, env):
        """Los desacuerdos son el dato interesante del estudio."""
        a = ScriptedLanguageModel(deque([exploitable([4]) for _ in range(8)]), "m1", "v1")
        b = ScriptedLanguageModel(
            deque([not_exploitable([4]) for _ in range(8)]), "m2", "v1"
        )
        c = await self._service(env).compare(env["execution"], [a, b])
        assert c.agreement() == 0.0
        assert len(c.disagreements()) == 4
        assert set(c.disagreements()[0]["por_corrida"]) == {"m1#1", "m2#1"}

    async def test_each_model_gets_its_own_budget(self, env):
        a = ScriptedLanguageModel(deque([exploitable([4]) for _ in range(8)]), "m1", "v1")
        b = ScriptedLanguageModel(deque([exploitable([4]) for _ in range(8)]), "m2", "v1")
        c = await self._service(env).compare(
            env["execution"], [a, b], max_queries_per_model=4
        )
        assert all(r.queries <= 4 for r in c.runs)
        assert all(r.queries == 4 for r in c.runs)

    async def test_hitting_the_cap_ends_that_run_not_the_comparison(self, env):
        """Agotar el tope de un modelo no puede tirar la comparación entera.

        El tope está por si una configuración mal puesta se desboca, no para
        abortar. Si al alcanzarlo se propaga el error, se pierde el cuadro de
        resultados de todos los modelos, incluidos los que ya terminaron y ya
        se pagaron, y lo medido se queda en la base sin que nadie lo lea.
        """
        a = ScriptedLanguageModel(deque([exploitable([4]) for _ in range(20)]), "m1", "v1")
        b = ScriptedLanguageModel(deque([exploitable([4]) for _ in range(20)]), "m2", "v1")
        c = await self._service(env).compare(
            env["execution"], [a, b], max_queries_per_model=2
        )
        assert len(c.runs) == 2, "los dos modelos tienen que aparecer en el cuadro"
        assert all(len(r.verdicts) == 2 for r in c.runs)
        assert all(r.budget_exhausted for r in c.runs)

    async def test_a_run_within_budget_is_not_marked_exhausted(self, env):
        a = ScriptedLanguageModel(deque([exploitable([4]) for _ in range(8)]), "m1", "v1")
        b = ScriptedLanguageModel(deque([exploitable([4]) for _ in range(8)]), "m2", "v1")
        c = await self._service(env).compare(env["execution"], [a, b])
        assert not any(r.budget_exhausted for r in c.runs)

    async def test_repetitions_do_not_reuse_verdicts(self, env):
        """Reutilizar entre repeticiones anularía lo que la repetición mide."""
        a = ScriptedLanguageModel(deque([exploitable([4]) for _ in range(20)]), "m1", "v1")
        b = ScriptedLanguageModel(deque([exploitable([4]) for _ in range(20)]), "m2", "v1")
        c = await self._service(env).compare(env["execution"], [a, b], repetitions=2)
        assert len(c.runs) == 4
        assert a.call_count == 8

    async def test_report_has_the_shape_the_interface_expects(self, env):
        a = ScriptedLanguageModel(deque([exploitable([4]) for _ in range(8)]), "m1", "v1")
        b = ScriptedLanguageModel(deque([exploitable([4]) for _ in range(8)]), "m2", "v1")
        r = (await self._service(env).compare(env["execution"], [a, b])).report()
        assert r["acuerdo"] == 1.0
        assert len(r["modelos"]) == 2
        assert "anclaje_primera" in r["modelos"][0]
        assert VerdictValue.EXPLOITABLE.value == "explotable"


# ═══════════════════════════════ una consulta fallida no se lleva el lote
class ModeloQueFallaUnaVez:
    """Responde bien salvo en la consulta indicada, donde rompe el contrato."""

    model_name = "modelo-que-falla"
    model_version = "v1"

    def __init__(self, falla_en: int) -> None:
        self._falla_en = falla_en
        self.consultas = 0

    async def judge(self, finding, context, retry_hint=None):
        self.consultas += 1
        if self.consultas == self._falla_en:
            raise ModelContractViolation("La respuesta no contiene ningún objeto JSON")
        return exploitable([4])


class TestUnaConsultaFallidaNoSeLlevaElLote:
    """Regresión de una corrida real sobre el conjunto de referencia.

    Una respuesta fuera de contrato subía sin atrapar desde el adaptador hasta
    el que recorre el lote. El lote moría ahí: los veredictos ya guardados se
    quedaban sin orden, la ejecución sin contar lo validado, y la corrida había
    que empezarla de nuevo aunque lo pagado siguiera en la base.
    """

    def _runner(self, env, modelo):
        sesion = env["session"]
        return RunExecutionCommandService(
            execution_repository=SqlExecutionRepository(sesion),
            finding_repository=SqlFindingRepository(sesion),
            context_repository=SqlCodeContextRepository(sesion),
            verdict_repository=SqlVerdictRepository(sesion),
            validator=_validator(env, modelo, BudgetGuard(max_queries=50)),
            budget=BudgetGuard(max_queries=50),
            priority_calculator=PriorityCalculator(),
            prompt_version="v1",
        )

    async def test_el_lote_continua_y_cuenta_el_fallo(self, env):
        modelo = ModeloQueFallaUnaVez(falla_en=2)
        informe = await self._runner(env, modelo).run(env["execution"])
        assert informe.failed == 1
        assert informe.validated == len(env["findings"]) - 1
        assert not informe.interrupted

    async def test_lo_validado_queda_ordenado(self, env):
        """El orden es lo que se perdía: sin él la lista priorizada no existe."""
        modelo = ModeloQueFallaUnaVez(falla_en=2)
        await self._runner(env, modelo).run(env["execution"])
        # La prioridad vive en la fila y no en la entidad: el dominio ordena,
        # la infraestructura guarda el orden.
        filas = (
            await env["session"].execute(
                select(FindingRow.priority).where(
                    FindingRow.execution_id == str(env["execution"].id)
                )
            )
        ).scalars()
        con_orden = [p for p in filas if p is not None]
        assert len(con_orden) == len(env["findings"]) - 1

    async def test_el_hallazgo_fallido_sigue_pendiente(self, env):
        """Queda para el siguiente intento, sin volver a pagar por los demás."""
        modelo = ModeloQueFallaUnaVez(falla_en=2)
        await self._runner(env, modelo).run(env["execution"])
        pendientes = await SqlFindingRepository(env["session"]).list_pending_validation(
            env["execution"].id
        )
        assert len(pendientes) == 1

    async def test_el_avance_cuenta_lo_guardado_y_no_lo_de_esta_corrida(self, env):
        """Dos corridas seguidas: la segunda no puede olvidar lo de la primera.

        El contador se llevaba sumando, de modo que una corrida que terminaba
        sin guardar la ejecución dejaba el avance por debajo de lo realmente
        validado, y con él el porcentaje y la decisión de darla por completa.
        """
        env["execution"].total_findings = len(env["findings"])
        primera = ModeloQueFallaUnaVez(falla_en=99)
        await self._runner(env, primera).run(env["execution"], batch_size=2)
        segunda = ModeloQueFallaUnaVez(falla_en=99)
        informe = await self._runner(env, segunda).run(env["execution"], batch_size=2)

        assert informe.validated == 2
        assert env["execution"].validated_findings == len(env["findings"])


# ═══════════════════════════ el trabajador toma lo que le toca
class LectorQueNoEncuentraNada:
    """Simula un trabajador cuyo repositorio no está donde lo busca."""

    async def recover_context(self, finding, caller_depth=2):
        raise FileNotFoundError(
            f"El archivo {finding.location.file_path} ya no existe en el repositorio"
        )


class TestElTrabajadorSoloTomaLoSuyo:
    """Dos arreglos que van juntos y protegen el mismo lote.

    El trabajador lee el código de SU disco. Sin filtro por proyecto reclama la
    ejecución de otro repositorio, y como el fallo de contexto se contaba por
    hallazgo y seguía, se comía el lote entero marcándolo todo como fallo. El
    trabajador que sí tenía ese código ya no lo encontraba, porque la ejecución
    había dejado de estar pendiente.
    """

    async def test_no_reclama_la_ejecucion_de_otro_proyecto(self, env):
        otro = uuid4()
        sesion = env["session"]
        sesion.add(ProjectRow(id=str(otro), name="Otro", repository_path="/otro"))
        await sesion.commit()

        ajena = Execution(project_id=otro, ruleset_version="1.0")
        repo = SqlExecutionRepository(sesion)
        await repo.save(ajena)

        # Atado al proyecto ajeno, no puede ver la del proyecto de la prueba.
        tomada = await repo.claim_next_pending("trabajador", project_id=otro)
        assert tomada is not None
        assert tomada.id == ajena.id

    async def test_sin_proyecto_toma_cualquiera(self, env):
        """El comportamiento de antes se conserva cuando no se ata a nada."""
        repo = SqlExecutionRepository(env["session"])
        tomada = await repo.claim_next_pending("trabajador")
        assert tomada is not None

    async def test_el_lote_vuelve_a_la_cola_si_no_encuentra_el_codigo(self, env):
        """Lo que antes consumía la ejecución entera ahora la devuelve."""
        sesion = env["session"]
        validador = ValidateFindingCommandService(
            code_reader=LectorQueNoEncuentraNada(),
            language_model=ScriptedLanguageModel(deque([exploitable([4])] * 8)),
            anchor_verifier=AnchorVerifier(),
            prefilter=DeterministicPrefilter(),
            budget=BudgetGuard(max_queries=50),
            prompt_version=PromptVersion.of("v1", "Juzga...", OUTPUT_CONTRACT_V1),
            verdict_cache={},
        )
        runner = RunExecutionCommandService(
            execution_repository=SqlExecutionRepository(sesion),
            finding_repository=SqlFindingRepository(sesion),
            context_repository=SqlCodeContextRepository(sesion),
            verdict_repository=SqlVerdictRepository(sesion),
            validator=validador,
            budget=BudgetGuard(max_queries=50),
            priority_calculator=PriorityCalculator(),
            prompt_version="v1",
        )
        informe = await runner.run(env["execution"])

        assert informe.interrupted
        assert "no parece estar donde este trabajador lo busca" in (
            informe.interruption_reason or ""
        )
        # Y lo que importa: sigue pendiente, de modo que otro puede retomarla.
        assert env["execution"].is_claimable

    async def test_no_aborta_si_ya_habia_validado_alguno(self, env):
        """Un archivo que se movió no es lo mismo que un repositorio ausente."""
        modelo = ScriptedLanguageModel(deque([exploitable([4])] * 8))
        runner = RunExecutionCommandService(
            execution_repository=SqlExecutionRepository(env["session"]),
            finding_repository=SqlFindingRepository(env["session"]),
            context_repository=SqlCodeContextRepository(env["session"]),
            verdict_repository=SqlVerdictRepository(env["session"]),
            validator=_validator(env, modelo, BudgetGuard(max_queries=50)),
            budget=BudgetGuard(max_queries=50),
            priority_calculator=PriorityCalculator(),
            prompt_version="v1",
        )
        informe = await runner.run(env["execution"])
        assert not informe.interrupted
        assert informe.validated == len(env["findings"])
