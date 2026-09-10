"""Traza, precómputo de sesión y comparación entre modelos."""

from collections import deque
from pathlib import Path
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from src.finding_validation.application.internal.commandservices.compare_models_command_service import (
    CompareModelsCommandService,
)
from src.finding_validation.application.internal.commandservices.prepare_session_command_service import (
    PrepareSessionCommandService,
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
from src.finding_validation.domain.value_objects.code_location import CodeLocation
from src.finding_validation.domain.value_objects.fingerprint import Fingerprint
from src.finding_validation.domain.value_objects.prompt_version import (
    OUTPUT_CONTRACT_V1,
    PromptVersion,
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
from src.shared.database import Base, ProjectRow
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
            emit(Stage.CONTEXT, "ok", mensaje="x" * 500)
        assert "omitidos" in sink.by_correlation("largo")[0].data["mensaje"]

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
        s.add(ProjectRow(id=str(PROJECT_ID), nombre="P", ruta_repositorio="/r"))
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
        assert set(c.disagreements()[0]["por_modelo"]) == {"m1", "m2"}

    async def test_each_model_gets_its_own_budget(self, env):
        a = ScriptedLanguageModel(deque([exploitable([4]) for _ in range(8)]), "m1", "v1")
        b = ScriptedLanguageModel(deque([exploitable([4]) for _ in range(8)]), "m2", "v1")
        c = await self._service(env).compare(
            env["execution"], [a, b], max_queries_per_model=4
        )
        assert all(r.queries <= 4 for r in c.runs)
        assert all(r.queries == 4 for r in c.runs)

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
