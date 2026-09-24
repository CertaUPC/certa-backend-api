"""Persistencia: mapeo, reanudación sin repetir, reutilización y purga.

Se ejercita sobre SQLite en memoria. Lo que aquí se prueba es la lógica de los
repositorios, que es idéntica en ambos motores. Lo único específico de
PostgreSQL es la omisión de filas bloqueadas en el reclamo de la cola, y esa
diferencia está aislada y declarada en `claim_next_pending`.
"""

from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from src.finding_validation.domain.entities.code_context import CodeContext
from src.finding_validation.domain.entities.execution import Execution, ExecutionStatus
from src.finding_validation.domain.entities.finding import Finding
from src.finding_validation.domain.entities.verdict import Verdict, VerdictValue
from src.finding_validation.domain.value_objects.code_location import CodeLocation
from src.finding_validation.domain.value_objects.fingerprint import Fingerprint
from src.finding_validation.domain.value_objects.justification import Justification
from src.finding_validation.infrastructure.persistence.sql_repositories import (
    SqlCodeContextRepository,
    SqlExecutionRepository,
    SqlFindingRepository,
    SqlVerdictRepository,
)
from src.shared.database import Base, ProjectRow, normalize_database_url

# Registra la tabla de cuentas, que executions referencia por clave
# foránea. Sin esto el archivo pasa dentro de la suite, porque otro
# módulo la importa, y falla al correrlo solo.
import src.iam.infrastructure.persistence.models  # noqa: F401
import src.shared.database_experiment  # noqa: F401  (registra sus tablas)

PROJECT_ID = uuid4()


@pytest_asyncio.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as s:
        s.add(
            ProjectRow(
                id=str(PROJECT_ID),
                name="OWASP Benchmark",
                repository_path="/repos/benchmark",
                is_public_dataset=True,
            )
        )
        await s.commit()
        yield s
    await engine.dispose()


def _finding(rule: str = "r.sqli", line: int = 10, body: str = "x") -> Finding:
    return Finding(
        rule_id=rule,
        severity="error",
        location=CodeLocation("UserDao.java", line, line),
        fingerprint=Fingerprint.compute(rule, "UserDao.java", body),
        cwe="CWE-89",
    )


def _verdict(finding: Finding, model: str = "m1", version: str = "v1") -> Verdict:
    return Verdict(
        finding_id=finding.id,
        model=model,
        model_version=version,
        value=VerdictValue.EXPLOITABLE,
        justification=Justification.from_model_output("sin sanear", [10, 11]),
        anchor_verified=True,
        confidence=0.9,
    )


class TestExecutionQueue:
    async def test_saves_and_reads_back(self, session):
        repo = SqlExecutionRepository(session)
        e = Execution(project_id=PROJECT_ID, ruleset_version="1.95.0")
        await repo.save(e)
        leida = await repo.get(e.id)
        assert leida is not None
        assert leida.ruleset_version == "1.95.0"
        assert leida.status is ExecutionStatus.PENDING

    async def test_claims_the_oldest_pending(self, session):
        repo = SqlExecutionRepository(session)
        primera = Execution(project_id=PROJECT_ID, ruleset_version="1")
        segunda = Execution(project_id=PROJECT_ID, ruleset_version="2")
        await repo.save(primera)
        await repo.save(segunda)

        tomada = await repo.claim_next_pending("worker-1")
        assert tomada is not None
        assert tomada.id == primera.id
        assert tomada.status is ExecutionStatus.IN_PROGRESS
        assert tomada.claimed_by == "worker-1"

    async def test_a_claimed_execution_is_not_claimed_again(self, session):
        """La garantía que sostiene la cola: nadie procesa lo mismo dos veces."""
        repo = SqlExecutionRepository(session)
        await repo.save(Execution(project_id=PROJECT_ID, ruleset_version="1"))

        primera = await repo.claim_next_pending("worker-1")
        segunda = await repo.claim_next_pending("worker-2")
        assert primera is not None
        assert segunda is None

    async def test_empty_queue_returns_none(self, session):
        assert await SqlExecutionRepository(session).claim_next_pending("w") is None

    async def test_resumed_execution_returns_to_the_queue(self, session):
        repo = SqlExecutionRepository(session)
        e = Execution(project_id=PROJECT_ID, ruleset_version="1")
        await repo.save(e)
        await repo.claim_next_pending("worker-1")

        e.status = ExecutionStatus.IN_PROGRESS
        e.claimed_by = "worker-1"
        e.resume()
        await repo.save(e)

        assert (await repo.claim_next_pending("worker-2")) is not None

    async def test_lists_by_project(self, session):
        repo = SqlExecutionRepository(session)
        for v in ("1", "2", "3"):
            await repo.save(Execution(project_id=PROJECT_ID, ruleset_version=v))
        assert len(await repo.list_by_project(PROJECT_ID)) == 3


class TestFindings:
    async def test_saves_and_lists(self, session):
        exec_repo = SqlExecutionRepository(session)
        repo = SqlFindingRepository(session)
        e = Execution(project_id=PROJECT_ID, ruleset_version="1")
        await exec_repo.save(e)

        findings = [_finding(line=n, body=f"cuerpo {n}") for n in (10, 20, 30)]
        await repo.save_all(findings, e.id)

        leidos = await repo.list_by_execution(e.id)
        assert len(leidos) == 3
        assert {f.location.start_line for f in leidos} == {10, 20, 30}

    async def test_fingerprint_survives_the_round_trip(self, session):
        exec_repo = SqlExecutionRepository(session)
        repo = SqlFindingRepository(session)
        e = Execution(project_id=PROJECT_ID, ruleset_version="1")
        await exec_repo.save(e)
        original = _finding()
        await repo.save_all([original], e.id)

        leido = await repo.get(original.id)
        assert leido.fingerprint == original.fingerprint
        assert leido.is_same_as(original)

    async def test_pending_excludes_what_already_has_a_verdict(self, session):
        """Reanudar no vuelve a pagar por lo ya validado."""
        exec_repo = SqlExecutionRepository(session)
        f_repo = SqlFindingRepository(session)
        v_repo = SqlVerdictRepository(session)
        e = Execution(project_id=PROJECT_ID, ruleset_version="1")
        await exec_repo.save(e)

        a, b, c = (_finding(line=n, body=f"c{n}") for n in (10, 20, 30))
        await f_repo.save_all([a, b, c], e.id)
        await v_repo.save(_verdict(a))

        pendientes = await f_repo.list_pending_validation(e.id)
        ids = {f.id for f in pendientes}
        assert a.id not in ids
        assert ids == {b.id, c.id}

    async def test_pending_respects_the_limit(self, session):
        exec_repo = SqlExecutionRepository(session)
        repo = SqlFindingRepository(session)
        e = Execution(project_id=PROJECT_ID, ruleset_version="1")
        await exec_repo.save(e)
        await repo.save_all([_finding(line=n, body=f"c{n}") for n in range(1, 11)], e.id)
        assert len(await repo.list_pending_validation(e.id, limit=4)) == 4

    async def test_priority_is_persisted(self, session):
        exec_repo = SqlExecutionRepository(session)
        repo = SqlFindingRepository(session)
        e = Execution(project_id=PROJECT_ID, ruleset_version="1")
        await exec_repo.save(e)
        f = _finding()
        await repo.save_all([f], e.id)
        await repo.set_priority(f.id, 0.87, "veredicto explotable")

        from sqlalchemy import select

        from src.shared.database import FindingRow

        row = (
            await session.execute(select(FindingRow).where(FindingRow.id == str(f.id)))
        ).scalar_one()
        assert row.priority == pytest.approx(0.87)
        assert "explotable" in row.priority_reason


class TestVerdictReuse:
    async def _prepare(self, session):
        exec_repo = SqlExecutionRepository(session)
        f_repo = SqlFindingRepository(session)
        e = Execution(project_id=PROJECT_ID, ruleset_version="1")
        await exec_repo.save(e)
        f = _finding()
        await f_repo.save_all([f], e.id)
        return e, f

    async def test_finds_a_reusable_verdict(self, session):
        _, f = await self._prepare(session)
        repo = SqlVerdictRepository(session)
        await repo.save(_verdict(f, "m1", "v1"))

        encontrado = await repo.find_reusable(f.fingerprint, "m1", "v1")
        assert encontrado is not None
        assert encontrado.value is VerdictValue.EXPLOITABLE

    async def test_another_model_does_not_answer_for_this_one(self, session):
        _, f = await self._prepare(session)
        repo = SqlVerdictRepository(session)
        await repo.save(_verdict(f, "m1", "v1"))
        assert await repo.find_reusable(f.fingerprint, "m2", "v1") is None

    async def test_another_version_does_not_answer_either(self, session):
        """Un cambio de versión del proveedor invalida la reutilización."""
        _, f = await self._prepare(session)
        repo = SqlVerdictRepository(session)
        await repo.save(_verdict(f, "m1", "v1"))
        assert await repo.find_reusable(f.fingerprint, "m1", "v2") is None

    async def test_justification_survives_the_round_trip(self, session):
        _, f = await self._prepare(session)
        repo = SqlVerdictRepository(session)
        await repo.save(_verdict(f))
        leido = (await repo.get_by_finding(f.id))[0]
        assert leido.justification.cited_lines == frozenset({10, 11})
        assert leido.anchor_verified


class TestContextPurge:
    async def test_purge_clears_text_and_keeps_metrics(self, session):
        exec_repo = SqlExecutionRepository(session)
        f_repo = SqlFindingRepository(session)
        c_repo = SqlCodeContextRepository(session)
        v_repo = SqlVerdictRepository(session)

        e = Execution(project_id=PROJECT_ID, ruleset_version="1")
        await exec_repo.save(e)
        f = _finding()
        await f_repo.save_all([f], e.id)
        await c_repo.save(
            CodeContext(
                finding_id=f.id,
                enclosing_function="find",
                text="10: codigo\n11: mas codigo",
                available_lines=frozenset({10, 11}),
                sanitizers=("escapeSql",),
            )
        )
        await v_repo.save(_verdict(f))

        assert await c_repo.get_by_finding(f.id) is not None
        purgados = await c_repo.purge_by_execution(e.id)
        assert purgados == 1

        # El texto ya no está...
        assert await c_repo.get_by_finding(f.id) is None
        # ...pero el veredicto y sus métricas siguen.
        assert len(await v_repo.get_by_finding(f.id)) == 1

    async def test_purging_twice_affects_nothing(self, session):
        exec_repo = SqlExecutionRepository(session)
        f_repo = SqlFindingRepository(session)
        c_repo = SqlCodeContextRepository(session)
        e = Execution(project_id=PROJECT_ID, ruleset_version="1")
        await exec_repo.save(e)
        f = _finding()
        await f_repo.save_all([f], e.id)
        await c_repo.save(
            CodeContext(
                finding_id=f.id,
                enclosing_function="find",
                text="10: codigo",
                available_lines=frozenset({10}),
            )
        )
        assert await c_repo.purge_by_execution(e.id) == 1
        assert await c_repo.purge_by_execution(e.id) == 0


class TestNormalizacionDeLaCadena:
    """La cadena que entregan los proveedores gestionados viene en formato libpq.

    Si no se adapta, el primer despliegue falla con un error que no dice lo que
    pasa realmente.
    """

    def test_elige_el_controlador_asincrono(self):
        url, _ = normalize_database_url("postgresql://u:c@host/certa")
        assert url.startswith("postgresql+asyncpg://")

    def test_retira_los_parametros_que_asyncpg_no_conoce(self):
        url, args = normalize_database_url(
            "postgresql://u:c@host/certa?sslmode=require&channel_binding=require"
        )
        assert "sslmode" not in url
        assert "channel_binding" not in url
        assert args["ssl"] is True

    def test_desactiva_la_cache_en_el_extremo_agrupado(self):
        """El agrupador multiplexa conexiones y ahi las sentencias preparadas
        de asyncpg dejan de ser validas entre una y otra."""
        _, args = normalize_database_url(
            "postgresql://u:c@ep-x-pooler.aws.neon.tech/certa?sslmode=require"
        )
        assert args["statement_cache_size"] == 0

    def test_el_extremo_directo_conserva_la_cache(self):
        _, args = normalize_database_url(
            "postgresql://u:c@ep-x.aws.neon.tech/certa?sslmode=require"
        )
        assert "statement_cache_size" not in args

    def test_conserva_la_contrasena(self):
        url, _ = normalize_database_url("postgresql://u:clave-secreta@host/certa")
        assert "clave-secreta" in url

    def test_no_toca_una_cadena_ya_correcta(self):
        url, args = normalize_database_url("postgresql+asyncpg://u:c@host/certa")
        assert url == "postgresql+asyncpg://u:c@host/certa"
        assert args == {}

    def test_no_toca_sqlite(self):
        url, args = normalize_database_url("sqlite+aiosqlite:///./certa.db")
        assert url == "sqlite+aiosqlite:///./certa.db"
        assert args == {}


class TestContextRoundTrip:
    """El contexto guardado tiene que volver entero.

    Los métodos llamados son lo que lleva al modelo hasta donde vive el
    saneamiento. Si se guardan a medias, el contexto que se recupera después
    para auditar un veredicto no es el que se envió, y la verificación de
    anclaje deja de ser comprobable sobre lo que de verdad ocurrió.
    """

    async def test_callees_survive_the_round_trip(self, session):
        ejecucion = Execution(project_id=PROJECT_ID, tool_name="semgrep",
                              ruleset_version="1.90.0")
        await SqlExecutionRepository(session).save(ejecucion)
        hallazgo = _finding()
        await SqlFindingRepository(session).save_all([hallazgo], ejecucion.id)

        repo = SqlCodeContextRepository(session)
        await repo.save(CodeContext(
            finding_id=hallazgo.id,
            enclosing_function="doPost",
            text="43: linea\n88: otra",
            available_lines=frozenset({43, 88}),
            callers=("doGet",),
            callees=("doSomething", "sanear"),
            sanitizers=("encodeForSQL",),
            caller_depth=2,
            callee_depth=2,
        ))
        vuelto = await repo.get_by_finding(hallazgo.id)
        assert vuelto is not None
        assert vuelto.callees == ("doSomething", "sanear")
        assert vuelto.callee_depth == 2
        assert vuelto.callers == ("doGet",)
        assert vuelto.sanitizers == ("encodeForSQL",)


class TestParticipanteDePiloto:
    """El protocolo declara un piloto cuyos datos se excluyen del analisis.

    Lo que esta clase protege no es la columna sino su consecuencia menos
    visible: el orden de condiciones se asigna con el contrabalanceador sobre
    el historial de sesiones, de modo que una sesion de piloto que contara
    desviaria el reparto de los participantes reales sin que nada lo delatara.
    """

    @staticmethod
    async def _registrar(session, codigo, piloto):
        from src.experimentation.domain.entities.participant import Participant
        from src.experimentation.domain.services.counterbalancer import (
            Counterbalancer,
        )
        from src.experimentation.infrastructure.persistence.sql_repositories import (
            SqlParticipantRepository,
            SqlSessionRepository,
        )
        from datetime import datetime, timezone

        participantes = SqlParticipantRepository(session)
        sesiones = SqlSessionRepository(session)
        p = Participant(
            anonymous_code=codigo,
            experience_band="de_1_a_3",
            consented_at=datetime.now(timezone.utc),
            is_pilot=piloto,
        )
        await participantes.save(p)
        asignacion = Counterbalancer().assign(await sesiones.existing_orders())
        await sesiones.create(p.id, asignacion)
        return p, asignacion

    async def test_la_marca_sobrevive_a_la_ida_y_vuelta(self, session):
        from src.experimentation.infrastructure.persistence.sql_repositories import (
            SqlParticipantRepository,
        )

        p, _ = await self._registrar(session, "PIL01", True)
        vuelto = await SqlParticipantRepository(session).get_by_code("PIL01")
        assert vuelto is not None
        assert vuelto.is_pilot is True

    async def test_por_omision_no_es_piloto(self, session):
        from src.experimentation.infrastructure.persistence.sql_repositories import (
            SqlParticipantRepository,
        )

        await self._registrar(session, "P01", False)
        vuelto = await SqlParticipantRepository(session).get_by_code("P01")
        assert vuelto is not None
        assert vuelto.is_pilot is False

    async def test_la_sesion_del_piloto_no_entra_en_el_historial(self, session):
        from src.experimentation.infrastructure.persistence.sql_repositories import (
            SqlSessionRepository,
        )

        await self._registrar(session, "PIL01", True)
        await self._registrar(session, "PIL02", True)
        historial = await SqlSessionRepository(session).existing_orders()
        assert historial == []

    async def test_el_piloto_no_desvia_el_orden_del_primer_participante(
        self, session
    ):
        """Sin el filtro, el primero de la muestra recibiria el segundo orden
        porque el piloto ya habria consumido el primero."""
        from src.experimentation.infrastructure.persistence.sql_repositories import (
            SqlSessionRepository,
        )

        _, del_piloto = await self._registrar(session, "PIL01", True)
        _, del_primero = await self._registrar(session, "P01", False)
        assert del_primero.order == del_piloto.order

        _, del_segundo = await self._registrar(session, "P02", False)
        assert del_segundo.order != del_primero.order
        historial = await SqlSessionRepository(session).existing_orders()
        assert len(historial) == 2
