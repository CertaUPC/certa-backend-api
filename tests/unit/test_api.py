"""La interfaz de programación de extremo a extremo, con modelo guionado.

Ejercita el recorrido completo que hará un usuario: registrarse, iniciar sesión,
cargar un SARIF, ejecutar la validación, ver la lista priorizada, auditar el
contexto, registrar decisiones y exportar.
"""

from collections import deque
from pathlib import Path
from uuid import uuid4

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import src.shared.database_experiment  # noqa: F401  registra las tablas
from src.finding_validation.infrastructure.external.code_reader_registry import (
    CodeReaderRegistry,
)
from src.finding_validation.infrastructure.persistence.sql_repositories import (
    SqlExecutionRepository,
)
from src.finding_validation.infrastructure.external.scripted_language_model import (
    ScriptedLanguageModel,
    exploitable,
)
from src.main import app
from src.shared.composition import Container
from src.shared.config import Settings
from src.shared.database import Base, ProjectRow

JAVA = """package com.acme;

public class UserDao {

    public User findUnsafe(String id) {
        String q = "SELECT * FROM users WHERE id = " + id;
        return jdbc.queryForObject(q, User.class);
    }

    public User handleRequest(String raw) {
        return findUnsafe(raw);
    }
}
"""

PROJECT_ID = uuid4()


def sarif_doc() -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "semgrep",
                        "semanticVersion": "1.95.0",
                        "rules": [
                            {
                                "id": "java.sqli",
                                "properties": {"tags": ["CWE-89"]},
                                "defaultConfiguration": {"level": "error"},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "java.sqli",
                        "message": {"text": "Concatenación en consulta"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "UserDao.java"},
                                    "region": {
                                        "startLine": 6,
                                        "endLine": 6,
                                        "snippet": {"text": 'q = "SELECT" + id'},
                                    },
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


class _FakeContainer(Container):
    """Contenedor de pruebas: mismo grafo, modelo guionado y base en memoria."""

    def __init__(self, settings: Settings, repo_root: Path) -> None:
        super().__init__(settings)
        from src.finding_validation.infrastructure.external.code_reader_registry import (
            CodeReaderRegistry,
        )

        self.code_reader = CodeReaderRegistry(repo_root)
        self.language_model = ScriptedLanguageModel(
            deque([exploitable([6, 7]) for _ in range(20)])
        )


@pytest_asyncio.fixture
async def client(tmp_path: Path):
    (tmp_path / "UserDao.java").write_text(JAVA, encoding="utf-8")

    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        jwt_secret="clave-de-prueba-larga",
        repository_root=str(tmp_path),
        budget_max_queries=50,
    )
    container = _FakeContainer(settings, tmp_path)

    # Una sola conexión en memoria compartida por todas las sesiones.
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=None,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    container.engine = engine
    container.sessions = async_sessionmaker(engine, expire_on_commit=False)

    async with container.sessions() as s:
        s.add(
            ProjectRow(
                id=str(PROJECT_ID),
                name="Benchmark",
                repository_path="/repos/bench",
                is_public_dataset=True,
            )
        )
        await s.commit()

    app.state.container = container
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c
    await engine.dispose()


async def _procesar(client: AsyncClient) -> None:
    """Ejecuta un ciclo del trabajador sobre la cola.

    El recorrido de la interfaz solo encola; quien valida es el trabajador. Las
    pruebas que necesitan veredictos hacen aquí lo que en producción hace el
    proceso desatendido, sin levantarlo.
    """
    container = app.state.container
    async with container.sessions() as s:
        budget = container.new_budget()
        runner = container.runner(s, budget)
        await runner.claim_and_run("prueba", None)


async def _token(client: AsyncClient, role: str = "investigador") -> str:
    """Una cuenta con el rol pedido.

    El alta ya no reparte roles: crea siempre el de menor privilegio, porque
    dejar elegir el propio convertia el registro publico en una puerta a los
    datos ajenos. Aqui el rol se pone en la base directamente, que es lo que
    hace un ayudante de pruebas; por la interfaz lo concede un lider_tecnico.
    """
    email = f"{role}@upc.edu.pe"
    await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "contrasena-segura"},
    )
    if role != "desarrollador":
        from sqlalchemy import update as _update

        from src.iam.infrastructure.persistence.models import UserRow

        async with app.state.container.sessions() as s:
            await s.execute(
                _update(UserRow).where(UserRow.email == email).values(role=role)
            )
            await s.commit()
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "contrasena-segura"},
    )
    return r.json()["access_token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


class TestHealth:
    async def test_health_is_open(self, client):
        r = await client.get("/health")
        assert r.status_code == 200
        cuerpo = r.json()
        assert cuerpo["status"] == "ok", cuerpo
        assert cuerpo["database"] == "ok", cuerpo


class TestAuth:
    async def test_registers_and_logs_in(self, client):
        token = await _token(client)
        assert token

    async def test_rejects_wrong_password(self, client):
        await _token(client)
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "investigador@upc.edu.pe", "password": "incorrecta"},
        )
        assert r.status_code == 401

    async def test_rejects_unknown_email(self, client):
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "nadie@upc.edu.pe", "password": "contrasena-segura"},
        )
        assert r.status_code == 401

    async def test_rejects_short_password(self, client):
        r = await client.post(
            "/api/v1/auth/register", json={"email": "a@upc.edu.pe", "password": "corta"}
        )
        assert r.status_code == 422

    async def test_rejects_duplicate_email(self, client):
        await _token(client)
        r = await client.post(
            "/api/v1/auth/register",
            json={"email": "investigador@upc.edu.pe", "password": "contrasena-segura"},
        )
        assert r.status_code == 409

    async def test_protected_route_needs_token(self, client):
        r = await client.post("/api/v1/executions", json={})
        assert r.status_code in (401, 422)


class TestProjects:
    """El recorrido que la aplicación necesita para poder cargar un archivo."""

    async def test_lists_projects_with_execution_count(self, client):
        token = await _token(client)
        await client.post(
            "/api/v1/executions",
            json={"project_id": str(PROJECT_ID), "sarif": sarif_doc()},
            headers=_auth(token),
        )
        r = await client.get("/api/v1/projects", headers=_auth(token))
        assert r.status_code == 200
        proyecto = next(p for p in r.json() if p["id"] == str(PROJECT_ID))
        assert proyecto["name"] == "Benchmark"
        assert proyecto["execution_count"] == 1

    async def test_creates_project(self, client):
        token = await _token(client)
        r = await client.post(
            "/api/v1/projects",
            json={"name": "Juliet", "repository_path": "/repos/juliet"},
            headers=_auth(token),
        )
        assert r.status_code == 201
        assert r.json()["name"] == "Juliet"

    async def test_same_repository_does_not_duplicate(self, client):
        """Duplicar repartiría las ejecuciones de un mismo código en dos filas."""
        token = await _token(client)
        primero = await client.post(
            "/api/v1/projects",
            json={"name": "Juliet", "repository_path": "/repos/juliet"},
            headers=_auth(token),
        )
        segundo = await client.post(
            "/api/v1/projects",
            json={"name": "Otro nombre", "repository_path": "/repos/juliet"},
            headers=_auth(token),
        )
        assert segundo.json()["id"] == primero.json()["id"]
        assert segundo.json()["name"] == "Juliet"

    async def test_developer_cannot_create(self, client):
        """Reformulada con la pertenencia al proyecto, conservando lo que la
        historia exige.

        Antes comprobaba que un `desarrollador` no podia crear proyectos. Eso
        dejaba a quien se registraba sin poder usar la herramienta, que es lo
        contrario de lo que el producto necesita. Lo que US006 demuestra de
        verdad es que crear un proyecto te hace su administrador y que el
        proyecto es tuyo, no de otro.
        """
        token = await _token(client, role="desarrollador")
        r = await client.post(
            "/api/v1/projects",
            json={"name": "Juliet", "repository_path": "/repos/juliet"},
            headers=_auth(token),
        )
        assert r.status_code in (200, 201), r.text

        miembros = (
            await client.get(
                f"/api/v1/projects/{r.json()['id']}/members", headers=_auth(token)
            )
        ).json()
        assert [m["role"] for m in miembros] == ["administrador"]
        assert miembros[0]["invited_by"] is None


class TestIngest:
    async def test_ingests_sarif(self, client):
        token = await _token(client)
        r = await client.post(
            "/api/v1/executions",
            json={"project_id": str(PROJECT_ID), "sarif": sarif_doc()},
            headers=_auth(token),
        )
        assert r.status_code == 201
        body = r.json()
        assert body["ingested"] == 1
        assert body["execution"]["tool_name"] == "semgrep"
        assert body["execution"]["ruleset_version"] == "1.95.0"

    async def test_la_ejecucion_guarda_quien_la_lanzo(self, client):
        """El rastro de auditoría, comprobado de extremo a extremo.

        La columna puede existir en el esquema y el endpoint no rellenarla
        nunca: eso daría un modelo de datos correcto sobre un sistema que sigue
        sin saber quién lanzó qué.
        """
        from sqlalchemy import select

        from src.main import app
        from src.shared.database import ExecutionRow
        from src.iam.infrastructure.persistence.models import UserRow

        token = await _token(client)
        r = await client.post(
            "/api/v1/executions",
            json={"project_id": str(PROJECT_ID), "sarif": sarif_doc()},
            headers=_auth(token),
        )
        assert r.status_code == 201

        async with app.state.container.sessions() as s:
            ejecucion = (await s.execute(select(ExecutionRow))).scalars().one()
            autor = (
                await s.execute(
                    select(UserRow).where(
                        UserRow.email == "investigador@upc.edu.pe"
                    )
                )
            ).scalars().one()

        assert ejecucion.created_by == autor.id

    async def test_rejects_wrong_sarif_version(self, client):
        token = await _token(client)
        r = await client.post(
            "/api/v1/executions",
            json={"project_id": str(PROJECT_ID), "sarif": {"version": "2.0.0"}},
            headers=_auth(token),
        )
        assert r.status_code == 422

    async def test_scope_filter_reports_zero_without_error(self, client):
        """Un filtro sin coincidencias se informa, no se convierte en fallo."""
        token = await _token(client)
        r = await client.post(
            "/api/v1/executions",
            json={
                "project_id": str(PROJECT_ID),
                "sarif": sarif_doc(),
                "scope": {"cwes": ["CWE-502"]},
            },
            headers=_auth(token),
        )
        assert r.status_code == 201
        body = r.json()
        assert body["ingested"] == 0
        assert body["filtered_out"] == 1
        assert "presupuesto" in body["message"]

    async def test_rejects_unknown_severity(self, client):
        token = await _token(client)
        r = await client.post(
            "/api/v1/executions",
            json={
                "project_id": str(PROJECT_ID),
                "sarif": sarif_doc(),
                "scope": {"min_severity": "critico"},
            },
            headers=_auth(token),
        )
        assert r.status_code == 422


class TestRunAndAudit:
    async def _ingest(self, client, token) -> str:
        r = await client.post(
            "/api/v1/executions",
            json={"project_id": str(PROJECT_ID), "sarif": sarif_doc()},
            headers=_auth(token),
        )
        return r.json()["execution"]["id"]

    async def test_runs_and_validates(self, client):
        """Encolar y validar son dos pasos, y esa separación es el diseño.

        La petición acusa recibo y vuelve; quien valida es el trabajador. Aquí
        se ejerce un ciclo suyo para comprobar la cadena de extremo a extremo.
        """
        token = await _token(client)
        eid = await self._ingest(client, token)

        r = await client.post(f"/api/v1/executions/{eid}/run", headers=_auth(token))
        assert r.status_code == 202
        assert r.json()["status"] == "pendiente"

        await _procesar(client)

        detalle = (
            await client.get(f"/api/v1/executions/{eid}", headers=_auth(token))
        ).json()
        assert detalle["validated_findings"] == 1

    async def test_developer_cannot_run(self, client):
        """Ejecutar consume presupuesto: exige rol autorizado."""
        investigador = await _token(client, "investigador")
        eid = await self._ingest(client, investigador)
        dev = await _token(client, "desarrollador")
        r = await client.post(f"/api/v1/executions/{eid}/run", headers=_auth(dev))
        assert r.status_code == 403

    async def test_lists_findings_with_verdict_and_priority(self, client):
        token = await _token(client)
        eid = await self._ingest(client, token)
        await client.post(f"/api/v1/executions/{eid}/run", headers=_auth(token))
        await _procesar(client)

        r = await client.get(
            f"/api/v1/executions/{eid}/findings", headers=_auth(token)
        )
        assert r.status_code == 200
        items = r.json()
        assert len(items) == 1
        assert items[0]["verdict"]["value"] == "explotable"
        assert items[0]["verdict"]["anchor_verified"]
        assert items[0]["priority"] is not None
        assert items[0]["priority_reason"]

    async def test_context_is_auditable(self, client):
        """Se puede recuperar el contexto exacto que vio el modelo."""
        token = await _token(client)
        eid = await self._ingest(client, token)
        await client.post(f"/api/v1/executions/{eid}/run", headers=_auth(token))
        await _procesar(client)
        items = (
            await client.get(f"/api/v1/executions/{eid}/findings", headers=_auth(token))
        ).json()

        r = await client.get(
            f"/api/v1/executions/findings/{items[0]['id']}/context",
            headers=_auth(token),
        )
        assert r.status_code == 200
        ctx = r.json()
        assert ctx["enclosing_function"] == "findUnsafe"
        assert "handleRequest" in ctx["callers"]
        assert "6:" in ctx["text"]
        # Sin la primera línea real, quien muestre el contexto lo numeraría
        # desde uno y las líneas citadas señalarían al lugar equivocado.
        assert ctx["first_line"] >= 1
        assert ctx["first_line"] <= items[0]["start_line"]

    async def test_filters_by_cwe(self, client):
        token = await _token(client)
        eid = await self._ingest(client, token)
        await client.post(f"/api/v1/executions/{eid}/run", headers=_auth(token))
        await _procesar(client)
        r = await client.get(
            f"/api/v1/executions/{eid}/findings",
            params={"cwe": "CWE-502"},
            headers=_auth(token),
        )
        assert r.json() == []

    async def test_progress_is_reported(self, client):
        token = await _token(client)
        eid = await self._ingest(client, token)
        await client.post(f"/api/v1/executions/{eid}/run", headers=_auth(token))
        await _procesar(client)
        r = await client.get(f"/api/v1/executions/{eid}", headers=_auth(token))
        body = r.json()
        assert body["validated_findings"] == 1
        assert body["pending_findings"] == 0
        assert "validados" in body["progress_text"]

    async def test_export_is_anonymous(self, client):
        token = await _token(client)
        eid = await self._ingest(client, token)
        await client.post(f"/api/v1/executions/{eid}/run", headers=_auth(token))
        await _procesar(client)
        r = await client.get(f"/api/v1/executions/{eid}/export", headers=_auth(token))
        assert r.status_code == 200
        cuerpo = r.text
        assert "finding_id" in cuerpo
        assert "@upc.edu.pe" not in cuerpo

    async def test_export_without_verdicts_is_not_empty_file(self, client):
        token = await _token(client)
        eid = await self._ingest(client, token)
        r = await client.get(f"/api/v1/executions/{eid}/export", headers=_auth(token))
        assert r.status_code == 404


class TestExperiment:
    async def test_registers_participant_with_assignment(self, client):
        token = await _token(client)
        r = await client.post(
            "/api/v1/experiment/participants",
            json={"anonymous_code": "P01", "experience_band": "de_1_a_3", "consented": True},
            headers=_auth(token),
        )
        assert r.status_code == 201
        body = r.json()
        assert body["experience_band"] == "de_1_a_3"
        assert len(body["order"]) == 2
        assert body["first_batch"] != body["second_batch"]

    async def test_refuses_without_consent(self, client):
        token = await _token(client)
        r = await client.post(
            "/api/v1/experiment/participants",
            json={"anonymous_code": "P02", "experience_band": "de_1_a_3", "consented": False},
            headers=_auth(token),
        )
        assert r.status_code == 422
        assert "consentimiento" in r.json()["detail"]

    async def test_counterbalances_across_participants(self, client):
        token = await _token(client)
        ordenes = []
        for n in range(4):
            r = await client.post(
                "/api/v1/experiment/participants",
                json={
                    "anonymous_code": f"P{n:02d}",
                    "experience_band": "de_1_a_3",
                    "consented": True,
                },
                headers=_auth(token),
            )
            ordenes.append(tuple(r.json()["order"]))
        primeros = [o[0] for o in ordenes]
        assert primeros.count("con_asistente") == 2

    async def test_rejects_duplicate_code(self, client):
        token = await _token(client)
        payload = {"anonymous_code": "P01", "experience_band": "de_1_a_3", "consented": True}
        await client.post(
            "/api/v1/experiment/participants", json=payload, headers=_auth(token)
        )
        r = await client.post(
            "/api/v1/experiment/participants", json=payload, headers=_auth(token)
        )
        assert r.status_code == 409

    async def test_records_the_theme_of_the_session(self, client):
        """US032. Registrar el tema permite descartarlo como factor.

        Sin este dato el análisis tendría que suponer que la presentación no
        influye en la decisión, que es justo lo que no se puede suponer cuando
        la usabilidad se declara variable extraña controlada.
        """
        token = await _token(client)
        participante = (
            await client.post(
                "/api/v1/experiment/participants",
                json={
                    "anonymous_code": "PT1",
                    "experience_band": "de_1_a_3",
                    "consented": True,
                },
                headers=_auth(token),
            )
        ).json()["participant_id"]

        r = await client.post(
            "/api/v1/experiment/sessions/theme",
            json={"participant_id": participante, "theme": "dark"},
            headers=_auth(token),
        )
        assert r.status_code == 200
        assert r.json()["theme"] == "dark"

    async def test_the_theme_cannot_change_within_a_session(self, client):
        """Un segundo tema distinto es la señal de que la presentación cambió a
        mitad de sesión. Aceptarlo borraría la evidencia de ese cambio."""
        token = await _token(client)
        participante = (
            await client.post(
                "/api/v1/experiment/participants",
                json={
                    "anonymous_code": "PT2",
                    "experience_band": "de_1_a_3",
                    "consented": True,
                },
                headers=_auth(token),
            )
        ).json()["participant_id"]
        cuerpo = {"participant_id": participante, "theme": "light"}
        await client.post(
            "/api/v1/experiment/sessions/theme", json=cuerpo, headers=_auth(token)
        )

        # El mismo, otra vez, no molesta: la pantalla puede reintentar.
        repetido = await client.post(
            "/api/v1/experiment/sessions/theme", json=cuerpo, headers=_auth(token)
        )
        assert repetido.status_code == 200

        distinto = await client.post(
            "/api/v1/experiment/sessions/theme",
            json={"participant_id": participante, "theme": "dark"},
            headers=_auth(token),
        )
        assert distinto.status_code == 409
        assert "no puede cambiar" in distinto.json()["detail"]

    async def test_rejects_a_theme_outside_the_two_declared(self, client):
        token = await _token(client)
        participante = (
            await client.post(
                "/api/v1/experiment/participants",
                json={
                    "anonymous_code": "PT3",
                    "experience_band": "de_1_a_3",
                    "consented": True,
                },
                headers=_auth(token),
            )
        ).json()["participant_id"]
        r = await client.post(
            "/api/v1/experiment/sessions/theme",
            json={"participant_id": participante, "theme": "sepia"},
            headers=_auth(token),
        )
        assert r.status_code == 422

    async def test_records_decision_and_supersedes(self, client):
        token = await _token(client)
        eid = (
            await client.post(
                "/api/v1/executions",
                json={"project_id": str(PROJECT_ID), "sarif": sarif_doc()},
                headers=_auth(token),
            )
        ).json()["execution"]["id"]
        await client.post(f"/api/v1/executions/{eid}/run", headers=_auth(token))
        await _procesar(client)
        finding_id = (
            await client.get(f"/api/v1/executions/{eid}/findings", headers=_auth(token))
        ).json()[0]["id"]

        participant_id = (
            await client.post(
                "/api/v1/experiment/participants",
                json={
                    "anonymous_code": "P01",
                    "experience_band": "de_1_a_3",
                    "consented": True,
                },
                headers=_auth(token),
            )
        ).json()["participant_id"]

        base = {
            "finding_id": finding_id,
            "participant_id": participant_id,
            "condition": "con_asistente",
        }
        r1 = await client.post(
            "/api/v1/experiment/decisions",
            json={**base, "value": "confirmado", "seconds": 42.0},
            headers=_auth(token),
        )
        assert r1.status_code == 201

        r2 = await client.post(
            "/api/v1/experiment/decisions",
            json={**base, "value": "descartado", "seconds": 15.0},
            headers=_auth(token),
        )
        assert r2.status_code == 201

        historial = (
            await client.get(
                f"/api/v1/experiment/findings/{finding_id}/decisions",
                headers=_auth(token),
            )
        ).json()
        assert len(historial) == 2
        vigentes = [d for d in historial if d["is_current"]]
        assert len(vigentes) == 1
        assert vigentes[0]["value"] == "descartado"

    async def test_rejects_non_positive_time(self, client):
        token = await _token(client)
        r = await client.post(
            "/api/v1/experiment/decisions",
            json={
                "finding_id": str(uuid4()),
                "participant_id": str(uuid4()),
                "value": "confirmado",
                "seconds": 0,
                "condition": "con_asistente",
            },
            headers=_auth(token),
        )
        assert r.status_code == 422

    async def test_metrics_report_full_confusion(self, client):
        token = await _token(client)
        eid = (
            await client.post(
                "/api/v1/executions",
                json={"project_id": str(PROJECT_ID), "sarif": sarif_doc()},
                headers=_auth(token),
            )
        ).json()["execution"]["id"]
        await client.post(f"/api/v1/executions/{eid}/run", headers=_auth(token))
        await _procesar(client)

        r = await client.get(
            f"/api/v1/experiment/executions/{eid}/metrics", headers=_auth(token)
        )
        assert r.status_code == 200
        body = r.json()
        assert body["total_verdicts"] == 1
        assert "exactitud" in body["confusion"]
        assert "verdaderos_positivos" in body["confusion"]
        assert body["anchor_rate_first_try"] == 1.0

    async def test_metrics_report_misleading_follow(self, client):
        """El recorrido de métricas informa qué hizo la persona con el veredicto
        equivocado.

        Sin ese dato, un incremento de la exactitud no distingue entre juzgar
        mejor y obedecer a una herramienta que acierta casi siempre, y ambos
        producen el mismo número en la variable principal.
        """
        token = await _token(client)
        eid = (
            await client.post(
                "/api/v1/executions",
                json={"project_id": str(PROJECT_ID), "sarif": sarif_doc()},
                headers=_auth(token),
            )
        ).json()["execution"]["id"]
        await client.post(f"/api/v1/executions/{eid}/run", headers=_auth(token))
        await _procesar(client)

        body = (
            await client.get(
                f"/api/v1/experiment/executions/{eid}/metrics", headers=_auth(token)
            )
        ).json()
        assert "misleading_verdicts" in body
        assert "misleading_follow_rate" in body
        # Sin hallazgos engañosos la tasa queda sin valor en lugar de en cero:
        # cero afirmaría que nadie siguió al modelo, y lo cierto es que no hubo
        # ocasión de hacerlo.
        if body["misleading_verdicts"] == 0:
            assert body["misleading_follow_rate"] is None

    async def test_run_encola_y_no_trabaja_en_la_peticion(self, client):
        """La petición deja el trabajo en la cola y vuelve de inmediato.

        Validar un hallazgo tarda entre diez y veinticinco segundos, y un lote
        son horas. Hacerlo dentro de la petición deja abierta una conexión que
        ninguna plataforma sostiene, y el trabajo muere con el primer reinicio
        del servicio web.
        """
        token = await _token(client)
        eid = (
            await client.post(
                "/api/v1/executions",
                json={"project_id": str(PROJECT_ID), "sarif": sarif_doc()},
                headers=_auth(token),
            )
        ).json()["execution"]["id"]

        r = await client.post(f"/api/v1/executions/{eid}/run", headers=_auth(token))
        assert r.status_code == 202, "encolar se acusa con 202, no con 200"
        cuerpo = r.json()
        assert cuerpo["execution_id"] == eid
        assert cuerpo["status"] == "pendiente"

        # La ejecución queda en la cola, a la espera de que un trabajador la tome.
        detalle = (
            await client.get(f"/api/v1/executions/{eid}", headers=_auth(token))
        ).json()
        assert detalle["status"] == "pendiente"

    async def test_la_corrida_tomada_dice_quien_la_tiene_y_desde_cuando(
        self, client
    ):
        """Una que se quedó en proceso hay que poder distinguirla de una viva.

        El trabajador de la plataforma gratuita se reinicia, y la corrida que
        tenía reclamada queda en proceso para siempre. Quien mira la pantalla
        decide si devolverla a la cola, y para eso necesita saber quién la tomó
        y cuánto lleva así.
        """
        token = await _token(client)
        eid = (
            await client.post(
                "/api/v1/executions",
                json={"project_id": str(PROJECT_ID), "sarif": sarif_doc()},
                headers=_auth(token),
            )
        ).json()["execution"]["id"]

        container = app.state.container
        async with container.sessions() as s:
            tomada = await SqlExecutionRepository(s).claim_next_pending("worker-1")
        assert tomada is not None

        detalle = (
            await client.get(f"/api/v1/executions/{eid}", headers=_auth(token))
        ).json()
        assert detalle["status"] == "en_proceso"
        assert detalle["claimed_by"] == "worker-1"
        assert detalle["started_at"] is not None

    async def test_devolver_a_la_cola_la_que_quedo_en_proceso(self, client):
        """Reanudar no es solo para las fallidas.

        El trabajador que muere a media corrida no deja rastro de fallo: la
        deja en proceso, y el estado que la cola consulta es ese. Sin esta
        transición la corrida no vuelve a tomarse nunca.
        """
        token = await _token(client)
        eid = (
            await client.post(
                "/api/v1/executions",
                json={"project_id": str(PROJECT_ID), "sarif": sarif_doc()},
                headers=_auth(token),
            )
        ).json()["execution"]["id"]
        container = app.state.container
        async with container.sessions() as s:
            await SqlExecutionRepository(s).claim_next_pending("worker-caido")

        r = await client.post(
            f"/api/v1/executions/{eid}/resume", headers=_auth(token)
        )
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "pendiente"
        assert r.json()["claimed_by"] is None

        # Y con eso vuelve a estar al alcance del siguiente trabajador.
        await _procesar(client)
        detalle = (
            await client.get(f"/api/v1/executions/{eid}", headers=_auth(token))
        ).json()
        assert detalle["validated_findings"] == 1

    async def test_encolar_dos_veces_no_duplica_el_trabajo(self, client):
        token = await _token(client)
        eid = (
            await client.post(
                "/api/v1/executions",
                json={"project_id": str(PROJECT_ID), "sarif": sarif_doc()},
                headers=_auth(token),
            )
        ).json()["execution"]["id"]
        await client.post(f"/api/v1/executions/{eid}/run", headers=_auth(token))
        segunda = await client.post(
            f"/api/v1/executions/{eid}/run", headers=_auth(token)
        )
        assert segunda.status_code == 202
        assert segunda.json()["status"] == "pendiente"


class TestLaSenalDelTrabajador:
    """Lo que el trabajador deja dicho cuando no puede ni empezar.

    Quien carga un SARIF por la web no ve el disco del trabajador. Si el
    repositorio no está ahí, la corrida vuelve a la cola sin consumirse, y
    antes de esto volvía indistinguible de una recién cargada: la pantalla
    decía «en espera» y no había forma de saber que ya se intentó.
    """

    async def test_el_repositorio_ausente_queda_escrito_en_la_ejecucion(
        self, client, tmp_path
    ):
        token = await _token(client)
        eid = (
            await client.post(
                "/api/v1/executions",
                json={"project_id": str(PROJECT_ID), "sarif": sarif_doc()},
                headers=_auth(token),
            )
        ).json()["execution"]["id"]

        # Este trabajador no tiene ese código en su disco.
        ausente = tmp_path / "no-clonado"
        app.state.container.code_reader = CodeReaderRegistry(ausente)
        await _procesar(client)

        detalle = (
            await client.get(f"/api/v1/executions/{eid}", headers=_auth(token))
        ).json()
        assert detalle["status"] == "pendiente", "vuelve a la cola sin consumirse"
        nota = detalle["last_attempt_note"]
        assert nota, "sin nota, la corrida se ve igual que una recién cargada"
        assert str(ausente) in nota, "la nota dice la ruta que se intentó"
        assert detalle["last_attempt_at"] is not None

    async def test_el_intento_que_si_avanza_borra_la_nota(self, client, tmp_path):
        """Una nota vieja describiría una corrida que ya no es esa."""
        token = await _token(client)
        eid = (
            await client.post(
                "/api/v1/executions",
                json={"project_id": str(PROJECT_ID), "sarif": sarif_doc()},
                headers=_auth(token),
            )
        ).json()["execution"]["id"]

        original = app.state.container.code_reader
        app.state.container.code_reader = CodeReaderRegistry(tmp_path / "no-clonado")
        await _procesar(client)
        assert (
            await client.get(f"/api/v1/executions/{eid}", headers=_auth(token))
        ).json()["last_attempt_note"]

        app.state.container.code_reader = original
        await _procesar(client)

        detalle = (
            await client.get(f"/api/v1/executions/{eid}", headers=_auth(token))
        ).json()
        assert detalle["validated_findings"] == 1
        assert detalle["last_attempt_note"] is None


class TestAuditoriaDelProducto:
    """El recorrido que sirve fuera del estudio.

    El del experimento exige participante y condición asignada, de modo que un
    usuario del producto tendría que registrarse como sujeto de un estudio para
    poder anotar lo que resolvió. Estas pruebas fijan que existe un camino que
    no lo exige, y que conserva el historial igual que el otro.
    """

    async def _un_hallazgo(self, client) -> tuple[str, str]:
        token = await _token(client)
        r = await client.post(
            "/api/v1/executions",
            json={"project_id": str(PROJECT_ID), "sarif": sarif_doc()},
            headers=_auth(token),
        )
        ejecucion = r.json()["execution"]["id"]
        r = await client.get(
            f"/api/v1/executions/{ejecucion}/findings", headers=_auth(token)
        )
        return token, r.json()[0]["id"]

    async def test_registra_sin_participante_ni_condicion(self, client):
        token, hallazgo = await self._un_hallazgo(client)
        r = await client.post(
            f"/api/v1/executions/findings/{hallazgo}/audit",
            json={"value": "confirmado", "seconds": 12.5},
            headers=_auth(token),
        )
        assert r.status_code == 201, r.text
        cuerpo = r.json()
        assert cuerpo["value"] == "confirmado"
        assert cuerpo["is_current"] is True

    async def test_rectificar_no_sobrescribe(self, client):
        """Sin historial no se distingue una primera impresión de una conclusión."""
        token, hallazgo = await self._un_hallazgo(client)
        for value in ("descartado", "confirmado"):
            await client.post(
                f"/api/v1/executions/findings/{hallazgo}/audit",
                json={"value": value, "seconds": 4.0},
                headers=_auth(token),
            )
        r = await client.get(
            f"/api/v1/executions/findings/{hallazgo}/audits", headers=_auth(token)
        )
        historial = r.json()
        assert len(historial) == 2
        vigentes = [a for a in historial if a["is_current"]]
        assert len(vigentes) == 1
        assert vigentes[0]["value"] == "confirmado"

    async def test_un_hallazgo_que_no_existe_se_rechaza(self, client):
        token = await _token(client)
        r = await client.post(
            f"/api/v1/executions/findings/{uuid4()}/audit",
            json={"value": "confirmado", "seconds": 1.0},
            headers=_auth(token),
        )
        assert r.status_code == 404

    async def test_un_valor_fuera_del_contrato_se_rechaza(self, client):
        token, hallazgo = await self._un_hallazgo(client)
        r = await client.post(
            f"/api/v1/executions/findings/{hallazgo}/audit",
            json={"value": "quizas", "seconds": 1.0},
            headers=_auth(token),
        )
        assert r.status_code == 422


class TestCredencialesAcotadas:
    """El recorrido completo de una credencial por la interfaz.

    Lo que se comprueba aquí no es solo que el canje funcione, sino que el
    token que devuelve no sirva para lo que no está acotado.
    """

    async def test_se_emite_y_se_canjea(self, client):
        cabecera = {"Authorization": f"Bearer {await _token(client)}"}
        r = await client.post(
            "/api/v1/auth/grants",
            json={
                "subject_kind": "worker",
                "subject_id": str(PROJECT_ID),
                "label": "portátil de prueba",
            },
            headers=cabecera,
        )
        assert r.status_code == 201, r.text
        emitida = r.json()
        assert emitida["token"].startswith("certa_wk_")

        canje = await client.post(
            "/api/v1/auth/token", json={"token": emitida["token"]}
        )
        assert canje.status_code == 200, canje.text
        assert canje.json()["role"] == "worker"

    async def test_el_token_del_canje_no_abre_lo_que_exige_cuenta(self, client):
        """La propiedad que sostiene el acotamiento.

        Si una credencial de participación pasara una comprobación de rol,
        quien tuviera el enlace de una sesión leería la lista de participantes
        y las ejecuciones de todos.
        """
        cabecera = {"Authorization": f"Bearer {await _token(client)}"}
        emitida = (
            await client.post(
                "/api/v1/auth/grants",
                json={"subject_kind": "participation", "subject_id": "p-1"},
                headers=cabecera,
            )
        ).json()
        acotado = (
            await client.post(
                "/api/v1/auth/token", json={"token": emitida["token"]}
            )
        ).json()["access_token"]

        r = await client.get(
            "/api/v1/experiment/participants",
            headers={"Authorization": f"Bearer {acotado}"},
        )
        assert r.status_code == 403
        assert "cuenta de persona" in r.json()["detail"]

    async def test_una_credencial_no_emite_otra(self, client):
        """Si pudiera, quien obtuviera una de participación se fabricaría la
        del trabajador y el acotamiento no serviría de nada."""
        cabecera = {"Authorization": f"Bearer {await _token(client)}"}
        emitida = (
            await client.post(
                "/api/v1/auth/grants",
                json={"subject_kind": "participation", "subject_id": "p-1"},
                headers=cabecera,
            )
        ).json()
        acotado = (
            await client.post(
                "/api/v1/auth/token", json={"token": emitida["token"]}
            )
        ).json()["access_token"]

        r = await client.post(
            "/api/v1/auth/grants",
            json={"subject_kind": "worker", "subject_id": str(PROJECT_ID)},
            headers={"Authorization": f"Bearer {acotado}"},
        )
        assert r.status_code == 403

    async def test_revocada_deja_de_canjearse(self, client):
        cabecera = {"Authorization": f"Bearer {await _token(client)}"}
        emitida = (
            await client.post(
                "/api/v1/auth/grants",
                json={"subject_kind": "worker", "subject_id": str(PROJECT_ID)},
                headers=cabecera,
            )
        ).json()
        assert (
            await client.post(
                "/api/v1/auth/token", json={"token": emitida["token"]}
            )
        ).status_code == 200

        borrado = await client.delete(
            f"/api/v1/auth/grants/{emitida['id']}", headers=cabecera
        )
        assert borrado.status_code == 204

        r = await client.post(
            "/api/v1/auth/token", json={"token": emitida["token"]}
        )
        assert r.status_code == 401

    async def test_el_motivo_del_rechazo_no_se_detalla(self, client):
        """Decir «venció» y no «no existe» ya confirma que existió."""
        inventado = "certa_wk_" + "a" * 32 + "_" + "b" * 64
        r = await client.post("/api/v1/auth/token", json={"token": inventado})
        assert r.status_code == 401
        assert r.json()["detail"] == "La credencial no es válida"

    async def test_se_listan_para_poder_revocarlas(self, client):
        cabecera = {"Authorization": f"Bearer {await _token(client)}"}
        await client.post(
            "/api/v1/auth/grants",
            json={"subject_kind": "worker", "subject_id": str(PROJECT_ID)},
            headers=cabecera,
        )
        r = await client.get(
            "/api/v1/auth/grants",
            params={"subject_kind": "worker", "subject_id": str(PROJECT_ID)},
            headers=cabecera,
        )
        assert r.status_code == 200
        assert len(r.json()) == 1
        assert r.json()[0]["active"] is True
        # El token no vuelve a salir por ninguna vía.
        assert "token" not in r.json()[0]


class TestElAltaNoRepartePapeles:
    """El agujero que el alta publica dejaba abierto.

    Registrarse solo no era el problema: un producto se registra solo. El
    problema era que el rol viajaba en la peticion, de modo que cualquiera que
    conociera la direccion se daba de alta como investigador y con eso leia los
    hallazgos ajenos, la lista de participantes y sus decisiones.
    """

    async def test_quien_se_registra_recibe_el_menor_privilegio(self, client):
        r = await client.post(
            "/api/v1/auth/register",
            json={"email": "cualquiera@upc.edu.pe", "password": "contrasena-segura"},
        )
        assert r.status_code == 201
        assert r.json()["role"] == "desarrollador"

    async def test_pedirse_un_rol_no_sirve_de_nada(self, client):
        """El parametro ya no existe; si alguien lo manda, se ignora."""
        r = await client.post(
            "/api/v1/auth/register",
            json={"email": "listillo@upc.edu.pe", "password": "contrasena-segura"},
            params={"role": "lider_tecnico"},
        )
        assert r.status_code == 201
        assert r.json()["role"] == "desarrollador"

    async def test_el_rol_lo_concede_quien_ya_tiene_el_mayor(self, client):
        lider = await _token(client, "lider_tecnico")
        alta = (
            await client.post(
                "/api/v1/auth/register",
                json={"email": "nuevo@upc.edu.pe", "password": "contrasena-segura"},
            )
        ).json()

        r = await client.patch(
            f"/api/v1/auth/users/{alta['id']}/role",
            params={"role": "investigador"},
            headers=_auth(lider),
        )
        assert r.status_code == 200
        assert r.json()["role"] == "investigador"

    async def test_un_desarrollador_no_se_asciende_a_si_mismo(self, client):
        suyo = await _token(client, "desarrollador")
        alta = (
            await client.post(
                "/api/v1/auth/register",
                json={"email": "otro@upc.edu.pe", "password": "contrasena-segura"},
            )
        ).json()
        r = await client.patch(
            f"/api/v1/auth/users/{alta['id']}/role",
            params={"role": "lider_tecnico"},
            headers=_auth(suyo),
        )
        assert r.status_code == 403

    async def test_un_investigador_tampoco_reparte_papeles(self, client):
        """Ni siquiera quien tiene acceso a los datos del estudio."""
        suyo = await _token(client, "investigador")
        alta = (
            await client.post(
                "/api/v1/auth/register",
                json={"email": "tercero@upc.edu.pe", "password": "contrasena-segura"},
            )
        ).json()
        r = await client.patch(
            f"/api/v1/auth/users/{alta['id']}/role",
            params={"role": "investigador"},
            headers=_auth(suyo),
        )
        assert r.status_code == 403


class TestNadieVeLoAjeno:
    """El aislamiento entre clientes.

    Antes, cualquiera autenticado listaba las ejecuciones de todos, y cada
    hallazgo arrastra el fragmento de codigo que se envio al modelo. Con el
    alta publica de entonces, eso era: registrarse y leer el codigo ajeno.
    """

    async def _proyecto_de(self, client, quien, path):
        token = await _token(client, quien)
        r = await client.post(
            "/api/v1/projects",
            json={
                "name": f"App de {quien}",
                "language": "java",
                "repository_path": path,
                "is_public_dataset": False,
            },
            headers=_auth(token),
        )
        assert r.status_code in (200, 201), r.text
        return token, r.json()

    async def test_dos_clientes_con_la_misma_ruta_no_comparten_proyecto(self, client):
        """Era el fallo mas silencioso: el segundo recibia el proyecto del
        primero y creia que era suyo."""
        _, uno = await self._proyecto_de(client, "investigador", "/repos/mi-app")
        _, otro = await self._proyecto_de(client, "lider_tecnico", "/repos/mi-app")
        assert uno["id"] != otro["id"]

    async def test_el_listado_no_trae_proyectos_ajenos(self, client):
        await self._proyecto_de(client, "investigador", "/repos/suyo")
        token_ajeno, _ = await self._proyecto_de(
            client, "lider_tecnico", "/repos/otro"
        )
        rutas = {
            p["repository_path"]
            for p in (
                await client.get("/api/v1/projects", headers=_auth(token_ajeno))
            ).json()
        }
        assert "/repos/otro" in rutas
        assert "/repos/suyo" not in rutas

    async def test_los_conjuntos_publicos_los_ve_todo_el_mundo(self, client):
        """Un conjunto de referencia no es de nadie: si no se viera, cada
        cliente tendria que cargarse su propio OWASP Benchmark."""
        token = await _token(client, "investigador")
        rutas = {
            p["repository_path"]
            for p in (
                await client.get("/api/v1/projects", headers=_auth(token))
            ).json()
        }
        assert "/repos/bench" in rutas

    async def test_el_listado_de_ejecuciones_tampoco(self, client):
        await self._proyecto_de(client, "investigador", "/repos/con-ejecucion")
        token_ajeno = await _token(client, "lider_tecnico")
        r = await client.get("/api/v1/executions", headers=_auth(token_ajeno))
        assert r.status_code == 200
        ajenas = [e for e in r.json() if e.get("project_name") == "App de investigador"]
        assert not ajenas


class TestLaFichaDecideLaParticipacion:
    """La ficha del anexo B, recogida por la herramienta.

    Vivia en un formulario aparte, y eso dejaba dos cosas al aire. La pregunta
    del rol de seguridad activa el criterio de exclusion del apartado 4.4, de
    modo que dependia de que alguien leyera la hoja de respuestas ANTES de
    dejar empezar. Y la experiencia es factor de control del analisis: cruzarla
    despues por un codigo tecleado a mano es donde se pierden filas.
    """

    async def _alta(self, client, **campos):
        token = await _token(client)
        cuerpo = {
            "anonymous_code": "F01",
            "experience_band": "de_4_a_7",
            "consented": True,
            **campos,
        }
        return await client.post(
            "/api/v1/experiment/participants", json=cuerpo, headers=_auth(token)
        )

    async def test_el_rol_de_seguridad_impide_la_participacion(self, client):
        """Es la pregunta que decide. Antes nunca llegaba, siempre valia falso
        y la regla del dominio no podia dispararse."""
        r = await self._alta(client, has_security_role=True)
        assert r.status_code == 422
        assert "seguridad de aplicaciones" in r.json()["detail"]

    async def test_sin_rol_de_seguridad_se_registra(self, client):
        r = await self._alta(client, has_security_role=False)
        assert r.status_code == 201

    async def test_la_banda_es_la_que_pregunta_la_ficha(self, client):
        """Guardar un entero obligaba a inventar un numero que nadie dio: la
        ficha pregunta por tramos."""
        r = await self._alta(client, experience_band="mas_de_7")
        assert r.status_code == 201
        assert r.json()["experience_band"] == "mas_de_7"

    async def test_una_banda_inventada_se_rechaza(self, client):
        r = await self._alta(client, experience_band="bastante")
        assert r.status_code == 422

    async def test_el_resto_de_la_ficha_se_guarda(self, client):
        r = await self._alta(
            client,
            main_language="Java",
            alert_frequency="semanal",
            security_training="autodidacta",
        )
        assert r.status_code == 201

    async def test_una_frecuencia_fuera_del_contrato_se_rechaza(self, client):
        """Un valor libre dejaria entrar cualquier cadena en una columna que el
        analisis va a usar como factor."""
        r = await self._alta(client, alert_frequency="de vez en cuando")
        assert r.status_code == 422


class TestCompararDosCorridas:
    """Qué cambió entre dos corridas del mismo proyecto.

    Se compara por huella, que se calcula sobre el contenido y no sobre el
    número de línea: sin eso, meter una importación arriba del archivo haría
    aparecer como nuevos a todos los hallazgos de ese archivo.
    """

    async def _corrida(self, client, token, doc):
        r = await client.post(
            "/api/v1/executions",
            json={"project_id": str(PROJECT_ID), "sarif": doc},
            headers=_auth(token),
        )
        assert r.status_code == 201, r.text
        return r.json()["execution"]["id"]

    def _movido(self, lineas: int) -> dict:
        """El mismo hallazgo, más abajo en el archivo."""
        doc = sarif_doc()
        region = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        region["startLine"] += lineas
        region["endLine"] += lineas
        return doc

    async def test_el_mismo_hallazgo_movido_no_cuenta_como_nuevo(self, client):
        token = await _token(client)
        vieja = await self._corrida(client, token, sarif_doc())
        nueva = await self._corrida(client, token, self._movido(20))

        r = await client.get(
            f"/api/v1/executions/{nueva}/compare",
            params={"against": vieja},
            headers=_auth(token),
        )
        assert r.status_code == 200, r.text
        cuerpo = r.json()
        assert cuerpo["nuevos"] == []
        assert cuerpo["resueltos"] == []
        assert len(cuerpo["siguen"]) == 1

    async def test_lo_que_desaparece_sale_como_resuelto(self, client):
        token = await _token(client)
        doc = sarif_doc()
        vieja = await self._corrida(client, token, doc)

        vacio = sarif_doc()
        vacio["runs"][0]["results"] = []
        nueva = await self._corrida(client, token, vacio)

        cuerpo = (
            await client.get(
                f"/api/v1/executions/{nueva}/compare",
                params={"against": vieja},
                headers=_auth(token),
            )
        ).json()
        assert cuerpo["nuevos"] == []
        assert len(cuerpo["resueltos"]) == 1
        assert cuerpo["resueltos"][0]["file_path"].endswith("UserDao.java")
        assert cuerpo["siguen"] == []

    async def test_no_se_comparan_proyectos_distintos(self, client):
        """Daría tres listas donde todo es nuevo y todo está resuelto, que no
        es una comparación."""
        token = await _token(client)
        mia = await self._corrida(client, token, sarif_doc())
        otro = (
            await client.post(
                "/api/v1/projects",
                json={"name": "Otro", "repository_path": "/repos/otro"},
                headers=_auth(token),
            )
        ).json()["id"]
        suya = (
            await client.post(
                "/api/v1/executions",
                json={"project_id": otro, "sarif": sarif_doc()},
                headers=_auth(token),
            )
        ).json()["execution"]["id"]

        r = await client.get(
            f"/api/v1/executions/{mia}/compare",
            params={"against": suya},
            headers=_auth(token),
        )
        assert r.status_code == 422

    async def test_una_corrida_de_proyecto_privado_ajeno_no_se_compara(
        self, client
    ):
        """Con un proyecto privado. El del montaje es conjunto público, y ese
        lo ve todo el mundo a propósito."""
        token = await _token(client)
        privado = (
            await client.post(
                "/api/v1/projects",
                json={"name": "Privado", "repository_path": "/repos/privado"},
                headers=_auth(token),
            )
        ).json()["id"]
        suya = (
            await client.post(
                "/api/v1/executions",
                json={"project_id": privado, "sarif": sarif_doc()},
                headers=_auth(token),
            )
        ).json()["execution"]["id"]

        await client.post(
            "/api/v1/auth/register",
            json={"email": "curioso@upc.edu.pe", "password": "contrasena-segura"},
        )
        ajeno = (
            await client.post(
                "/api/v1/auth/login",
                json={"email": "curioso@upc.edu.pe", "password": "contrasena-segura"},
            )
        ).json()["access_token"]

        r = await client.get(
            f"/api/v1/executions/{suya}/compare",
            params={"against": suya},
            headers=_auth(ajeno),
        )
        assert r.status_code == 404


class TestMembresiaDelProyecto:
    """El permiso viene de la relacion con el proyecto, no de un rango.

    De dieciseis comprobaciones del sistema, trece admitian indistintamente a
    investigador y lider tecnico: la distincion no existia. Y el rol mas bajo
    no podia ni crear un proyecto, de modo que quien se registraba no podia
    usar la herramienta.
    """

    async def _proyecto(self, client, token, path="/repos/mio"):
        r = await client.post(
            "/api/v1/projects",
            json={"name": "Mio", "repository_path": path},
            headers=_auth(token),
        )
        assert r.status_code in (200, 201), r.text
        return r.json()["id"]

    async def _cuenta(self, client, correo):
        alta = await client.post(
            "/api/v1/auth/register",
            json={"email": correo, "password": "contrasena-segura"},
        )
        sesion = await client.post(
            "/api/v1/auth/login",
            json={"email": correo, "password": "contrasena-segura"},
        )
        return alta.json()["id"], sesion.json()["access_token"]

    async def test_quien_crea_administra(self, client):
        token = await _token(client, "desarrollador")
        pid = await self._proyecto(client, token)
        miembros = (
            await client.get(f"/api/v1/projects/{pid}/members", headers=_auth(token))
        ).json()
        # Con el correo: sin el, la lista son identificadores de treinta y
        # seis caracteres y no hay pantalla que construir con eso.
        assert miembros == [
            {
                "user_id": miembros[0]["user_id"],
                "email": "desarrollador@upc.edu.pe",
                "role": "administrador",
                "invited_by": None,
            }
        ]

    async def test_se_invita_por_correo(self, client):
        """Es lo que quien invita tiene a mano: nadie conoce de memoria el
        identificador de un compañero."""
        dueno = await _token(client, "desarrollador")
        pid = await self._proyecto(client, dueno)
        _, ajeno = await self._cuenta(client, "porcorreo@upc.edu.pe")

        r = await client.post(
            f"/api/v1/projects/{pid}/members",
            params={"email": "porcorreo@upc.edu.pe"},
            headers=_auth(dueno),
        )
        assert r.status_code == 201, r.text
        assert r.json()["role"] == "miembro"

        visibles = {
            p["id"]
            for p in (await client.get("/api/v1/projects", headers=_auth(ajeno))).json()
        }
        assert pid in visibles

    async def test_un_correo_sin_cuenta_lo_dice(self, client):
        dueno = await _token(client, "desarrollador")
        pid = await self._proyecto(client, dueno)
        r = await client.post(
            f"/api/v1/projects/{pid}/members",
            params={"email": "nadie@upc.edu.pe"},
            headers=_auth(dueno),
        )
        assert r.status_code == 404
        assert "regístrese" in r.text or "registre" in r.text

    async def test_el_invitado_entra_como_miembro(self, client):
        dueno = await _token(client, "desarrollador")
        pid = await self._proyecto(client, dueno)
        ajeno_id, ajeno = await self._cuenta(client, "invitado@upc.edu.pe")

        r = await client.post(
            f"/api/v1/projects/{pid}/members",
            params={"user_id": ajeno_id},
            headers=_auth(dueno),
        )
        assert r.status_code == 201
        assert r.json()["role"] == "miembro"

        visibles = {
            p["id"]
            for p in (await client.get("/api/v1/projects", headers=_auth(ajeno))).json()
        }
        assert pid in visibles

    async def test_quien_no_pertenece_no_sabe_que_existe(self, client):
        """No se responde «no eres administrador» a quien no pertenece: eso ya
        confirmaria que el proyecto existe."""
        dueno = await _token(client, "desarrollador")
        pid = await self._proyecto(client, dueno)
        _, ajeno = await self._cuenta(client, "extrano@upc.edu.pe")

        r = await client.get(f"/api/v1/projects/{pid}/members", headers=_auth(ajeno))
        assert r.status_code == 404

    async def test_el_miembro_no_invita(self, client):
        dueno = await _token(client, "desarrollador")
        pid = await self._proyecto(client, dueno)
        invitado_id, invitado = await self._cuenta(client, "uno@upc.edu.pe")
        await client.post(
            f"/api/v1/projects/{pid}/members",
            params={"user_id": invitado_id},
            headers=_auth(dueno),
        )
        tercero_id, _ = await self._cuenta(client, "dos@upc.edu.pe")

        r = await client.post(
            f"/api/v1/projects/{pid}/members",
            params={"user_id": tercero_id},
            headers=_auth(invitado),
        )
        assert r.status_code == 403

    async def test_el_administrador_no_se_retira_a_si_mismo(self, client):
        """El proyecto quedaria sin quien lo gestione, y recuperarlo exigiria
        tocar la base."""
        dueno = await _token(client, "desarrollador")
        pid = await self._proyecto(client, dueno)
        miembros = (
            await client.get(f"/api/v1/projects/{pid}/members", headers=_auth(dueno))
        ).json()
        r = await client.delete(
            f"/api/v1/projects/{pid}/members/{miembros[0]['user_id']}",
            headers=_auth(dueno),
        )
        assert r.status_code == 409

    async def test_retirar_a_alguien_le_quita_la_vista(self, client):
        dueno = await _token(client, "desarrollador")
        pid = await self._proyecto(client, dueno)
        invitado_id, invitado = await self._cuenta(client, "temporal@upc.edu.pe")
        await client.post(
            f"/api/v1/projects/{pid}/members",
            params={"user_id": invitado_id},
            headers=_auth(dueno),
        )
        r = await client.delete(
            f"/api/v1/projects/{pid}/members/{invitado_id}", headers=_auth(dueno)
        )
        assert r.status_code == 204

        visibles = {
            p["id"]
            for p in (await client.get("/api/v1/projects", headers=_auth(invitado))).json()
        }
        assert pid not in visibles


class TestEntradaDelParticipante:
    """El participante entra con su codigo, no con el navegador del otro.

    El apano que esto retira: el participante entraba en el navegador que el
    investigador dejaba con su sesion abierta, de modo que durante la sesion el
    equipo guardaba un token con permisos de investigador.
    """

    async def _preparar(self, client, codigo="P01"):
        token = await _token(client)
        alta = await client.post(
            "/api/v1/experiment/participants",
            json={
                "anonymous_code": codigo,
                "experience_band": "de_1_a_3",
                "consented": True,
            },
            headers=_auth(token),
        )
        assert alta.status_code == 201, alta.text
        return token, alta.json()["participant_id"]

    async def test_sin_credencial_vigente_no_entra(self, client):
        """El codigo no es un secreto: lo que controla es que el investigador
        haya emitido la credencial y que siga en su ventana."""
        await self._preparar(client)
        r = await client.post(
            "/api/v1/auth/participant", json={"anonymous_code": "P01"}
        )
        assert r.status_code == 401

    async def test_con_credencial_vigente_entra_y_recibe_su_reparto(self, client):
        token, pid = await self._preparar(client)
        await client.post(
            "/api/v1/auth/grants",
            json={"subject_kind": "participation", "subject_id": pid},
            headers=_auth(token),
        )
        r = await client.post(
            "/api/v1/auth/participant", json={"anonymous_code": "P01"}
        )
        assert r.status_code == 200, r.text
        cuerpo = r.json()
        assert cuerpo["participant_id"] == pid
        assert len(cuerpo["order"]) == 2
        assert {cuerpo["first_batch"], cuerpo["second_batch"]} == {"A", "B"}

    async def test_el_guion_del_acta_no_deja_fuera_a_nadie(self, client):
        """El acta que la persona firma dice «P-04» y el campo pedia «P04».

        Quien dicta lee lo que tiene delante, de modo que un caracter de mas
        dejaba el acceso en 401 con la credencial vigente y la persona sentada.
        """
        token, pid = await self._preparar(client, codigo="P04")
        await client.post(
            "/api/v1/auth/grants",
            json={"subject_kind": "participation", "subject_id": pid},
            headers=_auth(token),
        )
        for tecleado in ("P-04", "P04", "p-4", "p 04"):
            r = await client.post(
                "/api/v1/auth/participant", json={"anonymous_code": tecleado}
            )
            assert r.status_code == 200, f"{tecleado}: {r.text}"
            assert r.json()["participant_id"] == pid

    async def test_lo_que_recibe_no_abre_nada_ajeno(self, client):
        """Es la propiedad que justifica todo esto."""
        token, pid = await self._preparar(client)
        await client.post(
            "/api/v1/auth/grants",
            json={"subject_kind": "participation", "subject_id": pid},
            headers=_auth(token),
        )
        suyo = (
            await client.post(
                "/api/v1/auth/participant", json={"anonymous_code": "P01"}
            )
        ).json()["access_token"]

        for ruta in ("/api/v1/experiment/participants", "/api/v1/projects"):
            r = await client.get(ruta, headers=_auth(suyo))
            assert r.status_code == 403, f"{ruta} respondió {r.status_code}"

    async def test_un_codigo_inventado_se_rechaza_igual(self, client):
        """Y con el mismo mensaje, para no decir que codigos existen."""
        await self._preparar(client)
        uno = await client.post(
            "/api/v1/auth/participant", json={"anonymous_code": "P01"}
        )
        otro = await client.post(
            "/api/v1/auth/participant", json={"anonymous_code": "NO-EXISTE"}
        )
        assert uno.status_code == otro.status_code == 401
        assert uno.json()["detail"] == otro.json()["detail"]

    async def test_una_credencial_revocada_cierra_la_puerta(self, client):
        token, pid = await self._preparar(client)
        emitida = (
            await client.post(
                "/api/v1/auth/grants",
                json={"subject_kind": "participation", "subject_id": pid},
                headers=_auth(token),
            )
        ).json()
        assert (
            await client.post(
                "/api/v1/auth/participant", json={"anonymous_code": "P01"}
            )
        ).status_code == 200

        await client.delete(
            f"/api/v1/auth/grants/{emitida['id']}", headers=_auth(token)
        )
        r = await client.post(
            "/api/v1/auth/participant", json={"anonymous_code": "P01"}
        )
        assert r.status_code == 401


class TestLaSesionDelParticipante:
    """Lo que su credencial tiene que alcanzar, y nada mas.

    Es el recorrido entero de una sesion: recibir la ejecucion sobre la que
    corre el estudio, pedir el lote, escribir la decision y anotar la
    presentacion. Que faltara uno solo de esos permisos no se notaba hasta
    tener al participante delante.
    """

    async def _estudio(self, client, codigo="P01"):
        """Una ejecucion con su lote congelado y un participante dentro."""
        token = await _token(client)
        eid = (
            await client.post(
                "/api/v1/executions",
                json={"project_id": str(PROJECT_ID), "sarif": sarif_doc()},
                headers=_auth(token),
            )
        ).json()["execution"]["id"]

        hallazgos = (
            await client.get(
                f"/api/v1/executions/{eid}/findings", headers=_auth(token)
            )
        ).json()

        from src.experimentation.infrastructure.persistence.sql_repositories import (
            SqlBatchRepository,
        )

        async with app.state.container.sessions() as s:
            await SqlBatchRepository(s).replace_all([(hallazgos[0]["id"], "A", 0)])

        alta = (
            await client.post(
                "/api/v1/experiment/participants",
                json={
                    "anonymous_code": codigo,
                    "experience_band": "de_1_a_3",
                    "consented": True,
                },
                headers=_auth(token),
            )
        ).json()
        await client.post(
            "/api/v1/auth/grants",
            json={
                "subject_kind": "participation",
                "subject_id": alta["participant_id"],
            },
            headers=_auth(token),
        )
        suyo = (
            await client.post(
                "/api/v1/auth/participant", json={"anonymous_code": codigo}
            )
        ).json()
        return eid, hallazgos[0]["id"], alta, suyo

    async def test_recibe_la_ejecucion_sobre_la_que_corre_el_estudio(self, client):
        """Sin ella la pantalla de sesion no sabe que hallazgos pedir, y el
        participante no tiene por que escribirla en la direccion."""
        eid, _, _, suyo = await self._estudio(client)
        assert suyo["execution_id"] == eid

    async def test_alcanza_el_lote_con_su_propia_credencial(self, client):
        _, finding_id, _, suyo = await self._estudio(client)
        cabeceras = _auth(suyo["access_token"])

        resumen = await client.get("/api/v1/experiment/batches", headers=cabeceras)
        assert resumen.status_code == 200, resumen.text
        assert resumen.json()["lotes"] == {"A": 1}

        mitad = await client.get("/api/v1/experiment/batches/A", headers=cabeceras)
        assert mitad.status_code == 200, mitad.text
        assert mitad.json()["hallazgos"] == [finding_id]

    async def test_escribe_su_decision_y_no_la_de_otro(self, client):
        _, finding_id, alta, suyo = await self._estudio(client)
        cabeceras = _auth(suyo["access_token"])
        cuerpo = {
            "finding_id": finding_id,
            "participant_id": alta["participant_id"],
            "value": "confirmado",
            "seconds": 12.5,
            "condition": "con_asistente",
        }

        mia = await client.post(
            "/api/v1/experiment/decisions", json=cuerpo, headers=cabeceras
        )
        assert mia.status_code == 201, mia.text

        ajena = await client.post(
            "/api/v1/experiment/decisions",
            json={**cuerpo, "participant_id": str(uuid4())},
            headers=cabeceras,
        )
        assert ajena.status_code == 403

    async def test_anota_su_presentacion_y_no_la_de_otro(self, client):
        _, _, alta, suyo = await self._estudio(client)
        cabeceras = _auth(suyo["access_token"])

        mia = await client.post(
            "/api/v1/experiment/sessions/theme",
            json={"participant_id": alta["participant_id"], "theme": "dark"},
            headers=cabeceras,
        )
        assert mia.status_code == 200, mia.text

        ajena = await client.post(
            "/api/v1/experiment/sessions/theme",
            json={"participant_id": str(uuid4()), "theme": "dark"},
            headers=cabeceras,
        )
        assert ajena.status_code == 403

    async def test_lo_que_sigue_sin_alcanzar(self, client):
        """El lote si, la lista de participantes no. Es lo que separa una
        credencial acotada de una sesion prestada."""
        _, _, _, suyo = await self._estudio(client)
        cabeceras = _auth(suyo["access_token"])
        for ruta in ("/api/v1/experiment/participants", "/api/v1/projects"):
            r = await client.get(ruta, headers=cabeceras)
            assert r.status_code == 403, f"{ruta} respondio {r.status_code}"


class TestElListadoDeParticipantes:
    """Cada uno con el reparto que le toco a el.

    El listado emparejaba participantes con sesiones por posicion, contra una
    lista que ademas excluye a los pilotos. Con un piloto de por medio cada
    persona aparecia con el reparto de otra, y es la pantalla desde la que se
    comprueba el contrabalanceo antes de convocar al siguiente.
    """

    async def _alta(self, client, token, codigo, piloto):
        r = await client.post(
            "/api/v1/experiment/participants",
            json={
                "anonymous_code": codigo,
                "experience_band": "de_1_a_3",
                "consented": True,
                "is_pilot": piloto,
            },
            headers=_auth(token),
        )
        assert r.status_code == 201, r.text
        return r.json()

    async def test_cada_uno_lleva_su_propio_reparto(self, client):
        token = await _token(client)
        # Se dan de alta sin guion a proposito: el codigo se guarda en su
        # forma canonica, y es esa la que el listado tiene que devolver.
        altas = {
            "PIL-01": await self._alta(client, token, "PIL1", True),
            "REA-01": await self._alta(client, token, "REA1", False),
            "REA-02": await self._alta(client, token, "REA2", False),
        }
        for canonico, alta in altas.items():
            assert alta["anonymous_code"] == canonico

        listado = (
            await client.get("/api/v1/experiment/participants", headers=_auth(token))
        ).json()
        por_codigo = {p["anonymous_code"]: p for p in listado}
        assert set(por_codigo) == set(altas)

        for codigo, alta in altas.items():
            fila = por_codigo[codigo]
            assert fila["order"] == alta["order"], codigo
            assert fila["first_batch"] == alta["first_batch"], codigo
            assert fila["second_batch"] == alta["second_batch"], codigo
            assert fila["is_pilot"] == alta["is_pilot"], codigo

    async def test_el_piloto_se_distingue_en_el_listado(self, client):
        """Sin esa marca, el reparto que se dibuja cuenta a quien esta excluido."""
        token = await _token(client)
        await self._alta(client, token, "PIL2", True)
        listado = (
            await client.get("/api/v1/experiment/participants", headers=_auth(token))
        ).json()
        assert [p["is_pilot"] for p in listado] == [True]
