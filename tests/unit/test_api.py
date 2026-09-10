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
                nombre="Benchmark",
                ruta_repositorio="/repos/bench",
                es_conjunto_publico=True,
            )
        )
        await s.commit()

    app.state.container = container
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c
    await engine.dispose()


async def _token(client: AsyncClient, role: str = "investigador") -> str:
    correo = f"{role}@upc.edu.pe"
    await client.post(
        "/api/v1/auth/register",
        json={"email": correo, "password": "contrasena-segura"},
        params={"role": role},
    )
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": correo, "password": "contrasena-segura"},
    )
    return r.json()["access_token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


class TestHealth:
    async def test_health_is_open(self, client):
        r = await client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


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
        token = await _token(client, role="desarrollador")
        r = await client.post(
            "/api/v1/projects",
            json={"name": "Juliet", "repository_path": "/repos/juliet"},
            headers=_auth(token),
        )
        assert r.status_code == 403


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
        token = await _token(client)
        eid = await self._ingest(client, token)
        r = await client.post(f"/api/v1/executions/{eid}/run", headers=_auth(token))
        assert r.status_code == 200
        assert r.json()["validated"] == 1
        assert not r.json()["interrupted"]

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
        r = await client.get(f"/api/v1/executions/{eid}", headers=_auth(token))
        body = r.json()
        assert body["validated_findings"] == 1
        assert body["pending_findings"] == 0
        assert "validados" in body["progress_text"]

    async def test_export_is_anonymous(self, client):
        token = await _token(client)
        eid = await self._ingest(client, token)
        await client.post(f"/api/v1/executions/{eid}/run", headers=_auth(token))
        r = await client.get(f"/api/v1/executions/{eid}/export", headers=_auth(token))
        assert r.status_code == 200
        cuerpo = r.text
        assert "hallazgo_id" in cuerpo
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
            json={"anonymous_code": "P01", "years_of_experience": 3, "consented": True},
            headers=_auth(token),
        )
        assert r.status_code == 201
        body = r.json()
        assert body["experience_band"] == "intermedio"
        assert len(body["order"]) == 2
        assert body["first_batch"] != body["second_batch"]

    async def test_refuses_without_consent(self, client):
        token = await _token(client)
        r = await client.post(
            "/api/v1/experiment/participants",
            json={"anonymous_code": "P02", "years_of_experience": 3, "consented": False},
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
                    "years_of_experience": 3,
                    "consented": True,
                },
                headers=_auth(token),
            )
            ordenes.append(tuple(r.json()["order"]))
        primeros = [o[0] for o in ordenes]
        assert primeros.count("con_asistente") == 2

    async def test_rejects_duplicate_code(self, client):
        token = await _token(client)
        payload = {"anonymous_code": "P01", "years_of_experience": 3, "consented": True}
        await client.post(
            "/api/v1/experiment/participants", json=payload, headers=_auth(token)
        )
        r = await client.post(
            "/api/v1/experiment/participants", json=payload, headers=_auth(token)
        )
        assert r.status_code == 409

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
        finding_id = (
            await client.get(f"/api/v1/executions/{eid}/findings", headers=_auth(token))
        ).json()[0]["id"]

        participant_id = (
            await client.post(
                "/api/v1/experiment/participants",
                json={
                    "anonymous_code": "P01",
                    "years_of_experience": 3,
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

        r = await client.get(
            f"/api/v1/experiment/executions/{eid}/metrics", headers=_auth(token)
        )
        assert r.status_code == 200
        body = r.json()
        assert body["total_verdicts"] == 1
        assert "exactitud" in body["confusion"]
        assert "verdaderos_positivos" in body["confusion"]
        assert body["anchor_rate_first_try"] == 1.0
