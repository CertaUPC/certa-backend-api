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
    email = f"{role}@upc.edu.pe"
    await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "contrasena-segura"},
        params={"role": role},
    )
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
                    "years_of_experience": 3,
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
                    "years_of_experience": 3,
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
                    "years_of_experience": 3,
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
        for valor in ("descartado", "confirmado"):
            await client.post(
                f"/api/v1/executions/findings/{hallazgo}/audit",
                json={"value": valor, "seconds": 4.0},
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
