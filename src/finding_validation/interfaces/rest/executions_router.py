"""Ingesta, avance y ejecución del análisis."""

import csv
import io
from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select

from ....shared.database import ExecutionRow, FindingRow, ProjectRow, VerdictRow
from ...domain.entities.execution import Execution
from ...domain.services.retention_policy import (
    ExecutionRetentionState,
    RetentionPolicy,
)
from ...domain.value_objects.scope_filter import ScopeFilter
from ...infrastructure.external.sarif_parser import SarifError
from ...infrastructure.persistence.sql_repositories import (
    SqlCodeContextRepository,
    SqlExecutionRepository,
    SqlFindingRepository,
    SqlVerdictRepository,
)
from ..schemas.schemas import (
    ContextResponse,
    ExecutionResponse,
    FindingResponse,
    IngestResponse,
    IngestSarifRequest,
    RunReportResponse,
    StabilityResponse,
    VerdictResponse,
)
from .dependencies import ContainerDep, SessionDep, UserDep

router = APIRouter(prefix="/api/v1/executions", tags=["Ejecuciones"])


def _to_response(e: Execution, project_name: str = "") -> ExecutionResponse:
    return ExecutionResponse(
        id=e.id,
        project_id=e.project_id,
        project_name=project_name,
        tool_name=e.tool_name,
        ruleset_version=e.ruleset_version,
        status=e.status.value,
        total_findings=e.total_findings,
        validated_findings=e.validated_findings,
        pending_findings=e.pending_findings,
        progress=e.progress,
        progress_text=e.describe_progress(),
        failure_reason=e.failure_reason,
        created_at=e.created_at,
    )


@router.post("", response_model=IngestResponse, status_code=status.HTTP_201_CREATED)
async def ingest(
    body: IngestSarifRequest,
    container: ContainerDep,
    session: SessionDep,
    user: UserDep,
) -> IngestResponse:
    """Carga un archivo SARIF y crea la ejecución."""
    scope = ScopeFilter.unrestricted()
    if body.scope:
        try:
            scope = ScopeFilter(
                cwes=frozenset(body.scope.cwes),
                min_severity=body.scope.min_severity,
            )
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    try:
        result = await container.ingest_service(session).from_payload(
            body.project_id, body.sarif, scope
        )
    except SarifError as exc:
        # No cumple el esquema. Se rechaza sin dejar una ejecución a medias.
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    nombres = await _project_names(session, {body.project_id})
    return IngestResponse(
        execution=_to_response(result.execution, nombres.get(body.project_id, "")),
        ingested=result.ingested,
        filtered_out=result.filtered_out,
        skipped=result.skipped,
        message=result.describe(),
    )


async def _project_names(session, ids: set[UUID]) -> dict[UUID, str]:
    """Nombres de proyecto en una sola consulta, no una por fila."""
    if not ids:
        return {}
    filas = (
        await session.execute(
            select(ProjectRow.id, ProjectRow.nombre).where(
                ProjectRow.id.in_([str(i) for i in ids])
            )
        )
    ).all()
    return {UUID(i): n for i, n in filas}


@router.get("", response_model=list[ExecutionResponse])
async def list_executions(
    session: SessionDep, user: UserDep, project_id: UUID | None = None
) -> list[ExecutionResponse]:
    """Ejecuciones más recientes primero."""
    stmt = select(ExecutionRow).order_by(ExecutionRow.creada_en.desc())
    if project_id:
        stmt = stmt.where(ExecutionRow.proyecto_id == str(project_id))
    rows = (await session.execute(stmt)).scalars().all()

    repo = SqlExecutionRepository(session)
    entidades = [repo._to_entity(r) for r in rows]
    nombres = await _project_names(session, {e.project_id for e in entidades})
    return [_to_response(e, nombres.get(e.project_id, "")) for e in entidades]


@router.get("/{execution_id}", response_model=ExecutionResponse)
async def get_execution(
    execution_id: UUID, session: SessionDep, user: UserDep
) -> ExecutionResponse:
    execution = await SqlExecutionRepository(session).get(execution_id)
    if execution is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No existe esa ejecución")
    nombres = await _project_names(session, {execution.project_id})
    return _to_response(execution, nombres.get(execution.project_id, ""))


@router.post("/{execution_id}/run", response_model=RunReportResponse)
async def run(
    execution_id: UUID,
    container: ContainerDep,
    session: SessionDep,
    user: UserDep,
    batch_size: int | None = None,
) -> RunReportResponse:
    """Valida los hallazgos pendientes de la ejecución."""
    user.require("investigador", "lider_tecnico")

    execution = await SqlExecutionRepository(session).get(execution_id)
    if execution is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No existe esa ejecución")

    budget = container.new_budget()
    try:
        runner = container.runner(session, budget)
    except RuntimeError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc

    report = await runner.run(execution, batch_size)
    return RunReportResponse(
        execution_id=report.execution_id,
        validated=report.validated,
        failed=report.failed,
        interrupted=report.interrupted,
        interruption_reason=report.interruption_reason,
        budget=budget.report(),
    )


@router.post("/{execution_id}/resume", response_model=ExecutionResponse)
async def resume(
    execution_id: UUID, session: SessionDep, user: UserDep
) -> ExecutionResponse:
    """Devuelve a la cola una ejecución interrumpida, conservando lo validado."""
    repo = SqlExecutionRepository(session)
    execution = await repo.get(execution_id)
    if execution is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No existe esa ejecución")
    try:
        execution.resume()
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    await repo.save(execution)
    return _to_response(execution)


@router.get("/{execution_id}/findings", response_model=list[FindingResponse])
async def list_findings(
    execution_id: UUID,
    session: SessionDep,
    user: UserDep,
    cwe: str | None = None,
    verdict: str | None = None,
    anchor: bool | None = None,
) -> list[FindingResponse]:
    """Lista priorizada. Nunca suprime: filtrar es del usuario, no del sistema."""
    rows = (
        await session.execute(
            select(FindingRow)
            .where(FindingRow.ejecucion_id == str(execution_id))
            .order_by(FindingRow.prioridad.desc().nullslast(), FindingRow.huella)
        )
    ).scalars().all()

    verdict_rows = (
        await session.execute(
            select(VerdictRow).where(
                VerdictRow.hallazgo_id.in_([r.id for r in rows] or [""])
            )
        )
    ).scalars().all()
    latest: dict[str, VerdictRow] = {}
    todos: dict[str, list[VerdictRow]] = {}
    for v in verdict_rows:
        actual = latest.get(v.hallazgo_id)
        if actual is None or v.repeticion >= actual.repeticion:
            latest[v.hallazgo_id] = v
        todos.setdefault(v.hallazgo_id, []).append(v)

    salida: list[FindingResponse] = []
    for r in rows:
        v = latest.get(r.id)
        if cwe and (r.cwe or "").upper() != cwe.upper():
            continue
        if verdict and (v is None or v.valor != verdict):
            continue
        if anchor is not None and (v is None or v.anclaje_verificado != anchor):
            continue
        salida.append(
            FindingResponse(
                id=UUID(r.id),
                rule_id=r.regla_id,
                cwe=r.cwe,
                severity=r.severidad_regla,
                file_path=r.archivo,
                start_line=r.linea_inicio,
                end_line=r.linea_fin,
                message=r.mensaje,
                fingerprint=r.huella,
                priority=r.prioridad,
                priority_reason=r.motivo_prioridad,
                stability=None
                if v is None
                else StabilityResponse(
                    runs=len(todos[r.id]),
                    agree=sum(1 for x in todos[r.id] if x.valor == v.valor),
                ),
                verdict=None
                if v is None
                else VerdictResponse(
                    model=v.modelo,
                    model_version=v.version_modelo,
                    value=v.valor,
                    confidence=v.confianza,
                    anchor_verified=v.anclaje_verificado,
                    attempts=v.intentos,
                    reused=v.reutilizado_de is not None,
                    justification=v.justificacion,
                    cited_lines=list(v.lineas_citadas or []),
                ),
            )
        )
    return salida


@router.get("/findings/{finding_id}/context", response_model=ContextResponse)
async def get_context(
    finding_id: UUID, session: SessionDep, user: UserDep
) -> ContextResponse:
    """El contexto exacto que vio el modelo. Es lo que hace auditable el anclaje."""
    context = await SqlCodeContextRepository(session).get_by_finding(finding_id)
    if context is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "No hay contexto disponible. O no se recuperó, o fue purgado por la "
            "política de retención.",
        )
    return ContextResponse(
        enclosing_function=context.enclosing_function,
        first_line=min(context.available_lines),
        callers=list(context.callers),
        sanitizers=list(context.sanitizers),
        degraded_to_file=context.degraded_to_file,
        recovered_lines=context.recovered_line_count,
        text=context.text,
    )


@router.get("/{execution_id}/export")
async def export_decisions(
    execution_id: UUID, session: SessionDep, user: UserDep
) -> StreamingResponse:
    """Exporta el registro para el análisis estadístico.

    Ninguna columna lleva nombre ni correo: el participante viaja como
    identificador anónimo, de modo que el archivo se pueda compartir sin
    exponer identidades.
    """
    user.require("investigador", "lider_tecnico")

    verdicts = await SqlVerdictRepository(session).list_by_execution(execution_id)
    findings = {
        f.id: f for f in await SqlFindingRepository(session).list_by_execution(execution_id)
    }
    if not verdicts:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "La ejecución no registra veredictos. No se genera un archivo vacío.",
        )

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "hallazgo_id", "regla", "cwe", "severidad", "archivo", "linea",
            "huella", "verdad_conocida", "modelo", "version_modelo", "repeticion",
            "veredicto", "confianza", "anclaje_verificado", "intentos",
            "lineas_citadas", "reutilizado", "latencia_ms",
        ]
    )
    for v in verdicts:
        f = findings.get(v.finding_id)
        writer.writerow(
            [
                str(v.finding_id),
                f.rule_id if f else "",
                f.cwe if f else "",
                f.severity if f else "",
                f.location.file_path if f else "",
                f.location.start_line if f else "",
                f.fingerprint.value if f else "",
                "" if not f or f.known_truth is None else int(f.known_truth),
                v.model,
                v.model_version,
                v.repetition,
                v.value.value,
                "" if v.confidence is None else v.confidence,
                int(v.anchor_verified),
                v.attempts,
                " ".join(str(n) for n in sorted(v.justification.cited_lines)),
                int(v.was_reused),
                v.latency_ms or "",
            ]
        )

    buffer.seek(0)
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="certa-{execution_id}.csv"'
        },
    )


@router.post("/{execution_id}/purge", status_code=status.HTTP_200_OK)
async def purge_context(
    execution_id: UUID, container: ContainerDep, session: SessionDep, user: UserDep
) -> dict:
    """Elimina el código recuperado y conserva las métricas."""
    user.require("investigador", "lider_tecnico")

    repo = SqlExecutionRepository(session)
    execution = await repo.get(execution_id)
    if execution is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No existe esa ejecución")

    policy = RetentionPolicy(container.settings.retention_days)
    decision = policy.decide(
        ExecutionRetentionState(
            closed_at=execution.finished_at,
            context_purged=execution.context_purged,
            used_in_active_session=False,
        )
    )
    if not decision.should_purge:
        raise HTTPException(status.HTTP_409_CONFLICT, decision.reason)

    purged = await SqlCodeContextRepository(session).purge_by_execution(execution_id)
    execution.context_purged = True
    await repo.save(execution)
    return {"purged": purged, "reason": decision.reason}
