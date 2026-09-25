"""Ingesta, avance y ejecución del análisis."""

import csv
import io
from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy import or_, select

from ....shared.database import ExecutionRow, FindingRow, ProjectRow, VerdictRow
from ...domain.entities.decision import Decision, DecisionValue
from ...domain.entities.execution import Execution, ExecutionStatus
from ...domain.services.retention_policy import (
    ExecutionRetentionState,
    RetentionPolicy,
)
from ...domain.value_objects.scope_filter import ScopeFilter
from ...infrastructure.external.sarif_parser import SarifError
from ...infrastructure.persistence.membership_repository import (
    SqlMembershipRepository,
)
from ...infrastructure.persistence.sql_repositories import (
    SqlDecisionRepository,
    SqlCodeContextRepository,
    SqlExecutionRepository,
    SqlFindingRepository,
    SqlVerdictRepository,
)
from ..schemas.schemas import (
    AuditRequest,
    AuditResponse,
    ContextResponse,
    EnqueuedResponse,
    ExecutionResponse,
    FindingResponse,
    IngestResponse,
    IngestSarifRequest,
    StabilityResponse,
    VerdictResponse,
)
from ....iam.interfaces.rest.dependencies import UserDep
from ....shared.rest import ContainerDep, SessionDep

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
        claimed_by=e.claimed_by,
        started_at=e.started_at,
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
            body.project_id, body.sarif, scope, created_by=user.user_id
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
        labeled=result.labeled,
        message=result.describe(),
    )


async def _project_names(session, ids: set[UUID]) -> dict[UUID, str]:
    """Nombres de proyecto en una sola consulta, no una por fila."""
    if not ids:
        return {}
    filas = (
        await session.execute(
            select(ProjectRow.id, ProjectRow.name).where(
                ProjectRow.id.in_([str(i) for i in ids])
            )
        )
    ).all()
    return {UUID(i): n for i, n in filas}


@router.get("", response_model=list[ExecutionResponse])
async def list_executions(
    session: SessionDep, user: UserDep, project_id: UUID | None = None
) -> list[ExecutionResponse]:
    """Las ejecuciones de quien pregunta, la más reciente primero.

    Se filtran por el dueño del proyecto. Sin este filtro, cualquiera
    autenticado veía las ejecuciones de todos, y con ellas los fragmentos de
    código que cada hallazgo arrastra.
    """
    miembros = SqlMembershipRepository(session)
    stmt = (
        select(ExecutionRow)
        .join(ProjectRow, ProjectRow.id == ExecutionRow.project_id)
        .where(miembros.visible_para(user.user_id))
        .order_by(ExecutionRow.created_at.desc())
    )
    if project_id:
        stmt = stmt.where(ExecutionRow.project_id == str(project_id))
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


@router.post("/{execution_id}/run", status_code=status.HTTP_202_ACCEPTED,
             response_model=EnqueuedResponse)
async def run(
    execution_id: UUID,
    session: SessionDep,
    user: UserDep,
) -> EnqueuedResponse:
    """Deja la ejecución en la cola y vuelve de inmediato.

    No valida aquí. Un hallazgo tarda entre diez y veinticinco segundos según el
    modelo, y un lote de cien con repeticiones son horas: hacerlo dentro de la
    petición deja abierta una conexión que ninguna plataforma sostiene, y el
    trabajo muere con el primer reinicio del servicio web.

    Quien ejecuta es el trabajador, que toma de la cola con bloqueo de fila. El
    avance se consulta por el recorrido de la ejecución.
    """
    user.require("investigador", "lider_tecnico")

    repo = SqlExecutionRepository(session)
    execution = await repo.get(execution_id)
    if execution is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No existe esa ejecución")

    # Encolar dos veces no duplica el trabajo: la ejecución ya pendiente se
    # queda como está, y una en proceso la toma ya un trabajador.
    if execution.status is ExecutionStatus.COMPLETED:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Esa ejecución ya terminó. Para volver a correrla, reanúdala.",
        )

    return EnqueuedResponse(
        execution_id=execution.id,
        status=execution.status.value,
        pending_findings=execution.pending_findings,
        message=(
            "En cola. La toma el siguiente trabajador disponible; el avance se "
            "consulta en el recorrido de la ejecución."
        ),
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
            .where(FindingRow.execution_id == str(execution_id))
            .order_by(FindingRow.priority.desc().nullslast(), FindingRow.fingerprint)
        )
    ).scalars().all()

    verdict_rows = (
        await session.execute(
            select(VerdictRow).where(
                VerdictRow.finding_id.in_([r.id for r in rows] or [""])
            )
        )
    ).scalars().all()
    latest: dict[str, VerdictRow] = {}
    todos: dict[str, list[VerdictRow]] = {}
    for v in verdict_rows:
        actual = latest.get(v.finding_id)
        if actual is None or v.repetition >= actual.repetition:
            latest[v.finding_id] = v
        todos.setdefault(v.finding_id, []).append(v)

    salida: list[FindingResponse] = []
    for r in rows:
        v = latest.get(r.id)
        if cwe and (r.cwe or "").upper() != cwe.upper():
            continue
        if verdict and (v is None or v.value != verdict):
            continue
        if anchor is not None and (v is None or v.anchor_verified != anchor):
            continue
        salida.append(
            FindingResponse(
                id=UUID(r.id),
                rule_id=r.rule_id,
                cwe=r.cwe,
                severity=r.rule_severity,
                file_path=r.file_path,
                start_line=r.start_line,
                end_line=r.end_line,
                message=r.message,
                fingerprint=r.fingerprint,
                priority=r.priority,
                priority_reason=r.priority_reason,
                stability=None
                if v is None
                else StabilityResponse(
                    runs=len(todos[r.id]),
                    agree=sum(1 for x in todos[r.id] if x.value == v.value),
                ),
                verdict=None
                if v is None
                else VerdictResponse(
                    model=v.model,
                    model_version=v.model_version,
                    value=v.value,
                    confidence=v.confidence,
                    anchor_verified=v.anchor_verified,
                    attempts=v.attempts,
                    reused=v.reused_from is not None,
                    justification=v.justification,
                    cited_lines=list(v.cited_lines or []),
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
            "finding_id", "regla", "cwe", "severidad", "file_path", "linea",
            "fingerprint", "known_truth", "model", "model_version", "repetition",
            "veredicto", "confidence", "anchor_verified", "attempts",
            "cited_lines", "reutilizado", "latency_ms",
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



@router.post(
    "/findings/{finding_id}/audit",
    response_model=AuditResponse,
    status_code=status.HTTP_201_CREATED,
)
async def record_audit(
    finding_id: UUID,
    body: AuditRequest,
    session: SessionDep,
    user: UserDep,
) -> AuditResponse:
    """Registra la decisión de quien revisa, fuera de cualquier estudio.

    Comparte tabla con las decisiones del estudio, porque el acto es el mismo,
    pero no carga ninguna de sus columnas: sin participante, sin condición y
    sin lote. Pedírselas obligaba a registrar a quien usa la herramienta como
    sujeto de un estudio.

    Rectificar no sobrescribe: se guarda otra y la anterior deja de ser la
    vigente, de modo que el historial permita distinguir una primera impresión
    de una conclusión.
    """
    finding = await SqlFindingRepository(session).get(finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No existe ese hallazgo")

    try:
        audit = Decision(
            finding_id=finding_id,
            value=DecisionValue(body.value),
            seconds=body.seconds,
            user_id=user.user_id,
            comment=body.comment,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    await SqlDecisionRepository(session).save(audit)
    return AuditResponse(
        id=audit.id,
        finding_id=audit.finding_id,
        value=audit.value.value,
        seconds=audit.seconds,
        is_current=audit.is_current,
        comment=audit.comment,
        created_at=audit.created_at,
    )


@router.get("/findings/{finding_id}/audits", response_model=list[AuditResponse])
async def audit_history(
    finding_id: UUID, session: SessionDep, user: UserDep
) -> list[AuditResponse]:
    """El historial, rectificaciones incluidas, de la más reciente a la primera."""
    registros = await SqlDecisionRepository(session).list_by_finding(finding_id)
    return [
        AuditResponse(
            id=a.id,
            finding_id=a.finding_id,
            value=a.value.value,
            seconds=a.seconds,
            is_current=a.is_current,
            comment=a.comment,
            created_at=a.created_at,
        )
        for a in registros
    ]


@router.get("/{execution_id}/compare")
async def compare_executions(
    execution_id: UUID, against: UUID, session: SessionDep, user: UserDep
) -> dict:
    """Qué cambió entre dos corridas del mismo proyecto.

    Se compara por huella y no por archivo y línea. La huella se calcula sobre
    el contenido, de modo que un hallazgo se reconoce como el mismo aunque el
    código se haya movido veinte líneas más abajo: sin eso, insertar una
    importación arriba del archivo haría aparecer como nuevos a todos los
    hallazgos de ese archivo.

    Las dos corridas tienen que ser del mismo proyecto. Comparar contra otro
    proyecto daría tres listas donde todo es nuevo y todo está resuelto, que no
    es una comparación sino un ruido.
    """
    miembros = SqlMembershipRepository(session)
    visibles = (
        await session.execute(
            select(ExecutionRow)
            .join(ProjectRow, ProjectRow.id == ExecutionRow.project_id)
            .where(
                ExecutionRow.id.in_([str(execution_id), str(against)]),
                miembros.visible_para(user.user_id),
            )
        )
    ).scalars().all()
    por_id = {r.id: r for r in visibles}
    nueva, vieja = por_id.get(str(execution_id)), por_id.get(str(against))
    if nueva is None or vieja is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No existe esa ejecución")
    if nueva.project_id != vieja.project_id:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Las dos corridas tienen que ser del mismo proyecto",
        )

    async def hallazgos(ident: str) -> dict[str, dict]:
        filas = (
            await session.execute(
                select(
                    FindingRow.id, FindingRow.fingerprint, FindingRow.rule_id,
                    FindingRow.cwe, FindingRow.rule_severity,
                    FindingRow.file_path, FindingRow.start_line,
                ).where(FindingRow.execution_id == ident)
            )
        ).all()
        return {
            f.fingerprint: {
                "id": f.id,
                "fingerprint": f.fingerprint,
                "rule_id": f.rule_id,
                "cwe": f.cwe,
                "severity": f.rule_severity,
                "file_path": f.file_path,
                "start_line": f.start_line,
            }
            for f in filas
        }

    de_ahora, de_antes = await hallazgos(nueva.id), await hallazgos(vieja.id)
    ahora, antes = set(de_ahora), set(de_antes)

    def ordenar(huellas, origen):
        return sorted(
            (origen[h] for h in huellas),
            key=lambda f: (f["file_path"], f["start_line"]),
        )

    return {
        "execution_id": str(execution_id),
        "against": str(against),
        "project_id": nueva.project_id,
        "nuevos": ordenar(ahora - antes, de_ahora),
        "resueltos": ordenar(antes - ahora, de_antes),
        "siguen": ordenar(ahora & antes, de_ahora),
    }
