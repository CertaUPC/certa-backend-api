"""Instrumentación del experimento: participantes, decisiones y métricas."""

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from ....iam.interfaces.rest.dependencies import UserDep
from ....shared.rest import SessionDep
from ....finding_validation.interfaces.schemas.schemas import (
    DecisionRequest,
    MetricsResponse,
    ParticipantRequest,
    SessionThemeRequest,
)
from ....shared.database import FindingRow, VerdictRow
from ....finding_validation.domain.entities.decision import Decision
from ....finding_validation.infrastructure.persistence.sql_repositories import (
    SqlDecisionRepository,
)
from ...domain.entities.participant import Participant, normalizar_codigo
from ...domain.services.counterbalancer import Counterbalancer
from ...domain.services.metrics_calculator import MetricsCalculator
from ...domain.services.misleading_follow import (
    MisleadingCase,
    follow_rate,
    misleading_cases,
)
from ...domain.value_objects.condition import Condition, DecisionValue
from ...infrastructure.persistence.sql_repositories import (
    SqlBatchRepository,
    SqlParticipantRepository,
    SqlSessionRepository,
)

router = APIRouter(prefix="/api/v1/experiment", tags=["Experimento"])


@router.post("/participants", status_code=status.HTTP_201_CREATED)
async def register_participant(
    body: ParticipantRequest, session: SessionDep, user: UserDep
) -> dict:
    """Registra un participante y le asigna el orden de condiciones.

    Sin consentimiento no se almacena ningún dato. La asignación del orden se
    calcula desde el historial persistido, de modo que el reparto quede
    equilibrado y sea reproducible.
    """
    user.require("investigador")

    if not body.consented:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Sin consentimiento informado no se registra ningún dato del participante",
        )

    participants = SqlParticipantRepository(session)
    codigo = normalizar_codigo(body.anonymous_code)
    if await participants.get_by_code(codigo):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Ya existe un participante con el código {codigo}",
        )

    try:
        participant = Participant(
            anonymous_code=codigo,
            experience_band=body.experience_band,
            has_security_role=body.has_security_role,
            main_language=body.main_language,
            alert_frequency=body.alert_frequency,
            security_training=body.security_training,
            consented_at=datetime.now(timezone.utc),
            is_pilot=body.is_pilot,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    await participants.save(participant)

    sessions = SqlSessionRepository(session)
    assignment = Counterbalancer().assign(await sessions.existing_orders())
    session_id = await sessions.create(participant.id, assignment)

    return {
        "participant_id": str(participant.id),
        "session_id": str(session_id),
        # El codigo canonico, que es el que hay que dictar: quien lo escribio
        # pudo teclearlo sin guion y la pantalla tiene que leer lo guardado.
        "anonymous_code": participant.anonymous_code,
        "experience_band": participant.experience_band,
        "is_pilot": participant.is_pilot,
        "order": [c.value for c in assignment.order],
        "first_batch": assignment.first_batch,
        "second_batch": assignment.second_batch,
    }


@router.get("/participants")
async def list_participants(session: SessionDep, user: UserDep) -> list[dict]:
    """Registrados, cada uno con el reparto que le tocó a él.

    Es lo que permite comprobar de un vistazo que el contrabalanceo sigue
    equilibrado antes de convocar al siguiente, de modo que emparejar mal a
    una persona con la sesión de otra no es un detalle de presentación.
    """
    user.require("investigador", "lider_tecnico")

    participants = SqlParticipantRepository(session)
    repartos = await SqlSessionRepository(session).assignments()

    salida: list[dict] = []
    for p in await participants.list_all():
        suyo = repartos.get(p.id, {})
        salida.append(
            {
                "participant_id": str(p.id),
                "anonymous_code": p.anonymous_code,
                "experience_band": p.experience_band,
                "is_pilot": p.is_pilot,
                "order": suyo.get("order", []),
                "first_batch": suyo.get("first_batch"),
                "second_batch": suyo.get("second_batch"),
            }
        )
    return salida


@router.get("/batches")
async def list_batches(session: SessionDep, user: UserDep) -> dict:
    """Cuantos hallazgos tiene cada mitad del lote congelado.

    Sirve para comprobar antes de convocar que el lote esta cargado y que las
    dos mitades tienen el mismo tamano. Un lote a medias no se detecta durante
    la sesion: se detecta al analizar, cuando ya no tiene arreglo.
    """
    user.require_study_access()
    cuenta = await SqlBatchRepository(session).batches()
    return {"lotes": cuenta, "total": sum(cuenta.values())}


@router.get("/batches/{batch}")
async def batch_findings(batch: str, session: SessionDep, user: UserDep) -> dict:
    """Los hallazgos de una mitad, en el orden registrado.

    La pantalla de auditoria pide esto antes de cargar nada mas. Sin el filtro
    serviria la ejecucion entera, y el participante veria el corpus completo en
    vez de los doce que le tocan.
    """
    user.require_study_access()
    ids = await SqlBatchRepository(session).finding_ids(batch)
    if not ids:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"El lote {batch!r} no tiene hallazgos registrados. Congelalo y "
            f"cargalo antes de convocar a nadie.",
        )
    return {"lote": batch, "hallazgos": [str(i) for i in ids]}


@router.post("/sessions/theme")
async def record_session_theme(
    body: SessionThemeRequest, session: SessionDep, user: UserDep
) -> dict:
    """Anota con qué presentación resolvió la tarea el participante.

    US032 exige que la presentación quede fijada durante la sesión y que se
    registre cuál se empleó, para que el análisis pueda descartarla como factor
    en lugar de suponer que no influye.

    Se escribe una sola vez. Un segundo intento con otro tema se rechaza: sería
    la señal de que la presentación cambió a mitad de sesión, y aceptarlo
    borraría la evidencia de ese cambio.
    """
    user.require_study_access(body.participant_id)

    sessions = SqlSessionRepository(session)
    if not await sessions.record_theme(body.participant_id, body.theme):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "No hay sesión para ese participante, o ya tiene registrado otro "
            "tema. La presentación no puede cambiar dentro de una sesión.",
        )
    return {
        "participant_id": str(body.participant_id),
        "theme": body.theme,
    }


@router.post("/decisions", status_code=status.HTTP_201_CREATED)
async def record_decision(
    body: DecisionRequest, session: SessionDep, user: UserDep
) -> dict:
    """Registra la decisión y el tiempo. Son las variables dependientes.

    Escribe en la misma tabla que las decisiones del producto, porque el acto
    es el mismo. Lo que la distingue es lo que trae: participante, sesión y
    condición asignada, que una decisión de uso ordinario deja vacíos.

    La condición se valida contra el objeto de valor del estudio y se guarda
    como texto: la tabla vive en el contexto de validación, que no conoce ese
    vocabulario ni tiene por qué.

    Una credencial de participación solo escribe a su propio nombre. Sin eso,
    quien tuviera una podría decidir por cualquier otro participante y la
    variable principal dejaría de ser atribuible.
    """
    user.require_study_access(body.participant_id)

    try:
        decision = Decision(
            finding_id=body.finding_id,
            participant_id=body.participant_id,
            session_id=body.session_id,
            value=DecisionValue(body.value),
            seconds=body.seconds,
            condition=Condition(body.condition).value,
            comment=body.comment,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    await SqlDecisionRepository(session).save(decision)
    return {"decision_id": str(decision.id), "recorded": True}


@router.get("/findings/{finding_id}/decisions")
async def decision_history(
    finding_id: UUID, session: SessionDep, user: UserDep
) -> list[dict]:
    """Historial completo, incluidas las rectificadas.

    Conservarlas permite distinguir un cambio de opinión de un dato ausente.
    """
    user.require("investigador", "lider_tecnico")
    historial = await SqlDecisionRepository(session).list_by_finding(finding_id)
    return [
        {
            "participant_id": str(d.participant_id),
            "value": d.value.value,
            "seconds": d.seconds,
            "condition": d.condition,
            "is_current": d.is_current,
        }
        for d in historial
    ]


@router.get("/executions/{execution_id}/metrics", response_model=MetricsResponse)
async def metrics(
    execution_id: UUID, session: SessionDep, user: UserDep
) -> MetricsResponse:
    """Matriz de confusión completa y validez de la corrida.

    Se reporta la matriz entera y no solo la exactitud: un modelo que declarase
    explotable a todo obtendría exactitud aceptable sobre un conjunto
    desbalanceado y utilidad nula, y solo la matriz lo hace visible.
    """
    user.require("investigador", "lider_tecnico")

    rows = (
        await session.execute(
            select(VerdictRow, FindingRow)
            .join(FindingRow, FindingRow.id == VerdictRow.finding_id)
            .where(FindingRow.execution_id == str(execution_id))
        )
    ).all()
    if not rows:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "La ejecución no registra veredictos"
        )

    calculator = MetricsCalculator()
    pares = [(f.known_truth, v.value == "explotable") for v, f in rows]
    confusion = calculator.confusion(pares)
    etiquetas = [v.value for v, _ in rows]
    quality = calculator.assess_run(etiquetas)
    anclados = sum(1 for v, _ in rows if v.anchor_verified and v.attempts == 1)

    # Los hallazgos en que la herramienta se equivocó, y qué hizo con ellos
    # quien los revisó. No se fabrican: son los errores reales del modelo.
    enganosos = misleading_cases([
        {"finding_id": str(f.id), "verdict": v.value, "known_truth": f.known_truth}
        for v, f in rows
    ])
    decididos = {
        str(d.finding_id): d.value
        for d in await SqlDecisionRepository(session).list_current_by_execution(
            execution_id
        )
    }
    casos = [
        MisleadingCase(
            finding_id=e["finding_id"],
            model_verdict=e["verdict"],
            known_truth=bool(e["known_truth"]),
            participant_decision=decididos[e["finding_id"]],
        )
        for e in enganosos
        if e["finding_id"] in decididos
    ]

    return MetricsResponse(
        execution_id=execution_id,
        total_verdicts=len(rows),
        misleading_verdicts=len(enganosos),
        misleading_follow_rate=(
            None if follow_rate(casos) is None else round(follow_rate(casos), 4)
        ),
        confusion=confusion.report(),
        anchor_rate_first_try=round(calculator.anchor_rate(anclados, len(rows)), 4),
        run_is_valid=quality.is_valid,
        run_quality_reason=quality.reason,
        budget="(el consumo se informa al ejecutar)",
    )
