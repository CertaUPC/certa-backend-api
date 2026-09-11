"""Instrumentación del experimento: participantes, decisiones y métricas."""

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from ....finding_validation.interfaces.rest.dependencies import SessionDep, UserDep
from ....finding_validation.interfaces.schemas.schemas import (
    DecisionRequest,
    MetricsResponse,
    ParticipantRequest,
)
from ....shared.database import FindingRow, VerdictRow
from ...domain.entities.decision import Decision
from ...domain.entities.participant import Participant
from ...domain.services.counterbalancer import Counterbalancer
from ...domain.services.metrics_calculator import MetricsCalculator
from ...domain.value_objects.condition import Condition, DecisionValue
from ...infrastructure.persistence.sql_repositories import (
    SqlDecisionRepository,
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
    if await participants.get_by_code(body.anonymous_code):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Ya existe un participante con el código {body.anonymous_code}",
        )

    try:
        participant = Participant(
            anonymous_code=body.anonymous_code,
            years_of_experience=body.years_of_experience,
            consented_at=datetime.now(timezone.utc),
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
        "experience_band": participant.experience_band,
        "order": [c.value for c in assignment.order],
        "first_batch": assignment.first_batch,
        "second_batch": assignment.second_batch,
    }


@router.get("/participants")
async def list_participants(session: SessionDep, user: UserDep) -> list[dict]:
    """Registrados, con el orden que les tocó.

    Es lo que permite comprobar de un vistazo que el contrabalanceo sigue
    equilibrado antes de convocar al siguiente.
    """
    user.require("investigador", "lider_tecnico")

    participants = SqlParticipantRepository(session)
    sessions = SqlSessionRepository(session)
    ordenes = await sessions.existing_orders()

    salida: list[dict] = []
    for i, p in enumerate(await participants.list_all()):
        orden = ordenes[i] if i < len(ordenes) else None
        salida.append(
            {
                "participant_id": str(p.id),
                "anonymous_code": p.anonymous_code,
                "experience_band": p.experience_band,
                "order": [c.value for c in orden] if orden else [],
                "first_batch": "A",
                "second_batch": "B",
            }
        )
    return salida


@router.post("/decisions", status_code=status.HTTP_201_CREATED)
async def record_decision(
    body: DecisionRequest, session: SessionDep, user: UserDep
) -> dict:
    """Registra la decisión y el tiempo. Son las variables dependientes."""
    try:
        decision = Decision(
            finding_id=body.finding_id,
            participant_id=body.participant_id,
            value=DecisionValue(body.value),
            seconds=body.seconds,
            condition=Condition(body.condition),
            comment=body.comment,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    await SqlDecisionRepository(session).record(decision, body.session_id)
    return {"decision_id": str(decision.id), "recorded": True}


@router.get("/findings/{finding_id}/decisions")
async def decision_history(
    finding_id: UUID, session: SessionDep, user: UserDep
) -> list[dict]:
    """Historial completo, incluidas las rectificadas.

    Conservarlas permite distinguir un cambio de opinión de un dato ausente.
    """
    user.require("investigador", "lider_tecnico")
    historial = await SqlDecisionRepository(session).history_for(finding_id)
    return [
        {
            "participant_id": str(d.participant_id),
            "value": d.value.value,
            "seconds": d.seconds,
            "condition": d.condition.value,
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

    return MetricsResponse(
        execution_id=execution_id,
        total_verdicts=len(rows),
        confusion=confusion.report(),
        anchor_rate_first_try=round(calculator.anchor_rate(anclados, len(rows)), 4),
        run_is_valid=quality.is_valid,
        run_quality_reason=quality.reason,
        budget="(el consumo se informa al ejecutar)",
    )
