"""Instrumentación del experimento: participantes, decisiones y métricas."""

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from ....iam.domain.access_grant import GrantKind, mint
from ....iam.infrastructure.persistence.grant_repository import (
    SqlAccessGrantRepository,
)
from ....iam.interfaces.rest.dependencies import UserDep
from ....shared.rest import SessionDep
from ....finding_validation.interfaces.schemas.schemas import (
    DecisionRequest,
    FinishSessionRequest,
    MetricsResponse,
    ParticipantRequest,
    SessionThemeRequest,
)
from ....shared.database import DecisionRow, FindingRow, VerdictRow
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
    """Registra un participante, le asigna el orden y le habilita el acceso.

    Sin consentimiento no se almacena ningún dato. La asignación del orden se
    calcula desde el historial persistido, de modo que el reparto quede
    equilibrado y sea reproducible.

    Las tres cosas van en una sola petición a propósito. Antes la pantalla
    llamaba aquí y después a la emisión de credenciales, y bastaba con que la
    segunda no llegara para dejar a una persona registrada y sin poder entrar:
    reintentar respondía que el código ya existía, y quien se sentaba delante
    leía que no tenía sesión abierta sin que nadie supiera por qué.
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
            f"Ya existe un participante con el código {codigo}. Si es quien "
            f"está sentado ahí, habilítale el acceso desde la tabla en lugar "
            f"de volver a registrarlo.",
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

    # La credencial, aquí mismo. El token en claro no se devuelve porque nadie
    # lo teclea: lo canjea el servicio cuando la persona escribe su código.
    credencial, _ = mint(
        subject_kind=GrantKind.PARTICIPATION,
        subject_id=str(participant.id),
        issued_by=str(user.user_id) if user.user_id else None,
        label=f"Sesión de {participant.anonymous_code}",
    )
    await SqlAccessGrantRepository(session).save(credencial)

    return {
        "participant_id": str(participant.id),
        "session_id": str(session_id),
        "access_expires_at": (
            credencial.expires_at.isoformat() if credencial.expires_at else None
        ),
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
    credenciales = SqlAccessGrantRepository(session)

    lotes = SqlBatchRepository(session)
    lote = await lotes.frozen_id()
    del_lote = sum((await lotes.batches()).values()) if lote else 0
    avance = await SqlSessionRepository(session).progress(lote)

    salida: list[dict] = []
    for p in await participants.list_all():
        suyo = repartos.get(p.id, {})
        # Si puede entrar o no es lo primero que hace falta saber cuando la
        # persona ya está sentada delante, y hasta ahora no se veía en ninguna
        # parte: la pantalla daba por hecho que todo registrado tenía acceso.
        vigentes = [
            g
            for g in await credenciales.list_for(GrantKind.PARTICIPATION, str(p.id))
            if g.is_active
        ]
        vence = max(
            (g.expires_at for g in vigentes if g.expires_at), default=None
        )
        marcha = avance.get(p.id, {})
        decidido = marcha.get("decided_by_condition", {})
        salida.append(
            {
                "participant_id": str(p.id),
                "anonymous_code": p.anonymous_code,
                "experience_band": p.experience_band,
                "is_pilot": p.is_pilot,
                # La ficha que contestó al consentir. Es factor de control del
                # análisis, y hasta ahora había que ir a la base para verla.
                "main_language": p.main_language,
                "alert_frequency": p.alert_frequency,
                "security_training": p.security_training,
                "has_security_role": p.has_security_role,
                "consented_at": p.consented_at.isoformat() if p.consented_at else None,
                "order": suyo.get("order", []),
                "first_batch": suyo.get("first_batch"),
                "second_batch": suyo.get("second_batch"),
                "puede_entrar": bool(vigentes),
                "access_expires_at": vence.isoformat() if vence else None,
                # Cómo va. Sin esto no se distinguía a quien se registró y no
                # empezó de quien recorrió los dos lotes.
                "session_id": marcha.get("session_id"),
                "is_complete": marcha.get("is_complete", False),
                "started_at": (
                    marcha["started_at"].isoformat()
                    if marcha.get("started_at")
                    else None
                ),
                "finished_at": (
                    marcha["finished_at"].isoformat()
                    if marcha.get("finished_at")
                    else None
                ),
                "theme": marcha.get("theme"),
                "decided_by_condition": decidido,
                "decided": sum(decidido.values()),
                "expected": del_lote,
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

    # El lote no se le pide al cliente: es unico y el servidor lo sabe.
    # Pedirselo seria darle ocasion de equivocarse en un dato que no es
    # suyo, y sin el no se puede decir contra que lote se midio.
    lote = await SqlBatchRepository(session).frozen_id()

    try:
        decision = Decision(
            finding_id=body.finding_id,
            participant_id=body.participant_id,
            session_id=body.session_id,
            worklist_id=lote,
            value=DecisionValue(body.value),
            seconds=body.seconds,
            condition=Condition(body.condition).value,
            comment=body.comment,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    await SqlDecisionRepository(session).save(decision)
    return {"decision_id": str(decision.id), "recorded": True}


@router.post("/sessions/finish")
async def finish_session(
    body: FinishSessionRequest, session: SessionDep, user: UserDep
) -> dict:
    """Cierra la sesión del participante y declara si quedó completa.

    El repositorio sabía cerrarla desde el principio y no había ruta que lo
    pidiera, de modo que ninguna sesión podía marcarse terminada: el análisis
    no distinguía a quien recorrió los dos lotes de quien abandonó en el
    primero.

    Lo completo no se declara desde el cliente. Se comprueba aquí contra el
    lote congelado: una sesión está completa cuando el participante tiene una
    decisión vigente para cada hallazgo de las dos mitades. Así el estado no
    depende de que la pantalla llegue viva hasta el final.
    """
    user.require_study_access(body.participant_id)

    lotes = SqlBatchRepository(session)
    esperados: set[str] = set()
    for mitad in ("A", "B"):
        esperados |= {str(i) for i in await lotes.finding_ids(mitad)}

    decididos = {
        str(f[0])
        for f in (
            await session.execute(
                select(DecisionRow.finding_id).where(
                    DecisionRow.participant_id == str(body.participant_id),
                    DecisionRow.is_current.is_(True),
                )
            )
        ).all()
    }

    completa = bool(esperados) and esperados <= decididos
    await SqlSessionRepository(session).close(body.session_id, completa)
    return {
        "session_id": str(body.session_id),
        "is_complete": completa,
        "decided": len(esperados & decididos),
        "expected": len(esperados),
    }


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
