"""Inicio de sesión, registro de usuarios y credenciales acotadas."""

from uuid import uuid4

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from ....shared.rest import ContainerDep, SessionDep
from ...domain.access_grant import GrantKind, InvalidGrant, mint, parse
from ...infrastructure.persistence.grant_repository import (
    SqlAccessGrantRepository,
)
from ...infrastructure.persistence.models import UserRow
from ...infrastructure.security import hash_password, issue_token, verify_password
from ..schemas.schemas import (
    GrantExchangeRequest,
    GrantRequest,
    GrantResponse,
    GrantSummary,
    LoginRequest,
    ParticipantAccessRequest,
    ParticipantAccessResponse,
    TokenResponse,
)
from .dependencies import UserDep

router = APIRouter(prefix="/api/v1/auth", tags=["Acceso"])

ROLES = ("desarrollador", "investigador", "lider_tecnico")

# Cuánto vive el JWT del canje. Corto a propósito: la credencial larga viaja
# una vez por sesión de trabajo y no en cada petición, y una revocación surte
# efecto en cuanto caduca el JWT en curso.
EXCHANGE_MINUTES = {
    GrantKind.WORKER: 30,
    GrantKind.PARTICIPATION: 120,
}


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest, container: ContainerDep, session: SessionDep
) -> TokenResponse:
    row = (
        await session.execute(
            select(UserRow).where(UserRow.email == body.email.lower().strip())
        )
    ).scalar_one_or_none()

    # Se verifica igual aunque el usuario no exista, para no revelar por el
    # tiempo de respuesta qué correos están registrados.
    hash_guardado = row.password_hash if row else hash_password("contrasena-inexistente")
    valida = verify_password(body.password, hash_guardado)

    if row is None or not valida or not row.is_active:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Correo o contraseña incorrectos"
        )

    token = issue_token(
        subject=str(row.id),
        secret=container.settings.jwt_secret,
        algorithm=container.settings.jwt_algorithm,
        minutes=container.settings.jwt_expiration_minutes,
        role=row.role,
        email=row.email,
    )
    return TokenResponse(access_token=token, role=row.role)


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(body: LoginRequest, session: SessionDep) -> dict:
    """Alta de cuenta, siempre con el rol de menor privilegio.

    El rol ya no se pide. Antes viajaba como parametro y el alta era publica,
    de modo que cualquiera podia darse de alta como investigador y leer los
    hallazgos ajenos. Los demas roles los concede quien ya tiene
    `lider_tecnico`, en el endpoint de mas abajo.
    """
    role = "desarrollador"
    email = body.email.lower().strip()
    existe = (
        await session.execute(select(UserRow).where(UserRow.email == email))
    ).scalar_one_or_none()
    if existe:
        raise HTTPException(status.HTTP_409_CONFLICT, "Ese correo ya está registrado")

    try:
        hashed = hash_password(body.password)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    user_id = str(uuid4())
    session.add(UserRow(id=user_id, email=email, password_hash=hashed, role=role))
    await session.commit()
    return {"id": user_id, "email": email, "role": role}


def _summary(g) -> GrantSummary:
    def iso(d):
        return d.isoformat() if d else None

    return GrantSummary(
        id=g.id,
        subject_kind=g.subject_kind.value,
        subject_id=g.subject_id,
        label=g.label,
        created_at=g.created_at.isoformat(),
        expires_at=iso(g.expires_at),
        revoked_at=iso(g.revoked_at),
        last_used_at=iso(g.last_used_at),
        active=g.is_active,
    )


@router.post("/grants", status_code=status.HTTP_201_CREATED, response_model=GrantResponse)
async def issue_grant(
    body: GrantRequest, session: SessionDep, user: UserDep
) -> GrantResponse:
    """Emite una credencial acotada y devuelve el token una sola vez.

    Emitirla exige una cuenta de persona: una credencial no puede emitir otra,
    porque entonces quien obtuviera una de participación se fabricaría la del
    trabajador y el acotamiento no serviría de nada.

    Quién puede emitir cuál se decidirá por dueño del proyecto cuando los
    proyectos tengan dueño. Hasta entonces lo gobierna el rol.
    """
    user.require("investigador", "lider_tecnico")

    try:
        tipo = GrantKind(body.subject_kind)
    except ValueError as exc:
        admitidos = ", ".join(k.value for k in GrantKind)
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Tipo de credencial desconocido. Se admiten: {admitidos}",
        ) from exc

    from datetime import timedelta

    lifetime = timedelta(days=body.days) if body.days else ...
    grant, token = mint(
        subject_kind=tipo,
        subject_id=body.subject_id,
        issued_by=str(user.user_id) if user.user_id else None,
        label=body.label,
        lifetime=lifetime,
    )
    await SqlAccessGrantRepository(session).save(grant)
    return GrantResponse(
        id=grant.id,
        token=token,
        subject_kind=grant.subject_kind.value,
        subject_id=grant.subject_id,
        expires_at=grant.expires_at.isoformat() if grant.expires_at else None,
    )


@router.get("/grants", response_model=list[GrantSummary])
async def list_grants(
    subject_kind: str, subject_id: str, session: SessionDep, user: UserDep
) -> list[GrantSummary]:
    """Las credenciales de un sujeto, para poder revocarlas.

    Se listan las vencidas y las revocadas junto a las vigentes: para decidir
    qué apagar hay que ver lo que existe.
    """
    user.require("investigador", "lider_tecnico")
    try:
        tipo = GrantKind(subject_kind)
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "Tipo de credencial desconocido"
        ) from exc
    grants = await SqlAccessGrantRepository(session).list_for(tipo, subject_id)
    return [_summary(g) for g in grants]


@router.delete("/grants/{grant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_grant(grant_id: str, session: SessionDep, user: UserDep) -> None:
    """Apaga una credencial. No la borra: hace falta saber que existió."""
    user.require("investigador", "lider_tecnico")
    if not await SqlAccessGrantRepository(session).revoke(grant_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No existe esa credencial")


@router.post("/token", response_model=TokenResponse)
async def exchange_grant(
    body: GrantExchangeRequest, container: ContainerDep, session: SessionDep
) -> TokenResponse:
    """Canjea una credencial por un token de acceso de vida corta.

    Es la única puerta que acepta la credencial larga. A partir de aquí el
    trabajador y el participante llevan un JWT acotado, de modo que el secreto
    no viaja en cada petición y su exposición se limita a este intercambio.

    El motivo del rechazo no se detalla hacia fuera: decir «venció» y no
    «revocada» ya confirma que la credencial existió.
    """
    invalida = HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        detail="La credencial no es válida",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        tipo, identifier, secret = parse(body.token)
    except InvalidGrant as exc:
        raise invalida from exc

    repo = SqlAccessGrantRepository(session)
    grant = await repo.get(identifier)
    if grant is None or grant.subject_kind is not tipo or not grant.matches(secret):
        raise invalida
    if grant.rejection_reason() is not None:
        raise invalida

    await repo.touch(grant.id)
    token = issue_token(
        subject=grant.subject_id,
        secret=container.settings.jwt_secret,
        algorithm=container.settings.jwt_algorithm,
        minutes=EXCHANGE_MINUTES[grant.subject_kind],
        kind=grant.subject_kind.value,
        grant=grant.id,
    )
    return TokenResponse(access_token=token, role=grant.subject_kind.value)


@router.patch("/users/{user_id}/role")
async def change_role(
    user_id: str, role: str, session: SessionDep, user: UserDep
) -> dict:
    """Concede un rol. Solo quien ya tiene el mayor.

    Es la unica via para que exista un investigador, y por eso el despliegue
    necesita sembrar el primero: sin nadie con `lider_tecnico`, nadie puede
    conceder nada.
    """
    user.require("lider_tecnico")
    if role not in ROLES:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Rol desconocido. Se admiten: {', '.join(ROLES)}",
        )
    fila = (
        await session.execute(select(UserRow).where(UserRow.id == user_id))
    ).scalar_one_or_none()
    if fila is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No existe esa cuenta")
    fila.role = role
    await session.commit()
    return {"id": fila.id, "email": fila.email, "role": fila.role}


@router.post("/participant", response_model=ParticipantAccessResponse)
async def participant_access(
    body: ParticipantAccessRequest, container: ContainerDep, session: SessionDep
) -> ParticipantAccessResponse:
    """Entrada del participante a su sesión, con su código anónimo.

    El código no es un secreto: el protocolo lo usa como identificador y quien
    dirige la sesión se lo dicta. Lo que controla el acceso es que exista una
    credencial de participación vigente para ese código, emitida al empezar y
    vencida en horas. Darle cuenta y contraseña a cada participante
    contradiría el consentimiento, que promete no recoger nada que le
    identifique.

    Lo que evita es el apaño anterior, que el participante entrara en el
    navegador del investigador con la sesión de este abierta.
    """
    from sqlalchemy import select as _select

    from ....experimentation.infrastructure.persistence.sql_repositories import (
        SqlBatchRepository,
    )
    from ....shared.database_experiment import ParticipantRow, SessionRow

    negado = HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        detail=(
            "Ese código no tiene una sesión abierta. Avisa a quien dirige el "
            "estudio."
        ),
    )

    codigo = body.anonymous_code.strip().upper()
    if not codigo:
        raise negado

    participante = (
        await session.execute(
            _select(ParticipantRow).where(ParticipantRow.anonymous_code == codigo)
        )
    ).scalar_one_or_none()
    if participante is None:
        raise negado

    repo = SqlAccessGrantRepository(session)
    vigentes = [
        g for g in await repo.list_for(GrantKind.PARTICIPATION, participante.id)
        if g.is_active
    ]
    if not vigentes:
        raise negado

    fila = (
        await session.execute(
            _select(SessionRow).where(SessionRow.participant_id == participante.id)
        )
    ).scalars().first()
    if fila is None:
        raise negado

    grant = vigentes[0]
    await repo.touch(grant.id)
    token = issue_token(
        subject=participante.id,
        secret=container.settings.jwt_secret,
        algorithm=container.settings.jwt_algorithm,
        minutes=EXCHANGE_MINUTES[GrantKind.PARTICIPATION],
        kind=GrantKind.PARTICIPATION.value,
        grant=grant.id,
    )
    return ParticipantAccessResponse(
        access_token=token,
        participant_id=participante.id,
        order=list(fila.condition_order or []),
        first_batch=fila.first_batch,
        second_batch=fila.second_batch,
        execution_id=str(await SqlBatchRepository(session).execution_id() or "")
        or None,
    )
