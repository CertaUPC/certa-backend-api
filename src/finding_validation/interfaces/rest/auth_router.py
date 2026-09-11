"""Inicio de sesión y registro de usuarios."""

from uuid import uuid4

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from ....shared.database_experiment import UserRow
from ....shared.security import hash_password, issue_token, verify_password
from ..schemas.schemas import LoginRequest, TokenResponse
from .dependencies import ContainerDep, SessionDep

router = APIRouter(prefix="/api/v1/auth", tags=["Acceso"])

ROLES = ("desarrollador", "investigador", "lider_tecnico")


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
async def register(
    body: LoginRequest, session: SessionDep, role: str = "desarrollador"
) -> dict:
    if role not in ROLES:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Rol desconocido. Se admiten: {', '.join(ROLES)}",
        )
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
