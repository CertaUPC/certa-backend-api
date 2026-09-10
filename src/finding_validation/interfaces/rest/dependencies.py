"""Dependencias compartidas por los routers."""

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from ....shared.composition import Container
from ....shared.security import InvalidToken, decode_token

_bearer = HTTPBearer(auto_error=False)


def get_container(request: Request) -> Container:
    return request.app.state.container


async def get_session(
    container: Annotated[Container, Depends(get_container)],
) -> AsyncIterator[AsyncSession]:
    async with container.sessions() as session:
        yield session


class CurrentUser:
    def __init__(self, subject: str, role: str) -> None:
        self.subject = subject
        self.role = role

    def require(self, *roles: str) -> None:
        if roles and self.role not in roles:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Esta operación exige el rol {' o '.join(roles)}, y la sesión "
                    f"tiene {self.role}"
                ),
            )


async def current_user(
    container: Annotated[Container, Depends(get_container)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> CurrentUser:
    if credentials is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="Falta el token de acceso",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_token(
            credentials.credentials,
            container.settings.jwt_secret,
            container.settings.jwt_algorithm,
        )
    except InvalidToken as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    return CurrentUser(payload.get("sub", ""), payload.get("role", "desarrollador"))


ContainerDep = Annotated[Container, Depends(get_container)]
SessionDep = Annotated[AsyncSession, Depends(get_session)]
UserDep = Annotated[CurrentUser, Depends(current_user)]
