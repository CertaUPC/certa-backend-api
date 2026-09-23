"""Quién llama, resuelto a partir del token.

Es lo que el contexto de acceso ofrece a los demás: los enrutadores de
validación y de experimentación dependen de esto para saber con qué rol se
opera, y no al revés. Antes vivía dentro de validación, de modo que la
dependencia iba en la dirección equivocada.
"""

from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ....shared.rest import ContainerDep
from ...infrastructure.security import InvalidToken, decode_token

_bearer = HTTPBearer(auto_error=False)


class CurrentUser:
    def __init__(self, subject: str, role: str) -> None:
        self.subject = subject
        self.role = role

    @property
    def user_id(self) -> UUID | None:
        """El sujeto del token, que es el identificador de la cuenta.

        Devuelve None si no se puede leer en lugar de reventar: un token
        antiguo o emitido por una herramienta no debe impedir la operacion,
        solo deja la ejecucion sin autor declarado.
        """
        try:
            return UUID(self.subject)
        except (ValueError, AttributeError, TypeError):
            return None

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
    container: ContainerDep,
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


UserDep = Annotated[CurrentUser, Depends(current_user)]
