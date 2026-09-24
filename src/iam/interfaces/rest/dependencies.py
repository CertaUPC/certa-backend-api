"""Quién llama, resuelto a partir del token.

Es lo que el contexto de acceso ofrece a los demás: los enrutadores de
validación y de experimentación dependen de esto para saber con qué rol se
opera, y no al revés. Antes vivía dentro de validación, de modo que la
dependencia iba en la dirección equivocada.

Hay tres clases de llamante: una cuenta de persona, que tiene rol; un
trabajador acotado a un proyecto; y una participación acotada a un
participante. Las dos últimas nacen de una credencial emitida.

Una credencial acotada nunca satisface una comprobación de rol, y de eso
depende lo demás: si `require` admitiera un token de participación porque trae
un rol dentro, abriría la lista de participantes y las ejecuciones de todos.
"""

from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ....shared.rest import ContainerDep
from ...domain.access_grant import GrantKind
from ...infrastructure.security import InvalidToken, decode_token

_bearer = HTTPBearer(auto_error=False)

ACCOUNT = "user"


class CurrentUser:
    """El llamante. Conserva el nombre porque es el que usan los enrutadores.

    `kind` distingue una cuenta de una credencial acotada. Un token anterior a
    las credenciales no lo trae y se lee como cuenta, porque solo el canje de
    una credencial escribe ese campo.
    """

    def __init__(
        self,
        subject: str,
        role: str,
        kind: str = ACCOUNT,
        grant_id: str | None = None,
    ) -> None:
        self.subject = subject
        self.role = role
        self.kind = kind
        self.grant_id = grant_id

    @property
    def is_account(self) -> bool:
        return self.kind == ACCOUNT

    @property
    def user_id(self) -> UUID | None:
        """El sujeto del token, o None si no se puede leer: un token antiguo
        no debe impedir la operacion, solo deja la ejecucion sin autor."""
        if not self.is_account:
            return None
        try:
            return UUID(self.subject)
        except (ValueError, AttributeError, TypeError):
            return None

    def require(self, *roles: str) -> None:
        if not self.is_account:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=(
                    "Esta operación exige una cuenta de persona. La credencial "
                    f"presentada es de tipo {self.kind} y solo sirve para "
                    "aquello a lo que está acotada"
                ),
            )
        if roles and self.role not in roles:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Esta operación exige el rol {' o '.join(roles)}, y la sesión "
                    f"tiene {self.role}"
                ),
            )

    def _require_grant(self, kind: GrantKind, subject_id: str, what: str) -> None:
        if self.kind != kind.value or self.subject != str(subject_id):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=f"La credencial presentada no autoriza {what}",
            )

    def require_worker(self, project_id) -> None:
        """Trabajador acotado a ese proyecto y no a otro."""
        self._require_grant(GrantKind.WORKER, project_id, "operar sobre este proyecto")

    def require_participation(self, participant_id) -> None:
        """Participación de esa persona y no de otra: sin esto, una credencial
        podría escribir decisiones a nombre de cualquier otro participante."""
        self._require_grant(
            GrantKind.PARTICIPATION, participant_id, "actuar por este participante"
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
    return CurrentUser(
        subject=payload.get("sub", ""),
        role=payload.get("role", "desarrollador"),
        kind=payload.get("kind", ACCOUNT),
        grant_id=payload.get("grant"),
    )


UserDep = Annotated[CurrentUser, Depends(current_user)]
