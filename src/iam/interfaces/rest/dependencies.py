"""Quién llama, resuelto a partir del token.

Es lo que el contexto de acceso ofrece a los demás: los enrutadores de
validación y de experimentación dependen de esto para saber con qué rol se
opera, y no al revés. Antes vivía dentro de validación, de modo que la
dependencia iba en la dirección equivocada.

HAY TRES CLASES DE LLAMANTE Y NO UNA. Una cuenta de persona, que tiene rol. Un
trabajador, acotado a un proyecto. Una participación, acotada a un participante
del estudio. Las dos últimas nacen de una credencial emitida y no de un inicio
de sesión.

LA PROPIEDAD QUE SOSTIENE ESTO: una credencial acotada NUNCA satisface una
comprobación de rol. Si `require` admitiera un token de participación porque
trae un rol dentro, la credencial del participante abriría la lista de
participantes y las ejecuciones de todos, que es exactamente lo que se quiere
evitar. Por eso `require` mira primero la clase de llamante y solo después el
rol.
"""

from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ....shared.rest import ContainerDep
from ...domain.access_grant import GrantKind
from ...infrastructure.security import InvalidToken, decode_token

_bearer = HTTPBearer(auto_error=False)

CUENTA = "user"


class CurrentUser:
    """El llamante. Conserva el nombre porque es el que usan los enrutadores.

    `kind` distingue una cuenta de una credencial acotada. Un token emitido
    antes de que existieran las credenciales no lo trae, y se lee como cuenta:
    solo el canje de una credencial escribe ese campo, de modo que su ausencia
    no puede venir de una credencial.
    """

    def __init__(
        self,
        subject: str,
        role: str,
        kind: str = CUENTA,
        grant_id: str | None = None,
    ) -> None:
        self.subject = subject
        self.role = role
        self.kind = kind
        self.grant_id = grant_id

    @property
    def is_account(self) -> bool:
        return self.kind == CUENTA

    @property
    def user_id(self) -> UUID | None:
        """El sujeto del token, que es el identificador de la cuenta.

        Devuelve None si no se puede leer en lugar de reventar: un token
        antiguo o emitido por una herramienta no debe impedir la operacion,
        solo deja la ejecucion sin autor declarado. Una credencial acotada no
        es una cuenta, de modo que tampoco tiene autor que declarar.
        """
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

    def _require_grant(self, kind: GrantKind, subject_id: str, que: str) -> None:
        if self.kind != kind.value or self.subject != str(subject_id):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=f"La credencial presentada no autoriza {que}",
            )

    def require_worker(self, project_id) -> None:
        """Trabajador acotado a ese proyecto y no a otro."""
        self._require_grant(GrantKind.WORKER, project_id, "operar sobre este proyecto")

    def require_participation(self, participant_id) -> None:
        """Participación de esa persona y no de otra.

        Sin esta comprobación, quien tuviera una credencial de participación
        podría escribir decisiones a nombre de cualquier otro participante, y
        la variable principal del experimento dejaría de ser atribuible.
        """
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
        kind=payload.get("kind", CUENTA),
        grant_id=payload.get("grant"),
    )


UserDep = Annotated[CurrentUser, Depends(current_user)]
