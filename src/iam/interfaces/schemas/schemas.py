"""Contratos de entrada y salida del contexto de acceso."""

from pydantic import BaseModel


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


class GrantRequest(BaseModel):
    """Emisión de una credencial acotada.

    `subject_kind` decide a qué apunta `subject_id`: al proyecto sobre el que
    operará el trabajador, o al participante al que representa la credencial de
    participación.
    """

    subject_kind: str
    subject_id: str
    label: str | None = None
    days: int | None = None


class GrantResponse(BaseModel):
    """El token va aquí y no vuelve a salir.

    Se entrega una sola vez, al emitirlo. A partir de ese punto en la base solo
    queda su huella, de modo que ni el servicio puede recuperarlo.
    """

    id: str
    token: str
    subject_kind: str
    subject_id: str
    expires_at: str | None


class GrantSummary(BaseModel):
    """Lo que se puede contar de una credencial sin poder usarla."""

    id: str
    subject_kind: str
    subject_id: str
    label: str | None
    created_at: str
    expires_at: str | None
    revoked_at: str | None
    last_used_at: str | None
    active: bool


class GrantExchangeRequest(BaseModel):
    token: str


class ParticipantAccessRequest(BaseModel):
    """Entrada del participante a su sesión, por código anónimo.

    No lleva contraseña, y es deliberado: el protocolo identifica a quien
    participa por un código y promete que no se recoge su nombre ni su correo.
    Pedirle credenciales obligaría a darle una cuenta, que es justo lo que el
    consentimiento dice que no ocurre.
    """

    anonymous_code: str


class ParticipantAccessResponse(BaseModel):
    """Lo que el participante necesita para empezar, y nada más.

    No devuelve la ficha ni el estado del estudio: solo su credencial acotada
    y el reparto que le tocó.
    """

    access_token: str
    token_type: str = "bearer"
    participant_id: str
    order: list[str]
    first_batch: str
    second_batch: str
    # Sobre que ejecucion corre el estudio. Sale del lote congelado y no del
    # participante, que no tiene por que saberla ni escribirla en la direccion.
    execution_id: str | None = None
