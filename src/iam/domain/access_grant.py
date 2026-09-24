"""Credenciales acotadas a un recurso, no a una persona.

El trabajador y el participante tienen que operar sin el token de un
investigador: uno se instala en una máquina ajena, el otro dura lo que dura una
sesión. El formato sigue al de los tokens personales de GitHub, que llevan
dentro el identificador de su fila, de modo que verificar es una búsqueda
indexada y una comparación y no recorrer la tabla cifrando.

Del secreto se guarda la huella SHA-256 y no un bcrypt: son treinta y dos bytes
de `secrets`, así que encarecer el intento no compra nada y bcrypt además trunca
a setenta y dos. Lo que sí importa es comparar en tiempo constante.

Qué puede hacer cada credencial lo decide quien atiende la petición; aquí vive
solo qué es, cómo se acuña y cómo se comprueba.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from uuid import uuid4

PREFIX = "certa"


class GrantKind(str, Enum):
    """A qué apunta la credencial."""

    WORKER = "worker"
    PARTICIPATION = "participation"

    @property
    def abbreviation(self) -> str:
        return "wk" if self is GrantKind.WORKER else "pt"

    @property
    def default_lifetime(self) -> timedelta | None:
        """La del trabajador se instala una vez y hay que rotarla; la de
        participación cubre la sesión de sesenta minutos y poco más."""
        return timedelta(days=90) if self is GrantKind.WORKER else timedelta(hours=12)

    @classmethod
    def from_abbreviation(cls, short: str) -> "GrantKind":
        for k in cls:
            if k.abbreviation == short:
                return k
        raise ValueError(f"Abreviatura de credencial desconocida: {short!r}")


class InvalidGrant(ValueError):
    """La credencial no se pudo leer, no existe, venció o fue revocada."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _digest(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


@dataclass
class AccessGrant:
    """Una credencial emitida, de la que solo queda la huella del secreto."""

    subject_kind: GrantKind
    subject_id: str
    secret_hash: str
    issued_by: str | None = None
    label: str | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    last_used_at: datetime | None = None
    id: str = field(default_factory=lambda: uuid4().hex)
    created_at: datetime = field(default_factory=_now)

    def __post_init__(self) -> None:
        if not self.subject_id or not self.subject_id.strip():
            raise ValueError("Una credencial tiene que apuntar a algo")
        if len(self.secret_hash) != 64:
            raise ValueError("La huella del secreto no tiene la forma esperada")
        # SQLite devuelve las fechas sin zona y PostgreSQL con ella, de modo que
        # comparar el vencimiento reventaba en local y no en el despliegue.
        for field_name in ("created_at", "expires_at", "revoked_at", "last_used_at"):
            value = getattr(self, field_name)
            if value is not None and value.tzinfo is None:
                object.__setattr__(self, field_name, value.replace(tzinfo=timezone.utc))

    @property
    def is_active(self) -> bool:
        return self.rejection_reason() is None

    def rejection_reason(self, at: datetime | None = None) -> str | None:
        """El motivo en vez de un booleano: vencer y ser revocada son cosas
        distintas y solo una es un incidente."""
        at = at or _now()
        if self.revoked_at is not None:
            return "La credencial fue revocada"
        if self.expires_at is not None and self.expires_at <= at:
            return "La credencial venció"
        return None

    def matches(self, secret: str) -> bool:
        """Comparación en tiempo constante, para no filtrar el secreto por el
        tiempo que tarda en fallar."""
        return hmac.compare_digest(self.secret_hash, _digest(secret))

    def revoke(self, at: datetime | None = None) -> None:
        """Se marca, no se borra: hace falta poder decir que existió."""
        if self.revoked_at is None:
            self.revoked_at = at or _now()


def mint(
    subject_kind: GrantKind,
    subject_id: str,
    issued_by: str | None = None,
    label: str | None = None,
    lifetime: timedelta | None = ...,  # type: ignore[assignment]
) -> tuple[AccessGrant, str]:
    """Crea la credencial y devuelve (entidad, token en claro).

    El token en claro sale de aquí y no vuelve a existir, así que quien llama
    tiene que entregarlo en la misma respuesta. `lifetime` sin declarar toma la
    de su tipo; `None` explícito crea una credencial que solo se apaga
    revocándola.
    """
    if lifetime is ...:
        lifetime = subject_kind.default_lifetime
    secret = secrets.token_hex(32)
    grant = AccessGrant(
        subject_kind=subject_kind,
        subject_id=subject_id,
        secret_hash=_digest(secret),
        issued_by=issued_by,
        label=label,
        expires_at=_now() + lifetime if lifetime else None,
    )
    token = f"{PREFIX}_{subject_kind.abbreviation}_{grant.id}_{secret}"
    return grant, token


def parse(token: str) -> tuple[GrantKind, str, str]:
    """Descompone un token en (tipo, identificador, secreto).

    Leerlo no lo valida: dice a qué fila hay que ir a buscar. El secreto se
    comprueba en la entidad, contra la huella guardada.
    """
    parts = token.strip().split("_", 3)
    if len(parts) != 4 or parts[0] != PREFIX:
        raise InvalidGrant("El token no tiene la forma de una credencial de Certa")
    _, short, identifier, secret = parts
    try:
        kind = GrantKind.from_abbreviation(short)
    except ValueError as exc:
        raise InvalidGrant(str(exc)) from exc
    if not identifier or not secret:
        raise InvalidGrant("El token está incompleto")
    return kind, identifier, secret
