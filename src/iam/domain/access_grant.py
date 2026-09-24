"""Credenciales que no son el inicio de sesión de una persona.

QUÉ PROBLEMA RESUELVE. Hoy la única credencial es el JWT que devuelve el login,
y eso obliga a dos apaños. El trabajador, para operar, se conecta directo a la
base de datos, de modo que entregárselo a alguien significa entregarle la base
entera. Y el participante del estudio entra en el navegador que el investigador
dejó con su sesión abierta, o sea que durante la sesión el equipo guarda un
token con permisos de investigador.

Las dos cosas son la misma carencia: falta una credencial acotada a un recurso,
revocable, que no represente a una persona.

DE DÓNDE SALE EL DISEÑO. Del patrón que usan los tokens de acceso personal de
GitHub y las claves de Stripe, que resuelven exactamente esto:

  el token lleva dentro su propio identificador, de modo que verificarlo es una
  búsqueda indexada y una comparación, y no recorrer la tabla entera cifrando;

  del secreto solo se guarda la huella, y el token en claro se muestra una vez
  al emitirlo;

  un prefijo reconocible permite encontrarlo en un registro o en un repositorio
  por descuido.

POR QUÉ SHA-256 Y NO BCRYPT, que es lo que ya hay en el módulo de seguridad.
Bcrypt existe para encarecer el intento por intento contra contraseñas humanas,
que tienen poca entropía. El secreto de aquí son treinta y dos bytes de
`secrets`, de modo que no hay nada que adivinar: el espacio es tan grande que la
lentitud no compra seguridad, solo latencia en cada petición del trabajador.
Bcrypt además trunca a setenta y dos bytes. La comparación va en tiempo
constante, que es lo que sí importa.

LO QUE ESTE MÓDULO NO HACE. No decide qué puede hacer cada credencial. Aquí solo
vive qué es, cómo se acuña y cómo se comprueba. Los permisos los resuelve quien
atiende la petición, porque dependen del recurso y no de la credencial.
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
    """A qué apunta la credencial.

    Son dos y están cerradas. Un catálogo abierto de permisos sería más
    flexible y también más difícil de auditar, y este sistema tiene dos casos.
    """

    WORKER = "worker"
    PARTICIPATION = "participation"

    @property
    def abbreviation(self) -> str:
        return "wk" if self is GrantKind.WORKER else "pt"

    @property
    def default_lifetime(self) -> timedelta | None:
        """Cuánto vive la credencial si nadie dice otra cosa.

        La del trabajador dura porque se instala una vez, pero no es eterna: un
        vencimiento obliga a rotarla. La de participación cubre la sesión de
        sesenta minutos con holgura y poco más, porque no hay motivo para que
        siga sirviendo al día siguiente.
        """
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
    """Una credencial emitida, sin el secreto.

    El secreto no se guarda ni viaja en esta entidad: solo su huella. Quien
    acuña la credencial recibe el token una vez y se lo lleva.
    """

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
        # Las fechas entran con zona horaria, vengan de donde vengan. SQLite
        # devuelve fechas sin zona aunque la columna la declare, mientras que
        # PostgreSQL las devuelve con ella, de modo que comparar el
        # vencimiento reventaba en local y no en el despliegue. El invariante
        # se sostiene aquí y no en cada comparación: lo que se guardó es UTC.
        for field_name in ("created_at", "expires_at", "revoked_at", "last_used_at"):
            value = getattr(self, field_name)
            if value is not None and value.tzinfo is None:
                object.__setattr__(self, field_name, value.replace(tzinfo=timezone.utc))

    @property
    def is_active(self) -> bool:
        return self.rejection_reason() is None

    def rejection_reason(self, at: datetime | None = None) -> str | None:
        """Por qué no sirve, o None si sirve.

        Devuelve el motivo en vez de un booleano porque el registro de quien
        rechaza una credencial necesita saber si venció o si fue revocada: son
        situaciones distintas y solo una es un incidente.
        """
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
        """Se marca, no se borra. Hace falta poder decir que existió."""
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

    El token en claro sale de aquí y no vuelve a existir: a partir de este
    punto solo queda su huella. Quien llama tiene que entregarlo en la misma
    respuesta o perderlo.

    `vigencia` sin declarar toma la de su tipo; `None` explícito crea una
    credencial sin vencimiento, que solo se apaga revocándola.
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

    Se parte en cuatro y no más, porque el secreto es lo último y no puede
    quedar recortado si algún día cambia el alfabeto y admite el separador.

    Leerlo no lo valida: dice a qué fila hay que ir a buscar. La comprobación
    del secreto es cosa de la entidad, contra la huella guardada.
    """
    partes = token.strip().split("_", 3)
    if len(partes) != 4 or partes[0] != PREFIX:
        raise InvalidGrant("El token no tiene la forma de una credencial de Certa")
    _, short, identifier, secret = partes
    try:
        tipo = GrantKind.from_abbreviation(short)
    except ValueError as exc:
        raise InvalidGrant(str(exc)) from exc
    if not identifier or not secret:
        raise InvalidGrant("El token está incompleto")
    return tipo, identifier, secret
