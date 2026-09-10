"""Credenciales y sesiones. Fuera del dominio: cómo se cifra una contraseña no
es una regla de validar hallazgos."""

from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
from jose import JWTError, jwt

# Coste de bcrypt. Doce rondas es el equilibrio habitual entre resistencia y
# latencia de inicio de sesión en hardware corriente.
_ROUNDS = 12


class InvalidToken(ValueError):
    """El token no es válido, venció o fue emitido con otra clave."""


def hash_password(plain: str) -> str:
    if len(plain) < 8:
        raise ValueError("La contraseña exige al menos ocho caracteres")
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(_ROUNDS)).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        # Un hash corrupto o de otro formato no es una excepción del servicio:
        # es simplemente una verificación que no pasa.
        return False


def issue_token(
    subject: str, secret: str, algorithm: str, minutes: int, **claims: Any
) -> str:
    ahora = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "iat": ahora,
        "exp": ahora + timedelta(minutes=minutes),
        **claims,
    }
    return jwt.encode(payload, secret, algorithm=algorithm)


def decode_token(token: str, secret: str, algorithm: str) -> dict[str, Any]:
    try:
        return jwt.decode(token, secret, algorithms=[algorithm])
    except JWTError as exc:
        raise InvalidToken(f"Token inválido o vencido: {exc}") from exc
