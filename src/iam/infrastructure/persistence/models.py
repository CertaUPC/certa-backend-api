"""Tabla de cuentas del contexto de acceso.

Vivía junto a las tablas de experimentación porque ambas se añadieron a la vez,
no porque compartan contexto. Una cuenta no es un participante del estudio: el
participante se identifica por un código anónimo y no tiene credenciales, y la
cuenta pertenece a quien opera la herramienta.
"""

from datetime import datetime, timezone

from sqlalchemy import Boolean, CheckConstraint, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from ....shared.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class UserRow(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(String(160), unique=True)
    password_hash: Mapped[str] = mapped_column(String(120))
    role: Mapped[str] = mapped_column(String(20), default="desarrollador")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    __table_args__ = (
        CheckConstraint(
            "role IN ('desarrollador','investigador','lider_tecnico')",
            name="ck_users_role",
        ),
    )
