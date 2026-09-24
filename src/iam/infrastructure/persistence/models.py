"""Tabla de cuentas del contexto de acceso.

Vivía junto a las tablas de experimentación porque ambas se añadieron a la vez,
no porque compartan contexto. Una cuenta no es un participante del estudio: el
participante se identifica por un código anónimo y no tiene credenciales, y la
cuenta pertenece a quien opera la herramienta.
"""

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
)
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


class AccessGrantRow(Base):
    """Credenciales acotadas que no representan a una persona.

    Viven en el contexto de acceso porque son credenciales, aunque protejan
    recursos de otros contextos. Esa es justo la razón de que `subject_id` no
    lleve clave foránea: apunta a un proyecto o a un participante según el
    tipo, de modo que el contexto de acceso no depende de ninguno de los dos y
    los tres pueden evolucionar por separado. Queda declarado como cruce de
    frontera en las pruebas de integridad del esquema.

    Del secreto solo se guarda la huella. El token en claro se entrega una vez
    al emitirlo y no vuelve a existir en ninguna parte.
    """

    __tablename__ = "access_grants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    subject_kind: Mapped[str] = mapped_column(String(20))
    subject_id: Mapped[str] = mapped_column(String(36))
    secret_hash: Mapped[str] = mapped_column(String(64))
    # Quien la emitió. Se conserva aunque la cuenta desaparezca, por lo mismo
    # que la autoría de una ejecución: la emisión es un hecho que ocurrió.
    issued_by: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    # Para reconocerla al revocarla. «Portátil de Ana» dice más que un uuid.
    label: Mapped[str | None] = mapped_column(String(80), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Se marca, no se borra: hace falta poder decir que existió y cuándo dejó
    # de servir.
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        CheckConstraint(
            "subject_kind IN ('worker','participation')",
            name="ck_access_grants_kind",
        ),
        # La verificación busca por tipo y sujeto al listar lo vigente de un
        # proyecto o de un participante.
        Index("ix_access_grants_subject", "subject_kind", "subject_id"),
    )
