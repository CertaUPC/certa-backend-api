"""Tablas de experimentación y de acceso.

Mismo esquema físico que las de validación, pero otro contexto: se relacionan
con los hallazgos por identidad, guardando el UUID, nunca con clave foránea. Esa
frontera permite retirar la instrumentación al terminar sin tocar el producto.
"""

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import VARIANT_JSON, Base


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
            "role IN ('desarrollador','investigador','lider_tecnico')", name="ck_users_role"
        ),
    )


class ParticipantRow(Base):
    """Sin nombre ni correo: el análisis nunca necesita la identidad."""

    __tablename__ = "participants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    anonymous_code: Mapped[str] = mapped_column(String(20), unique=True)
    years_of_experience: Mapped[int] = mapped_column(Integer)
    has_security_role: Mapped[bool] = mapped_column(Boolean, default=False)
    consented_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    sessions: Mapped[list["SessionRow"]] = relationship(
        back_populates="participant", cascade="all, delete-orphan"
    )

    __table_args__ = (
        # Criterio de exclusión del estudio, sostenido por el motor.
        CheckConstraint("has_security_role = false", name="ck_participants_role"),
    )


class SessionRow(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    participant_id: Mapped[str] = mapped_column(
        ForeignKey("participants.id", ondelete="CASCADE")
    )
    condition_order: Mapped[list] = mapped_column(VARIANT_JSON, default=list)
    first_batch: Mapped[str] = mapped_column(String(10))
    second_batch: Mapped[str] = mapped_column(String(10))
    is_complete: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    participant: Mapped[ParticipantRow] = relationship(back_populates="sessions")
    decisions: Mapped[list["DecisionRow"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )


class DecisionRow(Base):
    __tablename__ = "decisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    session_id: Mapped[str | None] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), nullable=True
    )
    # Identidad, no clave foránea: la frontera entre contextos delimitados.
    finding_id: Mapped[str] = mapped_column(String(36))
    participant_id: Mapped[str] = mapped_column(String(36))
    value: Mapped[str] = mapped_column(String(20))
    seconds: Mapped[float] = mapped_column(Float)
    condition: Mapped[str] = mapped_column(String(20))
    is_current: Mapped[bool] = mapped_column(Boolean, default=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    session: Mapped["SessionRow | None"] = relationship(back_populates="decisions")

    __table_args__ = (
        Index("ix_decisions_finding", "finding_id"),
        Index("ix_decisions_participant", "participant_id", "condition"),
        CheckConstraint("seconds > 0", name="ck_decisions_seconds"),
        CheckConstraint(
            "value IN ('confirmado','descartado','dudoso')", name="ck_decisions_value"
        ),
    )


class TransformationRow(Base):
    __tablename__ = "transformations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    original_finding_id: Mapped[str] = mapped_column(String(36))
    transformed_finding_id: Mapped[str] = mapped_column(String(36))
    kind: Mapped[str] = mapped_column(String(30))
    anchoring_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    original_verdict: Mapped[str | None] = mapped_column(String(20), nullable=True)
    transformed_verdict: Mapped[str | None] = mapped_column(String(20), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    __table_args__ = (
        UniqueConstraint(
            "original_finding_id", "transformed_finding_id", "anchoring_enabled",
            name="uq_transformations_pair",
        ),
        CheckConstraint(
            "original_finding_id <> transformed_finding_id",
            name="ck_transformations_distinct",
        ),
    )
