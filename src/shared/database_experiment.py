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
    __tablename__ = "usuarios"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    correo: Mapped[str] = mapped_column(String(160), unique=True)
    contrasena_hash: Mapped[str] = mapped_column(String(120))
    rol: Mapped[str] = mapped_column(String(20), default="desarrollador")
    activo: Mapped[bool] = mapped_column(Boolean, default=True)
    creado_en: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    __table_args__ = (
        CheckConstraint(
            "rol IN ('desarrollador','investigador','lider_tecnico')", name="ck_usuarios_rol"
        ),
    )


class ParticipantRow(Base):
    """Sin nombre ni correo: el análisis nunca necesita la identidad."""

    __tablename__ = "participantes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    codigo_anonimo: Mapped[str] = mapped_column(String(20), unique=True)
    anios_experiencia: Mapped[int] = mapped_column(Integer)
    tiene_rol_seguridad: Mapped[bool] = mapped_column(Boolean, default=False)
    consentimiento_en: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    creado_en: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    sessions: Mapped[list["SessionRow"]] = relationship(
        back_populates="participant", cascade="all, delete-orphan"
    )

    __table_args__ = (
        # Criterio de exclusión del estudio, sostenido por el motor.
        CheckConstraint("tiene_rol_seguridad = 0", name="ck_participantes_rol"),
    )


class SessionRow(Base):
    __tablename__ = "sesiones"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    participante_id: Mapped[str] = mapped_column(
        ForeignKey("participantes.id", ondelete="CASCADE")
    )
    orden_condiciones: Mapped[list] = mapped_column(VARIANT_JSON, default=list)
    lote_primero: Mapped[str] = mapped_column(String(10))
    lote_segundo: Mapped[str] = mapped_column(String(10))
    completa: Mapped[bool] = mapped_column(Boolean, default=False)
    iniciada_en: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finalizada_en: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    participant: Mapped[ParticipantRow] = relationship(back_populates="sessions")
    decisions: Mapped[list["DecisionRow"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )


class DecisionRow(Base):
    __tablename__ = "decisiones"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    sesion_id: Mapped[str | None] = mapped_column(
        ForeignKey("sesiones.id", ondelete="CASCADE"), nullable=True
    )
    # Identidad, no clave foránea: la frontera entre contextos delimitados.
    hallazgo_id: Mapped[str] = mapped_column(String(36))
    participante_id: Mapped[str] = mapped_column(String(36))
    valor: Mapped[str] = mapped_column(String(20))
    segundos: Mapped[float] = mapped_column(Float)
    condicion: Mapped[str] = mapped_column(String(20))
    es_vigente: Mapped[bool] = mapped_column(Boolean, default=True)
    comentario: Mapped[str | None] = mapped_column(Text, nullable=True)
    creada_en: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    session: Mapped["SessionRow | None"] = relationship(back_populates="decisions")

    __table_args__ = (
        Index("ix_decisiones_hallazgo", "hallazgo_id"),
        Index("ix_decisiones_participante", "participante_id", "condicion"),
        CheckConstraint("segundos > 0", name="ck_decisiones_segundos"),
        CheckConstraint(
            "valor IN ('confirmado','descartado','dudoso')", name="ck_decisiones_valor"
        ),
    )


class TransformationRow(Base):
    __tablename__ = "transformaciones"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    hallazgo_original_id: Mapped[str] = mapped_column(String(36))
    hallazgo_transformado_id: Mapped[str] = mapped_column(String(36))
    tipo: Mapped[str] = mapped_column(String(30))
    anclaje_activo: Mapped[bool] = mapped_column(Boolean, default=True)
    veredicto_original: Mapped[str | None] = mapped_column(String(20), nullable=True)
    veredicto_transformado: Mapped[str | None] = mapped_column(String(20), nullable=True)
    descripcion: Mapped[str | None] = mapped_column(Text, nullable=True)
    creada_en: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    __table_args__ = (
        UniqueConstraint(
            "hallazgo_original_id", "hallazgo_transformado_id", "anclaje_activo",
            name="uq_transf_par",
        ),
        CheckConstraint(
            "hallazgo_original_id <> hallazgo_transformado_id",
            name="ck_transf_distintos",
        ),
    )
