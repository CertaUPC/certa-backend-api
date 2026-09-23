"""Tablas de experimentación.

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


class ParticipantRow(Base):
    """Sin nombre ni correo: el análisis nunca necesita la identidad."""

    __tablename__ = "participants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    anonymous_code: Mapped[str] = mapped_column(String(20), unique=True)
    years_of_experience: Mapped[int] = mapped_column(Integer)
    has_security_role: Mapped[bool] = mapped_column(Boolean, default=False)
    consented_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # El protocolo declara un piloto cuyos datos se excluyen del análisis.
    # Marcarlo en el esquema, y no en el código anónimo, evita que la
    # exclusión dependa de que alguien recuerde la convención.
    is_pilot: Mapped[bool] = mapped_column(Boolean, default=False)
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
    # Con qué presentación resolvió la tarea. No se recoge por gusto: la
    # usabilidad queda controlada como variable extraña, y registrar el tema
    # permite descartarlo como factor en el análisis en vez de suponerlo
    # irrelevante. Nulo en las sesiones anteriores al cambio.
    theme: Mapped[str | None] = mapped_column(String(10), nullable=True)
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
    # El participante SÍ vive en este contexto, de modo que aquí no hay
    # frontera que respetar y la integridad la garantiza el motor. Estaba como
    # cadena suelta mientras sessions.participant_id sí la declaraba: la misma
    # relación resuelta de dos maneras dentro del mismo esquema. Y es la peor
    # tabla donde dejarla suelta, porque decisions guarda la variable principal
    # del experimento: una decisión huérfana es un resultado que no se sostiene.
    participant_id: Mapped[str] = mapped_column(
        ForeignKey("participants.id", ondelete="CASCADE")
    )
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
    # Identidad y no clave foránea, por la misma razón que en decisions: el
    # hallazgo pertenece al contexto de validación y esta tabla al de
    # experimentación. Se deja dicho porque era la única referencia del esquema
    # sin justificar, y una referencia suelta sin explicación se lee como
    # descuido aunque no lo sea.
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


class BatchItemRow(Base):
    """Qué hallazgos componen cada mitad del lote de las sesiones.

    El 4.5 exige que el lote quede fijado antes de reclutar. Fijarlo en un
    fichero no basta: si el servicio no lo conoce, la pantalla sirve la
    ejecución entera y el participante ve un corpus en vez de doce alertas.
    Esta tabla es ese lote, y vive aquí y no junto a los hallazgos porque el
    reparto es una decisión del experimento, no una propiedad del hallazgo.

    Identidad y no clave foránea, como el resto del contexto.
    """

    __tablename__ = "session_batch_items"

    finding_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    batch: Mapped[str] = mapped_column(String(10))
    # Orden dentro de la mitad. El reparto es reproducible y se registra, de
    # modo que dos participantes de la misma condición ven la misma secuencia.
    position: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    __table_args__ = (
        UniqueConstraint("batch", "position", name="uq_session_batch_position"),
        Index("ix_session_batch", "batch", "position"),
    )
