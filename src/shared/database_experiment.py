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
    # La banda que la ficha pregunta, y no un entero de años. El entero
    # obligaba a inventar un número que nadie dio: el formulario pregunta por
    # tramos, y las tres bandas que el modelo derivaba no coincidían con los
    # cuatro que preguntaba.
    experience_band: Mapped[str] = mapped_column(String(12))
    main_language: Mapped[str | None] = mapped_column(String(40), nullable=True)
    alert_frequency: Mapped[str | None] = mapped_column(String(12), nullable=True)
    security_training: Mapped[str | None] = mapped_column(String(12), nullable=True)
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
    # Las decisiones ya no cuelgan de aquí como colección. Viven en el esquema
    # del producto, porque el acto es el mismo lo use quien lo use, y esta
    # tabla no tiene por qué conocerlas para existir. La relación se resuelve
    # por consulta, que es lo que hacen los repositorios.




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
