"""Motor, sesión y tablas. Espejo de arquitectura/modelo-datos.

El mismo motor hace de persistencia y de cola: para este volumen no hace falta
un intermediario de mensajería aparte.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
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

# JSONB en PostgreSQL, JSON en cualquier otro motor. Permite ejercitar el
# mapeo con SQLite en las pruebas sin levantar una base real.
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

VARIANT_JSON = JSON().with_variant(JSONB(), "postgresql")


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class ProjectRow(Base):
    __tablename__ = "proyectos"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    nombre: Mapped[str] = mapped_column(String(200))
    lenguaje: Mapped[str] = mapped_column(String(50), default="java")
    ruta_repositorio: Mapped[str] = mapped_column(Text, unique=True)
    es_conjunto_publico: Mapped[bool] = mapped_column(Boolean, default=False)
    creado_en: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    executions: Mapped[list["ExecutionRow"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class ExecutionRow(Base):
    """Fila de ejecución. `estado` es también la columna de la cola."""

    __tablename__ = "ejecuciones"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    proyecto_id: Mapped[str] = mapped_column(
        ForeignKey("proyectos.id", ondelete="CASCADE")
    )
    herramienta: Mapped[str] = mapped_column(String(100), default="semgrep-oss")
    version_reglas: Mapped[str] = mapped_column(String(100))
    estado: Mapped[str] = mapped_column(String(20), default="pendiente")
    alcance: Mapped[str | None] = mapped_column(Text, nullable=True)
    total_hallazgos: Mapped[int] = mapped_column(Integer, default=0)
    validados: Mapped[int] = mapped_column(Integer, default=0)
    sarif_original: Mapped[dict | None] = mapped_column(VARIANT_JSON, nullable=True)
    tomada_por: Mapped[str | None] = mapped_column(String(120), nullable=True)
    motivo_fallo: Mapped[str | None] = mapped_column(Text, nullable=True)
    contexto_purgado: Mapped[bool] = mapped_column(Boolean, default=False)
    iniciada_en: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finalizada_en: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    creada_en: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    project: Mapped[ProjectRow] = relationship(back_populates="executions")
    findings: Mapped[list["FindingRow"]] = relationship(
        back_populates="execution", cascade="all, delete-orphan"
    )

    __table_args__ = (
        # Sostiene la cola: se consulta siempre por estado y antigüedad.
        Index("ix_ejecuciones_cola", "estado", "creada_en"),
        CheckConstraint(
            "estado IN ('pendiente','en_proceso','completada','fallida')",
            name="ck_ejecuciones_estado",
        ),
    )


class FindingRow(Base):
    __tablename__ = "hallazgos"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    ejecucion_id: Mapped[str] = mapped_column(
        ForeignKey("ejecuciones.id", ondelete="CASCADE")
    )
    regla_id: Mapped[str] = mapped_column(String(200))
    cwe: Mapped[str | None] = mapped_column(String(20), nullable=True)
    severidad_regla: Mapped[str] = mapped_column(String(20))
    archivo: Mapped[str] = mapped_column(Text)
    linea_inicio: Mapped[int] = mapped_column(Integer)
    linea_fin: Mapped[int] = mapped_column(Integer)
    mensaje: Mapped[str | None] = mapped_column(Text, nullable=True)
    huella: Mapped[str] = mapped_column(String(64))
    verdad_conocida: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    prioridad: Mapped[float | None] = mapped_column(Float, nullable=True)
    motivo_prioridad: Mapped[str | None] = mapped_column(Text, nullable=True)
    creado_en: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    execution: Mapped[ExecutionRow] = relationship(back_populates="findings")
    context: Mapped["ContextRow | None"] = relationship(
        back_populates="finding", cascade="all, delete-orphan", uselist=False
    )
    verdicts: Mapped[list["VerdictRow"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_hallazgos_ejecucion", "ejecucion_id"),
        # La huella se consulta para reutilizar veredictos ya pagados.
        Index("ix_hallazgos_huella", "huella"),
        Index("ix_hallazgos_prioridad", "ejecucion_id", "prioridad"),
        CheckConstraint("linea_fin >= linea_inicio", name="ck_hallazgos_lineas"),
    )


class ContextRow(Base):
    __tablename__ = "contextos"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    hallazgo_id: Mapped[str] = mapped_column(
        ForeignKey("hallazgos.id", ondelete="CASCADE"), unique=True
    )
    funcion_contenedora: Mapped[str] = mapped_column(Text)
    llamadores: Mapped[list] = mapped_column(VARIANT_JSON, default=list)
    saneadores: Mapped[list] = mapped_column(VARIANT_JSON, default=list)
    lineas_disponibles: Mapped[list] = mapped_column(VARIANT_JSON, default=list)
    fuente_identificada: Mapped[str | None] = mapped_column(Text, nullable=True)
    profundidad_llamadores: Mapped[int] = mapped_column(Integer, default=2)
    degradado_a_archivo: Mapped[bool] = mapped_column(Boolean, default=False)
    # El texto exacto enviado al modelo. Es contra esto que se verifica el
    # anclaje, y sin conservarlo la verificación no sería auditable después.
    texto_contexto: Mapped[str | None] = mapped_column(Text, nullable=True)
    creado_en: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    finding: Mapped[FindingRow] = relationship(back_populates="context")


class VerdictRow(Base):
    __tablename__ = "veredictos"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    hallazgo_id: Mapped[str] = mapped_column(
        ForeignKey("hallazgos.id", ondelete="CASCADE")
    )
    modelo: Mapped[str] = mapped_column(String(120))
    version_modelo: Mapped[str] = mapped_column(String(120))
    version_consulta: Mapped[str | None] = mapped_column(String(120), nullable=True)
    temperatura: Mapped[float] = mapped_column(Float, default=0.0)
    repeticion: Mapped[int] = mapped_column(Integer, default=1)
    valor: Mapped[str] = mapped_column(String(20))
    confianza: Mapped[float | None] = mapped_column(Float, nullable=True)
    lineas_citadas: Mapped[list] = mapped_column(VARIANT_JSON, default=list)
    anclaje_verificado: Mapped[bool] = mapped_column(Boolean)
    intentos: Mapped[int] = mapped_column(Integer, default=1)
    justificacion: Mapped[str | None] = mapped_column(Text, nullable=True)
    respuesta_completa: Mapped[dict | None] = mapped_column(VARIANT_JSON, nullable=True)
    latencia_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tokens_entrada: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tokens_salida: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reutilizado_de: Mapped[str | None] = mapped_column(String(36), nullable=True)
    creado_en: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    finding: Mapped[FindingRow] = relationship(back_populates="verdicts")

    __table_args__ = (
        # La versión del modelo entra en la clave: un cambio de versión a mitad
        # de la medición genera registros nuevos en lugar de sobrescribir.
        UniqueConstraint(
            "hallazgo_id", "modelo", "version_modelo", "repeticion",
            name="uq_veredictos_condicion",
        ),
        Index("ix_veredictos_hallazgo", "hallazgo_id"),
        Index("ix_veredictos_modelo", "modelo", "version_modelo", "repeticion"),
        CheckConstraint("intentos BETWEEN 1 AND 2", name="ck_veredictos_intentos"),
        CheckConstraint(
            "confianza IS NULL OR (confianza >= 0 AND confianza <= 1)",
            name="ck_veredictos_confianza",
        ),
    )


def create_engine(url: str, echo: bool = False) -> AsyncEngine:
    return create_async_engine(url, echo=echo, pool_pre_ping=True)


def session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@asynccontextmanager
async def schema(engine: AsyncEngine) -> AsyncIterator[None]:
    """Crea y destruye el esquema. Solo para pruebas: en producción manda Alembic."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    try:
        yield
    finally:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
