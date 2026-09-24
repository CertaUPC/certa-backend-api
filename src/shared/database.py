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
from sqlalchemy.engine.url import make_url
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
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    language: Mapped[str] = mapped_column(String(50), default="java")
    # La ruta deja de ser única a secas. Lo era globalmente, de modo que dos
    # clientes que analizaran «/repos/mi-app» compartían proyecto y, con él,
    # los hallazgos del otro. Ahora es única por dueño.
    repository_path: Mapped[str] = mapped_column(Text)
    # Nulo en los proyectos anteriores al dueño, y en los conjuntos públicos
    # como OWASP Benchmark, que no son de nadie y los ve todo el mundo.
    owner_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=True
    )
    is_public_dataset: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    executions: Mapped[list["ExecutionRow"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("owner_id", "repository_path", name="uq_project_owner_path"),
    )


class ExecutionRow(Base):
    """Fila de ejecución. `estado` es también la columna de la cola."""

    __tablename__ = "executions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE")
    )
    tool_name: Mapped[str] = mapped_column(String(100), default="semgrep-oss")
    ruleset_version: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(20), default="pendiente")
    scope: Mapped[str | None] = mapped_column(Text, nullable=True)
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    validated_findings: Mapped[int] = mapped_column(Integer, default=0)
    raw_sarif: Mapped[dict | None] = mapped_column(VARIANT_JSON, nullable=True)
    claimed_by: Mapped[str | None] = mapped_column(String(120), nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # El autor de la ejecución. Se conserva aunque la cuenta desaparezca: la
    # ejecución es un hecho que ocurrió, y borrarla al borrar al usuario
    # destruiría el registro en lugar de anonimizarlo. De ahí SET NULL y no
    # CASCADE.
    created_by: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    context_purged: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    project: Mapped[ProjectRow] = relationship(back_populates="executions")
    findings: Mapped[list["FindingRow"]] = relationship(
        back_populates="execution", cascade="all, delete-orphan"
    )

    __table_args__ = (
        # Sostiene la cola: se consulta siempre por estado y antigüedad.
        Index("ix_executions_queue", "status", "created_at"),
        CheckConstraint(
            "status IN ('pendiente','en_proceso','completada','fallida')",
            name="ck_executions_status",
        ),
    )


class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    execution_id: Mapped[str] = mapped_column(
        ForeignKey("executions.id", ondelete="CASCADE")
    )
    rule_id: Mapped[str] = mapped_column(String(200))
    cwe: Mapped[str | None] = mapped_column(String(20), nullable=True)
    rule_severity: Mapped[str] = mapped_column(String(20))
    file_path: Mapped[str] = mapped_column(Text)
    start_line: Mapped[int] = mapped_column(Integer)
    end_line: Mapped[int] = mapped_column(Integer)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    known_truth: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    priority: Mapped[float | None] = mapped_column(Float, nullable=True)
    priority_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    execution: Mapped[ExecutionRow] = relationship(back_populates="findings")
    context: Mapped["ContextRow | None"] = relationship(
        back_populates="finding", cascade="all, delete-orphan", uselist=False
    )
    verdicts: Mapped[list["VerdictRow"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_findings_execution", "execution_id"),
        # La huella se consulta para reutilizar veredictos ya pagados.
        Index("ix_findings_fingerprint", "fingerprint"),
        Index("ix_findings_priority", "execution_id", "priority"),
        CheckConstraint("end_line >= start_line", name="ck_findings_lines"),
    )


class ContextRow(Base):
    __tablename__ = "code_contexts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), unique=True
    )
    enclosing_function: Mapped[str] = mapped_column(Text)
    callers: Mapped[list] = mapped_column(VARIANT_JSON, default=list)
    # Los métodos a los que el contenedor delega el dato. Se guardan aparte de
    # los llamadores porque responden a preguntas distintas: el llamador dice de
    # dónde viene el dato y el llamado qué le hicieron antes del sumidero, que
    # es lo que decide el veredicto.
    callees: Mapped[list] = mapped_column(VARIANT_JSON, default=list)
    sanitizers: Mapped[list] = mapped_column(VARIANT_JSON, default=list)
    available_lines: Mapped[list] = mapped_column(VARIANT_JSON, default=list)
    source_expression: Mapped[str | None] = mapped_column(Text, nullable=True)
    caller_depth: Mapped[int] = mapped_column(Integer, default=2)
    callee_depth: Mapped[int] = mapped_column(Integer, default=2)
    degraded_to_file: Mapped[bool] = mapped_column(Boolean, default=False)
    # El texto exacto enviado al modelo. Es contra esto que se verifica el
    # anclaje, y sin conservarlo la verificación no sería auditable después.
    context_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    finding: Mapped[FindingRow] = relationship(back_populates="context")


class VerdictRow(Base):
    __tablename__ = "verdicts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE")
    )
    model: Mapped[str] = mapped_column(String(120))
    model_version: Mapped[str] = mapped_column(String(120))
    prompt_version: Mapped[str | None] = mapped_column(String(120), nullable=True)
    temperature: Mapped[float] = mapped_column(Float, default=0.0)
    repetition: Mapped[int] = mapped_column(Integer, default=1)
    value: Mapped[str] = mapped_column(String(20))
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    cited_lines: Mapped[list] = mapped_column(VARIANT_JSON, default=list)
    anchor_verified: Mapped[bool] = mapped_column(Boolean)
    attempts: Mapped[int] = mapped_column(Integer, default=1)
    justification: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_response: Mapped[dict | None] = mapped_column(VARIANT_JSON, nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    input_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reused_from: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    finding: Mapped[FindingRow] = relationship(back_populates="verdicts")

    __table_args__ = (
        # La versión del modelo entra en la clave: un cambio de versión a mitad
        # de la medición genera registros nuevos en lugar de sobrescribir.
        UniqueConstraint(
            "finding_id", "model", "model_version", "repetition",
            name="uq_verdicts_condition",
        ),
        Index("ix_verdicts_finding", "finding_id"),
        Index("ix_verdicts_model", "model", "model_version", "repetition"),
        CheckConstraint("attempts BETWEEN 1 AND 2", name="ck_verdicts_attempts"),
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name="ck_verdicts_confidence",
        ),
    )


# Parametros que solo entiende libpq. asyncpg los rechaza, y la cadena que
# entregan los proveedores gestionados los trae siempre.
_SOLO_LIBPQ = ("sslmode", "channel_binding", "options", "target_session_attrs")


def normalize_database_url(url: str) -> tuple[str, dict]:
    """Deja la cadena en la forma que asyncpg admite.

    Devuelve la cadena corregida y los argumentos de conexion que hagan falta.
    Se aplica sola: pegar la cadena del proveedor tal cual es lo que cualquiera
    va a hacer, y fallar ahi cuesta una tarde de diagnostico.
    """
    u = make_url(url)
    conectar: dict = {}

    if u.drivername in ("postgresql", "postgres"):
        u = u.set(drivername="postgresql+asyncpg")

    if u.drivername == "postgresql+asyncpg":
        consulta = dict(u.query)
        modo = consulta.pop("sslmode", None)
        for clave in _SOLO_LIBPQ:
            consulta.pop(clave, None)
        u = u.set(query=consulta)

        # libpq cifra con sslmode; asyncpg con ssl. Se traduce en vez de
        # descartarlo, porque el proveedor exige cifrado.
        if modo is not None and modo not in ("disable", "allow", "prefer"):
            conectar["ssl"] = True

        # El extremo agrupado multiplexa conexiones entre clientes, y ahi las
        # sentencias preparadas de asyncpg dejan de ser validas de una a otra.
        anfitrion = u.host or ""
        if "-pooler" in anfitrion or "pgbouncer" in anfitrion:
            conectar["statement_cache_size"] = 0

    return u.render_as_string(hide_password=False), conectar


class WorklistRow(Base):
    """Una selección de hallazgos dentro de una ejecución.

    Generaliza lo que el estudio llamaba «lote de la sesión». El producto
    quiere lo mismo sin congelarlo: «revisa estos doce», «los críticos de
    ayer». Que la sesión del experimento sea una lista de trabajo congelada, y
    no otro mecanismo, es lo que la convierte en una función del producto en
    vez de un apaño del estudio.

    `frozen_at` y `fingerprint` son lo propio del uso experimental: el
    protocolo exige que el lote quede fijado antes de reclutar, y la huella
    permite comprobar después que nadie lo cambió. En el producto van nulos,
    porque una lista que se puede reordenar no necesita acreditarse.
    """

    __tablename__ = "worklists"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    execution_id: Mapped[str] = mapped_column(
        ForeignKey("executions.id", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(String(120))
    fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    frozen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now
    )

    items: Mapped[list["WorklistItemRow"]] = relationship(
        back_populates="worklist", cascade="all, delete-orphan"
    )


class WorklistItemRow(Base):
    """Un hallazgo dentro de una lista, en su posición.

    `finding_id` es clave foránea de verdad, a diferencia de la tabla que
    sustituye. Allí era una cadena suelta, de modo que cargar un lote en una
    base que no tuviera esos hallazgos funcionaba sin protestar y la sesión
    reventaba en la primera alerta. Aquí el motor lo impide.
    """

    __tablename__ = "worklist_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    worklist_id: Mapped[str] = mapped_column(
        ForeignKey("worklists.id", ondelete="CASCADE")
    )
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE")
    )
    # Mitad del lote en el estudio, «A» o «B». Nulo en el producto, que no
    # reparte nada.
    bucket: Mapped[str | None] = mapped_column(String(10), nullable=True)
    position: Mapped[int] = mapped_column(Integer)

    worklist: Mapped["WorklistRow"] = relationship(back_populates="items")

    __table_args__ = (
        UniqueConstraint("worklist_id", "finding_id", name="uq_worklist_finding"),
        Index("ix_worklist_items_bucket", "worklist_id", "bucket", "position"),
    )


class DecisionRow(Base):
    """Alguien decidió algo sobre un hallazgo, en un tiempo.

    ANTES ERAN DOS TABLAS, y la separación estaba razonada. `audits` guardaba
    la decisión del producto y `decisions` la medición del experimento, con el
    argumento de que juntarlas obligaba a inventar un participante y una
    condición cada vez que alguien usara la herramienta fuera del estudio, y
    que eso impedía retirar la instrumentación al terminar la tesis.

    QUÉ REVIERTE ESA DECISIÓN. Que el acto es el mismo, y mantenerlo en dos
    sitios hacía que el experimento corriera por un camino paralelo al del
    producto en lugar de ser un caso suyo, con la lógica de rectificación
    escrita dos veces en sitios que podían divergir. La objeción de la
    invención se atiende sin fundir nada a la fuerza: `participant_id`,
    `condition` y `worklist_id` admiten nulos, de modo que una fila del
    producto no carga ni una columna del experimento. Retirar la
    instrumentación pasa de borrar una tabla a quitar tres columnas nulables.

    SE LLAMA `decisions` Y NO `audits` porque es la palabra que el acta, el
    protocolo y el artículo emplean para la variable principal, «exactitud de
    la decisión», y porque «auditoría» ya nombra otra cosa en este trabajo: el
    registro auditable con los once datos que reconstruyen cómo se produjo un
    veredicto.

    LA CLAVE AL PARTICIPANTE SE CONSERVA, aunque cruce la frontera del
    contexto de experimentación y la regla general de este esquema sea
    referenciar por identidad al cruzarla. La razón no es de diseño sino del
    consentimiento informado: admite retirarse en cualquier momento, y si al
    borrar al participante sus decisiones quedaran, el borrado no habría sido
    tal. El borrado en cascada lo garantiza el motor; dejarlo a cargo de la
    aplicación es justo lo que el objetivo primero reprochó a MongoDB.

    El precio es que quien cree el esquema tiene que registrar también las
    tablas del estudio. Es el mismo precio que ya se paga con las cuentas, que
    `executions` referencia, y se paga igual: importándolas en cada punto de
    entrada.
    """

    __tablename__ = "decisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE")
    )
    # Quién decidió. Exactamente uno de los dos, nunca ambos ni ninguno: una
    # cuenta cuando es uso del producto, un participante cuando es el estudio.
    # La cuenta se anonimiza al borrarse y el participante arrastra lo suyo,
    # porque sus datos existen solo mientras el estudio los necesita.
    user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    participant_id: Mapped[str | None] = mapped_column(
        ForeignKey("participants.id", ondelete="CASCADE"), nullable=True
    )
    # Propias del estudio. Nulas en el producto, que no reparte lotes ni asigna
    # condiciones: inventárselas sería imponerle vocabulario que no es suyo.
    session_id: Mapped[str | None] = mapped_column(
        ForeignKey("sessions.id", ondelete="SET NULL"), nullable=True
    )
    worklist_id: Mapped[str | None] = mapped_column(
        ForeignKey("worklists.id", ondelete="SET NULL"), nullable=True
    )
    condition: Mapped[str | None] = mapped_column(String(20), nullable=True)
    value: Mapped[str] = mapped_column(String(20))
    seconds: Mapped[float] = mapped_column(Float)
    # Una rectificación no sobrescribe: se guarda otra y la anterior deja de
    # ser la vigente. Sin ese historial no se distingue una primera impresión
    # de una conclusión, y esa distinción es la que hace auditable el registro.
    is_current: Mapped[bool] = mapped_column(Boolean, default=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now
    )

    __table_args__ = (
        Index("ix_decisions_finding", "finding_id", "is_current"),
        Index("ix_decisions_participant", "participant_id", "is_current"),
        CheckConstraint("seconds > 0", name="ck_decisions_seconds"),
        CheckConstraint(
            "value IN ('confirmado','descartado','dudoso')",
            name="ck_decisions_value",
        ),
        CheckConstraint(
            "condition IS NULL OR condition IN ('con_asistente','sin_asistente')",
            name="ck_decisions_condition",
        ),
        # El motor garantiza que toda decisión tenga un autor y uno solo. Si
        # admitiera las dos columnas a la vez, una fila diría que decidió una
        # cuenta y un participante, y el análisis no sabría a cuál atribuirla.
        CheckConstraint(
            "(user_id IS NOT NULL) <> (participant_id IS NOT NULL)",
            name="ck_decisions_un_solo_autor",
        ),
    )

def create_engine(url: str, echo: bool = False) -> AsyncEngine:
    cadena, conectar = normalize_database_url(url)
    return create_async_engine(
        cadena, echo=echo, pool_pre_ping=True, connect_args=conectar
    )


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
