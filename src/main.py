"""Arranque del servicio. El cableado vive en `shared/composition.py`."""

import logging
from uuid import uuid4
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from .experimentation.interfaces.rest.experiment_router import (
    router as experiment_router,
)
from .iam.interfaces.rest.auth_router import router as auth_router
from .finding_validation.interfaces.rest.executions_router import (
    router as executions_router,
)
from .finding_validation.interfaces.rest.projects_router import (
    router as projects_router,
)
from .shared.composition import Container
from .shared.config import get_settings
from .shared.database import Base

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)


async def sembrar_primer_administrador(container, settings) -> None:
    """Crea el primer lider tecnico si la base no tiene ninguna cuenta.

    Solo entonces. Si ya hay cuentas no toca nada, de modo que reiniciar el
    servicio no puede recrear una cuenta que alguien retiro a proposito ni
    devolverle la contrasena original.
    """
    if not settings.seed_admin_email or not settings.seed_admin_password:
        return
    from sqlalchemy import func, select as _select

    from .iam.infrastructure.persistence.models import UserRow
    from .iam.infrastructure.security import hash_password

    async with container.sessions() as s:
        cuantas = await s.scalar(_select(func.count()).select_from(UserRow))
        if cuantas:
            return
        s.add(
            UserRow(
                id=str(uuid4()),
                email=settings.seed_admin_email.lower().strip(),
                password_hash=hash_password(settings.seed_admin_password),
                role="lider_tecnico",
            )
        )
        await s.commit()
    logger.info("Primera cuenta creada: %s", settings.seed_admin_email)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    container = Container(settings)
    app.state.container = container

    if settings.debug:
        # Solo en desarrollo. En despliegue el esquema lo gobierna Alembic, para
        # que un cambio de modelo no altere la base sin dejar rastro.
        import src.shared.database_experiment  # noqa: F401

        async with container.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Esquema creado en modo depuración")

    await sembrar_primer_administrador(container, settings)

    logger.info(
        "Certa listo. Proveedor de modelo: %s. Origenes admitidos: %s",
        "configurado" if settings.llm_configured else "no configurado",
        ", ".join(settings.cors_origin_list) or "ninguno",
    )
    try:
        yield
    finally:
        await container.dispose()


app = FastAPI(
    title="Certa",
    description=(
        "Validación de hallazgos de análisis estático de seguridad. Consume "
        "hallazgos en formato SARIF, recupera el contexto del código, consulta a "
        "un modelo de lenguaje y verifica que la justificación cite líneas que "
        "existen antes de aceptarla."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(projects_router)
app.include_router(executions_router)
app.include_router(experiment_router)


async def _estado_de_la_base(container: Container) -> str:
    """Consulta la base y ademas comprueba que el esquema este aplicado.

    Distinguir ambos casos importa: sin conexion es configuracion del entorno,
    y con conexion pero sin tablas es que la migracion no corrio.
    """
    from sqlalchemy import text

    try:
        async with container.sessions() as s:
            await s.execute(text("SELECT 1"))
            try:
                await s.execute(text("SELECT 1 FROM users LIMIT 1"))
            except Exception:  # noqa: BLE001
                return "conecta, pero falta el esquema: ejecutar alembic upgrade head"
        return "ok"
    except Exception as exc:  # noqa: BLE001
        return f"sin conexion: {type(exc).__name__}"


@app.get("/health", tags=["Servicio"])
async def health(request: Request) -> dict:
    settings = get_settings()
    container = getattr(request.app.state, "container", None)
    base = await _estado_de_la_base(container) if container else "sin inicializar"
    return {
        "status": "ok" if base == "ok" else "degradado",
        "service": settings.app_name,
        "version": app.version,
        "database": base,
        "language_model": "configurado" if settings.llm_configured else "no configurado",
    }
