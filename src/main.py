"""Arranque del servicio. El cableado vive en `shared/composition.py`."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .experimentation.interfaces.rest.experiment_router import (
    router as experiment_router,
)
from .finding_validation.interfaces.rest.auth_router import router as auth_router
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

    logger.info(
        "Certa listo. Proveedor de modelo: %s",
        "configurado" if settings.llm_configured else "no configurado",
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


@app.get("/health", tags=["Servicio"])
async def health() -> dict:
    settings = get_settings()
    return {
        "status": "ok",
        "service": settings.app_name,
        "language_model": "configurado" if settings.llm_configured else "no configurado",
    }
