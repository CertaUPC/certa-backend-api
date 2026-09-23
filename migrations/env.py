"""Entorno de Alembic.

Toma la dirección de la base del entorno y no del archivo de configuración, de
modo que la credencial de producción nunca quede versionada.
"""

import asyncio
import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import src.iam.infrastructure.persistence.models  # noqa: F401  registra users
import src.shared.database_experiment  # noqa: F401  registra sus tablas
from src.shared.config import get_settings
from src.shared.database import Base, normalize_database_url

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# Alembic trabaja de forma síncrona sobre el motor asíncrono, de modo que la
# cadena debe traer el controlador correcto.
# La misma correccion que aplica el servicio: si no, la migracion falla
# justo cuando se despliega por primera vez.
_url, _conectar = normalize_database_url(
    os.getenv("DATABASE_URL") or get_settings().database_url
)
config.set_main_option("sqlalchemy.url", _url)


def run_migrations_offline() -> None:
    context.configure(
        url=_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run(connection) -> None:
    context.configure(
        connection=connection, target_metadata=target_metadata, compare_type=True
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    engine = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        connect_args=_conectar,
    )
    async with engine.connect() as connection:
        await connection.run_sync(_do_run)
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
