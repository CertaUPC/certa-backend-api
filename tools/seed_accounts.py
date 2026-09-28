"""Siembra las cuentas que hacen falta para grabar el video.

El alta pública crea siempre `desarrollador`, y subir de rol solo puede
hacerlo un `lider_tecnico`. Como no existía ninguno, nadie podía conceder
nada: es el problema del primero, y se resuelve sembrándolo fuera de la API,
que es exactamente lo que hace esto.

Crea dos cuentas y no toca la que ya existe:

    lider_tecnico   para demostrar la concesión de roles
    desarrollador   para demostrar lo que alguien sin permiso no puede hacer

Es idempotente: si la cuenta ya está, ajusta su rol y su contraseña en vez de
fallar.

    py tools/seed_accounts.py
    py tools/seed_accounts.py --despliegue
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path
from uuid import uuid4

from dotenv import load_dotenv
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))

from src.iam.infrastructure.persistence.models import UserRow  # noqa: E402
from src.iam.infrastructure.security import hash_password  # noqa: E402
from src.shared import database_experiment as _estudio  # noqa: F401,E402

# Las dos cuentas del video. El correo es el mismo de siempre con un sufijo,
# que el servidor de la universidad entrega igual: no se inventa una identidad
# para una grabación.
CUENTAS = [
    ("u202211399+lider@upc.edu.pe", "lider_tecnico", "Certa.Lider.2026"),
    ("u202211399+dev@upc.edu.pe", "desarrollador", "Certa.Dev.2026"),
]


async def sembrar(sesion) -> None:
    for correo, rol, clave in CUENTAS:
        fila = (
            await sesion.execute(select(UserRow).where(UserRow.email == correo))
        ).scalar_one_or_none()
        if fila is None:
            sesion.add(
                UserRow(
                    id=str(uuid4()),
                    email=correo,
                    password_hash=hash_password(clave),
                    role=rol,
                )
            )
            print(f"  creada    {correo}  rol {rol}")
        else:
            fila.role = rol
            fila.password_hash = hash_password(clave)
            print(f"  ajustada  {correo}  rol {rol}")
    await sesion.commit()


async def principal() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--despliegue",
        action="store_true",
        help="Contra la base del servicio desplegado en lugar de la local.",
    )
    args = p.parse_args()

    load_dotenv(RAIZ / ".env")
    if args.despliegue:
        url = os.environ["DATABASE_URL_DESPLIEGUE"].replace(
            "postgresql://", "postgresql+asyncpg://"
        )
        for sobra in ("?sslmode=require&channel_binding=require", "?sslmode=require"):
            url = url.replace(sobra, "")
        print("base del despliegue:")
    else:
        url = "sqlite+aiosqlite:///./certa.db"
        print("base local:")

    motor = create_async_engine(url)
    Sesion = async_sessionmaker(motor, expire_on_commit=False)
    async with Sesion() as sesion:
        await sembrar(sesion)
        todas = (await sesion.execute(select(UserRow))).scalars().all()
        print("  ahora hay:", ", ".join(f"{u.email} ({u.role})" for u in todas))
    await motor.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(principal()))
