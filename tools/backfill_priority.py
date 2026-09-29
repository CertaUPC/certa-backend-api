"""Calcula el orden sugerido de las ejecuciones que se quedaron sin él.

El orden y su razón los escribe el servicio que recorre una ejecución completa,
al terminar cada hallazgo. La corrida de la prueba de concepto no pasó por ahí:
se lanzó con el comparador de modelos, que emite veredictos y no ordena, de modo
que sus dos mil ciento sesenta y seis hallazgos quedaron con la prioridad y su
razón en blanco. En la pantalla de revisión eso se ve como un rótulo, «Por qué
está aquí», sin nada debajo.

Esto lo rellena con la misma calculadora del dominio y sobre los veredictos ya
guardados, así que no consulta al modelo ni gasta nada. Cuando un hallazgo tiene
varios veredictos, por repeticiones o por modelos distintos, se toma el último
guardado, que es el que la pantalla muestra.

    py tools/backfill_priority.py --dry-run
    py tools/backfill_priority.py
    py tools/backfill_priority.py --despliegue
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path
from uuid import UUID

from dotenv import load_dotenv
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))

from src.finding_validation.domain.services.priority_calculator import (  # noqa: E402
    PriorityCalculator,
)
from src.finding_validation.infrastructure.persistence.sql_repositories import (  # noqa: E402
    SqlFindingRepository,
    SqlVerdictRepository,
)
from src.iam.infrastructure.persistence import models as _cuentas  # noqa: F401,E402
from src.shared import database_experiment as _estudio  # noqa: F401,E402
from src.shared.database import ExecutionRow, FindingRow  # noqa: E402


async def sin_orden(sesion) -> list[tuple[str, int]]:
    """Ejecuciones con hallazgos sin prioridad, y cuántos."""
    filas = (
        await sesion.execute(
            select(FindingRow.execution_id, FindingRow.id).where(
                FindingRow.priority.is_(None)
            )
        )
    ).all()
    cuenta: dict[str, int] = {}
    for ejecucion, _ in filas:
        cuenta[ejecucion] = cuenta.get(ejecucion, 0) + 1
    return sorted(cuenta.items(), key=lambda x: -x[1])


async def principal() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--despliegue", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--ejecucion", help="Solo esta, por identificador.")
    args = p.parse_args()

    load_dotenv(RAIZ / ".env")
    if args.despliegue:
        url = os.environ["DATABASE_URL_DESPLIEGUE"].replace(
            "postgresql://", "postgresql+asyncpg://"
        )
        for sobra in ("?sslmode=require&channel_binding=require", "?sslmode=require"):
            url = url.replace(sobra, "")
        print("base del despliegue")
    else:
        url = "sqlite+aiosqlite:///./certa.db"
        print("base local")

    motor = create_async_engine(url)
    Sesion = async_sessionmaker(motor, expire_on_commit=False)
    calculadora = PriorityCalculator()
    total = 0

    async with Sesion() as sesion:
        pendientes = await sin_orden(sesion)
        if args.ejecucion:
            pendientes = [x for x in pendientes if x[0] == args.ejecucion]
        for ejecucion, cuantos in pendientes:
            nombre = (
                await sesion.execute(
                    select(ExecutionRow.id).where(ExecutionRow.id == ejecucion)
                )
            ).scalar_one_or_none()
            if nombre is None:
                print(f"  {ejecucion[:8]}: {cuantos} hallazgos huérfanos, se omiten")
                continue

            findings = SqlFindingRepository(sesion)
            verdicts = SqlVerdictRepository(sesion)
            hallazgos = await findings.list_by_execution(UUID(ejecucion))
            emparejados = []
            for f in hallazgos:
                suyos = await verdicts.get_by_finding(f.id)
                if suyos:
                    emparejados.append((f, suyos[-1]))

            print(f"  {ejecucion[:8]}: {cuantos} sin orden, "
                  f"{len(emparejados)} con veredicto que se puede ordenar")
            if args.dry_run or not emparejados:
                continue

            for f, v in emparejados:
                prioridad = calculadora.calculate(f, v)
                await sesion.execute(
                    update(FindingRow)
                    .where(FindingRow.id == str(f.id))
                    .values(priority=prioridad.score, priority_reason=prioridad.reason)
                )
                total += 1
            await sesion.commit()
            print(f"     ordenados {len(emparejados)}")

    await motor.dispose()
    print(f"\n{'simulacro, no se escribió nada' if args.dry_run else f'{total} hallazgos con su orden y su razón'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(principal()))
