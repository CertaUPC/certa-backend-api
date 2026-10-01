# -*- coding: utf-8 -*-
"""Repara las decisiones del estudio que quedaron sin sesion ni lote.

Que paso. Durante las primeras sesiones el cliente no mandaba el
identificador de la sesion, porque la credencial del participante no se lo
daba, y el lote no lo ponia nadie. Las decisiones se guardaron con
`session_id` y `worklist_id` nulos. Ademas ninguna sesion podia marcarse
completa, porque el repositorio sabia cerrarla y no habia ruta que lo pidiera.

El codigo ya esta corregido. Esto repone lo que se guardo antes de la
correccion, y solo eso:

  - A cada decision de participante sin sesion se le pone la sesion de ese
    participante, siempre que tenga exactamente una. Si tuviera mas de una no
    se toca, porque no habria forma de saber a cual pertenece.
  - A cada decision sin lote se le pone el lote congelado, que es unico.
  - Cada sesion se marca completa si su participante tiene una decision
    vigente para cada hallazgo de las dos mitades, con la misma regla que el
    endpoint de cierre. No se marca nada por recuento ni por confianza.

Por defecto no escribe: enseña lo que haria. Para aplicarlo:

    venv\\Scripts\\python tools/repair_study_links.py --aplicar
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from dotenv import load_dotenv  # noqa: E402
load_dotenv(RAIZ / ".env")

from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.shared.database import normalize_database_url  # noqa: E402

SIN_ENLACE = """
    SELECT d.participant_id,
           count(*) AS decisiones,
           count(*) FILTER (WHERE d.session_id IS NULL) AS sin_sesion,
           count(*) FILTER (WHERE d.worklist_id IS NULL) AS sin_lote,
           (SELECT count(*) FROM sessions s
             WHERE s.participant_id = d.participant_id) AS sesiones
      FROM decisions d
     WHERE d.participant_id IS NOT NULL
       AND (d.session_id IS NULL OR d.worklist_id IS NULL)
     GROUP BY d.participant_id
"""

LOTE = "SELECT id FROM worklists WHERE frozen_at IS NOT NULL ORDER BY frozen_at LIMIT 2"

LA_SESION = "SELECT id FROM sessions WHERE participant_id = :p"

PONER_SESION = """
    UPDATE decisions SET session_id = :s
     WHERE participant_id = :p AND session_id IS NULL
"""

PONER_LOTE = """
    UPDATE decisions SET worklist_id = :w
     WHERE participant_id IS NOT NULL AND worklist_id IS NULL
"""

COMPLETITUD = """
    SELECT s.id AS sesion, s.participant_id, s.is_complete,
           (SELECT count(*) FROM worklist_items i
             WHERE i.worklist_id = :w) AS del_lote,
           (SELECT count(DISTINCT d.finding_id) FROM decisions d
             JOIN worklist_items i ON i.finding_id = d.finding_id
            WHERE d.participant_id = s.participant_id AND d.is_current
              AND i.worklist_id = :w) AS decididos
      FROM sessions s
"""

CERRAR = """
    UPDATE sessions
       SET is_complete = TRUE,
           finished_at = COALESCE(finished_at, (
               SELECT max(created_at) FROM decisions d
                WHERE d.participant_id = sessions.participant_id))
     WHERE id = :s
"""


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--aplicar", action="store_true",
                        help="escribe; sin esto solo informa")
    parser.add_argument("--solo", metavar="PREFIJO", default=None,
                        help="cierra unicamente la sesion cuyo id empiece asi. "
                             "Sin esto cierra todas las que esten completas, "
                             "que puede no ser lo que quieres si alguna fila "
                             "viene de una prueba y no de un participante")
    args = parser.parse_args()

    url = os.environ.get("DATABASE_URL_DESPLIEGUE")
    if not url:
        print("falta DATABASE_URL_DESPLIEGUE")
        return 1
    destino, conectar = normalize_database_url(url)
    motor = create_async_engine(destino, connect_args=conectar)
    modo = "APLICANDO" if args.aplicar else "SIMULACION, no escribe nada"
    print(f"[{modo}]\n")

    try:
        async with motor.begin() as c:
            lotes = [f[0] for f in (await c.execute(text(LOTE))).all()]
            if len(lotes) != 1:
                print(f"hay {len(lotes)} lotes congelados; se esperaba uno. "
                      "No se toca nada.")
                return 1
            lote = lotes[0]
            print(f"lote congelado: {lote[:8]}\n")

            print("decisiones sueltas por participante")
            arreglables = []
            for f in (await c.execute(text(SIN_ENLACE))).mappings():
                p = f["participant_id"]
                print(f"  {p[:8]}  decisiones={f['decisiones']:>3}  "
                      f"sin sesion={f['sin_sesion']:>3}  sin lote={f['sin_lote']:>3}  "
                      f"sesiones del participante={f['sesiones']}")
                if f["sesiones"] == 1:
                    arreglables.append(p)
                else:
                    print("     se deja: no tiene exactamente una sesion")

            if args.aplicar:
                for p in arreglables:
                    s = (await c.execute(text(LA_SESION), {"p": p})).scalar_one()
                    r = await c.execute(text(PONER_SESION), {"p": p, "s": s})
                    print(f"  {p[:8]}: {r.rowcount} decisiones selladas con "
                          f"la sesion {s[:8]}")
                r = await c.execute(text(PONER_LOTE), {"w": lote})
                print(f"  lote puesto en {r.rowcount} decisiones")

            print("\ncompletitud por sesion, con la regla del endpoint de cierre")
            for f in (await c.execute(text(COMPLETITUD), {"w": lote})).mappings():
                completa = f["del_lote"] > 0 and f["decididos"] == f["del_lote"]
                marca = "COMPLETA" if completa else "incompleta"
                if f["is_complete"]:
                    marca += ", ya estaba marcada"
                print(f"  sesion {f['sesion'][:8]}  "
                      f"{f['decididos']:>2} de {f['del_lote']} del lote  -> {marca}")
                if completa and not f["is_complete"]:
                    if args.solo and not f["sesion"].startswith(args.solo):
                        print("     se deja abierta: no es la que se pidio")
                    elif args.aplicar:
                        await c.execute(text(CERRAR), {"s": f["sesion"]})
                        print("     marcada como completa")
    finally:
        await motor.dispose()

    if not args.aplicar:
        print("\nnada escrito. Repite con --aplicar para que surta efecto.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
