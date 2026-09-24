"""Carga en la base el lote congelado de las sesiones.

El lote se fija con tools/freeze_session_batch.py, que deja el CSV y su
manifiesto. Esto lo mete en la tabla que el servicio consulta, de modo que la
pantalla de auditoria sirva los doce hallazgos de la mitad que toca y no la
ejecucion entera.

Comprueba antes de escribir que el CSV es el que el manifiesto declara: si la
huella no coincide, el lote que se cargaria no seria el que el protocolo
declaro y la carga se rechaza. Esa comprobacion es el motivo de que la huella
exista.

Con --despliegue escribe en la base de arriba en vez de en la local, leyendo
DATABASE_URL_DESPLIEGUE del .env, que es como lo hace promote_execution.

    py tools/load_session_batch.py --dry-run
    py tools/load_session_batch.py
    py tools/load_session_batch.py --despliegue --dry-run
    py tools/load_session_batch.py --despliegue
"""

import argparse
import asyncio
import csv
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.experimentation.infrastructure.persistence.sql_repositories import (  # noqa: E402
    SqlBatchRepository,
)
from src.shared.composition import Container  # noqa: E402
from src.shared.config import get_settings  # noqa: E402


def url_del_despliegue() -> str:
    """La del .env, en la forma que espera el motor asincrono."""
    env = Path(__file__).resolve().parents[1] / ".env"
    if not env.is_file():
        sys.exit("No hay .env del que leer DATABASE_URL_DESPLIEGUE")
    pares = dict(
        linea.split("=", 1)
        for linea in env.read_text(encoding="utf-8").splitlines()
        if "=" in linea and not linea.lstrip().startswith("#")
    )
    cruda = pares.get("DATABASE_URL_DESPLIEGUE", "").strip().strip('"')
    if not cruda:
        sys.exit("Falta DATABASE_URL_DESPLIEGUE en .env")
    return cruda


def huella_de(registros) -> str:
    cuerpo = "".join(sorted(f"{r['lote']}|{r['huella']}\n" for r in registros))
    return hashlib.sha256(cuerpo.encode("utf-8")).hexdigest()


async def main(args) -> int:
    settings = get_settings()
    if args.despliegue:
        # Sin tocar el .env: la configuracion se copia con la base cambiada,
        # de modo que una corrida contra el despliegue no deja la local
        # apuntando a otro sitio.
        settings = settings.model_copy(
            update={"database_url": url_del_despliegue()}
        )
    raiz = Path(settings.repository_root)
    carpeta = raiz / "experimento"
    csv_lote = carpeta / "lote_sesion.csv"
    manifiesto = carpeta / "manifiesto_lote_sesion.json"

    if not csv_lote.is_file():
        print(f"FALLA: no existe {csv_lote}")
        return 1
    with csv_lote.open(encoding="utf-8", newline="") as fh:
        registros = list(csv.DictReader(fh))
    if not registros:
        print("FALLA: el CSV del lote está vacío")
        return 1

    calculada = huella_de(registros)
    print(f"base:    {'DESPLIEGUE' if args.despliegue else 'local'}")
    print(f"lote:    {csv_lote}")
    print(f"filas:   {len(registros)}")
    print(f"huella:  {calculada}")

    if manifiesto.is_file():
        declarada = json.loads(manifiesto.read_text(encoding="utf-8")).get(
            "huella_del_lote"
        )
        if declarada != calculada:
            print("FALLA: la huella del CSV no coincide con la del manifiesto.")
            print(f"  declarada:  {declarada}")
            print(f"  calculada:  {calculada}")
            print("  El lote que se cargaría no es el que el protocolo declaró.")
            return 1
        print("  coincide con la del manifiesto")
    else:
        print("  AVISO: no hay manifiesto contra el que comprobarla")

    por_lote: dict[str, int] = {}
    items = []
    for registro in registros:
        lote = registro["lote"]
        posicion = por_lote.get(lote, 0)
        items.append((registro["finding_id"], lote, posicion))
        por_lote[lote] = posicion + 1

    print(f"\nreparto: {por_lote}")
    if len(set(por_lote.values())) != 1:
        print("  AVISO: las mitades no tienen el mismo tamaño")

    if args.dry_run:
        print("\nSIMULACRO: no se escribió nada")
        return 0

    container = Container(settings)
    async with container.sessions() as sesion:
        escritos = await SqlBatchRepository(sesion).replace_all(items)
        cuenta = await SqlBatchRepository(sesion).batches()
    await container.dispose()

    print(f"\nescritos {escritos} hallazgos")
    print(f"verificación, lo que la base devuelve: {cuenta}")
    return 0 if cuenta == por_lote else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--despliegue", action="store_true",
                        help="escribe en la base de arriba y no en la local")
    parser.add_argument("--dry-run", action="store_true")
    return parser


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(asyncio.run(main(build_parser().parse_args())))
