"""Lleva una ejecucion analizada en local al despliegue, con todo lo suyo.

    py tools/promote_execution.py --execution <id> --into /repos/owasp-benchmark
    py tools/promote_execution.py --execution <id> --into ... --dry-run

El analisis del corpus de OWASP corrio en una maquina de escritorio contra
SQLite y tardo horas. Repetirlo contra el despliegue costaria lo mismo en
tiempo y en llamadas al proveedor, de modo que lo que viaja es el resultado.

El proyecto no se copia: el destino ya tiene el suyo, con su dueno y su ruta,
mientras que el de origen apunta a una carpeta de Windows que alli no significa
nada. La ejecucion se recuelga del proyecto que se indique.

Y el lote congelado del estudio viaja como `worklists` mas `worklist_items`,
que es donde vive desde que `session_batch_items` quedo atras.
"""

import argparse
import asyncio
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import asyncpg

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

RAIZ = Path(__file__).resolve().parents[1]

# En el orden en que las claves foraneas admiten que se inserten.
TABLES = ("executions", "findings", "code_contexts", "verdicts")


def deployment_url(explicit: str | None) -> str:
    if explicit:
        raw = explicit
    else:
        env = RAIZ / ".env"
        if not env.exists():
            sys.exit("No hay .env y no se paso --url")
        pairs = dict(
            line.split("=", 1)
            for line in env.read_text(encoding="utf-8").splitlines()
            if "=" in line and not line.lstrip().startswith("#")
        )
        raw = pairs.get("DATABASE_URL_DESPLIEGUE", "")
        if not raw:
            sys.exit("Falta DATABASE_URL_DESPLIEGUE en .env")
    return raw.strip().strip('"').replace("postgresql+asyncpg://", "postgresql://")


def as_utc(text):
    """Las fechas salen de SQLite como cadena y entran como instante."""
    if text is None or isinstance(text, datetime):
        return text
    moment = datetime.fromisoformat(str(text))
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def adapt(value, pg_type):
    """Ajusta un valor de SQLite al tipo que la columna declara en PostgreSQL."""
    if value is None:
        return None
    if pg_type == "boolean":
        return bool(value)
    if pg_type.startswith("timestamp"):
        return as_utc(value)
    if pg_type == "jsonb":
        # SQLite las guarda como texto; el codec de abajo las pasa tal cual,
        # pero una cadena que no sea JSON valido reventaria en el servidor.
        if isinstance(value, (dict, list)):
            return json.dumps(value)
        json.loads(value)
        return value
    return value


async def remote_columns(conn, table: str) -> dict[str, str]:
    rows = await conn.fetch(
        "select column_name, data_type from information_schema.columns "
        "where table_name = $1 order by ordinal_position",
        table,
    )
    return {r["column_name"]: r["data_type"] for r in rows}


def local_rows(db: sqlite3.Connection, query: str, *params) -> list[sqlite3.Row]:
    db.row_factory = sqlite3.Row
    return db.execute(query, params).fetchall()


async def insert_many(conn, table, columns, types, rows, remap=None) -> int:
    if not rows:
        return 0
    remap = remap or {}
    marks = ", ".join(f"${i}" for i in range(1, len(columns) + 1))
    sql = f'insert into {table} ({", ".join(columns)}) values ({marks})'
    payload = [
        tuple(
            adapt(remap[c](r) if c in remap else r[c], types[c])
            for c in columns
        )
        for r in rows
    ]
    await conn.executemany(sql, payload)
    return len(payload)


async def run(args) -> int:
    source = RAIZ / args.source
    if not source.exists():
        sys.exit(f"No existe la base de origen: {source}")
    db = sqlite3.connect(source)

    execution = local_rows(
        db, "select * from executions where id = ?", args.execution
    )
    if not execution:
        sys.exit(f"La base local no tiene la ejecucion {args.execution}")
    execution = execution[0]

    findings = local_rows(
        db, "select * from findings where execution_id = ?", args.execution
    )
    ids = tuple(f["id"] for f in findings)
    marks = ", ".join("?" * len(ids))
    contexts = local_rows(
        db, f"select * from code_contexts where finding_id in ({marks})", *ids
    )
    verdicts = local_rows(
        db, f"select * from verdicts where finding_id in ({marks})", *ids
    )
    batch = local_rows(
        db,
        f"select * from session_batch_items where finding_id in ({marks}) "
        "order by batch, position",
        *ids,
    )

    print(f"En origen, colgando de {args.execution[:8]}:")
    print(f"  {len(findings):5d} hallazgos")
    print(f"  {len(contexts):5d} contextos")
    print(f"  {len(verdicts):5d} veredictos")
    print(f"  {len(batch):5d} posiciones del lote congelado")

    conn = await asyncpg.connect(deployment_url(args.url), ssl="require")
    # Los jsonb viajan como el texto que SQLite guardo, sin reserializar.
    await conn.set_type_codec(
        "jsonb", encoder=str, decoder=str, schema="pg_catalog", format="text"
    )
    try:
        project = await conn.fetchrow(
            "select id, name from projects where repository_path = $1 or id = $1",
            args.into,
        )
        if project is None:
            sys.exit(f"El despliegue no tiene el proyecto {args.into!r}")

        author = None
        if args.author:
            author = await conn.fetchval(
                "select id from users where email = $1", args.author.lower()
            )
            if author is None:
                sys.exit(f"El despliegue no tiene la cuenta {args.author}")

        ya = await conn.fetchval(
            "select count(*) from executions where id = $1", args.execution
        )
        if ya:
            sys.exit(
                "Esa ejecucion ya esta en el despliegue. Borrala alli antes de "
                "volver a subirla, o sube otra."
            )

        print(f"\nDestino: «{project['name']}» ({project['id'][:8]})")
        if args.dry_run:
            print("Ensayo: no se escribe nada.")
            return 0

        types = {t: await remote_columns(conn, t) for t in TABLES}

        async with conn.transaction():
            escrito = {}
            escrito["executions"] = await insert_many(
                conn,
                "executions",
                [c for c in types["executions"] if c in execution.keys()],
                types["executions"],
                [execution],
                remap={
                    "project_id": lambda r: project["id"],
                    "created_by": lambda r: author or r["created_by"],
                },
            )
            for table, rows in (
                ("findings", findings),
                ("code_contexts", contexts),
                ("verdicts", verdicts),
            ):
                usable = [c for c in types[table] if rows and c in rows[0].keys()]
                escrito[table] = await insert_many(
                    conn, table, usable, types[table], rows
                )

            if batch:
                worklist_id = str(uuid4())
                await conn.execute(
                    "insert into worklists (id, execution_id, name, fingerprint, "
                    "frozen_at, created_at) values ($1, $2, $3, $4, $5, $6)",
                    worklist_id,
                    args.execution,
                    args.worklist,
                    None,
                    as_utc(batch[0]["created_at"]),
                    datetime.now(timezone.utc),
                )
                await conn.executemany(
                    "insert into worklist_items (id, worklist_id, finding_id, "
                    "bucket, position) values ($1, $2, $3, $4, $5)",
                    [
                        (str(uuid4()), worklist_id, r["finding_id"], r["batch"],
                         r["position"])
                        for r in batch
                    ],
                )
                escrito["worklist_items"] = len(batch)

        print("\nEscrito:")
        for t, n in escrito.items():
            print(f"  {n:5d}  {t}")

        print("\nComprobacion contra el despliegue:")
        for consulta, rotulo in (
            ("select count(*) from findings where execution_id = $1", "hallazgos"),
            ("select count(*) from code_contexts x join findings f on "
             "f.id = x.finding_id where f.execution_id = $1", "contextos"),
            ("select count(*) from verdicts v join findings f on "
             "f.id = v.finding_id where f.execution_id = $1", "veredictos"),
            ("select count(*) from worklist_items i join worklists w on "
             "w.id = i.worklist_id where w.execution_id = $1", "lote"),
        ):
            print(f"  {await conn.fetchval(consulta, args.execution):5d}  {rotulo}")
        return 0
    finally:
        await conn.close()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--execution", required=True, help="Id de la ejecucion local")
    p.add_argument("--into", required=True,
                   help="Ruta de repositorio o id del proyecto de destino")
    p.add_argument("--author", help="Correo de la cuenta a la que se atribuye")
    p.add_argument("--source", default="certa.db", help="Base local de origen")
    p.add_argument("--url", help="Cadena de conexion; por omision, la del .env")
    p.add_argument("--worklist", default="Lote del estudio",
                   help="Nombre de la lista de trabajo que se crea")
    p.add_argument("--dry-run", action="store_true",
                   help="Cuenta lo que viajaria y no escribe")
    return asyncio.run(run(p.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
