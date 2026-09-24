"""Retira a un participante, o solo lo que decidio, para repetir la sesion.

Hace falta dos veces. Una, cuando el ensayo del instrumento deja rastro en la
base que se va a usar de verdad: la fila afirma que alguien firmo un
consentimiento, y no hay tal persona. Otra, cuando una sesion se cae a medias
y la persona sigue sentada, dispuesta a repetirla.

  --solo-decisiones   borra lo que decidio y su sesion, y conserva el alta.
                      La ficha y el consentimiento siguen valiendo, asi que
                      no hay que volver a firmar nada. El contrabalanceo le
                      asigna orden de nuevo al registrarse la sesion.

  sin esa bandera     retira ademas el alta y las credenciales. Es lo que
                      corresponde a un rastro de ensayo.

Lo que se borra se vuelca antes a un JSON con la fecha, de modo que un borrado
por equivocacion se pueda reconstruir. El volcado NO va al repositorio: lleva
la ficha del participante.

En PostgreSQL las claves de `sessions` y `decisions` hacia `participants` van
con borrado en cascada, pero `access_grants.subject_id` no es clave foranea, a
proposito, porque apunta fuera de su contexto. Esa hay que retirarla a mano o
queda una credencial senalando a quien ya no existe.

    py tools/reset_participant.py --code P-00 --dry-run
    py tools/reset_participant.py --code P-00
    py tools/reset_participant.py --code P-00 --despliegue --dry-run
    py tools/reset_participant.py --code P-00 --despliegue
    py tools/reset_participant.py --code P-04 --despliegue --solo-decisiones
"""

import argparse
import asyncio
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import asyncpg

RAIZ = Path(__file__).resolve().parents[1]

# La misma forma canonica que el dominio: el acta dice «P-04» y quien teclea
# puede escribir «P04».
_CODIGO = re.compile(r"^([A-Z]+)[\s\-_]*([0-9]+)$")


def normalizar(codigo: str) -> str:
    limpio = codigo.strip().upper()
    m = _CODIGO.match(limpio)
    if not m:
        return limpio
    return f"{m.group(1)}-{int(m.group(2)):02d}"


def url_del_despliegue() -> str:
    env = RAIZ / ".env"
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
    return cruda.replace("postgresql+asyncpg://", "postgresql://")


def serializable(valor):
    if isinstance(valor, datetime):
        return valor.isoformat()
    return valor


async def recoger(conexion, participante_id: str) -> dict:
    """Todo lo que la base guarda de esta persona, tal cual."""
    volcado = {}
    for tabla, consulta in (
        ("participants", "select * from participants where id = $1"),
        ("sessions", "select * from sessions where participant_id = $1"),
        ("decisions", "select * from decisions where participant_id = $1"),
        ("access_grants",
         ("select * from access_grants where subject_kind = 'participation' "
          "and subject_id = $1")),
    ):
        filas = await conexion.fetch(consulta, participante_id)
        volcado[tabla] = [
            {k: serializable(v) for k, v in dict(f).items()} for f in filas
        ]
    return volcado


async def main(args) -> int:
    url = url_del_despliegue() if args.despliegue else (
        args.url or "postgresql://postgres@localhost/certa")
    codigo = normalizar(args.code)

    print(f"base:   {'DESPLIEGUE' if args.despliegue else url.split('@')[-1]}")
    print(f"código: {codigo}")

    conexion = await asyncpg.connect(url)
    try:
        fila = await conexion.fetchrow(
            "select id, anonymous_code, is_pilot, consented_at "
            "from participants where anonymous_code = $1",
            codigo,
        )
        if fila is None:
            print(f"\nNo hay ningún participante con el código {codigo}.")
            return 1

        participante_id = fila["id"]
        print(f"  id {participante_id}")
        print(f"  piloto: {'sí' if fila['is_pilot'] else 'NO'}")
        print(f"  consintió: {fila['consented_at']}")

        if not fila["is_pilot"] and not args.force:
            print("\nNO es piloto, de modo que sus decisiones entran en el "
                  "análisis. Si aun así hay que retirarlo, porque ejerció el "
                  "derecho a retirarse que el consentimiento le reconoce, "
                  "repite con --force.")
            return 2

        volcado = await recoger(conexion, participante_id)
        print()
        for tabla, filas in volcado.items():
            print(f"  {tabla:<14} {len(filas)}")

        if args.solo_decisiones:
            print("\nse retiran: decisiones y sesión")
            print("se conservan: el alta, la ficha y las credenciales")
        else:
            print("\nse retira todo, credenciales incluidas")

        if args.dry_run:
            print("\nSIMULACRO: no se borró nada")
            return 0

        sello = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        destino = RAIZ / f"retirado-{codigo}-{sello}.json"
        destino.write_text(
            json.dumps(volcado, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
        print(f"\nvolcado: {destino.name}")

        async with conexion.transaction():
            borradas = await conexion.execute(
                "delete from decisions where participant_id = $1",
                participante_id,
            )
            sesiones = await conexion.execute(
                "delete from sessions where participant_id = $1",
                participante_id,
            )
            print(f"  decisiones: {borradas}")
            print(f"  sesiones:   {sesiones}")
            if not args.solo_decisiones:
                grants = await conexion.execute(
                    "delete from access_grants where subject_kind = "
                    "'participation' and subject_id = $1",
                    participante_id,
                )
                alta = await conexion.execute(
                    "delete from participants where id = $1", participante_id
                )
                print(f"  credenciales: {grants}")
                print(f"  alta:         {alta}")

        quedan = await conexion.fetchval(
            "select count(*) from participants where anonymous_code = $1",
            codigo,
        )
        sueltas = await conexion.fetchval(
            "select count(*) from decisions where participant_id = $1",
            participante_id,
        )
        print(f"\nquedan con ese código: {quedan}")
        print(f"decisiones sueltas:    {sueltas}")
        return 0 if sueltas == 0 else 1
    finally:
        await conexion.close()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--code", required=True, help="Código anónimo, «P-00»")
    p.add_argument("--despliegue", action="store_true",
                   help="obra sobre la base de arriba y no sobre la local")
    p.add_argument("--url", help="Cadena de conexión, si no es el despliegue")
    p.add_argument("--solo-decisiones", action="store_true",
                   help="conserva el alta para que repita la sesión")
    p.add_argument("--force", action="store_true",
                   help="permite retirar a quien no está marcado como piloto")
    p.add_argument("--dry-run", action="store_true")
    return p


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(asyncio.run(main(build_parser().parse_args())))
