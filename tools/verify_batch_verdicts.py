"""Comprueba el lote congelado contra la verdad conocida del benchmark.

Se usa despues de reponer los veredictos, para saber que quedo. No pide que
los veinticuatro acierten: el protocolo exige que el lote conserve veredictos
equivocados reales, dos por mitad, porque si el asistente acertara siempre no
habria forma de distinguir que la persona decida mejor de que deje de decidir y
se limite a seguir lo que la herramienta dice. Lo que se comprueba es otra cosa:

  1. Que ningun veredicto siga alegando que falta un cuerpo que si se entrego.
     Es la prueba directa del arreglo del inventario.
  2. Cuanto concuerda con la verdad conocida, como cifra y no como umbral.
  3. Cuantos equivocados quedan y en que mitad, que es lo que OE4-I3 necesita.
  4. Que el veredicto que se muestra sea unico por hallazgo, sin empates que
     dependan del orden que devuelva el motor.
  5. Que todo el lote lleve la misma version de consulta.

    venv\\Scripts\\python tools/verify_batch_verdicts.py --despliegue
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(RAIZ / ".env")

from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.shared.database import normalize_database_url  # noqa: E402

CONSULTA = """
    SELECT i.bucket, i.position, f.id, f.file_path, f.known_truth,
           c.context_text, c.available_lines, c.callees,
           v.model, v.repetition, v.value, v.justification, v.prompt_version,
           v.anchor_verified, v.confidence
      FROM worklist_items i
      JOIN worklists w ON w.id = i.worklist_id
      JOIN findings f ON f.id = i.finding_id
      JOIN code_contexts c ON c.finding_id = f.id
      JOIN verdicts v ON v.finding_id = f.id
     WHERE w.frozen_at IS NOT NULL
     ORDER BY i.bucket, i.position
"""

# La justificacion alega que falta el cuerpo de algo.
ALEGA_FALTA = re.compile(
    r"(cuerpo|implementaci[oó]n|definici[oó]n)[^.]{0,80}"
    r"(no (aparece|est[aá]|se (ve|muestra|incluye))|NO est[aá]|ausente|"
    r"no (est[aá]|se encuentra) (presente|incluido|disponible)|no entregad)"
    r"|(no (aparece|est[aá]|se muestra))[^.]{0,60}(cuerpo|implementaci[oó]n)"
    r"|har[ií]a falta el cuerpo|falta.{0,30}(el cuerpo|la implementaci[oó]n)"
    r"|c[oó]digo (ausente|no entregado)",
    re.I,
)

DEF_METODO = re.compile(
    r"^\s*(\d+):\s*(?:@\w+\s*)?(?:(?:public|private|protected|static|final)\s+)+"
    r"[\w.<>\[\]]+\s+(\w+)\s*\("
)


def nombres(valor) -> list[str]:
    salida = []
    for c in valor or []:
        salida.append(c if isinstance(c, str) else (c.get("name") or str(c)))
    return salida


async def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--despliegue", action="store_true")
    args = p.parse_args()

    clave = "DATABASE_URL_DESPLIEGUE" if args.despliegue else "DATABASE_URL"
    url = os.environ.get(clave)
    if not url:
        print(f"falta {clave}")
        return 1
    destino, conectar = normalize_database_url(url)
    motor = create_async_engine(destino, connect_args=conectar)
    try:
        async with motor.connect() as c:
            filas = [dict(f) for f in (await c.execute(text(CONSULTA))).mappings()]
    finally:
        await motor.dispose()

    por_hallazgo: dict[str, list[dict]] = {}
    for f in filas:
        por_hallazgo.setdefault(f["id"], []).append(f)
    print(f"{len(filas)} veredictos sobre {len(por_hallazgo)} hallazgos del lote\n")

    versiones = sorted({f["prompt_version"] or "sin version" for f in filas})
    print(f"5. versiones de consulta en el lote: {versiones}")
    print(f"   {'UNA SOLA, correcto' if len(versiones) == 1 else 'MEZCLADAS, el lote no es una sola condicion'}\n")

    # El veredicto que se muestra: mayor repeticion, y el motor desempata.
    mostrado: dict[str, dict] = {}
    empatados = []
    for fid, vs in por_hallazgo.items():
        top = max(v["repetition"] for v in vs)
        cumbre = [v for v in vs if v["repetition"] == top]
        if len({v["value"] for v in cumbre}) > 1:
            empatados.append((fid, sorted({v["value"] for v in cumbre})))
        mostrado[fid] = cumbre[-1]

    print(f"4. hallazgos cuyo veredicto mostrado depende del desempate: "
          f"{len(empatados)}")
    for fid, vals in empatados:
        print(f"   {Path(mostrado[fid]['file_path']).stem}: {vals}")
    if not empatados:
        print("   ninguno, el mostrado es unico por hallazgo")
    print()

    # 1. Ausencias alegadas que no eran ciertas.
    falsas = []
    for f in filas:
        just = f["justification"] or ""
        if not ALEGA_FALTA.search(just):
            continue
        texto = f["context_text"] or ""
        disp = set(f["available_lines"] or [])
        definidos = {}
        for linea in texto.splitlines():
            m = DEF_METODO.match(linea)
            if m:
                definidos[m.group(2)] = int(m.group(1))
        citados = set(re.findall(r"\b(\w{4,})\s*\(", just))
        tenia = {n: l for n, l in definidos.items() if n in citados and l in disp}
        if tenia:
            falsas.append((f, tenia))

    print(f"1. veredictos que alegan una ausencia que no era cierta: "
          f"{len(falsas)}")
    for f, tenia in falsas:
        print(f"   [{f['bucket']}{f['position']:>2}] "
              f"{Path(f['file_path']).stem:20} {f['model']:26} "
              f"r{f['repetition']} -> {f['value']}")
        for n, l in tenia.items():
            print(f"        {n} estaba definido en la linea {l}")
    if not falsas:
        print("   ninguno")
    print()

    # 2. Concordancia con la verdad conocida, sobre el veredicto mostrado.
    acierta = yerra = calla = sin_verdad = 0
    for fid, v in mostrado.items():
        if v["known_truth"] is None:
            sin_verdad += 1
            continue
        if v["value"] == "indeterminado":
            calla += 1
        elif (v["value"] == "explotable") == bool(v["known_truth"]):
            acierta += 1
        else:
            yerra += 1
    con_verdad = len(mostrado) - sin_verdad
    print(f"2. concordancia con la verdad conocida, sobre lo que se muestra")
    print(f"   acierta       {acierta:>2} de {con_verdad}")
    print(f"   se equivoca   {yerra:>2} de {con_verdad}")
    print(f"   se abstiene   {calla:>2} de {con_verdad}")
    if sin_verdad:
        print(f"   sin verdad conocida: {sin_verdad}")
    print()

    # 3. Los equivocados que quedan, por mitad.
    print(f"3. veredictos equivocados que quedan en el lote")
    reparto: dict[str, int] = {}
    for fid, v in sorted(mostrado.items(),
                         key=lambda kv: (kv[1]["bucket"], kv[1]["position"])):
        if v["known_truth"] is None or v["value"] == "indeterminado":
            continue
        if (v["value"] == "explotable") != bool(v["known_truth"]):
            reparto[v["bucket"]] = reparto.get(v["bucket"], 0) + 1
            print(f"   [{v['bucket']}{v['position']:>2}] "
                  f"{Path(v['file_path']).stem:20} dijo {v['value']:14} "
                  f"verdad={v['known_truth']}")
    total = sum(reparto.values())
    print(f"   total {total}, reparto por mitad {reparto or '{}'}")
    print(f"   el protocolo pide cuatro, dos por mitad  ->  "
          f"{'CUADRA' if reparto.get('A') == 2 and reparto.get('B') == 2 else 'NO CUADRA, hay que decidir como se completa'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
