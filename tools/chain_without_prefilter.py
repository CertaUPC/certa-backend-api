"""La F1 de la cadena sin el filtro determinista, sobre el mismo lote.

Junta los veredictos de la corrida original con los de las ocho alertas que el
filtro había resuelto y que se reconsultaron después, y recalcula la cadena
completa de las dos maneras: como se midió, con la etapa activa, y sin ella.

La convención es la del artículo y no se cambia aquí: los pronunciamientos
entran en la matriz, las abstenciones quedan fuera, y las alertas que el filtro
resolvía cuentan como lo que la regla dijo de ellas, que era no explotable.

    py tools/chain_without_prefilter.py
"""

from __future__ import annotations

import csv
import statistics
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
SPOC = RAIZ.parent.parent / "spoc"
ORIGINAL = SPOC / "verdicts.csv"
RECONSULTA = SPOC / "verdicts_sin_filtro.csv"
POR_REGLA = "regla-determinista"


def f1(tp: int, fp: int, fn: int) -> float:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return 2 * p * r / (p + r) if p + r else 0.0


def matriz(veredictos: list[tuple[str, bool]]) -> tuple[int, int, int, int, int]:
    """(vp, fp, fn, vn, abstenciones) sobre una lista de (veredicto, es_real)."""
    vp = fp = fn = vn = abst = 0
    for valor, real in veredictos:
        if valor == "explotable":
            vp += real
            fp += not real
        elif valor == "no_explotable":
            fn += real
            vn += not real
        else:
            abst += 1
    return vp, fp, fn, vn, abst


def main() -> int:
    if not RECONSULTA.exists():
        print(f"ERROR: falta {RECONSULTA}. Corre antes tools/rerun_filtered.py",
              file=sys.stderr)
        return 2

    original = list(csv.DictReader(ORIGINAL.open(encoding="utf-8")))
    nuevos = list(csv.DictReader(RECONSULTA.open(encoding="utf-8")))

    verdad = {f["finding_id"]: f["known_truth"] in ("1", "True", "true")
              for f in original}
    lote = set(verdad)
    modelos = sorted({f["model"] for f in original if f["model"] != POR_REGLA})
    repeticiones = sorted({f["repetition"] for f in original
                           if f["model"] != POR_REGLA})

    # Lo que la regla resolvió, por hallazgo: siempre no explotable.
    por_regla = {f["finding_id"] for f in original if f["model"] == POR_REGLA}

    print(f"Lote: {len(lote)} alertas, {sum(verdad.values())} reales")
    print(f"Resueltas por la regla: {len(por_regla)}, "
          f"reales {sum(1 for f in por_regla if verdad[f])}")
    print(f"Reconsultadas: {len({f['finding_id'] for f in nuevos})} alertas, "
          f"{len(nuevos)} veredictos\n")

    print(f"{'modelo':28s} {'rep':>4s}  {'con filtro':>11s}  {'sin filtro':>11s}")
    resumen: dict[str, dict[str, list[float]]] = {}
    for modelo in modelos:
        resumen[modelo] = {"con": [], "sin": []}
        for rep in repeticiones:
            juzgados = [
                (f["veredicto"], verdad[f["finding_id"]])
                for f in original
                if f["model"] == modelo and f["repetition"] == rep
            ]
            # Con la etapa activa: las ocho entran como no explotable.
            con = juzgados + [("no_explotable", verdad[f]) for f in por_regla]
            # Sin la etapa: entran con lo que el modelo respondió al
            # reconsultarlas, en su misma repetición.
            reconsultados = [
                (f["veredicto"], verdad[f["finding_id"]])
                for f in nuevos
                if f["model"] == modelo and f["repetition"] == rep
            ]
            a = matriz(con)
            fa = f1(a[0], a[1], a[2])
            resumen[modelo]["con"].append(fa)

            # Una reconsulta que el proveedor no llegó a contestar deja el
            # hallazgo sin veredicto, que es lo mismo que una abstención: queda
            # fuera de la matriz y se informa en la cobertura, no se rellena.
            b = matriz(juzgados + reconsultados)
            fb = f1(b[0], b[1], b[2])
            resumen[modelo]["sin"].append(fb)
            faltan = len(por_regla) - len(reconsultados)
            cobertura = (b[0] + b[1] + b[2] + b[3]) / len(lote)
            nota = f"  ({faltan} sin respuesta)" if faltan else ""
            print(f"{modelo:28s} {rep:>4s}  {fa:>11.3f}  {fb:>11.3f}"
                  f"  cobertura {cobertura:.3f}{nota}")

    print()
    for modelo, valores in resumen.items():
        con = statistics.mean(valores["con"])
        if len(valores["sin"]) == len(valores["con"]):
            sin = statistics.mean(valores["sin"])
            print(f"{modelo:28s} media  {con:>11.3f}  {sin:>11.3f}  "
                  f"(+{sin - con:.3f})")
        else:
            print(f"{modelo:28s} media  {con:>11.3f}  {'pendiente':>11s}")

    print("\nQué dijo el modelo de las ocho que la regla había descartado:")
    for modelo in modelos:
        suyos = [f for f in nuevos if f["model"] == modelo]
        aciertos = sum(1 for f in suyos if f["veredicto"] == "explotable")
        anclados = sum(1 for f in suyos if f["anchor_verified"] == "1")
        primera = sum(1 for f in suyos
                      if f["anchor_verified"] == "1" and f["attempts"] == "1")
        print(f"  {modelo:28s} explotable en {aciertos} de {len(suyos)} | "
              f"anclaje {anclados}/{len(suyos)}, a la primera {primera}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
