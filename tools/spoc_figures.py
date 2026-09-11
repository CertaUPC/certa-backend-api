"""Dibuja la evidencia gráfica de la prueba de concepto.

Lee el paquete que deja `py -m src.cli compare --out-dir` y produce las figuras
del anexo. No recalcula nada: toma los números del cuadro de resultados y del
detalle por veredicto, de modo que lo que se ve sea lo mismo que se reportó.

    py tools/spoc_figures.py spoc/ --dest figuras/

Necesita matplotlib, que es dependencia de desarrollo y no del servicio.
"""

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

try:
    import matplotlib
except ModuleNotFoundError:
    print("Falta matplotlib. Instálalo con: pip install -r requirements-dev.txt",
          file=sys.stderr)
    raise SystemExit(1) from None

matplotlib.use("Agg")
import matplotlib.pyplot as plt

TINTA = "#1f2933"
BARRAS = ["#3d5a80", "#98c1d9", "#ee6c4d", "#c8d8e4"]
CRITERIO_F1 = 0.75        # declarado en el protocolo de validación
CRITERIO_ANCLAJE = 0.85


def leer(carpeta: Path) -> tuple[list[dict], list[dict], dict]:
    cuadro = carpeta / "scorecard.csv"
    detalle = carpeta / "verdicts.csv"
    manifiesto = carpeta / "manifest.json"
    for ruta in (cuadro, detalle, manifiesto):
        if not ruta.is_file():
            raise SystemExit(f"Falta {ruta.name} en {carpeta}. ¿Corriste compare "
                             f"con --out-dir?")
    with cuadro.open(encoding="utf-8") as f:
        filas = list(csv.DictReader(f))
    with detalle.open(encoding="utf-8") as f:
        veredictos = list(csv.DictReader(f))
    return filas, veredictos, json.loads(manifiesto.read_text(encoding="utf-8"))


def corto(modelo: str) -> str:
    """El identificador completo no cabe bajo una barra."""
    return modelo.split("/")[-1]


def base(ax, titulo: str, ylabel: str = "") -> None:
    ax.set_title(titulo, color=TINTA, fontsize=11, pad=12)
    if ylabel:
        ax.set_ylabel(ylabel, color=TINTA, fontsize=9)
    ax.spines[["top", "right"]].set_visible(False)
    ax.tick_params(colors=TINTA, labelsize=8)
    ax.grid(axis="y", color="#e4e7eb", linewidth=0.8)
    ax.set_axisbelow(True)


def promedio_por_modelo(filas: list[dict], campo: str) -> dict[str, float]:
    """Media entre repeticiones. Con una sola repetición devuelve su valor."""
    acumulado = defaultdict(list)
    for f in filas:
        acumulado[f["modelo"]].append(float(f[campo]))
    return {m: sum(v) / len(v) for m, v in acumulado.items()}


def fig_desempeno(filas: list[dict], dest: Path) -> Path:
    modelos = list(dict.fromkeys(f["modelo"] for f in filas))
    metricas = [("f1", "F1"), ("precision", "Precisión"), ("exhaustividad", "Exhaustividad")]
    fig, ax = plt.subplots(figsize=(7.2, 4.0), dpi=200)
    ancho = 0.26
    for i, (campo, etiqueta) in enumerate(metricas):
        medias = promedio_por_modelo(filas, campo)
        x = [j + i * ancho for j in range(len(modelos))]
        alturas = [medias[m] for m in modelos]
        barras = ax.bar(x, alturas, ancho, label=etiqueta, color=BARRAS[i])
        ax.bar_label(barras, fmt="%.2f", fontsize=7, color=TINTA, padding=2)
    ax.axhline(CRITERIO_F1, color="#ee6c4d", linestyle="--", linewidth=1)
    ax.text(len(modelos) - 0.45, CRITERIO_F1 + 0.015,
            f"criterio F1 = {CRITERIO_F1}", fontsize=7, color="#ee6c4d")
    ax.set_xticks([j + ancho for j in range(len(modelos))])
    ax.set_xticklabels([corto(m) for m in modelos])
    ax.set_ylim(0, 1.08)
    base(ax, "Desempeño de cada clase de modelo frente a la verdad conocida")
    ax.legend(frameon=False, fontsize=8, ncols=3, loc="upper left")
    return guardar(fig, dest / "spoc_desempeno.png")


def fig_matrices(filas: list[dict], dest: Path) -> Path:
    modelos = list(dict.fromkeys(f["modelo"] for f in filas))
    matrices = {
        m: [[promedio_por_modelo(filas, "verdaderos_positivos")[m],
             promedio_por_modelo(filas, "falsos_negativos")[m]],
            [promedio_por_modelo(filas, "falsos_positivos")[m],
             promedio_por_modelo(filas, "verdaderos_negativos")[m]]]
        for m in modelos
    }
    # Escala común: con una escala por panel, un 30 y un 90 se pintarían del
    # mismo tono y la comparación visual entre modelos engañaría.
    tope = max(v for celdas in matrices.values() for fila in celdas for v in fila) or 1

    fig, ejes = plt.subplots(1, len(modelos), figsize=(3.0 * len(modelos), 3.2), dpi=200)
    if len(modelos) == 1:
        ejes = [ejes]
    for ax, modelo in zip(ejes, modelos, strict=True):
        celdas = matrices[modelo]
        ax.imshow(celdas, cmap="Blues", vmin=0, vmax=tope)
        for i in range(2):
            for j in range(2):
                # Sobre fondo oscuro la tinta no se lee.
                claro = celdas[i][j] > 0.55 * tope
                ax.text(j, i, f"{celdas[i][j]:.0f}", ha="center", va="center",
                        fontsize=12, color="white" if claro else TINTA)
        ax.set_xticks([0, 1], ["predice\nexplotable", "predice\nno explotable"], fontsize=7)
        ax.set_yticks([0, 1], ["es real", "es falso\npositivo"], fontsize=7)
        ax.set_title(corto(modelo), fontsize=9, color=TINTA)
        ax.tick_params(length=0)
        ax.spines[:].set_visible(False)
    fig.suptitle("Matriz de confusión por clase de modelo", fontsize=11, color=TINTA)
    return guardar(fig, dest / "spoc_matrices.png")


def fig_anclaje(filas: list[dict], dest: Path) -> Path:
    medias = promedio_por_modelo(filas, "anclaje_primera")
    modelos = list(medias)
    fig, ax = plt.subplots(figsize=(6.4, 3.6), dpi=200)
    barras = ax.bar([corto(m) for m in modelos], [medias[m] for m in modelos],
                    color=BARRAS[0], width=0.5)
    ax.bar_label(barras, fmt="%.3f", fontsize=8, color=TINTA, padding=3)
    ax.axhline(CRITERIO_ANCLAJE, color="#ee6c4d", linestyle="--", linewidth=1)
    ax.text(len(modelos) - 0.6, CRITERIO_ANCLAJE + 0.012,
            f"criterio = {CRITERIO_ANCLAJE}", fontsize=7, color="#ee6c4d")
    ax.set_ylim(0, 1.08)
    base(ax, "Anclaje verificado a la primera consulta", "proporción de veredictos")
    return guardar(fig, dest / "spoc_anclaje.png")


def fig_costo(filas: list[dict], dest: Path) -> Path:
    """La decisión no es solo cuál acierta más, sino a qué precio."""
    f1 = promedio_por_modelo(filas, "f1")
    usd = promedio_por_modelo(filas, "usd")
    consultas = promedio_por_modelo(filas, "consultas")
    fig, ax = plt.subplots(figsize=(6.4, 4.2), dpi=200)
    for i, modelo in enumerate(f1):
        por_consulta = usd[modelo] / consultas[modelo] if consultas[modelo] else 0.0
        ax.scatter(por_consulta, f1[modelo], s=120, color=BARRAS[i % len(BARRAS)],
                   zorder=3)
        ax.annotate(corto(modelo), (por_consulta, f1[modelo]),
                    textcoords="offset points", xytext=(8, 6),
                    fontsize=8, color=TINTA)
    ax.axhline(CRITERIO_F1, color="#ee6c4d", linestyle="--", linewidth=1)
    ax.set_xlabel("costo por consulta (USD)", color=TINTA, fontsize=9)
    # Los rótulos van a la derecha del punto: sin margen, el del modelo más caro
    # se sale del lienzo.
    ax.margins(x=0.28, y=0.16)
    base(ax, "Desempeño frente a costo por consulta", "F1")
    return guardar(fig, dest / "spoc_costo.png")


def fig_estabilidad(veredictos: list[dict], dest: Path) -> Path | None:
    """Solo tiene sentido si hubo repeticiones del mismo modelo."""
    por_hallazgo = defaultdict(lambda: defaultdict(set))
    for v in veredictos:
        por_hallazgo[v["model"]][v["finding_id"]].add(v["veredicto"])
    estables = {}
    for modelo, hallazgos in por_hallazgo.items():
        repetidos = {k: val for k, val in hallazgos.items() if val}
        if not repetidos:
            continue
        coinciden = sum(1 for val in repetidos.values() if len(val) == 1)
        estables[modelo] = coinciden / len(repetidos)
    if not estables or all(v == 1.0 for v in estables.values()):
        return None

    fig, ax = plt.subplots(figsize=(6.4, 3.6), dpi=200)
    modelos = list(estables)
    barras = ax.bar([corto(m) for m in modelos], [estables[m] for m in modelos],
                    color=BARRAS[1], width=0.5)
    ax.bar_label(barras, fmt="%.3f", fontsize=8, color=TINTA, padding=3)
    ax.axhline(0.80, color="#ee6c4d", linestyle="--", linewidth=1)
    ax.text(len(modelos) - 0.6, 0.815, "criterio = 0.80", fontsize=7, color="#ee6c4d")
    ax.set_ylim(0, 1.08)
    base(ax, "Estabilidad del veredicto entre ejecuciones idénticas",
         "proporción de coincidencia")
    return guardar(fig, dest / "spoc_estabilidad.png")


def guardar(fig, ruta: Path) -> Path:
    fig.tight_layout()
    fig.savefig(ruta, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return ruta


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paquete", type=Path, help="Carpeta que dejó compare --out-dir")
    parser.add_argument("--dest", type=Path, default=None,
                        help="Dónde escribir las figuras. Por omisión, el paquete")
    args = parser.parse_args()

    filas, veredictos, manifiesto = leer(args.paquete)
    dest = args.dest or args.paquete
    dest.mkdir(parents=True, exist_ok=True)

    escritas = [
        fig_desempeno(filas, dest),
        fig_matrices(filas, dest),
        fig_anclaje(filas, dest),
        fig_costo(filas, dest),
    ]
    inestabilidad = fig_estabilidad(veredictos, dest)
    if inestabilidad:
        escritas.append(inestabilidad)
    else:
        print("Sin repeticiones que comparar: no se dibuja la estabilidad.")

    lote = manifiesto["lote"]
    print(f"\nCorrida del {manifiesto['fecha_utc']}")
    print(f"  {lote['con_verdad_conocida']} hallazgos etiquetados, "
          f"{lote['vulnerabilidades_reales']} reales")
    print(f"  huella del lote {lote['huella_del_lote'][:16]}")
    print("\nFiguras:")
    for ruta in escritas:
        print(f"  {ruta}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
