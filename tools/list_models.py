"""Lista los modelos que ofrece el proveedor, con su precio y su ventana.

Existe por dos razones. La primera es practica: el identificador exacto de un
modelo cambia y escribirlo de memoria produce un 404 a mitad de una corrida. La
segunda es que el benchmarking del objetivo primero compara clases de modelo, y
esa comparacion necesita como dato de partida el precio y la ventana vigentes
el dia en que se midio, no los que uno recuerda.

Con --csv deja el listado en disco, que es la evidencia de ese dia.

    py tools/list_models.py --filter claude --filter qwen
    py tools/list_models.py --filter claude --csv modelos.csv

Si la red de la maquina intercepta TLS, exporta REQUESTS_CA_BUNDLE o
SSL_CERT_FILE apuntando al certificado de la intercepcion.
"""

import argparse
import csv
import os
import sys

import httpx

ENDPOINT = "https://openrouter.ai/api/v1/models"
POR_MILLON = 1_000_000


def fetch(url: str) -> list[dict]:
    verify = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE") or True
    with httpx.Client(timeout=30, verify=verify) as cliente:
        r = cliente.get(url)
        r.raise_for_status()
        return r.json().get("data", [])


def precio(modelo: dict, clave: str) -> float:
    """El proveedor lo publica por token. Por millón se lee sin contar ceros."""
    try:
        return float(modelo.get("pricing", {}).get(clave) or 0.0) * POR_MILLON
    except (TypeError, ValueError):
        return 0.0


def filas(modelos: list[dict], filtros: list[str]) -> list[tuple]:
    salida = []
    for m in modelos:
        ident = m.get("id", "")
        if filtros and not any(f.lower() in ident.lower() for f in filtros):
            continue
        salida.append((
            ident,
            m.get("context_length") or 0,
            precio(m, "prompt"),
            precio(m, "completion"),
        ))
    return sorted(salida, key=lambda f: (f[2], f[0]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--filter", action="append", default=[],
                        help="Subcadena del identificador. Se puede repetir")
    parser.add_argument("--url", default=ENDPOINT)
    parser.add_argument("--csv", help="Guarda el listado para citarlo como evidencia")
    args = parser.parse_args()

    try:
        modelos = fetch(args.url)
    except httpx.HTTPError as exc:
        print(f"No se pudo consultar el catálogo: {exc}", file=sys.stderr)
        return 1

    encontrados = filas(modelos, args.filter)
    if not encontrados:
        print("Ningún modelo coincide con el filtro. El catálogo trae "
              f"{len(modelos)} modelos.", file=sys.stderr)
        return 1

    print(f"\n{'identificador':<46} {'ventana':>9} {'entrada':>12} {'salida':>12}")
    print(f"{'':<46} {'tokens':>9} {'USD/1M':>12} {'USD/1M':>12}")
    for ident, ventana, entrada, salida in encontrados:
        print(f"{ident:<46} {ventana:>9} {entrada:>12.3f} {salida:>12.3f}")
    print(f"\n{len(encontrados)} de {len(modelos)} modelos del catálogo.\n")

    if args.csv:
        with open(args.csv, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["identificador", "ventana_tokens", "usd_por_millon_entrada",
                        "usd_por_millon_salida"])
            w.writerows(encontrados)
        print(f"Listado guardado en {args.csv}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
