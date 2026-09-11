"""Mide la línea base del analizador sobre el conjunto de referencia.

Es el primer paso de la prueba de concepto del objetivo específico primero, y
el único que no necesita proveedor de modelo: deja fijado contra qué número hay
que competir después.

El recuento va por caso de prueba y no por hallazgo. El conjunto afirma una
cosa de cada archivo, y si el analizador dispara tres reglas sobre el mismo
caso eso sigue siendo un acierto, no tres. Contar hallazgos premiaría a la
herramienta más ruidosa.

    py tools/poc_baseline.py --expected ruta/expectedresults-1.2.csv --sarif salida.sarif
    py tools/poc_baseline.py --expected ruta/expectedresults-1.2.csv --corpus ruta/benchmark
"""

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.experimentation.domain.services.metrics_calculator import (
    MetricsCalculator,
)
from src.finding_validation.domain.entities.finding import Finding
from src.finding_validation.infrastructure.external.owasp_benchmark_ground_truth import (
    OwaspBenchmarkGroundTruth,
)
from src.finding_validation.infrastructure.external.sarif_parser import (
    parse_sarif_file,
)
from src.finding_validation.infrastructure.external.semgrep_analyzer import (
    SemgrepAnalyzer,
)


def report(findings: list[Finding], expected_path: Path) -> int:
    truth = OwaspBenchmarkGroundTruth(expected_path)
    casos = truth.cases

    # Un caso queda señalado cuando el analizador dispara sobre él una regla de
    # su misma categoría. Las reglas de otra categoría se cuentan aparte: el
    # conjunto no dice si aciertan.
    senalados = {
        par[0] for f in findings if (par := truth.case_of(f)) and truth.truth_for(f) is not None
    }
    fuera = [f for f in findings if truth.truth_for(f) is None]
    otra_categoria = sum(1 for f in fuera if truth.case_of(f) is not None)

    pares = [(caso.is_real, nombre in senalados) for nombre, caso in casos.items()]
    matriz = MetricsCalculator().confusion(pares)

    reales = sum(1 for c in casos.values() if c.is_real)
    print("\nCONJUNTO DE REFERENCIA")
    print(f"  casos de prueba              {len(casos)}")
    print(f"  vulnerabilidades reales      {reales}")
    print(f"  casos limpios                {len(casos) - reales}")

    print("\nSALIDA DEL ANALIZADOR")
    print(f"  hallazgos                    {len(findings)}")
    print(f"  casos señalados              {len(senalados)}")
    print(f"  hallazgos sin etiqueta       {len(fuera)}")
    print(f"    otra categoría sobre un caso del conjunto  {otra_categoria}")
    print(f"    archivo ajeno al conjunto                  {len(fuera) - otra_categoria}")

    print("\nMATRIZ DE CONFUSIÓN POR CASO DE PRUEBA")
    for clave, valor in matriz.report().items():
        print(f"  {clave:<28} {valor}")

    print(
        f"\n  Material de trabajo: {matriz.false_positives} falsos positivos que "
        f"descartar\n  sin perder ninguno de los {matriz.true_positives} reales "
        f"que el analizador sí vio.\n"
    )
    return 0 if matriz.total else 1


async def analyze(corpus: Path) -> list[Finding]:
    print(f"Analizando {corpus}. Sobre el conjunto completo esto tarda.")
    return await SemgrepAnalyzer().analyze(str(corpus))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected", required=True, type=Path)
    parser.add_argument("--sarif", type=Path, help="SARIF ya generado")
    parser.add_argument("--corpus", type=Path, help="Código a analizar ahora")
    args = parser.parse_args()

    if bool(args.sarif) == bool(args.corpus):
        parser.error("Indica --sarif o --corpus, uno de los dos")

    if args.sarif:
        findings = parse_sarif_file(args.sarif).findings
    else:
        findings = asyncio.run(analyze(args.corpus))

    return report(findings, args.expected)


if __name__ == "__main__":
    sys.exit(main())
