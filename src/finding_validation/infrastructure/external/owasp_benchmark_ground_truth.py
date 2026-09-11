"""Etiqueta los hallazgos contra la verdad conocida del OWASP Benchmark.

El conjunto reparte un archivo por caso de prueba y un CSV que dice, para cada
uno, si la vulnerabilidad es real y de qué categoría es. Con eso se puede medir
corrección funcional sin depender del juicio de nadie, que es lo que exige la
prueba de concepto del primer objetivo.
"""

import csv
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from ...domain.entities.finding import Finding

_TEST_NAME = re.compile(r"BenchmarkTest\d+", re.IGNORECASE)
_CWE_NUMBER = re.compile(r"(\d+)")

# Familias en las que el conjunto y los analizadores nombran lo mismo con
# números distintos. Fuera de estas equivalencias se exige coincidencia exacta:
# inventar parentescos entre categorías inflaría la exactitud medida.
_FAMILIES: tuple[frozenset[int], ...] = (
    frozenset({22, 23, 35, 36}),      # recorrido de rutas
    frozenset({77, 78, 88}),          # inyección de comandos
    frozenset({79, 80, 81, 83}),      # secuencias de comandos entre sitios
    frozenset({89, 564}),             # inyección SQL y su variante en HQL
    frozenset({330, 338}),            # aleatoriedad débil
)


@dataclass(frozen=True)
class BenchmarkCase:
    """Lo que el conjunto afirma de un archivo: su categoría y si es real."""

    cwe: int
    is_real: bool


class OwaspBenchmarkGroundTruth:
    """Adaptador de GroundTruthPort sobre el CSV de resultados esperados."""

    def __init__(self, expected_results_path: str | Path) -> None:
        self._cases = _read_expected_results(Path(expected_results_path))
        if not self._cases:
            raise ValueError(
                f"El archivo {expected_results_path} no trae ningún caso de "
                f"prueba. Sin etiquetas no hay verdad contra la cual medir."
            )

    def __len__(self) -> int:
        return len(self._cases)

    @property
    def cases(self) -> Mapping[str, BenchmarkCase]:
        """Los casos tal como los declara el conjunto.

        El recuento de una corrida va por caso y no por hallazgo, y para eso
        hace falta ver también los casos que el analizador no señaló.
        """
        return MappingProxyType(self._cases)

    def case_of(self, finding: Finding) -> tuple[str, BenchmarkCase] | None:
        """El caso al que pertenece el archivo del hallazgo, si pertenece."""
        nombre = _test_name(finding.location.file_path)
        if nombre is None:
            return None
        caso = self._cases.get(nombre)
        return (nombre, caso) if caso else None

    def truth_for(self, finding: Finding) -> bool | None:
        par = self.case_of(finding)
        if par is None:
            return None
        _, caso = par
        if not _same_family(finding.cwe, caso.cwe):
            # El analizador disparó una regla de otra categoría sobre este
            # archivo. El conjunto no dice nada al respecto.
            return None
        return caso.is_real


def _read_expected_results(path: Path) -> dict[str, BenchmarkCase]:
    if not path.is_file():
        raise FileNotFoundError(
            f"No existe {path}. Descarga el conjunto de referencia y apunta "
            f"GROUND_TRUTH_PATH a su archivo de resultados esperados."
        )

    casos: dict[str, BenchmarkCase] = {}
    with path.open(encoding="utf-8-sig", newline="") as archivo:
        for fila in csv.reader(archivo):
            if len(fila) < 4 or fila[0].lstrip().startswith("#"):
                continue
            nombre = _test_name(fila[0])
            cwe = _cwe_number(fila[3])
            if nombre is None or cwe is None:
                continue
            casos[nombre] = BenchmarkCase(cwe=cwe, is_real=fila[2].strip().lower() == "true")
    return casos


def _test_name(texto: str) -> str | None:
    """El identificador del caso, venga de una ruta o de la columna del CSV."""
    match = _TEST_NAME.search(texto)
    return match.group(0).lower() if match else None


def _cwe_number(texto: str | None) -> int | None:
    if not texto:
        return None
    match = _CWE_NUMBER.search(texto)
    return int(match.group(1)) if match else None


def _same_family(reported: str | None, expected: int) -> bool:
    numero = _cwe_number(reported)
    if numero is None:
        return False
    if numero == expected:
        return True
    return any(numero in f and expected in f for f in _FAMILIES)


__all__ = ["BenchmarkCase", "OwaspBenchmarkGroundTruth"]
