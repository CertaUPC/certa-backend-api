"""Traduce SARIF 2.1.0 al modelo interno. Contra el formato, no contra una
herramienta."""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ...domain.entities.finding import Finding
from ...domain.value_objects.code_location import CodeLocation
from ...domain.value_objects.fingerprint import Fingerprint

SARIF_VERSION = "2.1.0"

_CWE_PATTERN = re.compile(r"CWE[-_ ]?(\d{1,4})", re.IGNORECASE)

# SARIF admite además "none", que no es un hallazgo accionable.
_LEVELS = {"error", "warning", "note"}
_DEFAULT_LEVEL = "warning"


class SarifError(ValueError):
    """El archivo no cumple el esquema esperado.

    Se distingue de un archivo válido sin hallazgos, que no es un error.
    """


@dataclass
class SarifIngestion:
    """Resultado de ingerir un archivo SARIF."""

    findings: list[Finding] = field(default_factory=list)
    tool_name: str = ""
    ruleset_version: str = ""
    skipped: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def is_empty(self) -> bool:
        """No encontrar nada no es un fallo, pero hay que decirlo."""
        return not self.findings


def extract_cwe(*sources: Any) -> str | None:
    """Busca el identificador CWE en cualquiera de los campos donde suele venir.

    Las herramientas lo colocan en sitios distintos: en las etiquetas de la
    regla, en el identificador de la regla o en la descripción. Se recorre todo
    lo que llegue y se devuelve el primero que aparezca, normalizado.
    """
    for source in sources:
        if source is None:
            continue
        text = source if isinstance(source, str) else json.dumps(source)
        match = _CWE_PATTERN.search(text)
        if match:
            return f"CWE-{int(match.group(1))}"
    return None


def _normalize_level(raw: Any) -> str:
    level = str(raw or "").lower()
    return level if level in _LEVELS else _DEFAULT_LEVEL


def _rule_index(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Indexa las reglas para poder completar categoría y severidad de cada
    resultado."""
    driver = run.get("tool", {}).get("driver", {})
    rules = driver.get("rules") or []
    return {r.get("id"): r for r in rules if isinstance(r, dict) and r.get("id")}


def _physical_location(result: dict[str, Any]) -> tuple[str, int, int] | None:
    locations = result.get("locations") or []
    if not locations:
        return None
    physical = locations[0].get("physicalLocation") or {}
    uri = (physical.get("artifactLocation") or {}).get("uri")
    if not uri:
        return None
    region = physical.get("region") or {}
    start = region.get("startLine")
    if start is None:
        return None
    end = region.get("endLine") or start
    try:
        start_i, end_i = int(start), int(end)
    except (TypeError, ValueError):
        return None
    end_i = max(end_i, start_i)
    return uri, start_i, end_i


def _snippet(result: dict[str, Any]) -> str:
    """Texto de la región reportada, que alimenta la huella.

    Cuando la herramienta no lo entrega, se recurre al mensaje. Es una
    degradación consciente: la huella sigue siendo estable dentro de una misma
    herramienta, aunque pierda comparabilidad entre herramientas distintas.
    """
    locations = result.get("locations") or []
    if locations:
        physical = locations[0].get("physicalLocation") or {}
        region = physical.get("region") or {}
        text = (region.get("snippet") or {}).get("text")
        if text:
            return str(text)
    return str((result.get("message") or {}).get("text") or "")


def parse_sarif(payload: dict[str, Any]) -> SarifIngestion:
    """Convierte un documento SARIF ya cargado en memoria."""
    if not isinstance(payload, dict):
        raise SarifError("El documento SARIF debe ser un objeto")

    version = payload.get("version")
    if version != SARIF_VERSION:
        raise SarifError(
            f"Se esperaba SARIF {SARIF_VERSION} y el archivo declara {version!r}"
        )

    runs = payload.get("runs")
    if not isinstance(runs, list):
        raise SarifError("El documento SARIF no declara el arreglo 'runs'")

    ingestion = SarifIngestion()

    for run in runs:
        if not isinstance(run, dict):
            continue
        driver = run.get("tool", {}).get("driver", {})
        ingestion.tool_name = ingestion.tool_name or str(driver.get("name") or "")
        ingestion.ruleset_version = ingestion.ruleset_version or str(
            driver.get("semanticVersion") or driver.get("version") or ""
        )
        rules = _rule_index(run)

        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            rule_id = result.get("ruleId")
            if not rule_id:
                ingestion.skipped.append("resultado sin ruleId")
                continue

            location = _physical_location(result)
            if location is None:
                ingestion.skipped.append(f"{rule_id}: sin ubicación física utilizable")
                continue
            uri, start, end = location

            rule = rules.get(rule_id, {})
            severity = _normalize_level(
                result.get("level") or rule.get("defaultConfiguration", {}).get("level")
            )
            cwe = extract_cwe(
                rule.get("properties"),
                rule_id,
                (rule.get("fullDescription") or {}).get("text"),
                (rule.get("shortDescription") or {}).get("text"),
                # Algunas herramientas etiquetan el resultado y no la regla.
                # Sin esto el hallazgo llega sin categoría y queda fuera de
                # toda medición contra verdad conocida.
                result.get("properties"),
            )

            ingestion.findings.append(
                Finding(
                    rule_id=str(rule_id),
                    severity=severity,
                    location=CodeLocation(uri, start, end),
                    fingerprint=Fingerprint.compute(str(rule_id), uri, _snippet(result)),
                    cwe=cwe,
                    message=str((result.get("message") or {}).get("text") or "") or None,
                )
            )

    return ingestion


def parse_sarif_file(path: str | Path) -> SarifIngestion:
    """Carga y convierte un archivo SARIF del disco."""
    file_path = Path(path)
    if not file_path.exists():
        raise SarifError(f"No existe el archivo {file_path}")
    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SarifError(f"El archivo no es JSON válido: {exc}") from exc
    return parse_sarif(payload)
