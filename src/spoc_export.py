"""Empaqueta una corrida de la prueba de concepto para que otro la repita.

Una tabla de resultados sola no es evidencia reproducible: no dice sobre qué
hallazgos se midió, con qué versión de la consulta ni con qué modelo exacto.
Quien quisiera comprobarla tendría que creerse el número.

Aquí se escriben tres archivos. El cuadro de resultados, que es la tabla que se
lee. El detalle por veredicto, que permite recontar cualquier celda de esa
tabla. Y el manifiesto, que fija las condiciones de la corrida: si alguien
repite el procedimiento con el mismo manifiesto y obtiene otra cosa, la
diferencia está en algún sitio que el manifiesto nombra.

La clave del proveedor no se escribe en ninguno de los tres. Del proveedor solo
viaja el anfitrión, que es lo que hace falta para saber contra qué se midió.
"""

import csv
import hashlib
import json
import platform
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

VERDICT_COLUMNS = [
    "finding_id", "regla", "cwe", "severidad", "file_path", "linea",
    "fingerprint", "known_truth", "model", "model_version", "repetition",
    "veredicto", "confidence", "anchor_verified", "attempts",
    "cited_lines", "reutilizado", "latency_ms",
]


@dataclass
class RunContext:
    """Lo que hay que saber de la corrida para volver a montarla."""

    execution: object
    findings: list
    models: list[str]
    repetitions: int
    batch_size: int | None
    max_queries: int
    settings: object
    prompt_version: str


def batch_fingerprint(findings: list) -> str:
    """Huella del lote juzgado.

    Permite comprobar que se está midiendo sobre el mismo conjunto de hallazgos
    sin tener que distribuirlo. Va sobre las huellas ordenadas, de modo que no
    dependa del orden en que la base los devuelva.
    """
    material = "\n".join(sorted(f.fingerprint.value for f in findings))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def write_scorecard(destino: Path, filas: list[dict]) -> None:
    with destino.open("w", encoding="utf-8", newline="") as archivo:
        escritor = csv.DictWriter(archivo, fieldnames=list(filas[0].keys()))
        escritor.writeheader()
        escritor.writerows(filas)


def write_verdicts(destino: Path, verdicts: list, findings: list) -> None:
    """Una fila por veredicto, con el hallazgo al que corresponde."""
    indice = {f.id: f for f in findings}
    with destino.open("w", encoding="utf-8", newline="") as archivo:
        escritor = csv.writer(archivo)
        escritor.writerow(VERDICT_COLUMNS)
        for v in verdicts:
            f = indice.get(v.finding_id)
            escritor.writerow([
                str(v.finding_id),
                f.rule_id if f else "",
                f.cwe if f else "",
                f.severity if f else "",
                f.location.file_path if f else "",
                f.location.start_line if f else "",
                f.fingerprint.value if f else "",
                "" if not f or f.known_truth is None else int(f.known_truth),
                v.model,
                v.model_version,
                v.repetition,
                v.value.value,
                "" if v.confidence is None else v.confidence,
                int(v.anchor_verified),
                v.attempts,
                " ".join(str(n) for n in sorted(v.justification.cited_lines)),
                int(v.was_reused),
                v.latency_ms or "",
            ])


def build_manifest(contexto: RunContext, filas: list[dict], acuerdo: float) -> dict:
    etiquetados = [f for f in contexto.findings if f.has_known_truth]
    reales = sum(1 for f in etiquetados if f.known_truth)
    ejecucion = contexto.execution
    ajustes = contexto.settings
    return {
        "fecha_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "lote": {
            "execution_id": str(ejecucion.id),
            "huella_del_lote": batch_fingerprint(contexto.findings),
            "hallazgos": len(contexto.findings),
            "con_verdad_conocida": len(etiquetados),
            "vulnerabilidades_reales": reales,
            "falsos_positivos_declarados": len(etiquetados) - reales,
        },
        "analizador": {
            "herramienta": ejecucion.tool_name,
            "version_de_reglas": ejecucion.ruleset_version,
        },
        "consulta": {
            "version_del_prompt": contexto.prompt_version,
            "temperatura": ajustes.llm_temperature,
            "lineas_maximas_de_contexto": ajustes.max_context_lines,
            "profundidad_de_llamadores": ajustes.caller_depth,
        },
        "modelos": {
            "anfitrion": urlsplit(ajustes.llm_base_url).netloc or "no declarado",
            "identificadores": list(contexto.models),
            "repeticiones": contexto.repetitions,
            "tope_de_consultas_por_modelo": contexto.max_queries,
            "tamano_del_lote": contexto.batch_size,
        },
        "entorno": {
            "python": platform.python_version(),
            "sistema": platform.system(),
        },
        "resultado": {
            "acuerdo_entre_corridas": round(acuerdo, 4),
            "consultas": sum(f["consultas"] for f in filas),
            "usd": round(sum(f["usd"] for f in filas), 4),
            "corridas": len(filas),
        },
    }


def export(destino: Path, contexto: RunContext, filas: list[dict],
           verdicts: list, acuerdo: float) -> list[Path]:
    """Escribe el paquete y devuelve los archivos que dejó."""
    destino.mkdir(parents=True, exist_ok=True)
    cuadro = destino / "scorecard.csv"
    detalle = destino / "verdicts.csv"
    manifiesto = destino / "manifest.json"

    write_scorecard(cuadro, filas)
    write_verdicts(detalle, verdicts, contexto.findings)
    manifiesto.write_text(
        json.dumps(build_manifest(contexto, filas, acuerdo), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return [cuadro, detalle, manifiesto]


__all__ = ["RunContext", "batch_fingerprint", "build_manifest", "export"]
