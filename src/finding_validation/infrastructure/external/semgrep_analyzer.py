"""Corre el analizador y recoge su SARIF.

Por línea de comandos y no por biblioteca: así el mismo adaptador sirve para
cualquier analizador cambiando el binario y sus argumentos.
"""

import asyncio
import json
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ....shared.tracing import Stage, timed
from ...domain.entities.finding import Finding
from .sarif_parser import SarifError, parse_sarif

logger = logging.getLogger(__name__)


def _entorno_utf8() -> dict:
    """Fuerza UTF-8 en el proceso hijo.

    El analizador es un programa Python y hereda la codificación de la consola.
    En Windows esa codificación es cp1252 y su salida incluye emoji, de modo
    que el proceso muere al escribirla con UnicodeEncodeError antes de llegar a
    producir nada.
    """
    entorno = dict(os.environ)
    entorno["PYTHONIOENCODING"] = "utf-8"
    entorno["PYTHONUTF8"] = "1"
    return entorno

DEFAULT_TIMEOUT_SECONDS = 900
DEFAULT_CONFIG = "p/security-audit"


class AnalyzerUnavailable(RuntimeError):
    """El binario del analizador no está instalado o no se puede ejecutar."""


class AnalysisFailed(RuntimeError):
    """El analizador terminó con error y no produjo salida utilizable."""


@dataclass
class SemgrepAnalyzer:
    """Ejecuta el analizador sobre un repositorio y devuelve hallazgos.

    `config` es el conjunto de reglas. Se declara aquí y se persiste con la
    ejecución porque comparar dos corridas con conjuntos distintos no tendría
    sentido.
    """

    binary: str = "semgrep"
    config: str = DEFAULT_CONFIG
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    extra_args: tuple[str, ...] = field(default_factory=tuple)
    _version: str | None = field(default=None, init=False, repr=False)

    @property
    def tool_name(self) -> str:
        return "semgrep-oss"

    @property
    def ruleset_version(self) -> str:
        return self._version or self.config

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    async def version(self) -> str:
        if self._version:
            return self._version
        if not self.is_available():
            raise AnalyzerUnavailable(
                f"No se encontró el ejecutable '{self.binary}'. Instálalo o "
                f"indica otro con la configuración del servicio."
            )
        proc = await asyncio.create_subprocess_exec(
            self.binary, "--version",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env=_entorno_utf8(),
        )
        out, _ = await proc.communicate()
        version = out.decode("utf-8", errors="replace").strip()
        self._version = f"{self.config}@{version or 'desconocida'}"
        return self._version

    async def analyze(self, repository_path: str) -> list[Finding]:
        """Corre el análisis y devuelve los hallazgos ya normalizados."""
        root = Path(repository_path)
        if not root.exists():
            raise AnalysisFailed(f"No existe la ruta {repository_path}")
        if not self.is_available():
            raise AnalyzerUnavailable(
                f"No se encontró el ejecutable '{self.binary}'. Sin analizador "
                f"no hay hallazgos que validar."
            )

        await self.version()

        with tempfile.TemporaryDirectory() as tmp:
            salida = Path(tmp) / "resultado.sarif"
            args = [
                self.binary, "--config", self.config,
                "--sarif", "--output", str(salida),
                "--quiet", "--metrics=off", "--disable-version-check",
                *self.extra_args, str(root),
            ]

            with timed(Stage.INGEST, herramienta=self.tool_name, ruta=root.name) as t:
                proc = await asyncio.create_subprocess_exec(
                    *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=_entorno_utf8(),
                )
                try:
                    _, err = await asyncio.wait_for(
                        proc.communicate(), timeout=self.timeout_seconds
                    )
                except asyncio.TimeoutError as exc:
                    proc.kill()
                    raise AnalysisFailed(
                        f"El análisis excedió {self.timeout_seconds} s. Acota el "
                        f"alcance o sube el tiempo límite."
                    ) from exc

                # Devuelve 1 cuando encuentra hallazgos, que no es un fallo.
                if proc.returncode not in (0, 1):
                    raise AnalysisFailed(
                        f"El analizador terminó con código {proc.returncode}: "
                        f"{err.decode('utf-8', errors='replace')[:300]}"
                    )
                if not salida.exists():
                    raise AnalysisFailed(
                        "El analizador no produjo archivo SARIF. Revisa el "
                        "conjunto de reglas indicado."
                    )

                try:
                    payload = json.loads(salida.read_text(encoding="utf-8"))
                except json.JSONDecodeError as exc:
                    raise AnalysisFailed(f"La salida no es JSON válido: {exc}") from exc

                try:
                    ingestion = parse_sarif(payload)
                except SarifError as exc:
                    raise AnalysisFailed(str(exc)) from exc

                t["hallazgos"] = ingestion.total
                t["omitidos"] = len(ingestion.skipped)
                if ingestion.ruleset_version:
                    self._version = ingestion.ruleset_version

            return ingestion.findings
