"""Contexto por ventana. Sirve en cualquier lenguaje.

Es el piso de la cadena: PL/SQL, COBOL, un lenguaje sin perfil, o un hallazgo
que no cae dentro de ninguna función. Entrega las líneas de alrededor y lo marca
como degradado en vez de fallar.
"""

import re
from dataclasses import dataclass
from pathlib import Path

from ...domain.entities.code_context import CodeContext
from ...domain.entities.finding import Finding
from .language_profile import COMMON_SANITIZER_HINTS

DEFAULT_WINDOW_LINES = 200

# Nombre seguido de paréntesis. Cubre Java, C#, PHP, Python, JavaScript y PL/SQL.
_CALL = re.compile(r"\b([A-Za-z_][\w.]*)\s*\(")


class CodeUnavailable(RuntimeError):
    """El archivo que el hallazgo señala ya no existe o no se puede leer."""


def render_numbered(lines: list[str], start: int, end: int) -> str:
    """Los números no son cosméticos: son lo que el modelo cita y lo que el
    verificador comprueba."""
    start = max(1, start)
    end = min(len(lines), end)
    return "\n".join(f"{n}: {lines[n - 1]}" for n in range(start, end + 1))


def guess_sanitizers(text: str, hints: tuple[str, ...] = COMMON_SANITIZER_HINTS) -> list[str]:
    """Invocaciones cuyo nombre sugiere saneamiento, sin analizar sintaxis."""
    found: list[str] = []
    for match in _CALL.finditer(text):
        name = match.group(1)
        if name in found:
            continue
        if any(hint in name.lower() for hint in hints):
            found.append(name)
    return found


def window_around(
    finding: Finding, lines: list[str], target: int, max_lines: int
) -> CodeContext:
    """Contexto de ventana centrado en la línea del hallazgo."""
    half = max(1, max_lines // 2)
    start = max(1, target - half)
    end = min(len(lines), target + half)
    text = render_numbered(lines, start, end)
    return CodeContext(
        finding_id=finding.id,
        enclosing_function="(no identificada)",
        text=text,
        available_lines=frozenset(range(start, end + 1)),
        callers=(),
        sanitizers=tuple(guess_sanitizers("\n".join(lines[start - 1 : end]))),
        source_expression=lines[target - 1].strip() if target <= len(lines) else None,
        caller_depth=0,
        callee_depth=0,
        degraded_to_file=True,
    )


@dataclass
class WindowCodeReader:
    """`CodeReaderPort` sin conocer ningún lenguaje. Siempre degrada, y lo dice."""

    repository_root: Path
    max_context_lines: int = DEFAULT_WINDOW_LINES

    @property
    def language(self) -> str:
        return "(cualquiera)"

    async def recover_context(
        self, finding: Finding, caller_depth: int = 2
    ) -> CodeContext:
        path = self.repository_root / finding.location.file_path
        if not self.repository_root.exists():
            raise CodeUnavailable(
                f"No existe el repositorio en {self.repository_root}. "
                f"Se buscaba {finding.location.file_path} dentro de él."
            )
        if not path.exists():
            raise CodeUnavailable(
                f"No se encontró {path}. El repositorio sí está en "
                f"{self.repository_root}, de modo que el archivo cambió de "
                f"sitio o el SARIF viene de otro árbol."
            )
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise CodeUnavailable(f"No se pudo leer {path}: {exc}") from exc
        return window_around(
            finding, source.splitlines(), finding.location.start_line,
            self.max_context_lines,
        )
