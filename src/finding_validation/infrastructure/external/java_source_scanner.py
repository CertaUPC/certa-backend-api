"""Recorrido de Java por conteo de llaves, sin dependencias.

Respaldo del adaptador de árbol sintáctico, para entornos donde no se pueda
instalar la gramática. Sus límites están en LIMITATIONS.
"""

import re
from dataclasses import dataclass

LIMITATIONS = (
    "No distingue llaves dentro de literales de cadena ni de caracteres.",
    "No resuelve invocación dinámica ni reflexión.",
    (
        "Reconoce llamadores por coincidencia textual del nombre, de modo que la "
        "sobrecarga de métodos puede producir llamadores de más."
    ),
)

# Firma de método Java: modificadores, tipo de retorno, nombre y paréntesis.
_METHOD = re.compile(
    r"^[ \t]*(?:(?:public|protected|private|static|final|synchronized|abstract|native)\s+)*"
    r"(?:<[^>]+>\s*)?"
    r"[\w.<>\[\],\s]+\s+"
    r"(?P<name>\w+)\s*\([^;{]*\)\s*(?:throws\s+[\w.,\s]+)?\{",
    re.MULTILINE,
)

_STRING = re.compile(r'"(?:\\.|[^"\\])*"')
_CHAR = re.compile(r"'(?:\\.|[^'\\])*'")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT = re.compile(r"//[^\n]*")

# Catálogo explícito, no inferido: así se puede auditar. El adaptador de árbol
# sintáctico lo reutiliza.
SANITIZER_HINTS = (
    "escape", "sanitize", "sanitise", "encode", "htmlescape", "htmlencode",
    "urlencode", "quote", "clean", "strip", "filter", "whitelist", "allowlist",
    "validate", "verify", "check", "normalize", "canonicalize", "parameterize",
    "preparestatement", "setstring", "setint", "bind",
)


def _blank_out_literals(source: str) -> str:
    """Reemplaza literales y comentarios por espacios del mismo largo.

    Conserva las posiciones y los saltos de línea, de modo que los índices y los
    números de línea del texto enmascarado coincidan con los del original. Sin
    esto, una llave dentro de una cadena descuadraría el conteo.
    """

    def _mask(match: re.Match[str]) -> str:
        return "".join("\n" if c == "\n" else " " for c in match.group(0))

    masked = _BLOCK_COMMENT.sub(_mask, source)
    masked = _LINE_COMMENT.sub(_mask, masked)
    masked = _STRING.sub(_mask, masked)
    return _CHAR.sub(_mask, masked)


@dataclass(frozen=True)
class JavaMethod:
    """Método localizado dentro de un archivo, con su rango de líneas base 1."""

    name: str
    start_line: int
    end_line: int
    body: str

    @property
    def lines(self) -> frozenset[int]:
        return frozenset(range(self.start_line, self.end_line + 1))

    def covers(self, line: int) -> bool:
        return self.start_line <= line <= self.end_line


def _matching_brace(masked: str, open_index: int) -> int | None:
    """Índice de la llave que cierra la abierta en `open_index`, o None."""
    depth = 0
    for i in range(open_index, len(masked)):
        char = masked[i]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return i
    return None


def find_methods(source: str) -> list[JavaMethod]:
    """Localiza los métodos del archivo con su rango real de líneas."""
    masked = _blank_out_literals(source)
    methods: list[JavaMethod] = []

    for match in _METHOD.finditer(masked):
        open_index = masked.index("{", match.end() - 1)
        close_index = _matching_brace(masked, open_index)
        if close_index is None:
            # Archivo truncado o llaves descuadradas: se omite en lugar de
            # inventar un rango.
            continue
        start_line = source.count("\n", 0, match.start()) + 1
        end_line = source.count("\n", 0, close_index) + 1
        methods.append(
            JavaMethod(
                name=match.group("name"),
                start_line=start_line,
                end_line=end_line,
                body=source[match.start() : close_index + 1],
            )
        )
    return methods


def enclosing_method(source: str, line: int) -> JavaMethod | None:
    """Método que contiene la línea señalada.

    Ante métodos anidados, devuelve el más interno, que es el que aporta el
    contexto más preciso.
    """
    candidates = [m for m in find_methods(source) if m.covers(line)]
    if not candidates:
        return None
    return min(candidates, key=lambda m: m.end_line - m.start_line)


def find_callers(source: str, method_name: str) -> list[JavaMethod]:
    """Métodos del archivo que invocan al método indicado.

    Se excluye el propio método para no reportarlo como su propio llamador, y se
    ignoran las coincidencias dentro de literales gracias al enmascarado.
    """
    if not method_name:
        return []
    call = re.compile(r"\b" + re.escape(method_name) + r"\s*\(")
    callers: list[JavaMethod] = []
    for method in find_methods(source):
        if method.name == method_name:
            continue
        if call.search(_blank_out_literals(method.body)):
            callers.append(method)
    return callers


def find_sanitizers(body: str, hints: tuple[str, ...] = SANITIZER_HINTS) -> list[str]:
    """Invocaciones cuyo nombre sugiere saneamiento, en orden de aparición.

    Es heurística de nombres: no afirma que la función sanee, solo que lo
    parece. Quien decide es el modelo, con el código delante.
    """
    masked = _blank_out_literals(body)
    found: list[str] = []
    seen: set[str] = set()
    for match in re.finditer(r"\b(\w+)\s*\(", masked):
        name = match.group(1)
        lowered = name.lower()
        if name in seen:
            continue
        if any(hint in lowered for hint in hints):
            seen.add(name)
            found.append(name)
    return found
