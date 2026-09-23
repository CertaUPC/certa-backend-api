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
#
# Los modificadores y el tipo de retorno se buscan en la misma línea que el
# nombre. Admitirlos a lo largo de varias líneas dispara un retroceso
# desbocado: al fallar la firma, el motor reprueba cada reparto posible del
# espacio en blanco a lo largo del archivo entero. Medido sobre los archivos
# auxiliares del conjunto de referencia, esa variante tardaba 216 segundos por
# archivo; acotada a la línea tarda menos de un milisegundo.
#
# Dentro de los ángulos se admite cualquier cosa salvo el fin de línea y las
# llaves, para que un genérico anidado como ResponseEntity<List<Mensaje>> entre
# entero. Exigir ángulos balanceados dejaría fuera esas firmas.
#
# Las anotaciones que preceden a la firma entran en el método. Es lo que hace
# el recorrido por árbol sintáctico, y el contexto no puede depender de cuál de
# los dos esté disponible. Además la anotación informa: @GetMapping dice que el
# método es una entrada web, y eso pesa al juzgar si el dato lo controla quien
# ataca.
_METHOD = re.compile(
    r"^(?:[ \t]*@[\w.$]+(?:[ \t]*\([^\r\n]*\))?[ \t]*\r?\n)*"
    r"[ \t]*"
    r"(?:(?:public|protected|private|static|final|synchronized|abstract|native"
    r"|default|strictfp)[ \t]+)*"
    r"(?:<[^;{}\r\n]*>[ \t]*)?"
    r"[\w.$]+(?:[ \t]*<[^;{}\r\n]*>)?(?:[ \t]*\[[ \t]*\])*"
    r"[ \t]+"
    r"(?P<name>\w+)[ \t]*\([^;{]*?\)"
    r"[ \t\r\n]*(?:throws[ \t]+[\w.,\s]*?)?\{",
    re.MULTILINE,
)

# Palabras que abren un bloque precedido de paréntesis. Tienen la misma forma
# que una firma de método y el patrón no las distingue por sí solo.
#
# Confundirlas sale caro por partida doble: el bloque se añade otra vez al
# contexto aunque ya venga dentro del método que lo contiene, y se paga por
# token enviado; y el método contenedor que se informa pasa a ser el bloque más
# interno, de modo que el modelo recibe un `if` suelto en lugar del método
# entero y pierde de vista de dónde viene el dato.
_NOT_METHOD_NAMES = frozenset({
    "if", "else", "for", "while", "switch", "catch", "do", "try", "finally",
    "return", "new", "case", "instanceof", "assert", "throw", "synchronized",
})

# Una sola alternancia, no cuatro pasadas encadenadas. Encadenarlas hace que
# cada una vea lo que la anterior ya rompió: enmascarar los comentarios primero
# convierte la barra doble de "ldap://servidor" en un comentario, borra el resto
# de la línea con la comilla de cierre incluida, y a partir de ahí las comillas
# se emparejan con las de otras líneas y se enmascara código de verdad, llaves
# incluidas. Un método pasaba entonces a tragarse a los que venían detrás.
#
# Recorrido de una pasada, el motor decide por posición: gana quien empiece
# antes, que es la regla del lenguaje. El orden de las ramas solo desempata
# entre las que empiezan en el mismo sitio.
_MASKABLE = re.compile(
    r'"(?:\\.|[^"\\\n])*"'      # cadena
    r"|'(?:\\.|[^'\\\n])*'"     # carácter
    r"|/\*.*?\*/"               # comentario de bloque
    r"|//[^\n]*",               # comentario de línea
    re.DOTALL,
)

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

    return _MASKABLE.sub(_mask, source)


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
        if match.group("name") in _NOT_METHOD_NAMES:
            continue
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


def find_callees(source: str, method: JavaMethod | None) -> list[JavaMethod]:
    """Métodos del archivo a los que el método indicado delega.

    El saneamiento rara vez está en el método que contiene la línea señalada:
    está en el auxiliar al que ese método le pasa el dato. Sin su cuerpo se ve
    de dónde viene el dato y dónde acaba, pero no qué le hicieron por el camino,
    que es justo lo que decide si el hallazgo es real.

    Se limita a los métodos declarados en el mismo archivo. Resolver llamadas
    fuera de él exigiría un grafo de tipos que aquí no hay, y adivinar a qué
    método se refiere un nombre repetido sería peor que no traerlo.
    """
    if method is None:
        return []
    cuerpo = _blank_out_literals(method.body)
    salida: list[JavaMethod] = []
    for candidato in find_methods(source):
        if candidato.name == method.name:
            continue
        llamada = re.compile(r"\b" + re.escape(candidato.name) + r"\s*\(")
        if llamada.search(cuerpo) and candidato not in salida:
            salida.append(candidato)
    return salida


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
