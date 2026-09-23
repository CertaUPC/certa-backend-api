"""Datos que describen un lenguaje al recorredor.

Hay un solo recorredor, `TreeSitterCodeReader`. Sumar un lenguaje es agregar un
perfil: dos consultas y una lista de nombres, no un módulo nuevo.
"""

from dataclasses import dataclass, field
from types import ModuleType

# Catálogo explícito, no inferido: así se puede auditar. Cada perfil lo amplía
# con los nombres de su ecosistema.
COMMON_SANITIZER_HINTS = (
    "escape", "sanitize", "sanitise", "encode", "quote", "clean", "strip",
    "filter", "whitelist", "allowlist", "validate", "verify", "check",
    "normalize", "canonicalize",
)


@dataclass(frozen=True)
class LanguageProfile:
    """`function_query` captura `@function`, el nodo entero, y `@name`, el
    identificador. `call_query` captura `@callee`."""

    name: str
    extensions: tuple[str, ...]
    grammar_module: str
    function_query: str
    call_query: str
    sanitizer_hints: tuple[str, ...] = field(default=COMMON_SANITIZER_HINTS)

    def __post_init__(self) -> None:
        if "@function" not in self.function_query or "@name" not in self.function_query:
            raise ValueError(
                f"El perfil de {self.name} debe capturar @function y @name"
            )
        if "@callee" not in self.call_query:
            raise ValueError(f"El perfil de {self.name} debe capturar @callee")

    def matches(self, file_path: str) -> bool:
        lowered = file_path.lower()
        return any(lowered.endswith(ext) for ext in self.extensions)

    def load_grammar(self) -> ModuleType:
        """Se importa al usarse, para que falte una gramática no impida arrancar."""
        import importlib

        return importlib.import_module(self.grammar_module)


JAVA = LanguageProfile(
    name="java",
    extensions=(".java",),
    grammar_module="tree_sitter_java",
    # El constructor también transforma el dato, y a menudo es donde vive el
    # saneamiento. Capturar solo method_declaration lo dejaba fuera: el modelo
    # veía la llamada pero no el cuerpo, y lo honesto por su parte era
    # abstenerse.
    function_query=(
        "(method_declaration name: (identifier) @name) @function"
        "\n(constructor_declaration name: (identifier) @name) @function"
    ),
    call_query=(
        "(method_invocation name: (identifier) @callee)"
        "\n(object_creation_expression type: (type_identifier) @callee)"
    ),
    sanitizer_hints=COMMON_SANITIZER_HINTS
    + (
        "preparestatement", "setstring", "setint", "bind", "parameterize",
        "htmlescape", "htmlencode", "urlencode",
    ),
)

# Sin gramática instalada todavía. Quedan declarados para que activarlos sea
# instalar el paquete y nada más.
PYTHON = LanguageProfile(
    name="python",
    extensions=(".py",),
    grammar_module="tree_sitter_python",
    function_query="(function_definition name: (identifier) @name) @function",
    call_query="(call function: [(identifier) @callee (attribute attribute: (identifier) @callee)])",
)

CSHARP = LanguageProfile(
    name="csharp",
    extensions=(".cs",),
    grammar_module="tree_sitter_c_sharp",
    function_query="(method_declaration name: (identifier) @name) @function",
    call_query="(invocation_expression function: [(identifier) @callee (member_access_expression name: (identifier) @callee)])",
)

PHP = LanguageProfile(
    name="php",
    extensions=(".php",),
    grammar_module="tree_sitter_php",
    function_query="(function_definition name: (name) @name) @function",
    call_query="(function_call_expression function: (name) @callee)",
)

ALL_PROFILES: tuple[LanguageProfile, ...] = (JAVA, PYTHON, CSHARP, PHP)


def profile_for(file_path: str) -> LanguageProfile | None:
    """None no es un fallo: quiere decir que el contexto irá por ventana."""
    for profile in ALL_PROFILES:
        if profile.matches(file_path):
            return profile
    return None
