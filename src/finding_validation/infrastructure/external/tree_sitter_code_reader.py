"""Contexto por árbol sintáctico. Un solo adaptador, parametrizado por
`LanguageProfile`: sumar un lenguaje no toca este archivo."""

from dataclasses import dataclass, field
from pathlib import Path

from tree_sitter import Language, Node, Parser, Query, QueryCursor

from ...domain.entities.code_context import CodeContext
from ...domain.entities.finding import Finding
from .language_profile import LanguageProfile
from .window_code_reader import CodeUnavailable, render_numbered, window_around

DEFAULT_MAX_CONTEXT_LINES = 250


@dataclass(frozen=True)
class FunctionNode:
    """Función localizada en el árbol, con su rango de líneas base 1."""

    name: str
    start_line: int
    end_line: int
    node: Node

    def covers(self, line: int) -> bool:
        return self.start_line <= line <= self.end_line

    @property
    def lines(self) -> frozenset[int]:
        return frozenset(range(self.start_line, self.end_line + 1))

    @property
    def span(self) -> int:
        return self.end_line - self.start_line + 1


@dataclass
class TreeSitterCodeReader:
    """Implementa `CodeReaderPort` sobre una gramática de tree-sitter."""

    repository_root: Path
    profile: LanguageProfile
    max_context_lines: int = DEFAULT_MAX_CONTEXT_LINES
    _parser: Parser = field(init=False, repr=False)
    _language: Language = field(init=False, repr=False)

    def __post_init__(self) -> None:
        grammar = self.profile.load_grammar()
        self._language = Language(grammar.language())
        self._parser = Parser(self._language)

    @property
    def language(self) -> str:
        return self.profile.name

    def _read(self, relative_path: str) -> str:
        path = self.repository_root / relative_path
        if not path.exists():
            raise CodeUnavailable(
                f"El archivo {relative_path} ya no existe en el repositorio"
            )
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise CodeUnavailable(f"No se pudo leer {relative_path}: {exc}") from exc

    def _query(self, source: str, query_text: str) -> dict[str, list[Node]]:
        tree = self._parser.parse(source.encode("utf-8"))
        cursor = QueryCursor(Query(self._language, query_text))
        return cursor.captures(tree.root_node)

    def find_functions(self, source: str) -> list[FunctionNode]:
        captures = self._query(source, self.profile.function_query)
        functions = captures.get("function", [])
        names = captures.get("name", [])
        data = source.encode("utf-8")

        found: list[FunctionNode] = []
        for fn in functions:
            # Emparejar por posición y no por índice: una función anidada
            # descuadraría la correspondencia.
            propio = next(
                (n for n in names if fn.start_byte <= n.start_byte < fn.end_byte),
                None,
            )
            if propio is None:
                continue
            found.append(
                FunctionNode(
                    name=data[propio.start_byte : propio.end_byte].decode(
                        "utf-8", "replace"
                    ),
                    start_line=fn.start_point[0] + 1,
                    end_line=fn.end_point[0] + 1,
                    node=fn,
                )
            )
        return found

    def enclosing_function(self, source: str, line: int) -> FunctionNode | None:
        """La más interna de las que cubren la línea, que es la más precisa."""
        candidates = [f for f in self.find_functions(source) if f.covers(line)]
        return min(candidates, key=lambda f: f.span) if candidates else None

    def find_callers(self, source: str, function_name: str) -> list[FunctionNode]:
        data = source.encode("utf-8")
        callees = self._query(source, self.profile.call_query).get("callee", [])
        invocaciones = [
            n
            for n in callees
            if data[n.start_byte : n.end_byte].decode("utf-8", "replace")
            == function_name
        ]
        if not invocaciones:
            return []

        callers: list[FunctionNode] = []
        for fn in self.find_functions(source):
            if fn.name == function_name:
                continue
            if any(
                fn.node.start_byte <= inv.start_byte < fn.node.end_byte
                for inv in invocaciones
            ):
                callers.append(fn)
        return callers

    def find_sanitizers(self, source: str, node: Node) -> list[str]:
        """Invocaciones dentro del nodo cuyo nombre sugiere saneamiento.

        Es una heurística de nombres declarada como tal: el sistema no afirma
        que la función sanee, solo que su nombre lo sugiere. Esa distinción se
        traslada al modelo, que juzga con el código a la vista.
        """
        data = source.encode("utf-8")
        found: list[str] = []
        for callee in self._query(source, self.profile.call_query).get("callee", []):
            if not (node.start_byte <= callee.start_byte < node.end_byte):
                continue
            name = data[callee.start_byte : callee.end_byte].decode("utf-8", "replace")
            if name in found:
                continue
            lowered = name.lower()
            if any(hint in lowered for hint in self.profile.sanitizer_hints):
                found.append(name)
        return found

    async def recover_context(
        self, finding: Finding, caller_depth: int = 2
    ) -> CodeContext:
        source = self._read(finding.location.file_path)
        lines = source.splitlines()
        target = finding.location.start_line

        function = self.enclosing_function(source, target)
        if function is None:
            # No hay función que extraer, pero sí código alrededor. Se degrada
            # y se declara.
            return window_around(finding, lines, target, self.max_context_lines)

        callers = self.find_callers(source, function.name) if caller_depth > 0 else []
        sanitizers = self.find_sanitizers(source, function.node)

        covered = set(function.lines)
        blocks = [(function.start_line, function.end_line)]

        for caller in callers[:caller_depth]:
            if len(covered | caller.lines) > self.max_context_lines:
                break
            covered |= caller.lines
            blocks.append((caller.start_line, caller.end_line))
            for s in self.find_sanitizers(source, caller.node):
                if s not in sanitizers:
                    sanitizers.append(s)

        blocks.sort()
        text = "\n\n".join(render_numbered(lines, a, b) for a, b in blocks)

        return CodeContext(
            finding_id=finding.id,
            enclosing_function=function.name,
            text=text,
            available_lines=frozenset(covered),
            callers=tuple(c.name for c in callers[:caller_depth]),
            sanitizers=tuple(sanitizers),
            source_expression=lines[target - 1].strip() if target <= len(lines) else None,
            caller_depth=caller_depth,
            degraded_to_file=False,
        )
