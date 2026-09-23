"""Adaptador del puerto de recuperación de contexto para proyectos Java."""

from dataclasses import dataclass
from pathlib import Path

from ...domain.entities.code_context import CodeContext
from ...domain.entities.finding import Finding
from . import java_source_scanner as scanner

# Por debajo el modelo no ve de dónde viene el dato; por encima solo sube el
# costo por consulta.
TARGET_MIN_LINES = 150
TARGET_MAX_LINES = 250

# Techo del contexto una vez sumados llamadores y llamados. Es más alto que la
# ventana degradada porque aquí no se recorta por cercanía sino por unidades
# completas: entra el método entero o no entra.
TARGET_CONTEXT_LINES = 400

# Eslabones de delegación que se siguen. Dos alcanzan la forma habitual, en que
# el contenedor pasa el dato a un auxiliar y ese lo sanea o no.
CALLEE_DEPTH = 2


class CodeUnavailable(RuntimeError):
    """El archivo que el hallazgo señala ya no existe o no se puede leer."""


@dataclass
class JavaCodeReader:
    """Recupera el contexto desde el árbol de archivos.

    Si no encuentra el método contenedor entrega el archivo acotado alrededor
    del hallazgo y lo marca como degradado.
    """

    repository_root: Path
    max_file_lines: int = TARGET_MAX_LINES
    max_context_lines: int = TARGET_CONTEXT_LINES
    callee_depth: int = CALLEE_DEPTH

    @property
    def language(self) -> str:
        return "java"

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

    async def recover_context(
        self, finding: Finding, caller_depth: int = 2
    ) -> CodeContext:
        source = self._read(finding.location.file_path)
        lines = source.splitlines()
        target = finding.location.start_line

        method = scanner.enclosing_method(source, target)

        if method is None:
            return self._degraded_context(finding, lines, target)

        callers = (
            scanner.find_callers(source, method.name) if caller_depth > 0 else []
        )
        sanitizers = scanner.find_sanitizers(method.body)

        covered: set[int] = set(method.lines)
        blocks: list[tuple[int, str]] = [(method.start_line, method.body)]

        for caller in callers[:caller_depth]:
            covered |= caller.lines
            sanitizers.extend(
                s for s in scanner.find_sanitizers(caller.body) if s not in sanitizers
            )
            blocks.append((caller.start_line, caller.body))

        callees = self._collect_callees(source, method, covered)
        for callee in callees:
            covered |= callee.lines
            sanitizers.extend(
                s for s in scanner.find_sanitizers(callee.body) if s not in sanitizers
            )
            blocks.append((callee.start_line, callee.body))

        blocks.sort(key=lambda b: b[0])
        text = self._render(blocks)

        return CodeContext(
            finding_id=finding.id,
            enclosing_function=method.name,
            text=text,
            available_lines=frozenset(covered),
            callers=tuple(c.name for c in callers[:caller_depth]),
            callees=tuple(c.name for c in callees),
            sanitizers=tuple(sanitizers),
            source_expression=self._line_at(lines, target),
            caller_depth=caller_depth,
            callee_depth=self.callee_depth,
            degraded_to_file=False,
        )

    def _collect_callees(
        self, source: str, method, covered: set[int]
    ) -> list:
        """Los métodos a los que se delega, y a los que esos delegan a su vez.

        Se recorre en anchura porque la cadena puede tener varios eslabones: el
        contenedor pasa el dato a un auxiliar y ese a otro. Lo que decide el
        veredicto es el último, el que toca el dato antes del sumidero.

        Dos topes lo acotan: la profundidad, y el total de líneas del contexto.
        Sin ellos un archivo muy enlazado arrastraría el proyecto entero a cada
        consulta, y se paga por token enviado.
        """
        salida: list = []
        vistos = {method.name}
        frontera = [method]

        for _ in range(self.callee_depth):
            siguiente = []
            for actual in frontera:
                for candidato in scanner.find_callees(source, actual):
                    if candidato.name in vistos:
                        continue
                    if len(covered | set(candidato.lines)) > self.max_context_lines:
                        # El presupuesto de contexto se acabó. Se para aquí en
                        # lugar de recortar el cuerpo a la mitad: un método
                        # cortado induce a error más que la ausencia.
                        return salida
                    vistos.add(candidato.name)
                    covered |= set(candidato.lines)
                    salida.append(candidato)
                    siguiente.append(candidato)
            if not siguiente:
                break
            frontera = siguiente
        return salida

    def _degraded_context(
        self, finding: Finding, lines: list[str], target: int
    ) -> CodeContext:
        """Ventana alrededor del hallazgo cuando no hay método que extraer.

        Ocurre con inicializadores estáticos, campos de clase y código que el
        recorrido no reconoce como método.
        """
        half = self.max_file_lines // 2
        start = max(1, target - half)
        end = min(len(lines), target + half)
        covered = frozenset(range(start, end + 1))
        text = "\n".join(
            f"{n}: {lines[n - 1]}" for n in range(start, end + 1)
        )
        body = "\n".join(lines[start - 1 : end])
        return CodeContext(
            finding_id=finding.id,
            enclosing_function="(no identificada)",
            text=text,
            available_lines=covered,
            callers=(),
            sanitizers=tuple(scanner.find_sanitizers(body)),
            source_expression=self._line_at(lines, target),
            caller_depth=0,
            callee_depth=0,
            degraded_to_file=True,
        )

    @staticmethod
    def _render(blocks: list[tuple[int, str]]) -> str:
        """Numera cada línea del contexto.

        La numeración no es cosmética: es lo que permite al modelo citar líneas
        y al verificador comprobarlas. Sin números visibles, el anclaje no sería
        posible.
        """
        rendered: list[str] = []
        for start_line, body in blocks:
            for offset, line in enumerate(body.splitlines()):
                rendered.append(f"{start_line + offset}: {line}")
            rendered.append("")
        return "\n".join(rendered).rstrip()

    @staticmethod
    def _line_at(lines: list[str], number: int) -> str | None:
        if 1 <= number <= len(lines):
            return lines[number - 1].strip()
        return None
