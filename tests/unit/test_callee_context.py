"""El contexto tiene que llegar hasta donde vive el saneamiento.

Recuperar solo el método que contiene la línea señalada deja fuera al auxiliar
al que ese método delega el dato. El modelo ve entonces el origen y el sumidero
pero no la transformación intermedia, y lo correcto por su parte es abstenerse:
no puede afirmar que el dato llega sin sanear si no ha visto qué le hicieron.

Esa abstención no es un fallo del modelo, es una carencia del contexto, y se
corrige trayendo el cuerpo de los métodos invocados.
"""

import pytest

from src.finding_validation.domain.entities.finding import Finding
from src.finding_validation.domain.value_objects.code_location import CodeLocation
from src.finding_validation.domain.value_objects.fingerprint import Fingerprint
from src.finding_validation.infrastructure.external import (
    java_source_scanner as scanner,
)
from src.finding_validation.infrastructure.external.java_code_reader import (
    JavaCodeReader,
)

# Reproduce la forma del conjunto de referencia: el servlet toma el dato de la
# petición y lo delega a un auxiliar privado declarado más abajo en el archivo.
# Si el saneamiento existe, está ahí.
FUENTE = """package org.owasp.benchmark.testcode;

import java.sql.*;
import javax.servlet.http.*;

public class BenchmarkTest99999 extends HttpServlet {

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws java.io.IOException {
        String param = request.getParameter("BenchmarkTest99999");
        String bar = doSomething(request, param);
        String sql = "SELECT * FROM users WHERE name = '" + bar + "'";
        try {
            Statement st = DatabaseHelper.getSqlStatement();
            st.execute(sql);
        } catch (SQLException e) {
            response.getWriter().println("error");
        }
    }

    private static String doSomething(HttpServletRequest request, String param) {
        String escaped = org.owasp.esapi.ESAPI.encoder().encodeForSQL(param);
        return escaped;
    }

    private void metodoQueNadieLlama() {
        System.out.println("no entra en el contexto");
    }
}
"""

LINEA_DEL_SUMIDERO = 12  # la que concatena bar en la sentencia


@pytest.fixture
def archivo(tmp_path):
    ruta = tmp_path / "BenchmarkTest99999.java"
    ruta.write_text(FUENTE, encoding="utf-8")
    return tmp_path


@pytest.fixture
def hallazgo():
    location = CodeLocation(
        file_path="BenchmarkTest99999.java",
        start_line=LINEA_DEL_SUMIDERO,
        end_line=LINEA_DEL_SUMIDERO,
    )
    return Finding(
        rule_id="java.lang.security.audit.sqli",
        severity="error",
        location=location,
        fingerprint=Fingerprint.compute("java.lang.security.audit.sqli",
                                        "BenchmarkTest99999.java", "cuerpo"),
        cwe="CWE-89",
    )


CON_CONTROL = """class C {

    public void doPost(String param) {
        String bar = "bob";
        if (param != null) {
            bar = doSomething(param);
        }
        switch (bar.charAt(0)) {
            case 'A':
                bar = param;
                break;
            default:
                break;
        }
        sink(bar);
    }

    private String doSomething(String param) {
        return param;
    }

    private void sink(String s) { }
}
"""


class TestControlFlowIsNotAMethod:
    """`if (...) {` tiene la misma forma que una firma de método.

    Tomarlo por uno tiene dos consecuencias que se pagan: el bloque se vuelve a
    incluir en el contexto aunque ya esté dentro del método que lo contiene, y
    el método contenedor que se informa puede acabar siendo «if» en lugar del
    verdadero.
    """

    def test_keywords_are_not_reported_as_methods(self):
        nombres = {m.name for m in scanner.find_methods(CON_CONTROL)}
        assert not (nombres & {"if", "else", "for", "while", "switch", "catch"})
        assert {"doPost", "doSomething", "sink"} <= nombres

    def test_enclosing_method_is_the_real_one(self):
        # La línea del case está dentro del switch, que a su vez está dentro
        # del método. El método es lo que debe informarse.
        linea = CON_CONTROL.splitlines().index("                bar = param;") + 1
        metodo = scanner.enclosing_method(CON_CONTROL, linea)
        assert metodo is not None and metodo.name == "doPost"

    def test_callees_are_only_real_methods(self):
        metodo = scanner.enclosing_method(CON_CONTROL, 6)
        nombres = [m.name for m in scanner.find_callees(CON_CONTROL, metodo)]
        assert sorted(nombres) == ["doSomething", "sink"]


class TestFindCallees:
    def test_finds_the_helper_the_method_delegates_to(self):
        metodo = scanner.enclosing_method(FUENTE, LINEA_DEL_SUMIDERO)
        assert metodo is not None and metodo.name == "doPost"
        llamados = scanner.find_callees(FUENTE, metodo)
        assert "doSomething" in [m.name for m in llamados]

    def test_does_not_pull_in_unrelated_methods(self):
        metodo = scanner.enclosing_method(FUENTE, LINEA_DEL_SUMIDERO)
        llamados = [m.name for m in scanner.find_callees(FUENTE, metodo)]
        assert "metodoQueNadieLlama" not in llamados

    def test_a_method_is_not_its_own_callee(self):
        recursivo = """class C {
            int fact(int n) { return n <= 1 ? 1 : n * fact(n - 1); }
        }"""
        metodo = scanner.enclosing_method(recursivo, 2)
        assert [m.name for m in scanner.find_callees(recursivo, metodo)] == []

    def test_calls_inside_string_literals_are_ignored(self):
        fuente = """class C {
            void a() { log("doSomething(x)"); }
            void doSomething(String s) { }
        }"""
        metodo = scanner.enclosing_method(fuente, 2)
        assert [m.name for m in scanner.find_callees(fuente, metodo)] == []


@pytest.mark.asyncio
class TestTreeSitterReachesTheSanitizer:
    """El mismo requisito sobre el lector que de verdad se usa.

    El registro elige el recorrido por árbol sintáctico siempre que la gramática
    esté instalada, y solo cae al de expresiones regulares si falta. Comprobarlo
    únicamente sobre el de respaldo dejaría sin verificar el camino real.
    """

    @staticmethod
    def lector(raiz):
        from src.finding_validation.infrastructure.external.language_profile import JAVA
        from src.finding_validation.infrastructure.external.tree_sitter_code_reader import (
            TreeSitterCodeReader,
        )

        return TreeSitterCodeReader(raiz, JAVA)

    async def test_registry_picks_this_reader_for_java(self, archivo):
        from src.finding_validation.infrastructure.external.code_reader_registry import (
            CodeReaderRegistry,
        )

        elegido = CodeReaderRegistry(archivo)._reader_for("X.java")
        assert elegido is not None, (
            "sin gramática el lector real sería otro y esta prueba no diría nada"
        )

    async def test_helper_body_is_included(self, archivo, hallazgo):
        contexto = await self.lector(archivo).recover_context(hallazgo)
        assert "encodeForSQL" in contexto.text

    async def test_helper_lines_are_verifiable(self, archivo, hallazgo):
        contexto = await self.lector(archivo).recover_context(hallazgo)
        linea = FUENTE.splitlines().index(
            "        String escaped = org.owasp.esapi.ESAPI.encoder().encodeForSQL(param);"
        ) + 1
        assert contexto.contains_line(linea)

    async def test_the_callee_is_named(self, archivo, hallazgo):
        contexto = await self.lector(archivo).recover_context(hallazgo)
        assert "doSomething" in contexto.callees

    async def test_unrelated_method_stays_out(self, archivo, hallazgo):
        contexto = await self.lector(archivo).recover_context(hallazgo)
        assert "metodoQueNadieLlama" not in contexto.text

    async def test_the_sanitizer_is_reported(self, archivo, hallazgo):
        contexto = await self.lector(archivo).recover_context(hallazgo)
        assert any("encodeForSQL" in s for s in contexto.sanitizers)

    async def test_context_stays_within_the_declared_ceiling(self, archivo, hallazgo):
        """El tope de líneas manda sobre la ambición de traer más contexto.

        Cada línea se paga, y un archivo muy enlazado arrastraría medio proyecto
        a cada consulta.
        """
        from src.finding_validation.infrastructure.external.language_profile import JAVA
        from src.finding_validation.infrastructure.external.tree_sitter_code_reader import (
            TreeSitterCodeReader,
        )

        estrecho = TreeSitterCodeReader(archivo, JAVA, max_context_lines=12)
        contexto = await estrecho.recover_context(hallazgo)
        assert len(contexto.available_lines) <= 12
        assert contexto.callees == ()


@pytest.mark.asyncio
class TestContextReachesTheSanitizer:
    async def test_helper_body_is_included(self, archivo, hallazgo):
        contexto = await JavaCodeReader(archivo).recover_context(hallazgo)
        assert "encodeForSQL" in contexto.text, (
            "sin el cuerpo del auxiliar el modelo no puede decidir y se abstiene"
        )

    async def test_helper_lines_are_verifiable(self, archivo, hallazgo):
        """Citar una línea del auxiliar tiene que poder anclarse.

        Si la línea entra en el texto pero no en el rango declarado, el
        verificador la rechazaría y el veredicto se perdería igual.
        """
        contexto = await JavaCodeReader(archivo).recover_context(hallazgo)
        linea_del_saneador = FUENTE.splitlines().index(
            "        String escaped = org.owasp.esapi.ESAPI.encoder().encodeForSQL(param);"
        ) + 1
        assert contexto.contains_line(linea_del_saneador)

    async def test_the_sanitizer_is_reported(self, archivo, hallazgo):
        contexto = await JavaCodeReader(archivo).recover_context(hallazgo)
        assert any("encodeForSQL" in s for s in contexto.sanitizers)

    async def test_the_callee_is_named(self, archivo, hallazgo):
        contexto = await JavaCodeReader(archivo).recover_context(hallazgo)
        assert "doSomething" in contexto.callees

    async def test_unrelated_method_stays_out(self, archivo, hallazgo):
        contexto = await JavaCodeReader(archivo).recover_context(hallazgo)
        assert "metodoQueNadieLlama" not in contexto.text
