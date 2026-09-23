"""Cada función tiene que quedarse con su propio nombre.

El nombre no es una etiqueta decorativa: con él se buscan los llamadores y los
llamados, y con él se le dice al modelo dentro de qué función está mirando. Si
una función se queda con el nombre de otra, el contexto se arma alrededor de la
función equivocada.
"""

import pytest

from src.finding_validation.domain.entities.finding import Finding
from src.finding_validation.domain.value_objects.code_location import CodeLocation
from src.finding_validation.domain.value_objects.fingerprint import Fingerprint
from src.finding_validation.infrastructure.external.language_profile import JAVA
from src.finding_validation.infrastructure.external.tree_sitter_code_reader import (
    TreeSitterCodeReader,
)

# doPost contiene una clase anónima con su propio método. Los dos son
# method_declaration para la gramática, y el de dentro cae dentro del rango del
# de fuera.
CON_CLASE_ANONIMA = """package org.owasp.benchmark.testcode;

public class BenchmarkTest99998 extends HttpServlet {

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String param = request.getParameter("dato");
        RowMapper<String> mapeador = new RowMapper<String>() {
            @Override
            public String mapRow(ResultSet rs, int fila) throws SQLException {
                return rs.getString(1);
            }
        };
        String sql = "SELECT * FROM t WHERE c = '" + param + "'";
        plantilla.query(sql, mapeador);
    }
}
"""

CON_CONSTRUCTOR = """package org.owasp.benchmark.testcode;

public class Consulta {

    private final String criterio;

    public Consulta(String entrada) {
        this.criterio = org.owasp.esapi.ESAPI.encoder().encodeForSQL(entrada);
    }

    public void ejecutar(Statement st) throws SQLException {
        st.execute("SELECT * FROM t WHERE c = '" + criterio + "'");
    }
}
"""


def lector(raiz):
    return TreeSitterCodeReader(raiz, JAVA)


def hallazgo(archivo: str, linea: int) -> Finding:
    loc = CodeLocation(file_path=archivo, start_line=linea, end_line=linea)
    return Finding(
        rule_id="java.sqli", severity="error", location=loc,
        fingerprint=Fingerprint.compute("java.sqli", archivo, "cuerpo"),
        cwe="CWE-89",
    )


class TestNamePairing:
    """Las capturas de la consulta no vienen en orden de documento.

    Al emparejar cada función con la primera de la lista que cae dentro de su
    rango, una función que contiene a otra podía quedarse con el nombre de la de
    dentro. Se observó en el conjunto de referencia: doPost aparecía nombrado
    mapRow.
    """

    def test_the_outer_method_keeps_its_name(self):
        funciones = {f.start_line: f.name
                     for f in lector(".").find_functions(CON_CLASE_ANONIMA)}
        # doPost arranca en su anotación, línea 5.
        assert funciones.get(5) == "doPost"

    def test_the_inner_method_is_also_found_with_its_own_name(self):
        nombres = {f.name for f in lector(".").find_functions(CON_CLASE_ANONIMA)}
        assert {"doPost", "mapRow"} <= nombres

    def test_the_enclosing_function_of_a_line_is_the_innermost(self):
        linea = CON_CLASE_ANONIMA.splitlines().index(
            "                return rs.getString(1);") + 1
        fn = lector(".").enclosing_function(CON_CLASE_ANONIMA, linea)
        assert fn is not None and fn.name == "mapRow"

    def test_a_line_outside_the_inner_class_belongs_to_the_outer(self):
        linea = CON_CLASE_ANONIMA.splitlines().index(
            "        plantilla.query(sql, mapeador);") + 1
        fn = lector(".").enclosing_function(CON_CLASE_ANONIMA, linea)
        assert fn is not None and fn.name == "doPost"


class TestConstructors:
    """Un constructor también transforma el dato.

    La consulta capturaba solo method_declaration, y un constructor es
    constructor_declaration. Si el saneamiento vive ahí, su cuerpo no se
    recuperaba y el modelo se quedaba sin lo que decide el veredicto.
    """

    @pytest.fixture
    def archivo(self, tmp_path):
        (tmp_path / "Consulta.java").write_text(CON_CONSTRUCTOR, encoding="utf-8")
        return tmp_path

    @staticmethod
    def test_the_constructor_is_a_function():
        nombres = {f.name for f in lector(".").find_functions(CON_CONSTRUCTOR)}
        assert "Consulta" in nombres
        assert "ejecutar" in nombres

    @pytest.mark.asyncio
    async def test_a_finding_inside_the_constructor_finds_it(self, archivo):
        linea = CON_CONSTRUCTOR.splitlines().index(
            "        this.criterio = org.owasp.esapi.ESAPI.encoder()"
            ".encodeForSQL(entrada);") + 1
        ctx = await lector(archivo).recover_context(hallazgo("Consulta.java", linea))
        assert ctx.enclosing_function == "Consulta"
        assert "encodeForSQL" in ctx.text
