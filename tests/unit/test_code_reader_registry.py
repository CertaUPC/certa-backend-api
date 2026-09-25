"""El recuperador no falla ante un lenguaje que no conoce.

Es la propiedad que sostiene el alcance del proyecto: incorporar un lenguaje
mejora la calidad del contexto, no habilita la validación. Sin perfil, la cadena
sigue funcionando con contexto de ventana declarado como degradado.
"""

from pathlib import Path

import pytest

from src.finding_validation.domain.entities.finding import Finding
from src.finding_validation.domain.value_objects.code_location import CodeLocation
from src.finding_validation.domain.value_objects.fingerprint import Fingerprint
from src.finding_validation.infrastructure.external.code_reader_registry import (
    CodeReaderRegistry,
)
from src.finding_validation.infrastructure.external.language_profile import (
    JAVA,
    LanguageProfile,
    profile_for,
)
from src.finding_validation.infrastructure.external.window_code_reader import (
    CodeUnavailable,
)

JAVA_SRC = """package com.acme;

public class UserDao {

    public User findUnsafe(String id) {
        String q = "SELECT * FROM users WHERE id = " + id;
        return jdbc.queryForObject(q, User.class);
    }

    public User findSafe(String id) {
        String clean = escapeSql(id);
        return jdbc.queryForObject("SELECT " + clean, User.class);
    }

    public User handleRequest(String raw) {
        return findUnsafe(raw);
    }
}
"""

# PL/SQL no tiene perfil declarado. Es exactamente el caso que la pregunta de
# diseño plantea.
PLSQL_SRC = """CREATE OR REPLACE PROCEDURE get_user (p_id IN VARCHAR2) AS
  v_sql VARCHAR2(4000);
BEGIN
  v_sql := 'SELECT * FROM users WHERE id = ' || p_id;
  EXECUTE IMMEDIATE v_sql;
END get_user;
"""


def _finding(path: str, line: int, body: str = "x") -> Finding:
    return Finding(
        rule_id="rule.test",
        severity="error",
        location=CodeLocation(path, line, line),
        fingerprint=Fingerprint.compute("rule.test", path, body),
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "UserDao.java").write_text(JAVA_SRC, encoding="utf-8")
    (tmp_path / "get_user.sql").write_text(PLSQL_SRC, encoding="utf-8")
    (tmp_path / "notas.txt").write_text("linea\n" * 40, encoding="utf-8")
    return tmp_path


class TestProfileSelection:
    def test_java_has_a_profile(self):
        assert profile_for("src/UserDao.java") is JAVA

    def test_plsql_has_no_profile(self):
        assert profile_for("db/get_user.sql") is None

    def test_unknown_extension_has_no_profile(self):
        assert profile_for("flujo.nifi.xml") is None

    def test_profile_must_capture_required_nodes(self):
        with pytest.raises(ValueError, match="@function"):
            LanguageProfile(
                name="roto",
                extensions=(".x",),
                grammar_module="tree_sitter_x",
                function_query="(nada)",
                call_query="(call) @callee",
            )

    def test_profile_must_capture_callee(self):
        with pytest.raises(ValueError, match="@callee"):
            LanguageProfile(
                name="roto",
                extensions=(".x",),
                grammar_module="tree_sitter_x",
                function_query="(fn name: (id) @name) @function",
                call_query="(call)",
            )


class TestJavaThroughTreeSitter:
    async def test_recovers_enclosing_function(self, repo):
        reader = CodeReaderRegistry(repo)
        ctx = await reader.recover_context(_finding("UserDao.java", 6))
        assert ctx.enclosing_function == "findUnsafe"
        assert not ctx.degraded_to_file

    async def test_recovers_caller(self, repo):
        reader = CodeReaderRegistry(repo)
        ctx = await reader.recover_context(_finding("UserDao.java", 6))
        assert "handleRequest" in ctx.callers

    async def test_does_not_report_itself_as_caller(self, repo):
        reader = CodeReaderRegistry(repo)
        ctx = await reader.recover_context(_finding("UserDao.java", 6))
        assert "findUnsafe" not in ctx.callers

    async def test_detects_sanitizer_by_name(self, repo):
        reader = CodeReaderRegistry(repo)
        ctx = await reader.recover_context(_finding("UserDao.java", 11))
        assert ctx.enclosing_function == "findSafe"
        assert "escapeSql" in ctx.sanitizers

    async def test_does_not_invent_sanitizers(self, repo):
        reader = CodeReaderRegistry(repo)
        ctx = await reader.recover_context(_finding("UserDao.java", 6))
        assert not ctx.has_sanitizers

    async def test_context_lines_match_the_finding(self, repo):
        reader = CodeReaderRegistry(repo)
        ctx = await reader.recover_context(_finding("UserDao.java", 6))
        assert ctx.contains_line(6)
        assert "6:" in ctx.text

    async def test_registers_java_as_active(self, repo):
        reader = CodeReaderRegistry(repo)
        await reader.recover_context(_finding("UserDao.java", 6))
        assert "java" in reader.active_languages


class TestUnknownLanguageDegrades:
    """El caso que la pregunta de diseño plantea: PL/SQL, NiFi, lo que venga."""

    async def test_plsql_still_produces_context(self, repo):
        reader = CodeReaderRegistry(repo)
        ctx = await reader.recover_context(_finding("get_user.sql", 4))
        assert ctx.text
        assert ctx.contains_line(4)

    async def test_plsql_context_is_marked_degraded(self, repo):
        """No se oculta la degradación: se declara."""
        reader = CodeReaderRegistry(repo)
        ctx = await reader.recover_context(_finding("get_user.sql", 4))
        assert ctx.degraded_to_file
        assert ctx.enclosing_function == "(no identificada)"

    async def test_plsql_still_detects_call_shaped_sanitizers(self, repo):
        """La heurística de nombres no depende de la gramática."""
        (repo / "safe.sql").write_text(
            "BEGIN\n  v := dbms_assert.enquote_literal(p_id);\n  EXECUTE IMMEDIATE v;\nEND;\n",
            encoding="utf-8",
        )
        reader = CodeReaderRegistry(repo)
        ctx = await reader.recover_context(_finding("safe.sql", 2))
        assert any("quote" in s.lower() for s in ctx.sanitizers)

    async def test_plain_text_does_not_crash(self, repo):
        reader = CodeReaderRegistry(repo)
        ctx = await reader.recover_context(_finding("notas.txt", 20))
        assert ctx.degraded_to_file
        assert ctx.contains_line(20)

    async def test_no_language_is_marked_active(self, repo):
        reader = CodeReaderRegistry(repo)
        await reader.recover_context(_finding("get_user.sql", 4))
        assert reader.active_languages == ()


class TestMissingFile:
    async def test_reports_missing_file(self, repo):
        """El aviso nombra la ruta que se intentó, y dónde sí está el árbol.

        Quien carga un SARIF por la web no ve el disco del trabajador. Decir
        «el archivo ya no existe» no le permite distinguir un archivo que se
        movió de un repositorio que este trabajador no tiene.
        """
        reader = CodeReaderRegistry(repo)
        with pytest.raises(CodeUnavailable, match="No se encontró") as fallo:
            await reader.recover_context(_finding("Borrado.java", 3))
        assert str(repo / "Borrado.java") in str(fallo.value)

    async def test_reports_a_repository_that_is_not_there(self, tmp_path):
        """El repositorio ausente se nombra aparte del archivo ausente.

        Es el caso del trabajador que no tiene ese código en su disco, y el
        que hay que poder leer en la pantalla para saber qué configurar.
        """
        ausente = tmp_path / "no-clonado"
        reader = CodeReaderRegistry(ausente)
        with pytest.raises(CodeUnavailable, match="No existe el repositorio") as fallo:
            await reader.recover_context(_finding("UserDao.java", 3))
        assert str(ausente) in str(fallo.value)
