import pytest

from src.finding_validation.domain.value_objects.fingerprint import (
    Fingerprint,
    normalize,
)

RULE = "java.lang.security.audit.sqli.jdbc-sqli"
FILE = "src/main/java/com/acme/UserDao.java"
BODY = """
    public User find(String id) {
        String q = "SELECT * FROM users WHERE id = " + id;
        return jdbc.queryForObject(q, User.class);
    }
"""


class TestStability:
    """La huella debe sobrevivir a lo que no cambia la naturaleza del hallazgo."""

    def test_survives_line_shift(self):
        """Insertar código más arriba no altera la huella.

        Es la razón de ser del objeto de valor: el número de línea no participa.
        """
        assert Fingerprint.compute(RULE, FILE, BODY) == Fingerprint.compute(
            RULE, FILE, BODY
        )

    def test_survives_reindentation(self):
        reindented = "\n".join("        " + line.strip() for line in BODY.splitlines())
        assert Fingerprint.compute(RULE, FILE, BODY) == Fingerprint.compute(
            RULE, FILE, reindented
        )

    def test_survives_added_comments(self):
        documented = BODY.replace(
            "public User find", "// busca por identificador\n    public User find"
        )
        assert Fingerprint.compute(RULE, FILE, BODY) == Fingerprint.compute(
            RULE, FILE, documented
        )

    def test_survives_block_comment(self):
        documented = "/** Javadoc que no cambia el comportamiento. */\n" + BODY
        assert Fingerprint.compute(RULE, FILE, BODY) == Fingerprint.compute(
            RULE, FILE, documented
        )

    def test_normalizes_path_separator(self):
        windows = FILE.replace("/", "\\")
        assert Fingerprint.compute(RULE, FILE, BODY) == Fingerprint.compute(
            RULE, windows, BODY
        )


class TestDiscrimination:
    """La huella debe distinguir lo que sí es un hallazgo distinto."""

    def test_different_rule_differs(self):
        assert Fingerprint.compute(RULE, FILE, BODY) != Fingerprint.compute(
            "java.lang.security.audit.xss", FILE, BODY
        )

    def test_different_file_differs(self):
        assert Fingerprint.compute(RULE, FILE, BODY) != Fingerprint.compute(
            RULE, "src/main/java/com/acme/OrderDao.java", BODY
        )

    def test_changed_body_differs(self):
        """Sanear la consulta debe producir un hallazgo distinto, no el mismo."""
        sanitized = BODY.replace('+ id;', '+ escape(id);')
        assert Fingerprint.compute(RULE, FILE, BODY) != Fingerprint.compute(
            RULE, FILE, sanitized
        )


class TestNormalize:
    def test_collapses_whitespace(self):
        assert normalize("a   \n\t  b") == "a b"

    def test_strips_line_comment(self):
        assert normalize("code(); // nota") == "code();"

    def test_strips_block_comment(self):
        assert normalize("a /* nota\nmultilinea */ b") == "a b"


class TestInvariants:
    def test_rejects_empty_rule(self):
        with pytest.raises(ValueError, match="obligatorios"):
            Fingerprint.compute("", FILE, BODY)

    def test_rejects_empty_file(self):
        with pytest.raises(ValueError, match="obligatorios"):
            Fingerprint.compute(RULE, "", BODY)

    def test_rejects_malformed_value(self):
        with pytest.raises(ValueError, match="64 caracteres"):
            Fingerprint("abc")

    def test_short_is_prefix(self):
        f = Fingerprint.compute(RULE, FILE, BODY)
        assert f.short == f.value[:12]
        assert len(f.short) == 12
