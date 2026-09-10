from uuid import uuid4

import pytest

from src.finding_validation.domain.entities.code_context import CodeContext
from src.finding_validation.domain.entities.verdict import VerdictValue
from src.finding_validation.domain.services.anchor_verifier import AnchorVerifier
from src.finding_validation.domain.value_objects.justification import Justification


@pytest.fixture
def context():
    """Contexto que cubre las líneas 40 a 52, como lo entregaría el recuperador."""
    return CodeContext(
        finding_id=uuid4(),
        enclosing_function="find",
        text="\n".join(f"linea {n}" for n in range(40, 53)),
        available_lines=frozenset(range(40, 53)),
    )


@pytest.fixture
def verifier():
    return AnchorVerifier()


class TestVerifiedAnchor:
    def test_all_cited_lines_exist(self, verifier, context):
        j = Justification.from_model_output("El dato llega sin sanear", [42, 45])
        result = verifier.verify(j, context)
        assert result.verified
        assert not result.missing_lines

    def test_boundary_lines_count_as_present(self, verifier, context):
        """Los extremos exactos del contexto pertenecen al contexto."""
        j = Justification.from_model_output("Ver extremos", [40, 52])
        assert verifier.verify(j, context).verified

    def test_repeated_citation_collapses(self, verifier, context):
        j = Justification.from_model_output("Insiste en la misma línea", [42, 42, 42])
        result = verifier.verify(j, context)
        assert result.verified
        assert result.cited_lines == frozenset({42})

    def test_order_does_not_matter(self, verifier, context):
        directa = Justification.from_model_output("t", [42, 45])
        inversa = Justification.from_model_output("t", [45, 42])
        assert directa.cited_lines == inversa.cited_lines


class TestFailedAnchor:
    def test_line_beyond_context_fails(self, verifier, context):
        """El caso que motiva el mecanismo: cita una línea que no vio."""
        j = Justification.from_model_output("Se valida en la línea 91", [91])
        result = verifier.verify(j, context)
        assert result.failed
        assert result.missing_lines == frozenset({91})

    def test_line_just_outside_boundary_fails(self, verifier, context):
        j = Justification.from_model_output("t", [39])
        assert verifier.verify(j, context).failed

    def test_citing_nothing_fails(self, verifier, context):
        """Una conclusión sin líneas no es una justificación anclada."""
        j = Justification.from_model_output("Confía en mí, es seguro", [])
        result = verifier.verify(j, context)
        assert result.failed
        assert "no cita ninguna línea" in result.reason

    def test_partial_citation_fails(self, verifier, context):
        """Si una sola línea no existe, el anclaje falla completo."""
        j = Justification.from_model_output("t", [42, 91])
        result = verifier.verify(j, context)
        assert result.failed
        assert result.missing_lines == frozenset({91})


class TestRetryHint:
    def test_hint_names_the_missing_lines(self, verifier, context):
        j = Justification.from_model_output("t", [42, 91, 95])
        hint = verifier.verify(j, context).as_retry_hint()
        assert "91" in hint and "95" in hint
        assert "42" not in hint

    def test_hint_for_empty_citation_asks_for_lines(self, verifier, context):
        j = Justification.from_model_output("t", [])
        assert "no citó ninguna línea" in verifier.verify(j, context).as_retry_hint()

    def test_verified_anchor_has_no_hint(self, verifier, context):
        j = Justification.from_model_output("t", [42])
        with pytest.raises(ValueError, match="verificado"):
            verifier.verify(j, context).as_retry_hint()


class TestValueResolution:
    def test_verified_keeps_proposed_value(self, verifier, context):
        j = Justification.from_model_output("t", [42])
        result = verifier.verify(j, context)
        assert (
            verifier.resolve_value(VerdictValue.NOT_EXPLOITABLE, result, attempts=1)
            is VerdictValue.NOT_EXPLOITABLE
        )

    def test_first_failure_keeps_value_for_retry(self, verifier, context):
        j = Justification.from_model_output("t", [91])
        result = verifier.verify(j, context)
        assert (
            verifier.resolve_value(VerdictValue.NOT_EXPLOITABLE, result, attempts=1)
            is VerdictValue.NOT_EXPLOITABLE
        )

    def test_exhausted_retry_becomes_not_verifiable(self, verifier, context):
        """El descarte del modelo se anula si no logra sostenerlo."""
        j = Justification.from_model_output("t", [91])
        result = verifier.verify(j, context)
        assert (
            verifier.resolve_value(VerdictValue.NOT_EXPLOITABLE, result, attempts=2)
            is VerdictValue.NOT_VERIFIABLE
        )


class TestJustificationInvariants:
    def test_rejects_empty_text(self):
        with pytest.raises(ValueError, match="no justifica nada"):
            Justification.from_model_output("   ", [42])

    def test_rejects_string_as_lines(self):
        with pytest.raises(TypeError, match="lista de enteros"):
            Justification.from_model_output("t", "42")

    def test_rejects_non_numeric_line(self):
        with pytest.raises(ValueError, match="no numérica"):
            Justification.from_model_output("t", ["cuarenta y dos"])

    def test_rejects_line_zero(self):
        with pytest.raises(ValueError, match="desde 1"):
            Justification(text="t", cited_lines=frozenset({0}))
