import pytest

from src.finding_validation.domain.entities.finding import Finding
from src.finding_validation.domain.value_objects.code_location import CodeLocation
from src.finding_validation.domain.value_objects.fingerprint import Fingerprint
from src.finding_validation.infrastructure.external.owasp_benchmark_ground_truth import (
    OwaspBenchmarkGroundTruth,
)
from src.finding_validation.infrastructure.external.sarif_parser import parse_sarif

CSV = """# test name, category, real vulnerability, cwe, Benchmark version: 1.2
BenchmarkTest00001,pathtraver,true,22
BenchmarkTest00002,pathtraver,false,22
BenchmarkTest00042,sqli,true,89
BenchmarkTest00077,cmdi,false,78
"""


def finding(path: str, cwe: str | None) -> Finding:
    location = CodeLocation(file_path=path, start_line=10, end_line=10)
    return Finding(
        rule_id="java.lang.security.audit",
        severity="error",
        location=location,
        fingerprint=Fingerprint.compute("java.lang.security.audit", path, "cuerpo"),
        cwe=cwe,
    )


@pytest.fixture
def expected(tmp_path):
    ruta = tmp_path / "expectedresults-1.2.csv"
    ruta.write_text(CSV, encoding="utf-8")
    return ruta


@pytest.fixture
def truth(expected):
    return OwaspBenchmarkGroundTruth(expected)


class TestLoading:
    def test_reads_every_case_and_skips_the_header(self, truth):
        assert len(truth) == 4

    def test_missing_file_says_where_to_point(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="GROUND_TRUTH_PATH"):
            OwaspBenchmarkGroundTruth(tmp_path / "no-existe.csv")

    def test_file_without_cases_is_rejected(self, tmp_path):
        ruta = tmp_path / "vacio.csv"
        ruta.write_text("# test name, category, real vulnerability, cwe\n", "utf-8")
        with pytest.raises(ValueError, match="ningún caso"):
            OwaspBenchmarkGroundTruth(ruta)


class TestLabelling:
    def test_real_vulnerability(self, truth):
        f = finding("src/main/java/org/owasp/BenchmarkTest00001.java", "CWE-22")
        assert truth.truth_for(f) is True

    def test_declared_false_positive(self, truth):
        f = finding("src/main/java/org/owasp/BenchmarkTest00002.java", "CWE-22")
        assert truth.truth_for(f) is False

    def test_path_separator_does_not_matter(self, truth):
        f = finding("src\\main\\java\\BenchmarkTest00042.java", "CWE-89")
        assert truth.truth_for(f) is True


class TestWhatTheCorpusDoesNotAffirm:
    """None no es lo mismo que falso positivo, y de esa distinción depende que
    la exactitud medida no salga inflada."""

    def test_other_category_on_the_same_file(self, truth):
        f = finding("BenchmarkTest00001.java", "CWE-89")
        assert truth.truth_for(f) is None

    def test_finding_without_cwe(self, truth):
        f = finding("BenchmarkTest00001.java", None)
        assert truth.truth_for(f) is None

    def test_file_outside_the_corpus(self, truth):
        f = finding("src/OrderDao.java", "CWE-89")
        assert truth.truth_for(f) is None


class TestRelatedCategories:
    def test_hql_injection_counts_as_sql_injection(self, truth):
        """El conjunto etiqueta 89 y algunos analizadores reportan 564."""
        f = finding("BenchmarkTest00042.java", "CWE-564")
        assert truth.truth_for(f) is True

    def test_command_injection_variant(self, truth):
        f = finding("BenchmarkTest00077.java", "CWE-77")
        assert truth.truth_for(f) is False

    def test_unrelated_numbers_stay_apart(self, truth):
        """330 y 22 no son parientes; darlos por equivalentes sería inventar."""
        f = finding("BenchmarkTest00001.java", "CWE-330")
        assert truth.truth_for(f) is None


class TestCweFromSarif:
    """El CWE viene unas veces en la regla y otras en el resultado. Si se
    pierde, el hallazgo queda fuera de toda medición contra verdad conocida."""

    @staticmethod
    def sarif(rule_properties, result_properties):
        return {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "semgrep",
                    "semanticVersion": "1.90.0",
                    "rules": [{"id": "java.sqli", "properties": rule_properties}],
                }},
                "results": [{
                    "ruleId": "java.sqli",
                    "level": "error",
                    "message": {"text": "Dato sin sanear"},
                    "properties": result_properties,
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "BenchmarkTest00042.java"},
                        "region": {"startLine": 12, "endLine": 12},
                    }}],
                }],
            }],
        }

    def test_tagged_on_the_rule(self, truth):
        f = parse_sarif(self.sarif({"tags": ["CWE-89: SQL Injection"]}, {})).findings[0]
        assert f.cwe == "CWE-89"
        assert truth.truth_for(f) is True

    def test_tagged_on_the_result(self, truth):
        f = parse_sarif(self.sarif({}, {"cwe": ["CWE-89"]})).findings[0]
        assert f.cwe == "CWE-89"
        assert truth.truth_for(f) is True
