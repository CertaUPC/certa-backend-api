"""El paquete que deja la prueba de concepto para que otro la repita.

Lo que se comprueba aquí no son los números de la corrida, sino que el paquete
contenga lo necesario para reconstruirla y que no contenga lo que nunca debe
salir de la máquina.
"""

import json
from dataclasses import dataclass
from uuid import uuid4

import pytest

from src.finding_validation.domain.entities.finding import Finding
from src.finding_validation.domain.value_objects.code_location import CodeLocation
from src.finding_validation.domain.value_objects.fingerprint import Fingerprint
from src.spoc_export import RunContext, batch_fingerprint, build_manifest, export

CLAVE = "sk-or-v1-clave-que-no-debe-salir-de-la-maquina"


@dataclass
class FakeExecution:
    id: object
    tool_name: str = "semgrep"
    ruleset_version: str = "1.90.0"


@dataclass
class FakeSettings:
    llm_base_url: str = "https://openrouter.ai/api/v1"
    llm_api_key: str = CLAVE
    llm_temperature: float = 0.0
    max_context_lines: int = 250
    caller_depth: int = 2
    callee_depth: int = 2


def hallazgo(nombre: str, verdad: bool | None) -> Finding:
    loc = CodeLocation(file_path=nombre, start_line=10, end_line=10)
    return Finding(
        rule_id="java.sqli", severity="error", location=loc,
        fingerprint=Fingerprint.compute("java.sqli", nombre, "cuerpo"),
        cwe="CWE-89", known_truth=verdad,
    )


@pytest.fixture
def contexto():
    findings = [hallazgo("A.java", True), hallazgo("B.java", True),
                hallazgo("C.java", False), hallazgo("D.java", None)]
    return RunContext(
        execution=FakeExecution(id=uuid4()),
        findings=findings,
        models=["anthropic/claude-opus-5", "qwen/qwen3.8-27b"],
        repetitions=3,
        batch_size=350,
        max_queries=1000,
        settings=FakeSettings(),
        prompt_version="v1",
    )


FILAS = [{"modelo": "m", "repeticion": 1, "consultas": 40, "usd": 1.5, "f1": 0.8}]


class TestBatchFingerprint:
    def test_order_does_not_change_it(self):
        a = [hallazgo("A.java", True), hallazgo("B.java", False)]
        assert batch_fingerprint(a) == batch_fingerprint(list(reversed(a)))

    def test_a_different_batch_gives_a_different_fingerprint(self):
        a = [hallazgo("A.java", True)]
        b = [hallazgo("B.java", True)]
        assert batch_fingerprint(a) != batch_fingerprint(b)


class TestManifest:
    def test_counts_what_the_corpus_affirms(self, contexto):
        m = build_manifest(contexto, FILAS, acuerdo=0.9)
        assert m["lote"]["hallazgos"] == 4
        assert m["lote"]["con_verdad_conocida"] == 3
        assert m["lote"]["vulnerabilidades_reales"] == 2
        assert m["lote"]["falsos_positivos_declarados"] == 1

    def test_records_the_conditions_of_the_run(self, contexto):
        m = build_manifest(contexto, FILAS, acuerdo=0.9)
        assert m["consulta"]["version_del_prompt"] == "v1"
        assert m["consulta"]["temperatura"] == 0.0
        assert m["analizador"]["version_de_reglas"] == "1.90.0"
        assert m["modelos"]["repeticiones"] == 3
        assert m["modelos"]["identificadores"] == [
            "anthropic/claude-opus-5", "qwen/qwen3.8-27b"]

    def test_keeps_the_host_and_drops_the_key(self, contexto):
        """El anfitrión hace falta para saber contra qué se midió. La clave no
        hace falta para nada y no puede salir de la máquina."""
        m = build_manifest(contexto, FILAS, acuerdo=0.9)
        assert m["modelos"]["anfitrion"] == "openrouter.ai"
        assert CLAVE not in json.dumps(m)

    def test_provider_without_url_is_said_plainly(self, contexto):
        contexto.settings.llm_base_url = ""
        m = build_manifest(contexto, FILAS, acuerdo=0.9)
        assert m["modelos"]["anfitrion"] == "no declarado"


class TestExport:
    def test_writes_the_three_files(self, contexto, tmp_path):
        destino = tmp_path / "spoc"
        escritos = export(destino, contexto, FILAS, [], acuerdo=0.9)
        assert {r.name for r in escritos} == {
            "scorecard.csv", "verdicts.csv", "manifest.json"}
        assert all(r.is_file() for r in escritos)

    def test_the_key_is_in_no_file(self, contexto, tmp_path):
        destino = tmp_path / "spoc"
        for ruta in export(destino, contexto, FILAS, [], acuerdo=0.9):
            assert CLAVE not in ruta.read_text(encoding="utf-8")

    def test_creates_the_folder_if_missing(self, contexto, tmp_path):
        destino = tmp_path / "aun" / "no" / "existe"
        export(destino, contexto, FILAS, [], acuerdo=0.9)
        assert destino.is_dir()

    def test_verdicts_from_outside_the_batch_are_left_out(self, contexto, tmp_path):
        """El detalle describe el lote, no todo lo que haya en la base.

        La ejecución acumula veredictos de corridas anteriores sobre otros
        hallazgos. Volcarlos aquí llenaría el archivo de filas sin regla ni
        categoría, y daría por resultado de esta corrida lo que se midió en
        otra, quizá con otra configuración.
        """
        from dataclasses import dataclass as dc
        from dataclasses import field as fld

        @dc
        class FakeJustification:
            cited_lines: tuple = (12,)

        @dc
        class FakeValue:
            value: str = "explotable"

        @dc
        class FakeVerdict:
            finding_id: object
            model: str = "m"
            model_version: str = "v"
            repetition: int = 1
            value: object = fld(default_factory=FakeValue)
            confidence: float = 0.9
            anchor_verified: bool = True
            attempts: int = 1
            justification: object = fld(default_factory=FakeJustification)
            was_reused: bool = False
            latency_ms: int = 30

        del_lote = FakeVerdict(finding_id=contexto.findings[0].id)
        ajeno = FakeVerdict(finding_id=uuid4())
        destino = tmp_path / "spoc"
        export(destino, contexto, FILAS, [del_lote, ajeno], acuerdo=0.9)
        filas = (destino / "verdicts.csv").read_text(encoding="utf-8").strip().splitlines()
        assert len(filas) == 2, "encabezado y un solo veredicto, el del lote"
        assert str(ajeno.finding_id) not in "\n".join(filas)

    def test_empty_verdicts_still_write_the_header(self, contexto, tmp_path):
        """Un archivo con solo encabezado se lee; uno vacío confunde."""
        destino = tmp_path / "spoc"
        export(destino, contexto, FILAS, [], acuerdo=0.9)
        detalle = (destino / "verdicts.csv").read_text(encoding="utf-8")
        assert detalle.startswith("finding_id,regla,cwe")
