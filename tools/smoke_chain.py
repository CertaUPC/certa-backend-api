"""Comprobación de la cadena completa, solo con biblioteca estándar.

Ejercita SARIF, recuperación de contexto sobre Java real, filtro determinista,
juicio del modelo, verificación de anclaje, reintento dirigido, reutilización
por huella, presupuesto y priorización.

    py tools/smoke_chain.py
"""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.finding_validation.application.internal.commandservices.validate_finding_command_service import (
    ValidateFindingCommandService,
)
from src.finding_validation.domain.entities.verdict import VerdictValue
from src.finding_validation.domain.services.anchor_verifier import AnchorVerifier
from src.finding_validation.domain.services.budget_guard import BudgetGuard
from src.finding_validation.domain.services.deterministic_prefilter import (
    DeterministicPrefilter,
)
from src.finding_validation.domain.services.priority_calculator import (
    PriorityCalculator,
)
from src.finding_validation.domain.value_objects.prompt_version import (
    OUTPUT_CONTRACT_V1,
    PromptVersion,
)
from src.finding_validation.domain.value_objects.scope_filter import ScopeFilter
from src.finding_validation.infrastructure.external import (
    java_source_scanner as scanner,
)
from src.finding_validation.infrastructure.external.java_code_reader import (
    JavaCodeReader,
)
from src.finding_validation.infrastructure.external.sarif_parser import (
    SarifError,
    parse_sarif,
)
from src.finding_validation.infrastructure.external.scripted_language_model import (
    ScriptedLanguageModel,
    exploitable,
    hallucinated_dismissal,
    not_exploitable,
)

passed = 0
failed: list[str] = []


def check(name: str, condition: bool) -> None:
    global passed
    if condition:
        passed += 1
        print(f"  ok    {name}")
    else:
        failed.append(name)
        print(f"  FALLA {name}")


def raises(name: str, exc: type[Exception], fn) -> None:
    try:
        fn()
    except exc:
        check(name, True)
    except Exception as e:  # noqa: BLE001
        check(f"{name} (esperaba {exc.__name__}, llegó {type(e).__name__})", False)
    else:
        check(f"{name} (no lanzó nada)", False)


JAVA = '''package com.acme.dao;

import java.sql.*;

public class UserDao {

    private final JdbcTemplate jdbc;

    public UserDao(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public User findUnsafe(String id) {
        String q = "SELECT * FROM users WHERE id = " + id;
        return jdbc.queryForObject(q, User.class);
    }

    public User findSafe(String id) {
        String clean = escapeSql(id);
        String q = "SELECT * FROM users WHERE id = " + clean;
        return jdbc.queryForObject(q, User.class);
    }

    public User handleRequest(String raw) {
        // El comentario menciona findUnsafe( pero no lo invoca de verdad
        return findUnsafe(raw);
    }
}
'''

SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "semgrep",
                    "semanticVersion": "1.95.0",
                    "rules": [
                        {
                            "id": "java.lang.security.audit.sqli.jdbc-sqli",
                            "properties": {"tags": ["security", "CWE-89"]},
                            "defaultConfiguration": {"level": "error"},
                        },
                        {
                            "id": "java.lang.security.audit.xss.reflected",
                            "properties": {"tags": ["CWE-79"]},
                            "defaultConfiguration": {"level": "warning"},
                        },
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "java.lang.security.audit.sqli.jdbc-sqli",
                    "message": {"text": "Consulta construida por concatenación"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "UserDao.java"},
                                "region": {
                                    "startLine": 14,
                                    "endLine": 14,
                                    "snippet": {"text": 'String q = "SELECT" + id;'},
                                },
                            }
                        }
                    ],
                },
                {
                    "ruleId": "java.lang.security.audit.sqli.jdbc-sqli",
                    "message": {"text": "Consulta construida por concatenación"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "UserDao.java"},
                                "region": {
                                    "startLine": 20,
                                    "endLine": 20,
                                    "snippet": {"text": 'String q = "SELECT" + clean;'},
                                },
                            }
                        }
                    ],
                },
                {
                    "ruleId": "java.lang.security.audit.xss.reflected",
                    "message": {"text": "Salida sin escapar"},
                    "level": "note",
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "UserDao.java"},
                                "region": {"startLine": 25, "endLine": 25},
                            }
                        }
                    ],
                },
                {"ruleId": "sin.ubicacion", "message": {"text": "no tiene locations"}},
            ],
        }
    ],
}


print("\nINGESTA SARIF")
ing = parse_sarif(SARIF)
check("ingiere los tres resultados con ubicación", ing.total == 3)
check("omite el resultado sin ubicación", len(ing.skipped) == 1)
check("captura la herramienta", ing.tool_name == "semgrep")
check("captura la versión de reglas", ing.ruleset_version == "1.95.0")
check("extrae CWE-89 de las etiquetas", ing.findings[0].cwe == "CWE-89")
check("extrae CWE-79 de las etiquetas", ing.findings[2].cwe == "CWE-79")
check("hereda la severidad de la regla", ing.findings[0].severity == "error")
check("el nivel del resultado gana a la regla", ing.findings[2].severity == "note")
check("no está vacía", not ing.is_empty)
raises("rechaza versión distinta", SarifError, lambda: parse_sarif({"version": "2.0.0"}))
raises("rechaza documento sin runs", SarifError, lambda: parse_sarif({"version": "2.1.0"}))

vacio = parse_sarif({"version": "2.1.0", "runs": []})
check("un análisis sin hallazgos no es un error", vacio.is_empty)

print("\nFILTRO DE ALCANCE")
todos = ScopeFilter.unrestricted()
check("sin criterios procesa todo", len(todos.apply(ing.findings)) == 3)
solo_sqli = ScopeFilter(cwes=frozenset({"CWE-89"}))
check("filtra por CWE", len(solo_sqli.apply(ing.findings)) == 2)
graves = ScopeFilter(min_severity="error")
check("filtra por severidad mínima", len(graves.apply(ing.findings)) == 2)
combinado = ScopeFilter(cwes=frozenset({"cwe-89"}), min_severity="warning")
check("normaliza el CWE a mayúsculas", combinado.cwes == frozenset({"CWE-89"}))
check("combina ambos criterios", len(combinado.apply(ing.findings)) == 2)
check("describe el alcance aplicado", "CWE-89" in combinado.describe())
sin_coincidencia = ScopeFilter(cwes=frozenset({"CWE-502"}))
check("un filtro sin coincidencias devuelve vacío", sin_coincidencia.apply(ing.findings) == [])
raises("rechaza severidad inventada", ValueError, lambda: ScopeFilter(min_severity="critico"))

print("\nRECORRIDO DE JAVA")
metodos = scanner.find_methods(JAVA)
nombres = {m.name for m in metodos}
check("localiza los métodos", {"findUnsafe", "findSafe", "handleRequest"} <= nombres)
unsafe = scanner.enclosing_method(JAVA, 14)
check("encuentra el método contenedor", unsafe is not None and unsafe.name == "findUnsafe")
check("el rango cubre la línea del hallazgo", unsafe.covers(14))
check("no cubre líneas de otro método", not unsafe.covers(20))
llamadores = scanner.find_callers(JAVA, "findUnsafe")
check("encuentra el llamador", [c.name for c in llamadores] == ["handleRequest"])
check("no se reporta a sí mismo", "findUnsafe" not in [c.name for c in llamadores])
safe = scanner.enclosing_method(JAVA, 20)
saneadores = scanner.find_sanitizers(safe.body)
check("detecta el saneador por nombre", "escapeSql" in saneadores)
check("no inventa saneadores donde no hay", scanner.find_sanitizers(unsafe.body) == [])

with_string_brace = 'void f() { String s = "}"; int x = 1; }'
check(
    "no se descuadra por una llave dentro de una cadena",
    len(scanner.find_methods(with_string_brace)) == 1,
)

print("\nCADENA COMPLETA")


async def run_chain():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "UserDao.java").write_text(JAVA, encoding="utf-8")
        reader = JavaCodeReader(repository_root=root)
        version = PromptVersion.of("v1", "Juzga el hallazgo...", OUTPUT_CONTRACT_V1)

        inseguro, seguro = ing.findings[0], ing.findings[1]

        # --- contexto -------------------------------------------------------
        ctx = await reader.recover_context(inseguro)
        check("el contexto nombra la función contenedora", ctx.enclosing_function == "findUnsafe")
        check("el contexto incluye el llamador", "handleRequest" in ctx.callers)
        check("el contexto cubre la línea del hallazgo", ctx.contains_line(14))
        check("el contexto no está degradado", not ctx.degraded_to_file)
        check("el texto lleva números de línea", "14:" in ctx.text)

        ctx_safe = await reader.recover_context(seguro)
        check("detecta el saneador en la función segura", ctx_safe.has_sanitizers)

        # --- filtro determinista -------------------------------------------
        prefilter = DeterministicPrefilter()
        d_ins = prefilter.decide(inseguro, ctx)
        check("sin saneador escala al modelo", d_ins.spends_budget)
        d_seg = prefilter.decide(seguro, ctx_safe)
        check("con saneador previo resuelve por regla", not d_seg.spends_budget)

        # --- anclaje verificado a la primera --------------------------------
        budget = BudgetGuard(max_queries=10, usd_per_1k_input=0.003, usd_per_1k_output=0.015)
        modelo = ScriptedLanguageModel([exploitable([14, 15])])
        servicio = ValidateFindingCommandService(
            reader, modelo, AnchorVerifier(), prefilter, budget, version
        )
        r1 = await servicio.execute(inseguro)
        check("emite veredicto", r1.succeeded)
        check("el veredicto es explotable", r1.verdict.value is VerdictValue.EXPLOITABLE)
        check("el anclaje quedó verificado", r1.verdict.anchor_verified)
        check("bastó un intento", r1.verdict.attempts == 1)
        check("consumió una consulta", budget.spent_queries == 1)

        # --- reutilización por huella ---------------------------------------
        r1b = await servicio.execute(inseguro)
        check("reutiliza por huella", r1b.verdict.was_reused)
        check("la reutilización no gasta consulta", budget.spent_queries == 1)
        check("la reutilización se contabiliza", budget.reused_queries == 1)

        # --- resuelto por regla, sin consultar -------------------------------
        r_seg = await servicio.execute(seguro)
        check("resuelve por regla sin consultar", r_seg.verdict.model == "regla-determinista")
        check("la regla no gasta consulta", budget.spent_queries == 1)
        check("cuenta la resolución por regla", budget.resolved_by_rule == 1)

        # --- alucinación y reintento dirigido --------------------------------
        budget2 = BudgetGuard(max_queries=10)
        modelo2 = ScriptedLanguageModel(
            [hallucinated_dismissal(91), not_exploitable([14, 15])]
        )
        servicio2 = ValidateFindingCommandService(
            reader, modelo2, AnchorVerifier(), prefilter, budget2, version
        )
        r2 = await servicio2.execute(inseguro)
        check("el reintento se disparó", modelo2.call_count == 2)
        check("la pista de reintento nombra la línea falsa", "91" in (modelo2.last_hint or ""))
        check("el segundo intento quedó anclado", r2.verdict.anchor_verified)
        check("registra que hicieron falta dos intentos", r2.verdict.attempts == 2)

        # --- alucinación persistente ------------------------------------------
        budget3 = BudgetGuard(max_queries=10)
        modelo3 = ScriptedLanguageModel(
            [hallucinated_dismissal(91), hallucinated_dismissal(95)]
        )
        servicio3 = ValidateFindingCommandService(
            reader, modelo3, AnchorVerifier(), prefilter, budget3, version
        )
        r3 = await servicio3.execute(inseguro)
        check(
            "el descarte insostenible pasa a no verificable",
            r3.verdict.value is VerdictValue.NOT_VERIFIABLE,
        )
        check("no hay tercer intento", modelo3.call_count == 2)

        # --- presupuesto agotado ------------------------------------------------
        budget4 = BudgetGuard(max_queries=1)
        modelo4 = ScriptedLanguageModel([hallucinated_dismissal(91)])
        servicio4 = ValidateFindingCommandService(
            reader, modelo4, AnchorVerifier(), prefilter, budget4, version
        )
        r4 = await servicio4.execute(inseguro)
        check("el límite detiene la cadena", r4.verdict is None)
        check("el límite explica la causa", "límite" in (r4.error or ""))

        # --- priorización -------------------------------------------------------
        calc = PriorityCalculator()
        orden = calc.rank([(inseguro, r1.verdict), (seguro, r_seg.verdict), (inseguro, r3.verdict)])
        check("ordena sin suprimir", len(orden) == 3)
        check("el explotable encabeza", orden[0][2].score >= orden[1][2].score)
        check("el no explotable queda al final", orden[-1][1].value is VerdictValue.NOT_EXPLOITABLE)
        no_verif = next(t for t in orden if t[1].value is VerdictValue.NOT_VERIFIABLE)
        no_expl = next(t for t in orden if t[1].value is VerdictValue.NOT_EXPLOITABLE)
        check(
            "el no verificable asciende sobre el no explotable",
            no_verif[2].score > no_expl[2].score,
        )
        check("la prioridad explica su razón", "revisión humana" in no_verif[2].reason)

        # --- presupuesto: estimación e informe -----------------------------------
        est = BudgetGuard(max_queries=3000, usd_per_1k_input=0.003, usd_per_1k_output=0.015).estimate(300, repetitions=3)
        check("estima 900 consultas para 300 hallazgos por 3", est.queries == 900)
        check("la estimación reporta dólares", est.usd > 0)
        check("el informe menciona lo evitado", "evitadas" in budget.report())


asyncio.run(run_chain())

print("\nVERSIONADO DE LA CONSULTA")
v1 = PromptVersion.of("v1", "Juzga el hallazgo...", OUTPUT_CONTRACT_V1)
v1b = PromptVersion.of("v1", "Juzga el hallazgo...", OUTPUT_CONTRACT_V1)
v2 = PromptVersion.of("v2", "Juzga el hallazgo con más contexto...", OUTPUT_CONTRACT_V1)
check("la misma consulta da la misma versión", v1.identifier == v1b.identifier)
check("cambiar la consulta cambia la versión", v1.identifier != v2.identifier)
otro_contrato = dict(OUTPUT_CONTRACT_V1, extra="str")
check(
    "cambiar el contrato cambia la versión",
    v1.identifier != PromptVersion.of("v1", "Juzga el hallazgo...", otro_contrato).identifier,
)
raises("rechaza consulta vacía", ValueError, lambda: PromptVersion.of("v1", "   ", OUTPUT_CONTRACT_V1))

print(f"\n{'-' * 52}")
if failed:
    print(f"{passed} comprobaciones pasaron, {len(failed)} fallaron:")
    for name in failed:
        print(f"  - {name}")
    sys.exit(1)
print(f"{passed} comprobaciones pasaron.")
