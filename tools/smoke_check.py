"""Comprobación rápida del dominio, solo con biblioteca estándar.

Existe porque la suite de pytest necesita dependencias que no siempre se pueden
instalar. Esto no reemplaza a `pytest tests/`: verifica que las invariantes del
dominio se sostienen, para poder ejecutar algo el mismo día que se escribe.

    py tools/smoke_check.py
"""

import sys
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.finding_validation.domain.entities.code_context import CodeContext
from src.finding_validation.domain.entities.finding import Finding
from src.finding_validation.domain.entities.verdict import Verdict, VerdictValue
from src.finding_validation.domain.services.anchor_verifier import AnchorVerifier
from src.finding_validation.domain.value_objects.code_location import CodeLocation
from src.finding_validation.domain.value_objects.fingerprint import Fingerprint
from src.finding_validation.domain.value_objects.justification import Justification

RULE = "java.lang.security.audit.sqli.jdbc-sqli"
FILE = "src/main/java/com/acme/UserDao.java"
BODY = """
    public User find(String id) {
        String q = "SELECT * FROM users WHERE id = " + id;
        return jdbc.queryForObject(q, User.class);
    }
"""

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


print("\nHUELLA")
base = Fingerprint.compute(RULE, FILE, BODY)
reindented = "\n".join("        " + ln.strip() for ln in BODY.splitlines())
documented = BODY.replace("public User", "// busca\n    public User")
check("sobrevive a reindentar", base == Fingerprint.compute(RULE, FILE, reindented))
check("sobrevive a comentar", base == Fingerprint.compute(RULE, FILE, documented))
check(
    "normaliza separador de ruta",
    base == Fingerprint.compute(RULE, FILE.replace("/", "\\"), BODY),
)
check(
    "distingue otra regla",
    base != Fingerprint.compute("java.lang.security.audit.xss", FILE, BODY),
)
check(
    "distingue cuerpo saneado",
    base != Fingerprint.compute(RULE, FILE, BODY.replace("+ id;", "+ escape(id);")),
)
check("prefijo corto de 12", len(base.short) == 12)
raises("rechaza regla vacía", ValueError, lambda: Fingerprint.compute("", FILE, BODY))

print("\nUBICACION")
loc = CodeLocation(FILE, 40, 52)
check("cubre 13 líneas", loc.height == 13)
check("incluye los extremos", 40 in loc.lines and 52 in loc.lines)
raises("rechaza línea 0", ValueError, lambda: CodeLocation(FILE, 0, 5))
raises("rechaza rango invertido", ValueError, lambda: CodeLocation(FILE, 9, 2))

print("\nVERIFICACION DE ANCLAJE")
verifier = AnchorVerifier()
ctx = CodeContext(
    finding_id=uuid4(),
    enclosing_function="find",
    text="\n".join(f"linea {n}" for n in range(40, 53)),
    available_lines=frozenset(range(40, 53)),
)

ok = verifier.verify(Justification.from_model_output("dentro", [42, 45]), ctx)
check("acepta líneas presentes", ok.verified)

borde = verifier.verify(Justification.from_model_output("bordes", [40, 52]), ctx)
check("acepta los extremos exactos", borde.verified)

repetida = verifier.verify(Justification.from_model_output("repite", [42, 42]), ctx)
check("colapsa la cita repetida", repetida.cited_lines == frozenset({42}))

fuera = verifier.verify(Justification.from_model_output("se valida en 91", [91]), ctx)
check("rechaza línea inexistente", fuera.failed)
check("nombra la línea faltante", fuera.missing_lines == frozenset({91}))
check("la pista de reintento cita el 91", "91" in fuera.as_retry_hint())

parcial = verifier.verify(Justification.from_model_output("mixto", [42, 91]), ctx)
check("una sola línea ausente hace fallar todo", parcial.failed)

vacia = verifier.verify(Justification.from_model_output("confía en mí", []), ctx)
check("rechaza justificación sin líneas", vacia.failed)

check(
    "el descarte se anula al agotar el reintento",
    verifier.resolve_value(VerdictValue.NOT_EXPLOITABLE, fuera, attempts=2)
    is VerdictValue.NOT_VERIFIABLE,
)
check(
    "el primer fallo conserva el valor para reintentar",
    verifier.resolve_value(VerdictValue.NOT_EXPLOITABLE, fuera, attempts=1)
    is VerdictValue.NOT_EXPLOITABLE,
)
check(
    "el anclaje verificado conserva el valor propuesto",
    verifier.resolve_value(VerdictValue.EXPLOITABLE, ok, attempts=1)
    is VerdictValue.EXPLOITABLE,
)
raises(
    "el anclaje verificado no da pista de reintento", ValueError, ok.as_retry_hint
)

print("\nENTIDADES")
f1 = Finding(rule_id=RULE, severity="ERROR", location=loc, fingerprint=base, cwe="CWE-89")
f2 = Finding(
    rule_id=RULE,
    severity="ERROR",
    location=CodeLocation(FILE, 70, 82),
    fingerprint=base,
)
check("el hallazgo desplazado sigue siendo el mismo", f1.is_same_as(f2))
check("sin etiqueta no hay verdad conocida", not f1.has_known_truth)

v = Verdict(
    finding_id=f1.id,
    model="modelo-medio",
    model_version="2026-08-01",
    value=VerdictValue.EXPLOITABLE,
    justification=Justification.from_model_output("el dato llega sin sanear", [42]),
    anchor_verified=True,
)
check("la versión entra en la clave de condición", v.condition_key[2] == "2026-08-01")
check("un intento no es reintento", not v.needed_retry)
raises(
    "rechaza tres intentos",
    ValueError,
    lambda: Verdict(
        finding_id=f1.id,
        model="m",
        model_version="v",
        value=VerdictValue.EXPLOITABLE,
        justification=Justification.from_model_output("t", [42]),
        anchor_verified=True,
        attempts=3,
    ),
)
raises(
    "rechaza confianza fuera de rango",
    ValueError,
    lambda: Verdict(
        finding_id=f1.id,
        model="m",
        model_version="v",
        value=VerdictValue.EXPLOITABLE,
        justification=Justification.from_model_output("t", [42]),
        anchor_verified=True,
        confidence=1.4,
    ),
)

print(f"\n{'-' * 52}")
if failed:
    print(f"{passed} comprobaciones pasaron, {len(failed)} fallaron:")
    for name in failed:
        print(f"  - {name}")
    sys.exit(1)
print(f"{passed} comprobaciones pasaron.")
