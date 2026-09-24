"""Comprobación del contexto de experimentación y de los habilitadores técnicos.

    py tools/smoke_experiment.py
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from random import Random
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.experimentation.domain.entities.decision import Decision
from src.experimentation.domain.entities.participant import Participant
from src.experimentation.domain.services.counterbalancer import (
    ORDERS,
    Counterbalancer,
)
from src.experimentation.domain.services.metrics_calculator import MetricsCalculator
from src.experimentation.domain.services.semantic_preserving_transformer import (
    AdversarialResult,
    SemanticPreservingTransformer,
    TransformationType,
    incorrect_dismissal_rate,
)
from src.experimentation.domain.value_objects.condition import Condition, DecisionValue
from src.finding_validation.domain.services.retention_policy import (
    ExecutionRetentionState,
    RetentionPolicy,
)
from src.shared.rate_limiter import BackoffPolicy, RateLimiter

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


NOW = datetime(2026, 9, 10, tzinfo=timezone.utc)

print("\nPARTICIPANTES")
p = Participant(anonymous_code="P01", experience_band="de_1_a_3", consented_at=NOW)
check("acepta un participante válido", p.anonymous_code == "P01")
check("estratifica por experiencia", p.experience_band == "intermedio")
check("un año es inicial", Participant("P02", 1, NOW).experience_band == "inicial")
check("seis años es senior", Participant("P03", 6, NOW).experience_band == "senior")
raises(
    "excluye a quien tiene rol de seguridad",
    ValueError,
    lambda: Participant("P04", 5, NOW, has_security_role=True),
)
raises("rechaza código anónimo vacío", ValueError, lambda: Participant("  ", 3, NOW))
raises("rechaza experiencia negativa", ValueError, lambda: Participant("P05", -1, NOW))

print("\nDECISIONES")
fid, pid = uuid4(), p.id
d_ok = Decision(fid, pid, DecisionValue.CONFIRMED, 42.5, Condition.WITH_ASSISTANT)
check("acierta al confirmar un verdadero positivo", d_ok.is_correct_against(True) is True)
check("falla al confirmar un falso positivo", d_ok.is_correct_against(False) is False)
d_desc = Decision(fid, pid, DecisionValue.DISMISSED, 20.0, Condition.CONTROL)
check("acierta al descartar un falso positivo", d_desc.is_correct_against(False) is True)
d_dud = Decision(fid, pid, DecisionValue.DOUBTFUL, 30.0, Condition.CONTROL)
check("dudoso no cuenta como acierto ni error", d_dud.is_correct_against(True) is None)
check("sin verdad conocida no hay acierto", d_ok.is_correct_against(None) is None)
check("la decisión nace vigente", d_ok.is_current)
d_ok.supersede()
check("la rectificación se conserva, no se borra", not d_ok.is_current)
raises(
    "rechaza tiempo no positivo",
    ValueError,
    lambda: Decision(fid, pid, DecisionValue.CONFIRMED, 0.0, Condition.CONTROL),
)

print("\nCONDICIONES")
check("la condición con asistente muestra veredicto", Condition.WITH_ASSISTANT.shows_verdict)
check("el control lo oculta", not Condition.CONTROL.shows_verdict)
check("el control no reordena", not Condition.CONTROL.orders_by_priority)
check("la opuesta del control es con asistente", Condition.CONTROL.opposite is Condition.WITH_ASSISTANT)

print("\nCONTRABALANCEO")
cb = Counterbalancer()
historial: list[tuple[Condition, Condition]] = []
for _ in range(6):
    a = cb.assign(historial)
    historial.append(a.order)
check("reparte seis participantes de forma equilibrada", cb.is_balanced(historial, tolerance=0))
check("alterna el orden", historial[0] != historial[1])
check("es determinista", cb.assign([]).order == cb.assign([]).order)
a = cb.assign([])
check("asigna dos lotes distintos", a.first_batch != a.second_batch)
check("cada lote tiene su condición", a.condition_for(a.first_batch) is a.order[0])
raises("rechaza un lote ajeno", ValueError, lambda: a.condition_for("Z"))
raises("rechaza lotes iguales", ValueError, lambda: Counterbalancer(("A", "A")))
desequilibrado = [ORDERS[0]] * 5
check("detecta el desequilibrio", not Counterbalancer.is_balanced(desequilibrado, tolerance=1))

print("\nMETRICAS")
m = MetricsCalculator()
# 8 verdaderos positivos, 2 falsos positivos, 8 verdaderos negativos, 2 falsos negativos
pares = [(True, True)] * 8 + [(False, True)] * 2 + [(False, False)] * 8 + [(True, False)] * 2
cm = m.confusion(pares)
check("cuenta verdaderos positivos", cm.true_positives == 8)
check("cuenta falsos positivos", cm.false_positives == 2)
check("cuenta falsos negativos", cm.false_negatives == 2)
check("exactitud correcta", abs(cm.accuracy - 0.80) < 1e-9)
check("precisión correcta", abs(cm.precision - 0.80) < 1e-9)
check("exhaustividad correcta", abs(cm.recall - 0.80) < 1e-9)
check("F1 correcto", abs(cm.f1 - 0.80) < 1e-9)
check("tasa de falsos positivos correcta", abs(cm.false_positive_rate - 0.20) < 1e-9)
check("omite los hallazgos sin verdad conocida", m.confusion([(None, True)] * 5).total == 0)
check("el informe trae las nueve claves", len(cm.report()) == 9)

check("tasa de anclaje", abs(m.anchor_rate(87, 100) - 0.87) < 1e-9)
check("tasa de anclaje sin datos es cero", m.anchor_rate(0, 0) == 0.0)

degenerada = ["explotable"] * 95 + ["no_explotable"] * 5
q = m.assess_run(degenerada)
check("rechaza la corrida degenerada", not q.is_valid)
check("nombra la clase dominante", q.dominant_label == "explotable")
check("el motivo cita el umbral", "90%" in q.reason)
sana = ["explotable"] * 60 + ["no_explotable"] * 40
check("acepta una distribución admisible", m.assess_run(sana).is_valid)
check("una corrida vacía no es válida", not m.assess_run([]).is_valid)

r1 = ["explotable", "no_explotable", "explotable", "explotable"]
r2 = ["explotable", "no_explotable", "explotable", "no_explotable"]
r3 = ["explotable", "no_explotable", "explotable", "explotable"]
check("acuerdo entre tres ejecuciones", abs(m.agreement([r1, r2, r3]) - 0.75) < 1e-9)
check("acuerdo perfecto", m.agreement([r1, r1, r1]) == 1.0)
raises("exige al menos dos ejecuciones", ValueError, lambda: m.agreement([r1]))
raises("exige los mismos hallazgos", ValueError, lambda: m.agreement([r1, r1[:2]]))

print("\nTRANSFORMACIONES ADVERSARIALES")
JAVA = """public class Dao {
    public User find(String id) {
        String q = "SELECT * FROM users WHERE id = " + id;
        return jdbc.queryForObject(q, User.class);
    }
}
"""
t = SemanticPreservingTransformer()

ren = t.rename_to_sanitizer(JAVA, "id")
check("renombra la variable", "validatedInput" in ren.transformed)
check("la variable original desaparece", " id;" not in ren.transformed)
check("el tipo es el correcto", ren.type is TransformationType.RENAMED_SANITIZER)
raises("rechaza variable inexistente", ValueError, lambda: t.rename_to_sanitizer(JAVA, "zzz"))

com = t.add_validation_comment(JAVA, 3)
check("inserta el comentario", "ya fue validada" in com.transformed)
check("el archivo crece una línea", len(com.transformed.splitlines()) == len(JAVA.splitlines()) + 1)
check("conserva la sangría", "        // La entrada" in com.transformed)
raises("rechaza línea fuera del archivo", ValueError, lambda: t.add_validation_comment(JAVA, 99))

wrap = t.wrap_in_verifier(JAVA, "id")
check("envuelve la expresión", "ensureSafe(id)" in wrap.transformed)
check("añade la función envolvente", "private static String ensureSafe" in wrap.transformed)
check("la envolvente devuelve el valor sin tocarlo", "return value;" in wrap.transformed)
raises("rechaza expresión ausente", ValueError, lambda: t.wrap_in_verifier(JAVA, "zzz"))

todas = t.all_for(JAVA, "id", 3, "id")
check("genera las tres transformaciones", len(todas) == 3)
check("los tres tipos son distintos", len({x.type for x in todas}) == 3)
check("cada una declara su señal", all(x.signal for x in todas))

con_anclaje = [
    AdversarialResult(TransformationType.RENAMED_SANITIZER, True, "explotable", "explotable"),
    AdversarialResult(TransformationType.VALIDATION_COMMENT, True, "explotable", "explotable"),
    AdversarialResult(TransformationType.VERIFIER_WRAPPER, True, "explotable", "no_explotable"),
]
sin_anclaje = [
    AdversarialResult(TransformationType.RENAMED_SANITIZER, False, "explotable", "no_explotable"),
    AdversarialResult(TransformationType.VALIDATION_COMMENT, False, "explotable", "no_explotable"),
    AdversarialResult(TransformationType.VERIFIER_WRAPPER, False, "explotable", "explotable"),
]
tasa_con = incorrect_dismissal_rate(con_anclaje)
tasa_sin = incorrect_dismissal_rate(sin_anclaje)
check("mide la tasa con anclaje", abs(tasa_con - 1 / 3) < 1e-9)
check("mide la tasa sin anclaje", abs(tasa_sin - 2 / 3) < 1e-9)
check("el anclaje reduce la tasa", tasa_con < tasa_sin)
check("un lote vacío da tasa cero", incorrect_dismissal_rate([]) == 0.0)

print("\nCONTROL DE TASA Y RETROCESO")
b = BackoffPolicy(max_attempts=4, base_delay=1.0, jitter=0.0)
check("el primer intento no espera", b.delay_for(1) == 0.0)
check("el segundo espera la base", b.delay_for(2) == 1.0)
check("el tercero duplica", b.delay_for(3) == 2.0)
check("el cuarto vuelve a duplicar", b.delay_for(4) == 4.0)
check("se acota al máximo", BackoffPolicy(base_delay=1.0, max_delay=3.0, jitter=0.0).delay_for(9) == 3.0)
check("reintenta mientras quedan intentos", b.should_retry(3))
check("no reintenta al agotarlos", not b.should_retry(4))
disperso = BackoffPolicy(base_delay=10.0, jitter=0.25)
d = disperso.delay_for(2, rng=Random(7))
check("la dispersión mantiene el retraso en rango", 7.5 <= d <= 12.5)
raises("rechaza cero intentos", ValueError, lambda: BackoffPolicy(max_attempts=0))
raises("rechaza dispersión de 1", ValueError, lambda: BackoffPolicy(jitter=1.0))

rl = RateLimiter(queries_per_minute=3)
for i in range(3):
    check(f"hay cupo para la consulta {i + 1}", rl.wait_seconds(100.0 + i) == 0.0)
    rl.record(100.0 + i)
espera = rl.wait_seconds(103.0)
check("la cuarta consulta debe esperar", espera > 0)
check("la espera no excede la ventana", espera <= 60.0)
check("pasada la ventana vuelve a haber cupo", rl.wait_seconds(200.0) == 0.0)
raises("rechaza límite nulo", ValueError, lambda: RateLimiter(queries_per_minute=0))

print("\nRETENCION")
rp = RetentionPolicy(retention_days=30)
vieja = ExecutionRetentionState(NOW - timedelta(days=40), False, False)
check("purga la ejecución vencida", rp.decide(vieja, NOW).should_purge)
reciente = ExecutionRetentionState(NOW - timedelta(days=5), False, False)
check("conserva la reciente", not rp.decide(reciente, NOW).should_purge)
check("informa los días restantes", "días" in rp.decide(reciente, NOW).reason)
en_uso = ExecutionRetentionState(NOW - timedelta(days=40), False, True)
check("nunca purga una ejecución en uso", not rp.decide(en_uso, NOW).should_purge)
check("explica que está en uso", "en curso" in rp.decide(en_uso, NOW).reason)
abierta = ExecutionRetentionState(None, False, False)
check("conserva la ejecución abierta", not rp.decide(abierta, NOW).should_purge)
ya = ExecutionRetentionState(NOW - timedelta(days=40), True, False)
check("no repurga lo ya purgado", not rp.decide(ya, NOW).should_purge)
raises("rechaza ventana negativa", ValueError, lambda: RetentionPolicy(-1))

print(f"\n{'-' * 52}")
if failed:
    print(f"{passed} comprobaciones pasaron, {len(failed)} fallaron:")
    for name in failed:
        print(f"  - {name}")
    sys.exit(1)
print(f"{passed} comprobaciones pasaron.")
