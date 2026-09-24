"""Elige y congela el lote de 24 hallazgos de las sesiones con participantes.

El 4.5 del protocolo exige que el lote quede fijado antes de reclutar, y el 4.2
que el número de veredictos equivocados se declare antes de medir. Este guion
produce las dos cosas: la lista de los 24 con su reparto, y un manifiesto con
los parámetros y una huella que permite comprobar después que nadie la cambió.

No consulta al modelo. Los veredictos ya existen: son los que la prueba de
concepto del primer objetivo produjo sobre el conjunto de referencia.

REGLAS DE SELECCIÓN, todas declaradas de antemano

1. Fondo elegible. Hallazgos con verdad conocida, veredicto del modelo
   seleccionado, anclaje verificado y contexto conservado. La verdad conocida
   ya incorpora la regla del 5.2: el conjunto solo etiqueta el hallazgo cuando
   la categoría del analizador coincide con la del caso de prueba.

2. Equilibrio entre clases. Doce casos reales y doce que no lo son. El fondo
   tiene 65% de reales, y con esa proporción quien respondiera siempre lo mismo
   alcanzaría 65% de exactitud sin juzgar nada. Al equilibrarlo, la respuesta
   constante queda en 50% y la exactitud vuelve a medir criterio.

3. Reparto por categoría. Los veinte hallazgos de veredicto correcto se
   muestrean con la misma función estratificada que el proyecto usó para el
   lote de la prueba de concepto, con semilla declarada, de modo que no salgan
   todos de la misma familia de debilidad.

4. Veredictos equivocados. Cuatro, dos por lote, y en cada lote uno de cada
   tipo de error: una falsa alarma, donde el sistema dijo explotable y el caso
   no lo es, y una vulnerabilidad desestimada, donde dijo no explotable y sí lo
   era. No se fabrican: son errores que el modelo cometió de verdad.

   Van dos por lote y no cuatro en uno porque el contrabalanceo hace que el
   lote A sea el asistido para la mitad de los participantes y el B para la
   otra mitad. Repartirlos desigualmente daría a una mitad más trampas que a la
   otra.

5. Reparto A y B. Lo hace la regla del propio sistema, que ordena por huella y
   alterna. La semilla es la más baja que produce un reparto conforme a las
   reglas 2, 4 y 6 en ambos lotes.

6. Abstenciones repartidas. Ocho de los veinticuatro son hallazgos sobre los
   que el modelo no se pronuncia, cuatro por lote. Ocho de veinticuatro es el
   33%, y en el fondo elegible las abstenciones son el 35%: el lote representa
   lo que la herramienta hace de verdad, y no una versión suya que siempre
   responde.

   Van cuatro por lote porque de eso depende sobre cuántas alertas recibe
   ayuda decisiva quien está en la condición asistida. Con seis en un lote y
   tres en el otro, la diferencia entre condiciones dependía de qué mitad te
   tocó asistida, y el contrabalanceo cruza mitad con condición, de modo que
   esa variación entraba entera en la medición.

   Las cuatro se reparten además por verdad conocida, dos de casos reales y
   dos de los que no lo son, para que la abstención no se concentre en una
   sola clase.

    py tools/freeze_session_batch.py --dry-run
    py tools/freeze_session_batch.py
"""

import argparse
import asyncio
import csv
import hashlib
import json
import random
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import text  # noqa: E402

from src.cli import muestra_estratificada  # noqa: E402
from src.finding_validation.application.internal.commandservices.prepare_session_command_service import (  # noqa: E402
    PrepareSessionCommandService,
)
from src.finding_validation.domain.entities.finding import Finding  # noqa: E402
from src.finding_validation.domain.value_objects.code_location import (  # noqa: E402
    CodeLocation,
)
from src.finding_validation.domain.value_objects.fingerprint import (  # noqa: E402
    Fingerprint,
)
from src.shared.composition import Container  # noqa: E402
from src.shared.config import get_settings  # noqa: E402

BATCH_TOTAL = 24
PER_CONDITION = BATCH_TOTAL // 2
WRONG_PER_BATCH = 2

# Regla 6. Ocho abstenciones, cuatro por lote y dos de cada clase de verdad.
ABSTENTIONS_TOTAL = 8
ABSTENTIONS_PER_HALF = ABSTENTIONS_TOTAL // 2
ABSTENTIONS_PER_CLASS = ABSTENTIONS_TOTAL // 2
# Lo que sobra son veredictos acertados, mitad de cada clase.
CORRECT_PER_CLASS = (BATCH_TOTAL - WRONG_PER_BATCH * 2 - ABSTENTIONS_TOTAL) // 2

FALSE_ALARM = "falsa alarma"
DISMISSED = "vulnerabilidad desestimada"

# La repeticion mas alta, que es la que el servicio devuelve al pintar la
# alerta. Antes se congelaba sobre la repeticion 1 y se ensenaba la ultima, de
# modo que el lote quedaba declarado sobre veredictos que el participante no
# llegaba a ver.
ELIGIBLE = text(
    """
    select f.id, f.rule_id, f.cwe, f.rule_severity, f.file_path,
           f.start_line, f.end_line, f.message, f.fingerprint, f.known_truth,
           f.execution_id, v.value, v.confidence
      from findings f
      join (
          select finding_id, value, confidence, anchor_verified,
                 row_number() over (
                     partition by finding_id order by repetition desc
                 ) rn
            from verdicts
           where model_version = :model
      ) v on v.finding_id = f.id and v.rn = 1
     where f.known_truth is not null
       and v.anchor_verified = 1
       and exists (select 1 from code_contexts c where c.finding_id = f.id)
     order by f.file_path, f.start_line
    """
)


def build_finding(row) -> Finding:
    return Finding(
        id=UUID(row.id),
        rule_id=row.rule_id,
        severity=row.rule_severity,
        location=CodeLocation(row.file_path, row.start_line, row.end_line),
        fingerprint=Fingerprint(row.fingerprint),
        cwe=row.cwe,
        message=row.message or "",
        known_truth=bool(row.known_truth),
    )


def wrong_kind(row) -> str | None:
    """Tipo de error, o None si el veredicto no contradice la verdad.

    Una abstencion no contradice nada, de modo que tampoco es un error: es su
    propia clase, y la regla 6 le da cuota aparte.
    """
    if row.value == "explotable" and not row.known_truth:
        return FALSE_ALARM
    if row.value == "no_explotable" and row.known_truth:
        return DISMISSED
    return None


def abstains(row) -> bool:
    """El modelo analizo la alerta y no alcanzo a pronunciarse."""
    return row.value == "indeterminado"


def pick(rows, seed: int):
    """Los 24 de esta semilla, o None si no alcanzan los errores de cada tipo."""
    by_id = {row.id: row for row in rows}
    alarms = [r for r in rows if wrong_kind(r) == FALSE_ALARM]
    dismissed = [r for r in rows if wrong_kind(r) == DISMISSED]
    if len(alarms) < WRONG_PER_BATCH or len(dismissed) < WRONG_PER_BATCH:
        return None

    chance = random.Random(seed)
    wrong = (chance.sample(alarms, WRONG_PER_BATCH)
             + chance.sample(dismissed, WRONG_PER_BATCH))
    taken = {r.id for r in wrong}

    # Regla 6. Las abstenciones entran con cuota propia y repartidas por
    # verdad. Antes caian en el mismo saco que los aciertos, y el lote acababa
    # con seis en una mitad y tres en la otra.
    idle = [r for r in rows if r.id not in taken and abstains(r)]
    idle_real = [r for r in idle if r.known_truth]
    idle_not = [r for r in idle if not r.known_truth]
    if (len(idle_real) < ABSTENTIONS_PER_CLASS
            or len(idle_not) < ABSTENTIONS_PER_CLASS):
        return None
    abstentions = (
        muestra_estratificada([build_finding(r) for r in idle_real],
                              ABSTENTIONS_PER_CLASS, seed)
        + muestra_estratificada([build_finding(r) for r in idle_not],
                                ABSTENTIONS_PER_CLASS, seed))
    taken |= {str(f.id) for f in abstentions}

    # Lo que queda son veredictos acertados. Entre las tres cuotas salen doce
    # casos reales y doce que no lo son, que es la regla 2.
    correct = [r for r in rows
               if r.id not in taken and not wrong_kind(r) and not abstains(r)]
    real = [r for r in correct if r.known_truth]
    not_real = [r for r in correct if not r.known_truth]
    if len(real) < CORRECT_PER_CLASS or len(not_real) < CORRECT_PER_CLASS:
        return None

    sample = (muestra_estratificada([build_finding(r) for r in real],
                                    CORRECT_PER_CLASS, seed)
              + muestra_estratificada([build_finding(r) for r in not_real],
                                      CORRECT_PER_CLASS, seed))
    batch = (wrong
             + [by_id[str(f.id)] for f in abstentions]
             + [by_id[str(f.id)] for f in sample])
    return batch if len(batch) == BATCH_TOTAL else None


def complies(batch, plan) -> tuple[bool, str]:
    by_id = {row.id: row for row in batch}
    for name, ids in (("A", plan.batch_a), ("B", plan.batch_b)):
        half = [by_id[str(i)] for i in ids]
        if len(half) != PER_CONDITION:
            return False, f"el lote {name} tiene {len(half)} y no {PER_CONDITION}"
        real = sum(1 for r in half if r.known_truth)
        if real != PER_CONDITION // 2:
            return False, f"el lote {name} tiene {real} reales de {PER_CONDITION}"
        kinds = sorted(k for k in (wrong_kind(r) for r in half) if k)
        if kinds != [FALSE_ALARM, DISMISSED]:
            return False, f"el lote {name} tiene los errores {kinds}"
        # Regla 6, que es de lo que depende sobre cuantas alertas recibe ayuda
        # decisiva quien esta en la condicion asistida.
        idle = [r for r in half if abstains(r)]
        if len(idle) != ABSTENTIONS_PER_HALF:
            return False, (f"el lote {name} tiene {len(idle)} abstenciones "
                           f"y no {ABSTENTIONS_PER_HALF}")
        idle_real = sum(1 for r in idle if r.known_truth)
        if idle_real != ABSTENTIONS_PER_HALF // 2:
            return False, (f"el lote {name} tiene {idle_real} abstenciones "
                           f"sobre casos reales y no {ABSTENTIONS_PER_HALF // 2}")
    return True, "conforme"


async def main(args) -> int:
    settings = get_settings()
    container = Container(settings)
    root = Path(settings.repository_root)

    async with container.sessions() as session:
        rows = (await session.execute(ELIGIBLE, {"model": args.model})).all()

    print(f"modelo:  {args.model}")
    print(f"fondo elegible: {len(rows)} hallazgos")
    if len(rows) < BATCH_TOTAL:
        print("FALLA: el fondo no alcanza para el lote")
        return 1
    real = sum(1 for r in rows if r.known_truth)
    print(f"  reales {real}, no reales {len(rows) - real} "
          f"({real / len(rows):.1%} reales)")
    wrong = [r for r in rows if wrong_kind(r)]
    print(f"  con veredicto equivocado: {len(wrong)} "
          f"({sum(1 for r in wrong if wrong_kind(r) == FALSE_ALARM)} "
          f"falsas alarmas, "
          f"{sum(1 for r in wrong if wrong_kind(r) == DISMISSED)} "
          f"desestimadas)\n")

    batch = plan = chosen = None
    for seed in range(1, args.seeds + 1):
        candidate = pick(rows, seed)
        if candidate is None:
            continue
        proposal = PrepareSessionCommandService._split(
            [build_finding(r) for r in candidate]
        )
        ok, reason = complies(candidate, proposal)
        if ok:
            batch, plan, chosen = candidate, proposal, seed
            break
        if args.verbose:
            print(f"  semilla {seed}: {reason}")
    if batch is None:
        print(f"FALLA: ninguna semilla hasta {args.seeds} cumple las reglas")
        return 1

    print(f"semilla elegida: {chosen}\n")

    by_id = {row.id: row for row in batch}
    records = []
    for name, ids in (("A", plan.batch_a), ("B", plan.batch_b)):
        print(f"--- lote {name}")
        for i in ids:
            row = by_id[str(i)]
            kind = wrong_kind(row) or ""
            print(f"  {row.cwe:<8} "
                  f"verdad={'real ' if row.known_truth else 'no   '} "
                  f"veredicto={row.value:<14} "
                  f"{row.file_path.split('/')[-1]:<24} {kind}")
            records.append({
                "lote": name,
                "finding_id": row.id,
                "cwe": row.cwe,
                "regla": row.rule_id,
                "archivo": row.file_path,
                "linea": row.start_line,
                "huella": row.fingerprint,
                "verdad_conocida": int(bool(row.known_truth)),
                "veredicto_del_sistema": row.value,
                "confianza": row.confidence,
                "veredicto_equivocado": kind,
            })
        print()

    body = "".join(sorted(f"{r['lote']}|{r['huella']}\n" for r in records))
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()

    manifest = {
        "fecha_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "proposito": "Lote de las sesiones con participantes del objetivo "
                     "específico cuarto",
        "huella_del_lote": digest,
        "semilla": chosen,
        "fondo_elegible": {
            "hallazgos": len(rows),
            "criterio": "verdad conocida, veredicto del modelo seleccionado "
                        "en la última repetición, que es la que el servicio "
                        "devuelve al pintar la alerta, anclaje verificado y "
                        "contexto conservado",
            "abstenciones": sum(1 for r in rows if abstains(r)),
            "execution_id": sorted({r.execution_id for r in rows}),
        },
        "modelo": args.model,
        "lote": {
            "hallazgos": BATCH_TOTAL,
            "por_condicion": PER_CONDITION,
            "casos_reales": sum(1 for r in batch if r.known_truth),
            "casos_no_reales": sum(1 for r in batch if not r.known_truth),
            "abstenciones": sum(1 for r in batch if abstains(r)),
            "abstenciones_por_lote": ABSTENTIONS_PER_HALF,
            "ayuda_decisiva_por_lote": PER_CONDITION - ABSTENTIONS_PER_HALF,
            "veredictos_equivocados": sum(1 for r in batch if wrong_kind(r)),
            "veredictos_equivocados_por_lote": WRONG_PER_BATCH,
            "falsas_alarmas": sum(1 for r in batch
                                  if wrong_kind(r) == FALSE_ALARM),
            "vulnerabilidades_desestimadas": sum(1 for r in batch
                                                 if wrong_kind(r) == DISMISSED),
        },
        "denominador_de_la_variable_principal": {
            "condicion_asistida": PER_CONDITION - WRONG_PER_BATCH,
            "condicion_sin_asistencia": PER_CONDITION,
            "nota": "Los hallazgos de veredicto equivocado se excluyen del "
                    "cálculo de la exactitud, conforme al 4.2, y sostienen la "
                    "variable secundaria de seguimiento del veredicto "
                    "equivocado.",
        },
    }

    for name, ids in (("A", plan.batch_a), ("B", plan.batch_b)):
        half = [by_id[str(i)] for i in ids]
        decisivos = [r for r in half if not abstains(r)]
        aciertos = sum(1 for r in decisivos if not wrong_kind(r))
        print(f"lote {name}: se pronuncia en {len(decisivos)} de "
              f"{PER_CONDITION}, acierta {aciertos} de {len(decisivos)}")
    print()
    print(f"huella del lote: {digest}")
    print(f"reales {manifest['lote']['casos_reales']}, "
          f"no reales {manifest['lote']['casos_no_reales']}, "
          f"abstenciones {manifest['lote']['abstenciones']}, "
          f"equivocados {manifest['lote']['veredictos_equivocados']}")

    if args.dry_run:
        print("\nSIMULACRO: no se escribió nada")
        return 0

    destination = root / "experimento"
    destination.mkdir(exist_ok=True)
    batch_file = destination / "lote_sesion.csv"
    manifest_file = destination / "manifiesto_lote_sesion.json"

    with batch_file.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)
    manifest_file.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"\nescrito: {batch_file}")
    print(f"escrito: {manifest_file}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="anthropic/claude-opus-5")
    parser.add_argument("--seeds", type=int, default=500,
                        help="hasta qué semilla buscar un reparto conforme")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(asyncio.run(main(build_parser().parse_args())))
