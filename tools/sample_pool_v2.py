"""Repregunta una muestra aleatoria del fondo elegible con la consulta vigente.

Para que exista. Arreglar el inventario del prompt cambio diez de los
veinticuatro veredictos del lote, y con ellos las dos propiedades que el lote
declara de antemano: los cuatro veredictos equivocados, uno de cada tipo por
mitad, y las ocho abstenciones repartidas. La regla 6 no exige ocho
abstenciones por si mismas: exige que la proporcion del lote espeje la del
fondo, que bajo v1 era del 35%. Esa proporcion bajo v2 hay que medirla, y se
mide con una muestra.

Que entrega. Tres cosas de una sola corrida: la tasa de abstencion del fondo
bajo v2, que es lo que justifica cuantas lleva el lote; la tasa de error y su
mezcla de tipos; y el inventario de candidatos de cada tipo con los que
reponer la regla 4 sin elegir ninguno a mano.

Que no entrega. La cifra de exactitud del objetivo primero, que pide el fondo
entero. Esta muestra la estima, no la sustituye.

La muestra es aleatoria con semilla declarada sobre el fondo ordenado por
huella, igual que el reparto del propio lote, de modo que repetir la orden
devuelve la misma muestra. Salta lo que ya este en la version vigente, asi que
se puede correr por tramos.

    venv\\Scripts\\python tools/sample_pool_v2.py --despliegue
    venv\\Scripts\\python tools/sample_pool_v2.py --despliegue --aplicar
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import os
import random
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(RAIZ / ".env")

from sqlalchemy import text  # noqa: E402

from src.finding_validation.application.internal.commandservices.validate_finding_command_service import (  # noqa: E402
    ValidateFindingCommandService,
)
from src.finding_validation.domain.entities.code_context import CodeContext  # noqa: E402
from src.finding_validation.domain.entities.finding import Finding  # noqa: E402
from src.finding_validation.domain.services.budget_guard import BudgetGuard  # noqa: E402
from src.finding_validation.domain.services.deterministic_prefilter import (  # noqa: E402
    DeterministicPrefilter,
)
from src.finding_validation.infrastructure.persistence.sql_repositories import (  # noqa: E402
    SqlCodeContextRepository,
    SqlFindingRepository,
    SqlVerdictRepository,
)
from src.shared.composition import Container  # noqa: E402
from src.shared.config import get_settings  # noqa: E402

MODELO = "anthropic/claude-opus-5"
SEMILLA = 65  # La misma que declaro el manifiesto del lote.
EJECUCION = "75aa891c-4e35-4ca8-84bf-7153fd3a7d48"
SALIDA = RAIZ.parent.parent / "experimento" / "muestra_fondo_v2"

# El fondo elegible, con el mismo criterio que declara el manifiesto: verdad
# conocida, veredicto del modelo seleccionado en la ultima repeticion, anclaje
# verificado y contexto conservado.
FONDO = """
    SELECT f.id, f.fingerprint, f.known_truth, v.value AS v1,
           v.prompt_version,
           f.id IN (SELECT i.finding_id FROM worklist_items i
                      JOIN worklists w ON w.id = i.worklist_id
                     WHERE w.frozen_at IS NOT NULL) AS en_el_lote
      FROM findings f
      JOIN code_contexts c ON c.finding_id = f.id
      JOIN (SELECT DISTINCT ON (finding_id) finding_id, value, anchor_verified,
                   prompt_version
              FROM verdicts WHERE model = :modelo
              ORDER BY finding_id, repetition DESC, created_at DESC) v
        ON v.finding_id = f.id
     WHERE f.execution_id = :ejecucion
       AND f.known_truth IS NOT NULL
       AND v.anchor_verified
"""


class StoredContext:
    """Lector que no lee: entrega el contexto que ya estaba guardado.

    Volver a extraerlo introduciria una diferencia que no se quiere medir. Lo
    unico que cambia entre la respuesta vieja y la nueva es la consulta.
    """

    def __init__(self, ctx: CodeContext) -> None:
        self._ctx = ctx

    async def recover_context(self, finding: Finding, caller_depth: int = 2):
        return self._ctx

    @property
    def language(self) -> str:
        return "java"


def clasificar(valor: str, verdad: bool) -> str:
    if valor == "indeterminado":
        return "abstencion"
    if (valor == "explotable") == verdad:
        return "acierto"
    return "falsa_alarma" if valor == "explotable" else "vulnerabilidad_desestimada"


async def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--aplicar", action="store_true",
                   help="consulta y escribe; sin esto solo informa")
    p.add_argument("--despliegue", action="store_true")
    p.add_argument("--cuantos", type=int, default=100,
                   help="tamano de la muestra (por omision 100)")
    args = p.parse_args()

    if args.despliegue:
        url = os.environ.get("DATABASE_URL_DESPLIEGUE")
        if not url:
            print("falta DATABASE_URL_DESPLIEGUE")
            return 1
        os.environ["DATABASE_URL"] = url
        get_settings.cache_clear()

    settings = get_settings()
    container = Container(settings)
    version = str(container.prompt_version)
    print(f"consulta vigente: {version}")
    print(f"modelo: {MODELO}   semilla: {SEMILLA}\n")

    async with container.sessions() as s:
        filas = (
            await s.execute(
                text(FONDO), {"modelo": MODELO, "ejecucion": EJECUCION}
            )
        ).mappings().all()

    fondo = [f for f in filas if not f["en_el_lote"]]
    print(f"fondo elegible: {len(filas)} hallazgos, {len(fondo)} fuera del lote")

    # Orden por huella y muestreo con semilla: repetir la orden devuelve la
    # misma muestra, que es lo que permite declararla en lugar de defenderla.
    fondo.sort(key=lambda f: f["fingerprint"])
    rng = random.Random(SEMILLA)
    muestra = rng.sample(fondo, min(args.cuantos, len(fondo)))
    pendientes = [f for f in muestra if f["prompt_version"] != version]
    print(f"muestra: {len(muestra)}   ya en {version}: "
          f"{len(muestra) - len(pendientes)}   por preguntar: {len(pendientes)}")
    reales = sum(1 for f in muestra if f["known_truth"])
    print(f"  reparto de la muestra: {reales} reales, "
          f"{len(muestra) - reales} no reales")

    if not args.aplicar:
        print("\nSIMULACION: no se consulto nada ni se escribio nada.")
        return 0

    guardia = BudgetGuard(
        max_queries=len(pendientes) * 2,
        usd_per_1k_input=settings.usd_per_1k_input,
        usd_per_1k_output=settings.usd_per_1k_output,
    )
    modelo = container.language_model_named(MODELO)

    resultados: list[dict] = []
    inicio = datetime.now(timezone.utc)
    async with container.sessions() as s:
        repo_f = SqlFindingRepository(s)
        repo_c = SqlCodeContextRepository(s)
        repo_v = SqlVerdictRepository(s)
        for n, f in enumerate(pendientes, 1):
            hallazgo = await repo_f.get(UUID(f["id"]))
            ctx = await repo_c.get_by_finding(UUID(f["id"]))
            if hallazgo is None or ctx is None:
                print(f"  [{n}/{len(pendientes)}] {f['id'][:8]}: sin contexto")
                continue
            servicio = ValidateFindingCommandService(
                code_reader=StoredContext(ctx),
                language_model=modelo,
                anchor_verifier=container.anchor_verifier,
                prefilter=DeterministicPrefilter(),
                budget=guardia,
                prompt_version=container.prompt_version,
            )
            r = await servicio.execute(hallazgo, repetition=1)
            v = r.verdict
            caso = Path(hallazgo.location.file_path).stem
            if v is None:
                print(f"  [{n}/{len(pendientes)}] {caso}: sin veredicto "
                      f"({r.error})")
                continue
            await repo_v.save(v, prompt_version=version)
            verdad = bool(hallazgo.known_truth)
            clase = clasificar(v.value.value, verdad)
            resultados.append({
                "finding_id": str(hallazgo.id),
                "caso": caso,
                "cwe": hallazgo.cwe or "",
                "linea": hallazgo.location.start_line,
                "known_truth": int(verdad),
                "v1": f["v1"],
                "v2": v.value.value,
                "clase": clase,
                "confidence": v.confidence if v.confidence is not None else "",
                "anchor_verified": int(v.anchor_verified),
                "prompt_version": version,
            })
            print(f"  [{n}/{len(pendientes)}] {caso:20} {str(hallazgo.cwe):9} "
                  f"verdad={verdad!s:5} v1={str(f['v1']):14} "
                  f"v2={v.value.value:14} {clase}")

    print(f"\n{len(resultados)} respuestas nuevas")
    cuenta: dict[str, int] = {}
    for r in resultados:
        cuenta[r["clase"]] = cuenta.get(r["clase"], 0) + 1
    total = len(resultados) or 1
    print("\nlo que hace la herramienta sobre la muestra, bajo la consulta nueva")
    for clase in ("acierto", "abstencion", "falsa_alarma",
                  "vulnerabilidad_desestimada"):
        n = cuenta.get(clase, 0)
        print(f"  {clase:28} {n:>3} de {total}  {n / total:6.1%}")

    print("\ncandidatos para la regla 4, por tipo de error")
    for clase in ("falsa_alarma", "vulnerabilidad_desestimada"):
        suyos = [r for r in resultados if r["clase"] == clase]
        print(f"  {clase} ({len(suyos)}):")
        for r in suyos:
            print(f"     {r['caso']:20} {r['cwe']:9} verdad={r['known_truth']} "
                  f"dijo {r['v2']}")
            print(f"         {r['finding_id']}")

    SALIDA.mkdir(parents=True, exist_ok=True)
    destino = SALIDA / "muestra_v2.csv"
    if resultados:
        with destino.open("w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(resultados[0]))
            w.writeheader()
            w.writerows(resultados)
        print(f"\nregistro en {destino}")
    print(guardia.report())
    print(f"duracion: "
          f"{(datetime.now(timezone.utc) - inicio).total_seconds() / 60:.1f} min")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
