"""Repone los veredictos del lote congelado con la consulta vigente.

Hace falta cuando la consulta cambia a mitad de estudio. La version v2 arreglo
el inventario del prompt, que declaraba los llamadores y no los llamados: el
cuerpo del metodo llamado viajaba en el codigo entregado y el inventario no lo
nombraba, de modo que el modelo declaraba ausente lo que tenia delante. Once de
los veinticuatro veredictos del lote se apoyaban en esa ausencia falsa.

Repone el mismo reparto y no uno nuevo. El lote no es uniforme: dieciseis
hallazgos llevan una sola consulta y cinco llevan entre tres y nueve, porque
sobre esos se midio la estabilidad entre modelos y repeticiones. La pantalla
del estudio ensena «se pregunto N veces igual y respondio X de N» en cuanto hay
mas de un veredicto, asi que reponer las mismas combinaciones de modelo y
repeticion es lo que deja la pantalla igual. Anadir los nuevos como repeticion
aparte le sacaria a dieciseis hallazgos un aviso de inestabilidad que la tanda
anterior no vio.

No recupera contexto. Usa el que cada hallazgo ya tiene guardado, de modo que
lo unico que cambia entre la corrida vieja y la nueva es la consulta. Volver a
extraerlo introduciria una diferencia que no se quiere medir.

Primero consulta todo y guarda al final. Si una consulta falla a mitad, los
veredictos anteriores siguen intactos y no queda un lote mezclado.

    venv\\Scripts\\python tools/regenerate_batch_verdicts.py
    venv\\Scripts\\python tools/regenerate_batch_verdicts.py --aplicar
    venv\\Scripts\\python tools/regenerate_batch_verdicts.py --aplicar --despliegue
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(RAIZ / ".env")

from sqlalchemy import delete, select  # noqa: E402

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
from src.experimentation.infrastructure.persistence.sql_repositories import (  # noqa: E402
    SqlBatchRepository,
)
from src.shared.composition import Container  # noqa: E402
from src.shared.config import get_settings  # noqa: E402
from src.shared.database import VerdictRow  # noqa: E402
from src.shared.tracing import correlate  # noqa: E402

SALIDA = RAIZ.parent.parent / "experimento" / "veredictos_prompt_v2"


class StoredContext:
    """Lector que no lee: devuelve el contexto que la corrida ya guardo."""

    def __init__(self, contexts: dict[UUID, CodeContext]) -> None:
        self._contexts = contexts

    async def recover_context(
        self, finding: Finding, caller_depth: int = 2
    ) -> CodeContext:
        return self._contexts[finding.id]

    @property
    def language(self) -> str:
        return "java"


async def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--aplicar", action="store_true",
                   help="consulta y escribe; sin esto solo informa")
    p.add_argument("--despliegue", action="store_true",
                   help="corre contra DATABASE_URL_DESPLIEGUE")
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
    print(f"consulta vigente: {version}\n")

    async with container.sessions() as s:
        lotes = SqlBatchRepository(s)
        lote = await lotes.frozen_id()
        if lote is None:
            print("no hay lote congelado")
            return 1
        ejecucion = await lotes.execution_id()
        ids: list[UUID] = []
        for mitad in sorted((await lotes.batches()).keys()):
            ids.extend(await lotes.finding_ids(mitad))
        print(f"lote {str(lote)[:8]} sobre la ejecucion {str(ejecucion)[:8]}, "
              f"{len(ids)} hallazgos")

        todos = await SqlFindingRepository(s).list_by_execution(ejecucion)
        hallazgos = {f.id: f for f in todos if f.id in set(ids)}
        if len(hallazgos) != len(ids):
            print(f"ERROR: el lote declara {len(ids)} hallazgos y la ejecucion "
                  f"tiene {len(hallazgos)}")
            return 2

        repo_ctx = SqlCodeContextRepository(s)
        contextos: dict[UUID, CodeContext] = {}
        for fid in ids:
            ctx = await repo_ctx.get_by_finding(fid)
            if ctx is None:
                print(f"ERROR: {fid} no tiene contexto guardado. Reponerlo "
                      f"exigiria volver a extraerlo, y eso cambiaria lo que "
                      f"se mide.")
                return 2
            contextos[fid] = ctx

        # Las combinaciones que ya existen, que son las que hay que reponer.
        filas = (
            await s.execute(
                select(
                    VerdictRow.finding_id,
                    VerdictRow.model,
                    VerdictRow.repetition,
                    VerdictRow.prompt_version,
                ).where(VerdictRow.finding_id.in_([str(i) for i in ids]))
            )
        ).all()

    combos = sorted({(f.finding_id, f.model, f.repetition) for f in filas})
    ya_en_version = sum(1 for f in filas if f.prompt_version == version)
    print(f"{len(combos)} consultas a reponer, de {len(filas)} veredictos")
    if ya_en_version:
        print(f"  {ya_en_version} ya estan en {version}; se repondran igual, "
              f"porque la corrida debe ser una sola")
    por_modelo: dict[str, int] = {}
    for _, modelo, _ in combos:
        por_modelo[modelo] = por_modelo.get(modelo, 0) + 1
    for modelo, n in sorted(por_modelo.items()):
        print(f"  {modelo:28} {n} consultas")

    if not args.aplicar:
        print("\nSIMULACION: no se consulto nada ni se escribio nada.")
        print("Repite con --aplicar para que surta efecto.")
        return 0

    guardia = BudgetGuard(
        max_queries=len(combos) * 2,
        usd_per_1k_input=settings.usd_per_1k_input,
        usd_per_1k_output=settings.usd_per_1k_output,
    )

    # Se consulta todo antes de escribir nada: una corrida que muera a mitad
    # dejaria el lote con unos veredictos de una consulta y otros de otra, y la
    # condicion con asistente deja de ser una sola cosa.
    obtenidos: list[tuple] = []
    fallos: list[tuple] = []
    inicio = datetime.now(timezone.utc)
    with correlate() as cid:
        print(f"\ncorrelacion {cid}\n")
        for fid, nombre, repeticion in combos:
            hallazgo = hallazgos[UUID(fid)]
            modelo = container.language_model_named(nombre)
            servicio = ValidateFindingCommandService(
                code_reader=StoredContext(contextos),
                language_model=modelo,
                anchor_verifier=container.anchor_verifier,
                prefilter=DeterministicPrefilter(),
                budget=guardia,
                prompt_version=container.prompt_version,
            )
            resultado = await servicio.execute(hallazgo, repetition=repeticion)
            v = resultado.verdict
            caso = Path(hallazgo.location.file_path).stem
            if v is None:
                fallos.append((caso, nombre, repeticion, resultado.error))
                print(f"  {caso:20} {nombre:26} r{repeticion}  SIN VEREDICTO "
                      f"({resultado.error})")
                continue
            obtenidos.append((hallazgo, v))
            print(f"  {caso:20} {nombre:26} r{repeticion}  "
                  f"{v.value.value:14} anclaje="
                  f"{'si' if v.anchor_verified else 'NO':3} "
                  f"intentos={v.attempts}")

    if fallos:
        print(f"\n{len(fallos)} consultas sin veredicto. No se escribe nada: "
              f"un lote a medias no es una condicion.")
        for caso, nombre, rep, err in fallos:
            print(f"  {caso} {nombre} r{rep}: {err}")
        return 3

    async with container.sessions() as s:
        repo = SqlVerdictRepository(s)
        for _, v in obtenidos:
            await repo.save(v, prompt_version=version)
        # El proveedor puede devolver otra `model_version` con el mismo nombre,
        # y entonces el reemplazo de `save` no alcanza al veredicto viejo y el
        # hallazgo se queda con dos. Lo que no lleva la version vigente sobra.
        sobrantes = await s.execute(
            delete(VerdictRow).where(
                VerdictRow.finding_id.in_([str(i) for i in ids]),
                VerdictRow.prompt_version.is_distinct_from(version),
            )
        )
        await s.commit()
    print(f"\n{len(obtenidos)} veredictos escritos con {version}")
    print(f"{sobrantes.rowcount or 0} veredictos de consultas anteriores "
          f"retirados del lote")

    SALIDA.mkdir(parents=True, exist_ok=True)
    destino = SALIDA / "veredictos_v2.csv"
    with destino.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["finding_id", "caso", "cwe", "linea", "known_truth",
                    "model", "model_version", "repetition", "veredicto",
                    "confidence", "anchor_verified", "attempts", "cited_lines",
                    "prompt_version", "medido_utc"])
        for f, v in obtenidos:
            w.writerow([
                str(f.id), Path(f.location.file_path).stem, f.cwe or "",
                f.location.start_line, int(bool(f.known_truth)), v.model,
                v.model_version, v.repetition, v.value.value,
                v.confidence if v.confidence is not None else "",
                int(v.anchor_verified), v.attempts,
                " ".join(str(n) for n in sorted(v.justification.cited_lines)),
                version,
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
            ])
    print(f"registro en {destino}")
    print(guardia.report())
    print(f"duracion: {(datetime.now(timezone.utc) - inicio).total_seconds() / 60:.1f} "
          f"minutos")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
