"""Reconstruye el paquete de la corrida desde los veredictos guardados.

Cada veredicto se guarda en cuanto se obtiene, de modo que lo medido sobrevive a
que la corrida se caiga antes de imprimir el cuadro. Esto vuelve a armar el
cuadro, el detalle y el manifiesto sin consultar al proveedor y sin gastar nada.

    py tools/rebuild_scorecard.py <execution-id> --out-dir carpeta
"""

import argparse
import asyncio
import sys
from pathlib import Path
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.cli import (
    _aplicar_costo_real,
    _print_scorecard,
    _scorecard,
    muestra_estratificada,
)
from src.finding_validation.application.internal.commandservices.compare_models_command_service import (
    Comparison,
    ModelRun,
)
from src.finding_validation.infrastructure.persistence.sql_repositories import (
    SqlExecutionRepository,
    SqlFindingRepository,
    SqlVerdictRepository,
)
from src.shared.composition import Container
from src.shared.config import get_settings
from src.spoc_export import RunContext, export


def reconstruir(verdicts, del_lote: set) -> Comparison:
    """Arma las corridas a partir de los veredictos, una por modelo y repetición.

    Se descarta el filtro determinista: no consulta al modelo y mezclarlo con los
    veredictos de uno haría pasar por acierto suyo lo que resolvió una regla.
    """
    por_corrida: dict[tuple[str, str, int], ModelRun] = {}
    for v in verdicts:
        if v.finding_id not in del_lote or v.model.startswith("regla"):
            continue
        clave = (v.model, v.model_version, v.repetition)
        corrida = por_corrida.setdefault(
            clave,
            ModelRun(model=v.model, model_version=v.model_version,
                     repetition=v.repetition),
        )
        corrida.verdicts[v.finding_id] = v.value
        if v.anchor_verified and v.attempts == 1:
            corrida.anchored_first_try += 1
        if v.attempts > 1:
            corrida.retries += 1
        corrida.input_tokens += v.input_tokens or 0
        corrida.output_tokens += v.output_tokens or 0
        corrida.queries += v.attempts or 1
    return Comparison(
        execution_id=UUID(int=0),
        runs=sorted(por_corrida.values(), key=lambda r: (r.model, r.repetition)),
    )


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("execution_id")
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--seed", type=int, default=20260912)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()

    settings = get_settings()
    container = Container(settings)
    ejec = UUID(args.execution_id)
    async with container.sessions() as s:
        execution = await SqlExecutionRepository(s).get(ejec)
        todos = await SqlFindingRepository(s).list_by_execution(ejec)
        registrados = await SqlVerdictRepository(s).list_by_execution(ejec)
    await container.dispose()

    if execution is None:
        print("ERROR: no existe esa ejecución", file=sys.stderr)
        return 2

    findings = muestra_estratificada(todos, args.batch_size, args.seed)
    del_lote = {f.id for f in findings}
    comparacion = reconstruir(registrados, del_lote)
    comparacion.execution_id = ejec
    if not comparacion.runs:
        print("ERROR: no hay veredictos guardados para ese lote", file=sys.stderr)
        return 2

    verdad = {f.id: f.known_truth for f in findings if f.has_known_truth}
    filas = _scorecard(comparacion, verdad)
    modelos = sorted({r.model for r in comparacion.runs})
    del_lote_verdicts = [v for v in registrados if v.finding_id in del_lote]
    _aplicar_costo_real(filas, del_lote_verdicts, modelos, settings)
    _print_scorecard(filas, comparacion)

    contexto = RunContext(
        execution=execution,
        findings=findings,
        models=modelos,
        repetitions=max(r.repetition for r in comparacion.runs),
        batch_size=args.batch_size,
        max_queries=0,
        settings=settings,
        prompt_version=str(container.prompt_version),
    )
    escritos = export(Path(args.out_dir), contexto, filas,
                      del_lote_verdicts, comparacion.agreement())
    print("Paquete reconstruido:")
    for ruta in escritos:
        print(f"  {ruta}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
