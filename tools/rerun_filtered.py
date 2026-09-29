"""Consulta al modelo las alertas que el filtro determinista había resuelto.

El filtro resolvía sin consultar cuando reconocía un saneador antes del punto
sensible. Sobre el lote de la prueba de concepto resolvió ocho alertas de cien
y las ocho eran vulnerabilidades reales, de modo que la etapa se retiró de la
cadena. Lo que queda por hacer es medir la cadena sin ella, y para eso hay que
preguntarle al modelo justo por esas ocho.

La comparación se sostiene porque no se recupera nada de nuevo: el contexto de
cada una está guardado desde la corrida original, así que el modelo recibe el
mismo texto que habría recibido entonces, con la misma versión de consulta y a
temperatura cero. Lo único que cambia es la fecha, y eso se declara en el
archivo de salida, porque el proveedor puede cambiar el modelo sin cambiarle el
nombre.

Cuesta lo que cuestan las consultas que emite y ni una más: el tope del guardia
de presupuesto se fija en el número exacto de consultas previstas, contando el
reintento que el anclaje puede pedir.

    py tools/rerun_filtered.py --dry-run
    py tools/rerun_filtered.py
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))

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
)
from src.shared.composition import Container  # noqa: E402
from src.shared.config import get_settings  # noqa: E402
from src.shared.tracing import correlate  # noqa: E402

EJECUCION = UUID("75aa891c-4e35-4ca8-84bf-7153fd3a7d48")
MODELOS = ["anthropic/claude-opus-5", "google/gemini-3.8-flash", "qwen/qwen3.8-27b"]
REPETICIONES = 3
SALIDA = RAIZ.parent.parent / "spoc" / "verdicts_sin_filtro.csv"

# Los ocho que el filtro resolvió, tomados de la corrida original: son los del
# lote que no tienen veredicto de modelo alguno.
POR_REGLA = "regla-determinista"


class ContextoGuardado:
    """Lector que no lee: devuelve el contexto que la corrida ya guardó.

    Volver a extraerlo introduciría una diferencia que no se quiere medir. Lo
    que se mide es qué dice el modelo ante el mismo texto.
    """

    def __init__(self, contextos: dict[UUID, CodeContext]) -> None:
        self._contextos = contextos

    async def recover_context(self, finding: Finding, caller_depth: int = 2) -> CodeContext:
        return self._contextos[finding.id]

    @property
    def language(self) -> str:
        return "java"


async def filtradas(sesion) -> list[Finding]:
    """Los ocho del lote de la prueba de concepto, tomados de su propio archivo.

    Se leen de `spoc/verdicts.csv` y no de la base: ese archivo es el registro
    de la corrida que se está corrigiendo, y en él los ocho son exactamente los
    hallazgos cuyo único veredicto lo emitió la regla. Buscarlos por consulta
    sobre la ejecución entera traería los de las otras dos mil alertas, que no
    pertenecen al lote.
    """
    registro = RAIZ.parent.parent / "spoc" / "verdicts.csv"
    con_modelo: set[str] = set()
    por_regla: set[str] = set()
    with registro.open(encoding="utf-8", newline="") as fh:
        for fila in csv.DictReader(fh):
            destino = por_regla if fila["model"] == POR_REGLA else con_modelo
            destino.add(fila["finding_id"])
    ids = {UUID(x) for x in por_regla - con_modelo}

    todos = await SqlFindingRepository(sesion).list_by_execution(EJECUCION)
    elegidos = [f for f in todos if f.id in ids]
    if len(elegidos) != len(ids):
        raise SystemExit(
            f"ERROR: el lote declara {len(ids)} resueltos por regla y la base "
            f"tiene {len(elegidos)}"
        )
    return elegidos


async def principal() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dry-run", action="store_true", help="No consulta ni gasta.")
    p.add_argument("--modelo", action="append", help="Limita a estos modelos.")
    args = p.parse_args()

    settings = get_settings()
    container = Container(settings)
    modelos = args.modelo or MODELOS

    async with container.sessions() as s:
        hallazgos = await filtradas(s)
        repo_ctx = SqlCodeContextRepository(s)
        contextos: dict[UUID, CodeContext] = {}
        sin_contexto = []
        for f in hallazgos:
            ctx = await repo_ctx.get_by_finding(f.id)
            if ctx is None:
                sin_contexto.append(f)
            else:
                contextos[f.id] = ctx

    print(f"Hallazgos que resolvió el filtro: {len(hallazgos)}")
    for f in hallazgos:
        print(f"  {f.cwe or 'sin CWE':10s} {Path(f.location.file_path).name}:"
              f"{f.location.start_line}  verdad conocida: {f.known_truth}")
    if sin_contexto:
        print(f"ERROR: {len(sin_contexto)} sin contexto guardado; no se pueden "
              f"reconsultar sin volver a extraerlo", file=sys.stderr)
        return 2

    consultas = len(hallazgos) * len(modelos) * REPETICIONES
    print(f"\nModelos: {', '.join(modelos)}")
    print(f"Repeticiones: {REPETICIONES}")
    print(f"Consultas previstas: {consultas}, más el reintento que pida el anclaje")
    if args.dry_run:
        print("\nSIMULACRO: no se consultó nada")
        return 0

    # El tope deja sitio a un reintento por consulta y ni uno más.
    guardia = BudgetGuard(
        max_queries=consultas * 2,
        usd_per_1k_input=settings.usd_per_1k_input,
        usd_per_1k_output=settings.usd_per_1k_output,
    )

    filas: list[dict] = []
    inicio = datetime.now(timezone.utc)
    with correlate() as cid:
        print(f"\ncorrelación {cid}\n")
        for nombre in modelos:
            modelo = container.language_model_named(nombre)
            for repeticion in range(1, REPETICIONES + 1):
                for f in hallazgos:
                    servicio = ValidateFindingCommandService(
                        code_reader=ContextoGuardado(contextos),
                        language_model=modelo,
                        anchor_verifier=container.anchor_verifier,
                        prefilter=DeterministicPrefilter(),
                        budget=guardia,
                        prompt_version=container.prompt_version,
                    )
                    resultado = await servicio.execute(f, repetition=repeticion)
                    v = resultado.verdict
                    if v is None:
                        print(f"  {nombre} r{repeticion} {f.id.hex[:8]}: sin veredicto "
                              f"({resultado.error})")
                        continue
                    filas.append({
                        "finding_id": str(f.id),
                        "cwe": f.cwe or "",
                        "file_path": f.location.file_path,
                        "linea": f.location.start_line,
                        "known_truth": int(bool(f.known_truth)),
                        "model": nombre,
                        "model_version": v.model_version,
                        "repetition": repeticion,
                        "veredicto": v.value.value,
                        "confidence": v.confidence if v.confidence is not None else "",
                        "anchor_verified": int(v.anchor_verified),
                        "attempts": v.attempts,
                        "cited_lines": " ".join(str(n) for n in sorted(v.justification.cited_lines)),
                        "latency_ms": v.latency_ms or "",
                        "medido_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    })
                    print(f"  {nombre} r{repeticion} {Path(f.location.file_path).name}: "
                          f"{v.value.value}, anclaje {'sí' if v.anchor_verified else 'no'}, "
                          f"{v.attempts} intento(s)")

    # Se acumula en lugar de sobrescribir: los modelos pueden correrse por
    # separado, y perder lo de la corrida anterior obligaría a pagarla de nuevo.
    SALIDA.parent.mkdir(parents=True, exist_ok=True)
    previas: list[dict] = []
    if SALIDA.exists():
        with SALIDA.open(encoding="utf-8", newline="") as fh:
            previas = [r for r in csv.DictReader(fh) if r["model"] not in modelos]
    with SALIDA.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(filas[0].keys()))
        w.writeheader()
        w.writerows(previas + filas)
    print(f"({len(previas)} veredictos de corridas anteriores conservados)")

    minutos = (datetime.now(timezone.utc) - inicio).total_seconds() / 60
    print(f"\n{len(filas)} veredictos escritos en {SALIDA}")
    print(guardia.report())
    print(f"Duración: {minutos:.1f} minutos")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(principal()))
