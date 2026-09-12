"""Línea de comandos, para incorporar la validación a la entrega continua sin
abrir la aplicación. Códigos de salida pensados para un paso de integración:

    0  terminó y no quedó nada por encima del umbral indicado
    1  hay hallazgos que superan el umbral
    2  el análisis o la validación fallaron

    py -m src.cli analyze ./repo --project "Mi proyecto"
    py -m src.cli validate <execution-id>
    py -m src.cli check ./repo --fail-on real
    py -m src.cli compare <execution-id> --model a --model b --model c
"""

import argparse
import asyncio
import sys
from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy import select

import src.shared.database_experiment  # noqa: F401  registra sus tablas

from .experimentation.domain.services.metrics_calculator import MetricsCalculator
from .finding_validation.domain.entities.execution import Execution
from .finding_validation.domain.entities.verdict import VerdictValue
from .finding_validation.domain.value_objects.scope_filter import ScopeFilter
from .finding_validation.infrastructure.external.sarif_parser import (
    SarifError,
    parse_sarif_file,
)
from .finding_validation.infrastructure.external.semgrep_analyzer import (
    AnalysisFailed,
    AnalyzerUnavailable,
    SemgrepAnalyzer,
)
from .finding_validation.infrastructure.persistence.sql_repositories import (
    SqlExecutionRepository,
    SqlFindingRepository,
    SqlVerdictRepository,
)
from .shared.composition import Container
from .shared.config import get_settings
from .shared.database import Base, ProjectRow
from .shared.tracing import correlate, install_memory_sink
from .spoc_export import RunContext, export


async def _ensure_schema(container: Container) -> None:
    async with container.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def _project_id(container: Container, name: str, path: str) -> UUID:
    """Encuentra el proyecto por su ruta, o lo crea."""
    async with container.sessions() as s:
        row = (
            await s.execute(select(ProjectRow).where(ProjectRow.repository_path == path))
        ).scalar_one_or_none()
        if row:
            return UUID(row.id)
        pid = uuid4()
        s.add(ProjectRow(id=str(pid), name=name, repository_path=path))
        await s.commit()
        return pid


async def cmd_analyze(args: argparse.Namespace) -> int:
    settings = get_settings()
    container = Container(settings)
    await _ensure_schema(container)

    ruta = str(Path(args.path).resolve())

    if args.sarif:
        # El analizador ya corrió y su salida está en disco. Correrlo otra vez
        # sobre el corpus entero costaría minutos y podría no coincidir con la
        # salida que se archivó como evidencia.
        try:
            ingestion = parse_sarif_file(args.sarif)
        except (SarifError, OSError) as exc:
            print(f"ERROR: no se pudo leer {args.sarif}: {exc}", file=sys.stderr)
            return 2
        findings = ingestion.findings
        herramienta = ingestion.tool_name or "desconocida"
        version_reglas = ingestion.ruleset_version or "desconocida"
        print(f"Leído {args.sarif}: {len(findings)} hallazgos de {herramienta}")
    else:
        analyzer = SemgrepAnalyzer(config=args.config, timeout_seconds=args.timeout)
        herramienta = analyzer.tool_name
        version_reglas = analyzer.ruleset_version
        try:
            with correlate() as cid:
                print(f"Analizando {ruta}  (correlación {cid})")
                findings = await analyzer.analyze(ruta)
        except AnalyzerUnavailable as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        except AnalysisFailed as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2

    scope = ScopeFilter(
        cwes=frozenset(args.cwe or ()),
        min_severity=args.min_severity,
    )
    admitidos = scope.apply(findings)

    project_id = await _project_id(container, args.project or Path(ruta).name, ruta)

    async with container.sessions() as s:
        execution = Execution(
            project_id=project_id,
            tool_name=herramienta,
            ruleset_version=version_reglas,
            total_findings=len(admitidos),
            scope=scope,
        )
        etiquetados = 0
        if container.ground_truth is not None:
            for f in admitidos:
                verdad = container.ground_truth.truth_for(f)
                if verdad is not None:
                    f.known_truth = verdad
                    etiquetados += 1
        await SqlExecutionRepository(s).save(execution)
        if admitidos:
            await SqlFindingRepository(s).save_all(admitidos, execution.id)

    descartados = len(findings) - len(admitidos)
    print(f"Ejecución {execution.id}")
    print(f"  {len(admitidos)} hallazgos ingeridos", end="")
    print(f", {descartados} fuera del alcance" if descartados else "")
    if etiquetados:
        print(f"  {etiquetados} con verdad conocida del conjunto de referencia")
    elif container.ground_truth is not None:
        print("  AVISO: ninguno coincidió con el conjunto de referencia")
    if not admitidos:
        print("  El análisis no dejó nada que validar.")
    else:
        print(f"  Para validarlos:  py -m src.cli validate {execution.id}")

    await container.dispose()
    return 0


async def cmd_validate(args: argparse.Namespace) -> int:
    settings = get_settings()
    container = Container(settings)

    if not settings.llm_configured:
        print(
            "ERROR: no hay proveedor de modelo configurado. Define LLM_BASE_URL, "
            "LLM_API_KEY y LLM_MODEL en el entorno.",
            file=sys.stderr,
        )
        return 2

    async with container.sessions() as s:
        repo = SqlExecutionRepository(s)
        execution = await repo.get(UUID(args.execution_id))
        if execution is None:
            print("ERROR: no existe esa ejecución", file=sys.stderr)
            return 2

        budget = container.new_budget()
        runner = container.runner(s, budget)
        with correlate() as cid:
            print(f"Validando {execution.id}  (correlación {cid})")
            report = await runner.run(execution, args.batch_size, worker="cli")

    print(f"  {report.describe()}")
    print(f"  {budget.report()}")
    await container.dispose()
    return 0 if not report.interrupted else 2


async def cmd_compare(args: argparse.Namespace) -> int:
    """Corre el mismo lote con varias clases de modelo y las contrasta.

    Es la prueba de concepto del objetivo específico primero. Solo tiene sentido
    sobre una ejecución cuyos hallazgos traigan verdad conocida: sin etiqueta no
    hay contra qué medir la exactitud, y el resultado se quedaría en acuerdo
    entre modelos, que no dice cuál acierta.
    """
    settings = get_settings()
    container = Container(settings)

    async with container.sessions() as s:
        execution = await SqlExecutionRepository(s).get(UUID(args.execution_id))
        if execution is None:
            print("ERROR: no existe esa ejecución", file=sys.stderr)
            return 2

        findings = await SqlFindingRepository(s).list_by_execution(execution.id)
        if args.batch_size:
            findings = findings[: args.batch_size]
        etiquetados = [f for f in findings if f.has_known_truth]
        if not etiquetados:
            print(
                "ERROR: ninguno de los hallazgos trae verdad conocida. Vuelve a "
                "ingerir el lote con GROUND_TRUTH_PATH apuntando al conjunto de "
                "referencia.",
                file=sys.stderr,
            )
            return 2

        try:
            modelos = [container.language_model_named(m) for m in args.model]
        except RuntimeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2

        print(f"Lote de {len(findings)} hallazgos, {len(etiquetados)} con etiqueta")
        print(f"Modelos: {', '.join(args.model)}")
        print(f"Repeticiones por modelo: {args.repetitions}\n")

        with correlate() as cid:
            print(f"correlación {cid}")
            comparacion = await container.comparator(s).compare(
                execution,
                modelos,
                repetitions=args.repetitions,
                max_queries_per_model=args.max_queries,
                usd_per_1k_input=settings.usd_per_1k_input,
                usd_per_1k_output=settings.usd_per_1k_output,
                batch_size=args.batch_size,
            )

    verdad = {f.id: f.known_truth for f in findings if f.has_known_truth}
    filas = _scorecard(comparacion, verdad)
    _print_scorecard(filas, comparacion)

    if args.out_dir:
        async with container.sessions() as s:
            registrados = await SqlVerdictRepository(s).list_by_execution(execution.id)
        contexto = RunContext(
            execution=execution,
            findings=findings,
            models=args.model,
            repetitions=args.repetitions,
            batch_size=args.batch_size,
            max_queries=args.max_queries,
            settings=settings,
            prompt_version=str(container.prompt_version),
        )
        escritos = export(
            Path(args.out_dir), contexto, filas, registrados, comparacion.agreement()
        )
        print("Paquete de la corrida:")
        for ruta in escritos:
            print(f"  {ruta}")
        print()

    await container.dispose()
    return 0


def _scorecard(comparacion, verdad: dict) -> list[dict]:
    """Una fila por corrida, con su matriz de confusión frente a la etiqueta."""
    calculador = MetricsCalculator()
    filas = []
    for run in comparacion.runs:
        pares = [
            (verdad[fid], valor is VerdictValue.EXPLOITABLE)
            for fid, valor in run.verdicts.items()
            if fid in verdad
        ]
        matriz = calculador.confusion(pares)
        filas.append({
            "modelo": run.model,
            "repeticion": run.repetition,
            "veredictos": len(run.verdicts),
            "contrastados": len(pares),
            "anclaje_primera": round(run.anchor_rate, 4),
            "reintentos": run.retries,
            "no_verificables": run.not_verifiable,
            "consultas": run.queries,
            "usd": round(run.usd, 4),
            **matriz.report(),
        })
    return filas


def _print_scorecard(filas: list[dict], comparacion) -> None:
    print(f"\n{'modelo':<34} {'rep':>4} {'F1':>7} {'prec':>7} {'exh':>7} "
          f"{'anclaje':>8} {'USD':>8}")
    for f in filas:
        print(f"{f['modelo']:<34} {f['repeticion']:>4} {f['f1']:>7.3f} "
              f"{f['precision']:>7.3f} {f['exhaustividad']:>7.3f} "
              f"{f['anclaje_primera']:>8.3f} {f['usd']:>8.4f}")
    print(f"\nAcuerdo entre corridas: {comparacion.agreement():.4f}")
    print(f"Desacuerdos: {len(comparacion.disagreements())}")
    print(f"Costo total: {sum(f['usd'] for f in filas):.4f} USD\n")


async def cmd_check(args: argparse.Namespace) -> int:
    """Analiza, valida y decide si la entrega debe detenerse."""
    codigo = await cmd_analyze(args)
    if codigo != 0:
        return codigo

    settings = get_settings()
    container = Container(settings)
    async with container.sessions() as s:
        executions = await SqlExecutionRepository(s).list_by_project(
            await _project_id(container, args.project or "", str(Path(args.path).resolve()))
        )
        if not executions:
            print("No hay ejecuciones que revisar.")
            return 0
        ultima = executions[0]

        budget = container.new_budget()
        if settings.llm_configured:
            with correlate():
                await container.runner(s, budget).run(ultima, worker="cli")

        verdicts = await SqlVerdictRepository(s).list_by_execution(ultima.id)

    umbral = {
        "real": {VerdictValue.EXPLOITABLE},
        "revisar": {VerdictValue.EXPLOITABLE, VerdictValue.NOT_VERIFIABLE},
    }[args.fail_on]
    marcados = [v for v in verdicts if v.value in umbral]

    print(f"\n{len(marcados)} hallazgos superan el umbral '{args.fail_on}'")
    for v in marcados[:10]:
        print(f"  {v.value.value}  hallazgo {v.finding_id}")
    if len(marcados) > 10:
        print(f"  ... y {len(marcados) - 10} más")

    await container.dispose()
    return 1 if marcados else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="certa", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("path", help="Ruta del repositorio a analizar")
        sp.add_argument("--project", help="Nombre del proyecto")
        sp.add_argument("--config", default="p/security-audit", help="Conjunto de reglas")
        sp.add_argument("--cwe", action="append", help="Acotar a esta categoría, repetible")
        sp.add_argument(
            "--min-severity", choices=("error", "warning", "note"),
            help="Severidad mínima a procesar",
        )
        sp.add_argument("--timeout", type=int, default=900, help="Segundos máximos")

    a = sub.add_parser("analyze", help="Analiza un repositorio y crea la ejecución")
    common(a)
    a.add_argument("--sarif",
                   help="Ingiere un SARIF ya generado en lugar de correr el "
                        "analizador. Evita analizar dos veces el mismo corpus")

    v = sub.add_parser("validate", help="Valida los hallazgos pendientes")
    v.add_argument("execution_id")
    v.add_argument("--batch-size", type=int, default=None)

    m = sub.add_parser(
        "compare", help="Corre el lote con varias clases de modelo y las contrasta")
    m.add_argument("execution_id")
    m.add_argument("--model", action="append", required=True,
                   help="Identificador del modelo, repetible. Exige al menos dos")
    m.add_argument("--repetitions", type=int, default=1,
                   help="Corridas por modelo. Tres miden la estabilidad del veredicto")
    m.add_argument("--batch-size", type=int, default=None,
                   help="Acota el lote. Conviene fijarlo: el costo crece con él")
    m.add_argument("--max-queries", type=int, default=1000,
                   help="Tope de consultas por modelo, como red de seguridad")
    m.add_argument("--out-dir",
                   help="Carpeta donde dejar el paquete de la corrida: cuadro de "
                        "resultados, detalle por veredicto y manifiesto")

    c = sub.add_parser("check", help="Analiza, valida y falla si hay hallazgos")
    common(c)
    c.add_argument(
        "--fail-on", choices=("real", "revisar"), default="real",
        help="Qué hace fallar la entrega: solo lo explotable, o también lo no verificable",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    install_memory_sink()
    args = build_parser().parse_args(argv)
    handlers = {"analyze": cmd_analyze, "validate": cmd_validate,
                "compare": cmd_compare, "check": cmd_check}
    return asyncio.run(handlers[args.command](args))


if __name__ == "__main__":
    sys.exit(main())
