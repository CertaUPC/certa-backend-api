"""Línea de comandos, para incorporar la validación a la entrega continua sin
abrir la aplicación. Códigos de salida pensados para un paso de integración:

    0  terminó y no quedó nada por encima del umbral indicado
    1  hay hallazgos que superan el umbral
    2  el análisis o la validación fallaron

    py -m src.cli analyze ./repo --project "Mi proyecto"
    py -m src.cli validate <execution-id>
    py -m src.cli check ./repo --fail-on real
"""

import argparse
import asyncio
import sys
from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy import select

import src.shared.database_experiment  # noqa: F401  registra sus tablas

from .finding_validation.domain.entities.execution import Execution
from .finding_validation.domain.entities.verdict import VerdictValue
from .finding_validation.domain.value_objects.scope_filter import ScopeFilter
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
    analyzer = SemgrepAnalyzer(config=args.config, timeout_seconds=args.timeout)

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
            tool_name=analyzer.tool_name,
            ruleset_version=analyzer.ruleset_version,
            total_findings=len(admitidos),
            scope=scope,
        )
        await SqlExecutionRepository(s).save(execution)
        if admitidos:
            await SqlFindingRepository(s).save_all(admitidos, execution.id)

    descartados = len(findings) - len(admitidos)
    print(f"Ejecución {execution.id}")
    print(f"  {len(admitidos)} hallazgos ingeridos", end="")
    print(f", {descartados} fuera del alcance" if descartados else "")
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

    v = sub.add_parser("validate", help="Valida los hallazgos pendientes")
    v.add_argument("execution_id")
    v.add_argument("--batch-size", type=int, default=None)

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
    handlers = {"analyze": cmd_analyze, "validate": cmd_validate, "check": cmd_check}
    return asyncio.run(handlers[args.command](args))


if __name__ == "__main__":
    sys.exit(main())
