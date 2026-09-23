"""Vuelve a recuperar el contexto de los hallazgos que ya tienen veredicto.

La corrida principal dejó los veredictos y sus líneas citadas, pero la tabla de
contextos quedó vacía. Sin el fragmento, la pantalla de auditoría no puede
mostrar el código al que la justificación se refiere, y la reauditoría del
anclaje tampoco puede aplicarse a ese lote.

La recuperación es sintáctica y determinista: lee el archivo Java del corpus,
recorta la función que contiene la alerta y sus llamadores, y no consulta al
modelo. Por eso regenerarla no cuesta nada y produce el mismo fragmento que se
le entregó en su momento, siempre que el corpus y los parámetros de recorte no
hayan cambiado.

Esa igualdad no se supone, se comprueba: para cada contexto regenerado se
contrasta que las líneas que el veredicto cita caigan dentro. Un contexto que
no las cubra indicaría que el corpus cambió, y el guion lo informa y no lo
guarda, en lugar de dejar pasar un fragmento que no es el que se juzgó.

    py tools/rebuild_contexts.py --dry-run
    py tools/rebuild_contexts.py
"""

import argparse
import ast
import asyncio
import sys
from collections import Counter
from pathlib import Path
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import text  # noqa: E402

from src.finding_validation.domain.entities.finding import Finding  # noqa: E402
from src.finding_validation.domain.value_objects.code_location import (  # noqa: E402
    CodeLocation,
)
from src.finding_validation.domain.value_objects.fingerprint import (  # noqa: E402
    Fingerprint,
)
from src.finding_validation.infrastructure.persistence.sql_repositories import (  # noqa: E402
    SqlCodeContextRepository,
)
from src.shared.composition import Container  # noqa: E402
from src.shared.config import get_settings  # noqa: E402

PENDING = text(
    """
    select f.id, f.rule_id, f.cwe, f.rule_severity, f.file_path,
           f.start_line, f.end_line, f.message, f.fingerprint, f.known_truth
      from findings f
     where exists (select 1 from verdicts v where v.finding_id = f.id)
       and not exists (select 1 from code_contexts c where c.finding_id = f.id)
     order by f.file_path, f.start_line
    """
)

CITED_LINES = text("select cited_lines from verdicts where finding_id = :fid")

ORPHAN_VERDICTS = text(
    """
    select count(*) from verdicts v
     where not exists (select 1 from code_contexts c
                        where c.finding_id = v.finding_id)
    """
)

CONTEXT_COUNT = text("select count(*) from code_contexts")


def build_finding(row) -> Finding:
    return Finding(
        id=UUID(row.id),
        rule_id=row.rule_id,
        severity=row.rule_severity,
        location=CodeLocation(row.file_path, row.start_line, row.end_line),
        fingerprint=Fingerprint(row.fingerprint),
        cwe=row.cwe,
        message=row.message or "",
        known_truth=None if row.known_truth is None else bool(row.known_truth),
    )


async def main(args) -> int:
    settings = get_settings()
    container = Container(settings)
    root = Path(settings.repository_root)
    print(f"base:    {settings.database_url}")
    print(f"corpus:  {root}")
    print(f"recorte: {settings.max_context_lines} líneas como máximo, "
          f"profundidad de llamados {settings.callee_depth}")
    print("SIMULACRO: no se escribe nada\n" if args.dry_run else "")

    tally: Counter = Counter()
    outside: list[tuple[str, list[int]]] = []

    async with container.sessions() as session:
        rows = (await session.execute(PENDING)).all()
        if args.limit:
            rows = rows[: args.limit]
        print(f"hallazgos con veredicto y sin contexto: {len(rows)}\n")
        if not rows:
            print("nada que hacer")
            return 0

        contexts = SqlCodeContextRepository(session)

        for position, row in enumerate(rows, start=1):
            if not (root / row.file_path).is_file():
                tally["archivo ausente del corpus"] += 1
                continue
            try:
                finding = build_finding(row)
            except ValueError as exc:
                tally[f"hallazgo inválido: {exc}"] += 1
                continue

            try:
                context = await container.code_reader.recover_context(finding)
            except Exception as exc:  # noqa: BLE001 - el adaptador define sus fallos
                tally[f"falla de recuperación: {type(exc).__name__}"] += 1
                continue

            available = set(context.available_lines)
            cited: set[int] = set()
            for (raw,) in (await session.execute(CITED_LINES,
                                                 {"fid": row.id})).all():
                if raw:
                    cited |= set(ast.literal_eval(raw))
            if cited and not cited <= available:
                outside.append((row.file_path, sorted(cited - available)))
                tally["anclaje fuera del contexto, NO guardado"] += 1
                continue

            tally["recuperado"] += 1
            if context.degraded_to_file:
                tally["degradado a archivo"] += 1
            if not args.dry_run:
                await contexts.save(context)
            if position % 100 == 0:
                print(f"  ...{position} de {len(rows)}")

    print()
    for label, count in tally.most_common():
        print(f"  {label:<40} {count:>5}")

    if outside:
        print(f"\n  AVISO: {len(outside)} contexto(s) no cubren las líneas "
              f"citadas.")
        print("  El corpus o los parámetros de recorte cambiaron desde la "
              "corrida.")
        for path, lines in outside[:10]:
            print(f"    {path}: {lines[:10]}")

    if args.dry_run:
        return 0

    async with container.sessions() as session:
        stored = (await session.execute(CONTEXT_COUNT)).scalar_one()
        orphans = (await session.execute(ORPHAN_VERDICTS)).scalar_one()
    print("\nverificación:")
    print(f"  filas en code_contexts:              {stored}")
    print(f"  veredictos que siguen sin contexto:  {orphans}")
    return 1 if outside else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true",
                        help="recupera y comprueba, pero no escribe en la base")
    parser.add_argument("--limit", type=int, default=0,
                        help="procesa solo los primeros N, para probar")
    return parser


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(asyncio.run(main(build_parser().parse_args())))
