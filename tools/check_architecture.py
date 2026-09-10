"""Verifica la regla de dependencia sin necesitar pytest.

Misma comprobación que tests/arquitectura/test_dependency_rule.py, ejecutable
con biblioteca estándar. No cuida el estilo: sostiene el argumento de la tesis.
El objetivo específico cuarto compara clases de modelo entre sí, y esa
comparación solo es válida si la lógica sometida a prueba permanece idéntica al
cambiar de proveedor. Si un módulo del dominio importara un adaptador concreto,
esa condición dejaría de cumplirse en silencio.

    py tools/check_architecture.py
"""

import ast
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
CONTEXTS = ("finding_validation", "experimentation")

FORBIDDEN_LAYERS = ("infrastructure", "interfaces", "application")
FORBIDDEN_LIBRARIES = {
    "fastapi",
    "sqlalchemy",
    "psycopg",
    "asyncpg",
    "httpx",
    "requests",
    "pydantic",
    "tree_sitter",
    "openai",
    "anthropic",
    "alembic",
}


def imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            found.add("." * node.level + (node.module or ""))
    return found


def domain_files() -> list[Path]:
    files: list[Path] = []
    for context in CONTEXTS:
        domain = SRC / context / "domain"
        if domain.exists():
            files.extend(p for p in domain.rglob("*.py") if p.stat().st_size > 0)
    return sorted(files)


def main() -> int:
    files = domain_files()
    if not files:
        print("FALLA  no se encontró ningún módulo de dominio que verificar")
        return 1

    violations: list[str] = []

    for path in files:
        relative = path.relative_to(SRC)
        for module in imported_modules(path):
            for layer in FORBIDDEN_LAYERS:
                if layer in module:
                    violations.append(
                        f"{relative} importa '{module}': el dominio no puede "
                        f"depender de la capa '{layer}'"
                    )
            root = module.lstrip(".").split(".")[0]
            if root in FORBIDDEN_LIBRARIES:
                violations.append(
                    f"{relative} importa '{module}': el dominio declara puertos, "
                    f"la tecnología concreta vive en infrastructure"
                )

    print(f"\nREGLA DE DEPENDENCIA  ({len(files)} módulos de dominio)")
    if violations:
        for v in violations:
            print(f"  FALLA {v}")
        print(f"\n{len(violations)} violaciones de la regla de dependencia.")
        return 1

    for path in files:
        print(f"  ok    {path.relative_to(SRC)}")
    print(f"\nLa dependencia va hacia adentro en los {len(files)} módulos.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
