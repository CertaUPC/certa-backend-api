"""El dominio no importa nada de las capas exteriores.

Esta prueba no cuida el estilo: sostiene el argumento de la tesis. El objetivo
específico cuarto compara clases de modelo de lenguaje entre sí, y esa
comparación solo es válida si la lógica sometida a prueba permanece idéntica al
cambiar de proveedor. Si un módulo del dominio importara un adaptador concreto,
esa condición dejaría de cumplirse en silencio.
"""

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src"
CONTEXTS = ("finding_validation", "experimentation")

FORBIDDEN_IN_DOMAIN = ("infrastructure", "interfaces", "application")
FORBIDDEN_LIBRARIES = (
    "fastapi",
    "sqlalchemy",
    "psycopg",
    "httpx",
    "requests",
    "pydantic",
    "tree_sitter",
    "openai",
    "anthropic",
)


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            # level > 0 es import relativo; se reconstruye para poder inspeccionarlo
            found.add("." * node.level + (node.module or ""))
    return found


def _domain_files() -> list[Path]:
    files: list[Path] = []
    for context in CONTEXTS:
        domain = SRC / context / "domain"
        if domain.exists():
            files.extend(p for p in domain.rglob("*.py") if p.stat().st_size > 0)
    return files


@pytest.mark.parametrize("path", _domain_files(), ids=lambda p: p.name)
def test_domain_does_not_import_outer_layers(path):
    for module in _imported_modules(path):
        for forbidden in FORBIDDEN_IN_DOMAIN:
            assert forbidden not in module, (
                f"{path.relative_to(SRC)} importa '{module}'. El dominio no puede "
                f"depender de la capa '{forbidden}': la dependencia va hacia adentro."
            )


@pytest.mark.parametrize("path", _domain_files(), ids=lambda p: p.name)
def test_domain_does_not_import_concrete_technology(path):
    for module in _imported_modules(path):
        root = module.lstrip(".").split(".")[0]
        assert root not in FORBIDDEN_LIBRARIES, (
            f"{path.relative_to(SRC)} importa '{module}'. El dominio declara puertos; "
            f"la tecnología concreta vive en infrastructure."
        )


def test_domain_files_were_actually_found():
    """Guarda contra un falso verde si la ruta cambia y no se recorre nada."""
    assert _domain_files(), "No se encontró ningún módulo de dominio que verificar"
