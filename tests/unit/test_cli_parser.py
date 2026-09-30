"""La línea de órdenes tiene que entregarle a cada manejador lo que consulta.

`check` no analiza por su cuenta: llama a `cmd_analyze` con el mismo espacio de
nombres. Cuando una opción estaba declarada solo en `analyze`, la orden que la
cabecera del módulo documenta moría con un AttributeError antes de analizar
nada, y no había prueba que lo dijera porque la línea de órdenes no tenía
ninguna. Estas comprobaciones cubren el reparto de opciones, que es donde vive
ese fallo, y no lo que cada orden hace después.
"""

import ast
import inspect
import shlex
import textwrap

import pytest

from src import cli

# Una orden mínima por subcomando, con lo obligatorio y nada más.
MINIMAS = {
    "analyze": ["analyze", "./repo"],
    "validate": ["validate", "b9a1d4c0-0000-4000-8000-000000000000"],
    "compare": [
        "compare", "b9a1d4c0-0000-4000-8000-000000000000",
        "--model", "uno", "--model", "dos",
    ],
    "check": ["check", "./repo"],
}

# `check` reutiliza el manejador de `analyze`, así que hereda lo que aquel lee.
DELEGA_EN = {"check": (cli.cmd_analyze,)}


def atributos_que_lee(funcion) -> set[str]:
    """Los `args.x` que la función consulta, sacados de su propio código."""
    arbol = ast.parse(textwrap.dedent(inspect.getsource(funcion)))
    return {
        nodo.attr
        for nodo in ast.walk(arbol)
        if isinstance(nodo, ast.Attribute)
        and isinstance(nodo.value, ast.Name)
        and nodo.value.id == "args"
    }


@pytest.mark.parametrize("subcomando", sorted(MINIMAS))
def test_cada_orden_trae_lo_que_su_manejador_consulta(subcomando):
    manejador = {
        "analyze": cli.cmd_analyze,
        "validate": cli.cmd_validate,
        "compare": cli.cmd_compare,
        "check": cli.cmd_check,
    }[subcomando]

    args = cli.build_parser().parse_args(MINIMAS[subcomando])

    esperados = atributos_que_lee(manejador)
    for otro in DELEGA_EN.get(subcomando, ()):
        esperados |= atributos_que_lee(otro)

    faltan = sorted(a for a in esperados if not hasattr(args, a))
    assert not faltan, (
        f"'{subcomando}' no declara {faltan}, y su manejador las consulta: "
        f"la orden se cae antes de hacer nada"
    )


def test_check_puede_partir_de_un_sarif_ya_generado():
    """Analizar el corpus dos veces cuesta minutos y puede no coincidir."""
    p = cli.build_parser()
    assert p.parse_args(["check", "./repo"]).sarif is None
    assert p.parse_args(["check", "./repo", "--sarif", "salida.sarif"]).sarif == (
        "salida.sarif"
    )


def test_las_ordenes_que_documenta_la_cabecera_se_analizan():
    """Lo que el módulo enseña como ejemplo tiene que poder correrse."""
    documentadas = [
        shlex.split(linea.strip().removeprefix("py -m src.cli"))
        for linea in (cli.__doc__ or "").splitlines()
        if linea.strip().startswith("py -m src.cli")
    ]
    assert documentadas, "la cabecera dejó de documentar órdenes"
    for orden in documentadas:
        # Los marcadores de la cabecera no son valores reales, pero el análisis
        # sintáctico no los mira: lo que se comprueba es la forma de la orden.
        cli.build_parser().parse_args(orden)
