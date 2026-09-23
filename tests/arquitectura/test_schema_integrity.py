"""La integridad referencial del esquema, comprobada y no supuesta.

El objetivo 1 elimina MongoDB de la capa de persistencia por dejar la
integridad referencial a cargo de la aplicación, y elige PostgreSQL porque el
motor la garantiza. Ese argumento obliga: si el propio esquema deja referencias
sueltas, la eliminación de MongoDB se vuelve indefendible.

La excepción legítima es la frontera entre contextos delimitados. Una decisión
del experimento apunta a un hallazgo que pertenece al contexto de validación, y
el diseño guiado por el dominio dice referenciar eso por identidad y no por
clave foránea, para que los dos contextos puedan evolucionar por separado.

Esa excepción se declara aquí, una por una. Lo que no está declarado tiene que
llevar su clave foránea, y la prueba falla si aparece una nueva referencia
suelta sin que nadie haya tenido que justificarla.
"""
from __future__ import annotations

import pathlib

import pytest

import src.iam.infrastructure.persistence.models  # noqa: F401  (registra users)
import src.shared.database_experiment  # noqa: F401  (registra sus tablas)
from src.shared.database import Base

# Referencias que cruzan la frontera entre contextos y por eso van por
# identidad. Cada una está comentada en el modelo con su razón.
CRUCES_DE_CONTEXTO = {
    ("decisions", "finding_id"),
    ("session_batch_items", "finding_id"),
    ("transformations", "original_finding_id"),
    ("transformations", "transformed_finding_id"),
}

# Columnas que acaban en _id y no son referencias a nada de este esquema.
NO_SON_REFERENCIAS = {
    # El identificador de la regla que emitió el analizador, por ejemplo
    # "java.lang.security.audit.sqli". Pertenece al catálogo del analizador.
    ("findings", "rule_id"),
}


def referencias_sueltas() -> list[tuple[str, str]]:
    sueltas = []
    for nombre in sorted(Base.metadata.tables):
        tabla = Base.metadata.tables[nombre]
        for columna in tabla.columns:
            if not columna.name.endswith("_id") or columna.primary_key:
                continue
            if columna.foreign_keys:
                continue
            clave = (nombre, columna.name)
            if clave in CRUCES_DE_CONTEXTO or clave in NO_SON_REFERENCIAS:
                continue
            sueltas.append(clave)
    return sueltas


class TestIntegridadReferencial:
    def test_ninguna_referencia_queda_a_cargo_de_la_aplicacion(self):
        sueltas = referencias_sueltas()
        assert not sueltas, (
            "Estas columnas parecen referencias y no declaran clave foránea: "
            f"{sueltas}. Si cruzan la frontera entre contextos, decláralo en "
            "CRUCES_DE_CONTEXTO y coméntalo en el modelo; si no, ponle la "
            "clave foránea."
        )

    def test_la_decision_referencia_a_su_participante(self):
        # Es la tabla de la variable dependiente principal del experimento.
        # Una decisión huérfana no es un dato incompleto: es un resultado que
        # no se puede atribuir a nadie.
        columna = Base.metadata.tables["decisions"].c["participant_id"]
        destinos = {f"{k.column.table.name}.{k.column.name}"
                    for k in columna.foreign_keys}
        assert destinos == {"participants.id"}

    def test_la_retirada_del_participante_arrastra_sus_decisiones(self):
        # El consentimiento informado admite retirarse. Si se borra al
        # participante y sus decisiones quedan, el borrado no fue tal.
        columna = Base.metadata.tables["decisions"].c["participant_id"]
        clave = next(iter(columna.foreign_keys))
        assert clave.ondelete == "CASCADE"

    @pytest.mark.parametrize("tabla,columna", sorted(CRUCES_DE_CONTEXTO))
    def test_el_cruce_declarado_existe_de_verdad(self, tabla, columna):
        # Impide que la lista de excepciones sobreviva a la columna que
        # justificaba, y se convierta en un permiso para cualquier cosa.
        assert columna in Base.metadata.tables[tabla].c


class TestRastroDeAuditoria:
    """La ejecución recuerda quién la lanzó.

    Sin esta columna la tabla de usuarios no se relacionaba con ninguna otra:
    la autorización se comprobaba al entrar al recurso y no quedaba registrada,
    de modo que el sistema sabía que quien entró tenía permiso y no sabía quién
    era. Un registro de decisiones sin autor no es un rastro de auditoría.
    """

    def test_la_ejecucion_referencia_a_su_autor(self):
        columna = Base.metadata.tables["executions"].c["created_by"]
        destinos = {f"{k.column.table.name}.{k.column.name}"
                    for k in columna.foreign_keys}
        assert destinos == {"users.id"}

    def test_borrar_la_cuenta_conserva_la_ejecucion(self):
        # Una ejecución es un hecho que ocurrió. Arrastrarla al borrar al
        # usuario destruiría el registro en lugar de anonimizarlo.
        columna = Base.metadata.tables["executions"].c["created_by"]
        clave = next(iter(columna.foreign_keys))
        assert clave.ondelete == "SET NULL"

    def test_admite_nulo(self):
        # Las ejecuciones anteriores al cambio no tienen autor que inventarles,
        # y la ingesta por línea de órdenes no pasa por sesión.
        assert Base.metadata.tables["executions"].c["created_by"].nullable

    def test_ninguna_tabla_queda_sin_relacionar(self):
        # Una tabla suelta en el diagrama entidad-relación es lo primero que se
        # pregunta. Las referencias por identidad cuentan: existen en el modelo
        # aunque el motor no las imponga.
        relacionadas = set()
        for nombre in Base.metadata.tables:
            tabla = Base.metadata.tables[nombre]
            for columna in tabla.columns:
                for clave in columna.foreign_keys:
                    relacionadas.add(nombre)
                    relacionadas.add(clave.column.table.name)
        for tabla, _ in CRUCES_DE_CONTEXTO:
            relacionadas.add(tabla)
        relacionadas.add("findings")

        sueltas = set(Base.metadata.tables) - relacionadas
        assert not sueltas, (
            f"Estas tablas no se relacionan con ninguna otra: {sorted(sueltas)}. "
            "O les falta su referencia, o hay que declarar por qué existen "
            "aisladas."
        )


class TestElEsquemaSeCreaDesdeCadaPuntoDeEntrada:
    """Cada punto de entrada tiene que poder crear el esquema por sí solo.

    La tabla de cuentas vive en el contexto de acceso y `executions` la
    referencia por clave foránea. Un punto de entrada que no importe ese módulo
    deja el metadata incompleto y `create_all` falla con NoReferencedTableError
    sobre una base nueva, aunque la suite entera pase: basta con que OTRO
    módulo importe las cuentas para que el fallo no aparezca aquí.

    Por eso se comprueba en un intérprete aparte, que es la única forma de
    reproducir lo que ocurre en una máquina limpia.
    """

    ENTRADAS = ("src.cli", "src.worker", "src.main")

    @pytest.mark.parametrize("modulo", ENTRADAS)
    def test_crea_el_esquema_en_un_interprete_limpio(self, modulo, tmp_path):
        import subprocess
        import sys

        guion = (
            f"import {modulo};"
            "from src.shared.database import Base;"
            "from sqlalchemy import create_engine;"
            f"Base.metadata.create_all(create_engine('sqlite:///{tmp_path.as_posix()}/e.db'))"
        )
        hecho = subprocess.run(
            [sys.executable, "-c", guion],
            capture_output=True, text=True,
            cwd=str(pathlib.Path(__file__).resolve().parents[2]),
        )
        assert hecho.returncode == 0, (
            f"importar {modulo} no basta para crear el esquema:\n"
            f"{hecho.stderr[-600:]}"
        )
