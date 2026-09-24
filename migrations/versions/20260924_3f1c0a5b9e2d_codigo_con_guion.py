"""Normaliza el código del participante a su forma con guion

El acta de consentimiento que la persona firma lleva «P-04» y el campo de la
pantalla pedía «P04». Quien dicta lee lo que tiene delante, así que el acceso
fallaba por un carácter. El dominio ya devuelve la forma canónica; esto pone
al día lo que se guardó antes.

Revision ID: 3f1c0a5b9e2d
Revises: 07322ebdaced
"""
from __future__ import annotations

import re

import sqlalchemy as sa
from alembic import op

revision = "3f1c0a5b9e2d"
down_revision = "07322ebdaced"
branch_labels = None
depends_on = None

_CODIGO = re.compile(r"^([A-Za-z]+)[\s\-_]*([0-9]+)$")


def upgrade() -> None:
    conexion = op.get_bind()
    filas = conexion.execute(
        sa.text("SELECT id, anonymous_code FROM participants")
    ).fetchall()
    for identificador, codigo in filas:
        m = _CODIGO.match((codigo or "").strip())
        if not m:
            continue
        canonico = f"{m.group(1).upper()}-{int(m.group(2)):02d}"
        if canonico == codigo:
            continue
        conexion.execute(
            sa.text(
                "UPDATE participants SET anonymous_code = :nuevo WHERE id = :id"
            ),
            {"nuevo": canonico, "id": identificador},
        )


def downgrade() -> None:
    # El guion no estorba a nada y quitarlo volvería a romper el dictado.
    pass
