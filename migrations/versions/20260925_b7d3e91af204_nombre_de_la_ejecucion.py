"""Deja que una ejecución tenga nombre

Una corrida se identificaba por los primeros ocho caracteres de su UUID. Con
dos del mismo proyecto en la lista, ubicar la que uno cargó ayer era abrirlas
una por una. La columna es nula porque la ingesta por línea de órdenes no pide
nombre, y ahí la pantalla resuelve con la fecha en vez de inventar uno.

Revision ID: b7d3e91af204
Revises: 8c41d7e0b6a2
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "b7d3e91af204"
down_revision = "8c41d7e0b6a2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "executions",
        sa.Column("label", sa.String(length=120), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("executions", "label")
