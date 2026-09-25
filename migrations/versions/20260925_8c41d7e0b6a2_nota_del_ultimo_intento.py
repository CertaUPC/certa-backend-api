"""Guarda lo que el trabajador dejó dicho en el último intento

Una corrida que vuelve a la cola pierde `failure_reason`, porque reanudar lo
borra. Es justo lo que ocurre cuando el trabajador no encuentra el repositorio
en su disco: la devuelve sin consumirla y el diagnóstico se pierde, de modo que
la pantalla solo puede decir «en espera» sin explicar de qué. Estas dos
columnas conservan esa señal entre intentos.

Revision ID: 8c41d7e0b6a2
Revises: 3f1c0a5b9e2d
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "8c41d7e0b6a2"
down_revision = "3f1c0a5b9e2d"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "executions",
        sa.Column("last_attempt_note", sa.Text(), nullable=True),
    )
    op.add_column(
        "executions",
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("executions", "last_attempt_at")
    op.drop_column("executions", "last_attempt_note")
