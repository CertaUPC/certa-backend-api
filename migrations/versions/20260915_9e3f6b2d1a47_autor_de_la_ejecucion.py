# -*- coding: utf-8 -*-
"""Registra quien lanzo cada ejecucion.

Hasta aqui la tabla de usuarios no se relacionaba con ninguna otra. La
autorizacion se comprobaba por rol al entrar al recurso y no se persistia nada,
de modo que cualquier investigador podia lanzar cualquier ejecucion y despues no
habia forma de saber quien lo hizo. El sistema declara un registro de decisiones
auditable, y un registro sin autor no es un rastro de auditoria.

La columna admite nulo por dos razones distintas y las dos legitimas: las
ejecuciones anteriores a este cambio existen y no se les puede inventar un
autor, y la ingesta por linea de ordenes no pasa por sesion.

Al borrar la cuenta la ejecucion se conserva con el autor a nulo. Es deliberado:
una ejecucion es un hecho que ocurrio, y arrastrarla al borrar al usuario
destruiria el registro en lugar de anonimizarlo.

Revision ID: 9e3f6b2d1a47
Revises: 7d1a4c8e5f92
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "9e3f6b2d1a47"
down_revision: str | None = "7d1a4c8e5f92"
branch_labels = None
depends_on = None

RESTRICCION = "fk_executions_created_by"


def upgrade() -> None:
    # En lote, como la migracion anterior: en desarrollo la base es SQLite y no
    # admite anadir una restriccion sobre una tabla existente.
    with op.batch_alter_table("executions") as lote:
        lote.add_column(sa.Column("created_by", sa.String(36), nullable=True))
        lote.create_foreign_key(
            RESTRICCION,
            referent_table="users",
            local_cols=["created_by"],
            remote_cols=["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    with op.batch_alter_table("executions") as lote:
        lote.drop_constraint(RESTRICCION, type_="foreignkey")
        lote.drop_column("created_by")
