# -*- coding: utf-8 -*-
"""Separa la auditoria del producto de la decision del estudio.

Hasta aqui la unica forma de registrar lo que alguien resolvia sobre un hallazgo
era el recorrido de decisiones del experimento, que exige participante y
condicion asignada. Eso obligaba a registrar a cualquier usuario como sujeto de
un estudio para poder usar la herramienta, y contradecia la frontera que el
propio proyecto declara: la instrumentacion del experimento debe poder retirarse
al terminar la tesis sin tocar la cadena de analisis, que es el producto.

Son dos hechos distintos y por eso son dos tablas. `decisions` guarda una
medicion: que decidio un participante bajo una condicion asignada, con su
tiempo, para contrastarla con la condicion contraria. `audits` guarda un
registro de auditoria: quien reviso que y que resolvio. Fundirlas obligaba a
inventar la mitad de los campos en cada uso.

La clave foranea al usuario es SET NULL y no CASCADE, por la misma razon que en
executions: la revision es un hecho que ocurrio, y borrar la cuenta debe
anonimizar el registro, no destruirlo.

Revision ID: 3c5a8d1f2b64
Revises: 9e3f6b2d1a47
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "3c5a8d1f2b64"
down_revision: str | None = "9e3f6b2d1a47"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audits",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=True),
        sa.Column("value", sa.String(length=20), nullable=False),
        sa.Column("seconds", sa.Float(), nullable=False),
        sa.Column("is_current", sa.Boolean(), nullable=False),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint("seconds > 0", name="ck_audits_seconds"),
        sa.CheckConstraint(
            "value IN ('confirmado','descartado','dudoso')",
            name="ck_audits_value",
        ),
    )
    # El indice lleva is_current porque la consulta que mas se hace es «la
    # decision vigente de este hallazgo», no el historial completo.
    op.create_index("ix_audits_finding", "audits", ["finding_id", "is_current"])


def downgrade() -> None:
    op.drop_index("ix_audits_finding", table_name="audits")
    op.drop_table("audits")
