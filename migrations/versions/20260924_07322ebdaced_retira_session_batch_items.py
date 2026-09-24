"""Retira session_batch_items, que quedo sin quien la lea.

Era el lote congelado del estudio. La migracion 1d733f89ff62 introdujo
`worklists` y `worklist_items`, que generalizan la misma idea como una
seleccion de hallazgos dentro de una ejecucion, y el repositorio del lote pasa
a leer de ahi. La tabla vieja se quedo sin lectores y sin ninguna relacion, de
modo que en el modelo de datos aparecia suelta y no decia nada.

El contenido se trasvasa antes de borrar, por si alguna base conserva su lote
ahi y no en la tabla nueva. En el despliegue ya estaba en worklists.

Revision ID: 07322ebdaced
Revises: 0d7281b14e8e
Create Date: 2026-09-24
"""
import uuid

import sqlalchemy as sa
from alembic import op

revision = "07322ebdaced"
down_revision = "0d7281b14e8e"
branch_labels = None
depends_on = None

NOMBRE = "Lote del estudio"


def _existe(conexion, tabla):
    return sa.inspect(conexion).has_table(tabla)


def upgrade() -> None:
    conexion = op.get_bind()
    if not _existe(conexion, "session_batch_items"):
        return

    pendientes = conexion.execute(sa.text(
        "select b.finding_id, b.batch, b.position, b.created_at "
        "from session_batch_items b "
        "where not exists (select 1 from worklist_items i "
        "                  where i.finding_id = b.finding_id) "
        "order by b.batch, b.position"
    )).fetchall()

    if pendientes:
        ejecucion = conexion.execute(sa.text(
            "select execution_id from findings where id = :fid"
        ), {"fid": pendientes[0].finding_id}).scalar()
        if ejecucion is not None:
            lista = str(uuid.uuid4())
            conexion.execute(sa.text(
                "insert into worklists (id, execution_id, name, fingerprint, "
                "frozen_at, created_at) values (:id, :eid, :nombre, null, "
                ":congelado, :congelado)"
            ), {"id": lista, "eid": ejecucion, "nombre": NOMBRE,
                "congelado": pendientes[0].created_at})
            for f in pendientes:
                conexion.execute(sa.text(
                    "insert into worklist_items (id, worklist_id, finding_id, "
                    "bucket, position) values (:id, :wid, :fid, :b, :p)"
                ), {"id": str(uuid.uuid4()), "wid": lista,
                    "fid": f.finding_id, "b": f.batch, "p": f.position})

    op.drop_table("session_batch_items")


def downgrade() -> None:
    op.create_table(
        "session_batch_items",
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("batch", sa.String(length=10), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("finding_id"),
        sa.UniqueConstraint("batch", "position",
                            name="uq_session_batch_position"),
    )
    op.create_index("ix_session_batch", "session_batch_items",
                    ["batch", "position"])
