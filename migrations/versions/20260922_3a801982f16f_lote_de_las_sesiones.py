"""Registra que hallazgos componen cada mitad del lote de las sesiones.

El 4.5 del protocolo exige que el lote quede fijado antes de reclutar, y ya lo
esta: veinticuatro hallazgos repartidos en dos mitades, con su huella y su
manifiesto. Lo que faltaba es que el servicio lo conozca. Sin esta tabla la
pantalla de auditoria sirve la ejecucion entera, de modo que el participante
veria el corpus completo en lugar de los doce que le tocan, y la comparacion
entre condiciones quedaria sin sentido.

La tabla vive en el contexto de experimentacion y se relaciona con el hallazgo
por identidad, nunca por clave foranea, como el resto de ese contexto: el
reparto es una decision del estudio y no una propiedad del hallazgo, y al
terminar se retira sin tocar el producto.

Revision ID: 3a801982f16f
Revises: 3c5a8d1f2b64
Create Date: 2026-09-22 07:57:53.238547
"""
import sqlalchemy as sa
from alembic import op

revision = "3a801982f16f"
down_revision = "3c5a8d1f2b64"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "session_batch_items",
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("batch", sa.String(length=10), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("finding_id"),
        # Dos hallazgos no pueden ocupar el mismo sitio de la misma mitad: el
        # orden se registra para que la secuencia sea reproducible.
        sa.UniqueConstraint("batch", "position", name="uq_session_batch_position"),
    )
    op.create_index(
        "ix_session_batch", "session_batch_items", ["batch", "position"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_session_batch", table_name="session_batch_items")
    op.drop_table("session_batch_items")
