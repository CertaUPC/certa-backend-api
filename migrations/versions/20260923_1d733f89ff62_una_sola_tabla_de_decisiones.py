"""Una sola tabla de decisiones, y las listas de trabajo.

FUNDE `audits` Y `decisions`. Guardaban el mismo acto, alguien decidio algo
sobre un hallazgo en un tiempo, y se distinguian solo en a quien identificaban.
Sostenerlo en dos sitios hacia que el estudio corriera por un camino paralelo
al del producto en lugar de ser un caso suyo, con la logica de rectificacion
escrita dos veces en sitios que podian divergir.

Lo propio del estudio, participante, sesion, lote y condicion, admite ausencia,
de modo que una decision del producto no carga ni una columna del experimento.

SE RECREA EN VEZ DE REMENDARSE. Las dos tablas estan vacias en local y en el
despliegue, asi que recrear produce un esquema identico al que declara el
modelo, sin el rastro de ALTERs encadenados que SQLite ademas no admite sobre
restricciones sin nombre. Si hubiera datos, esta migracion no valdria: habria
que trasvasarlos.

ANADE `worklists` Y `worklist_items`, que generalizan el lote congelado del
estudio. Aqui `finding_id` si es clave foranea, a diferencia de
`session_batch_items`, donde era una cadena suelta: cargar un lote en una base
sin esos hallazgos funcionaba sin protestar y la sesion reventaba en la primera
alerta.

Revision ID: 1d733f89ff62
Revises: e262fe51f9d8
Create Date: 2026-09-23
"""
import sqlalchemy as sa
from alembic import op

revision = "1d733f89ff62"
down_revision = "e262fe51f9d8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "worklists",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("execution_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=True),
        sa.Column("frozen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["execution_id"], ["executions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "worklist_items",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("worklist_id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("bucket", sa.String(length=10), nullable=True),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["worklist_id"], ["worklists.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("worklist_id", "finding_id", name="uq_worklist_finding"),
    )
    op.create_index(
        "ix_worklist_items_bucket",
        "worklist_items",
        ["worklist_id", "bucket", "position"],
    )

    op.drop_table("audits")
    op.drop_table("decisions")

    op.create_table(
        "decisions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=True),
        sa.Column("participant_id", sa.String(length=36), nullable=True),
        sa.Column("session_id", sa.String(length=36), nullable=True),
        sa.Column("worklist_id", sa.String(length=36), nullable=True),
        sa.Column("condition", sa.String(length=20), nullable=True),
        sa.Column("value", sa.String(length=20), nullable=False),
        sa.Column("seconds", sa.Float(), nullable=False),
        sa.Column("is_current", sa.Boolean(), nullable=False),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        # El consentimiento admite retirarse. Si al borrar al participante sus
        # decisiones quedaran, el borrado no habria sido tal.
        sa.ForeignKeyConstraint(
            ["participant_id"], ["participants.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["session_id"], ["sessions.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["worklist_id"], ["worklists.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint("seconds > 0", name="ck_decisions_seconds"),
        sa.CheckConstraint(
            "value IN ('confirmado','descartado','dudoso')",
            name="ck_decisions_value",
        ),
        sa.CheckConstraint(
            "condition IS NULL OR condition IN ('con_asistente','sin_asistente')",
            name="ck_decisions_condition",
        ),
        # Toda decision tiene un autor y uno solo. Con las dos columnas a la
        # vez, una fila diria que decidio una cuenta y un participante, y el
        # analisis no sabria a cual atribuirla.
        sa.CheckConstraint(
            "(user_id IS NOT NULL) <> (participant_id IS NOT NULL)",
            name="ck_decisions_un_solo_autor",
        ),
    )
    op.create_index("ix_decisions_finding", "decisions", ["finding_id", "is_current"])
    op.create_index(
        "ix_decisions_participant", "decisions", ["participant_id", "is_current"]
    )


def downgrade() -> None:
    op.drop_index("ix_decisions_participant", table_name="decisions")
    op.drop_index("ix_decisions_finding", table_name="decisions")
    op.drop_table("decisions")

    op.create_table(
        "decisions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("session_id", sa.String(length=36), nullable=True),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("participant_id", sa.String(length=36), nullable=False),
        sa.Column("value", sa.String(length=20), nullable=False),
        sa.Column("seconds", sa.Float(), nullable=False),
        sa.Column("condition", sa.String(length=20), nullable=False),
        sa.Column("is_current", sa.Boolean(), nullable=False),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["session_id"], ["sessions.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["participant_id"], ["participants.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_decisions_finding", "decisions", ["finding_id"])
    op.create_index("ix_decisions_participant", "decisions", ["participant_id", "condition"])

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
    )
    op.create_index("ix_audits_finding", "audits", ["finding_id", "is_current"])

    op.drop_index("ix_worklist_items_bucket", table_name="worklist_items")
    op.drop_table("worklist_items")
    op.drop_table("worklists")
