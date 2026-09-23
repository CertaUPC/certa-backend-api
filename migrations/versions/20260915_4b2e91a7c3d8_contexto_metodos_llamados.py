"""contexto: métodos llamados

El recuperador de contexto pasó a seguir la ruta del dato en los dos sentidos.
Además de los llamadores, que dicen de dónde procede, recupera los métodos a los
que la función contenedora delega el dato, que son los que dicen qué le hicieron
antes de alcanzar el punto sensible. Ahí vive el saneamiento casi siempre, y sin
su cuerpo el modelo se abstiene con razón: la proporción de veredictos
indeterminados cayó del 51 al 15 por ciento al incorporarlo.

Se guardan en columna propia y no junto a los llamadores porque responden a
preguntas distintas, y se anota la profundidad empleada en cada recorrido para
que un veredicto antiguo pueda auditarse contra el contexto con que se emitió.

Las columnas admiten nulo y traen valor por omisión, de modo que las filas
anteriores a este cambio siguen siendo legibles: declaran un contexto recuperado
sin ese recorrido, que es exactamente lo que fueron.

Revision ID: 4b2e91a7c3d8
Revises: 89c7ef767641
Create Date: 2026-09-15 10:12:04.117903
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy import Text
from sqlalchemy.dialects import postgresql

revision = "4b2e91a7c3d8"
down_revision = "89c7ef767641"
branch_labels = None
depends_on = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql")


def upgrade() -> None:
    op.add_column(
        "code_contexts",
        sa.Column("callees", _JSON, nullable=False, server_default="[]"),
    )
    op.add_column(
        "code_contexts",
        sa.Column("callee_depth", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("code_contexts", "callee_depth")
    op.drop_column("code_contexts", "callees")
