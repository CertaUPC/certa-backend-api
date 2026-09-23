"""Marca a los participantes de la sesion piloto.

El protocolo de validacion declara que antes de la primera sesion se ejecuta un
piloto cuyos datos se excluyen del analisis, y hace de haber participado en el
un criterio de exclusion del estudio. Hasta ahora el esquema no tenia por donde
distinguirlos: la unica manija era el codigo anonimo, aplicado a mano al
analizar, que es justo lo que se olvida.

Y hay una razon mas apremiante que el analisis. El orden de condiciones se
asigna con el contrabalanceador sobre el historial persistido de sesiones. Sin
esta columna, la sesion del piloto entra en ese historial y desvia el reparto
de los participantes reales: el primero de los doce recibiria el orden que
equilibra una cuenta que incluye a alguien que no cuenta.

No nulo y con falso por omision: una fila sin valor aqui seria una fila de la
que no se sabe si entra en el analisis, y esa duda no se resuelve despues.

Revision ID: b4f92c1d7a08
Revises: d7e1a7eaf911
Create Date: 2026-09-22 21:05:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = 'b4f92c1d7a08'
down_revision = 'd7e1a7eaf911'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        'participants',
        sa.Column('is_pilot', sa.Boolean(), nullable=False,
                  server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column('participants', 'is_pilot')
