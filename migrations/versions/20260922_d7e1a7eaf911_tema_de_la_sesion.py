"""Registra con qué presentación resolvió la tarea cada participante.

El criterio de aceptación de US032 no se conforma con que el tema quede fijado
durante la sesion: pide ademas que el sistema registre cual se empleo, para que
el analisis pueda descartarlo como factor en vez de suponer que no influye.

Admite nulo porque las sesiones anteriores al cambio no tienen un tema que
inventarles, y porque el uso de la herramienta fuera del experimento no fija
ninguno.

Revision ID: d7e1a7eaf911
Revises: 3a801982f16f
Create Date: 2026-09-22 08:30:22.815194
"""
from alembic import op
import sqlalchemy as sa


revision = 'd7e1a7eaf911'
down_revision = '3a801982f16f'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('sessions', sa.Column('theme', sa.String(length=10), nullable=True))


def downgrade() -> None:
    op.drop_column('sessions', 'theme')
