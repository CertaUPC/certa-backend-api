"""Los proyectos tienen dueno, y la ruta deja de ser unica a secas.

`repository_path` era unica globalmente. Con un solo equipo usando la
herramienta no se notaba; en cuanto hay dos clientes, el segundo que analice
«/repos/mi-app» recibe el proyecto del primero y con el sus hallazgos, que
arrastran fragmentos de su codigo. Pasa a ser unica por dueno.

El dueno admite nulo por dos motivos distintos. Los proyectos anteriores a esta
migracion no tienen a quien atribuirse, e inventarles uno seria peor que
dejarlos sin el. Y los conjuntos publicos, como OWASP Benchmark, no son de
nadie a proposito: los ve todo el mundo, que es lo que se espera de un conjunto
de referencia.

Se recrea la tabla con el modo por lotes porque SQLite no sabe retirar una
restriccion de unicidad de una columna, y remendarla a mano dejaria el esquema
distinto segun el motor.

Revision ID: a131347907c9
Revises: 1d733f89ff62
Create Date: 2026-09-23
"""
import sqlalchemy as sa
from alembic import op

revision = "a131347907c9"
down_revision = "1d733f89ff62"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "projects", sa.Column("owner_id", sa.String(length=36), nullable=True)
    )
    with op.batch_alter_table("projects", schema=None) as lote:
        lote.create_foreign_key(
            "fk_projects_owner", "users", ["owner_id"], ["id"], ondelete="CASCADE"
        )
        lote.create_unique_constraint(
            "uq_project_owner_path", ["owner_id", "repository_path"]
        )


def downgrade() -> None:
    with op.batch_alter_table("projects", schema=None) as lote:
        lote.drop_constraint("uq_project_owner_path", type_="unique")
        lote.drop_constraint("fk_projects_owner", type_="foreignkey")
    op.drop_column("projects", "owner_id")
