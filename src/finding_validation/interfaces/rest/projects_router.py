"""Proyectos, que es lo que agrupa las ejecuciones.

Se identifican por ruta de repositorio dentro de su dueño: volver a cargarla
devuelve el proyecto que ya existe, para que las corridas de un mismo código no
queden repartidas entre dos filas.

DENTRO DE SU DUEÑO, y ahí está la diferencia. La ruta era única globalmente, de
modo que dos clientes que analizaran «/repos/mi-app» compartían proyecto y, con
él, los hallazgos del otro. Los conjuntos públicos no tienen dueño y los ve
todo el mundo, que es lo que se espera de OWASP Benchmark.
"""

from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import func, or_, select

from ....shared.database import ExecutionRow, ProjectRow
from ..schemas.schemas import ProjectRequest, ProjectResponse
from ....iam.interfaces.rest.dependencies import UserDep
from ....shared.rest import SessionDep

router = APIRouter(prefix="/api/v1/projects", tags=["Proyectos"])


def _to_response(row: ProjectRow, executions: int) -> ProjectResponse:
    return ProjectResponse(
        id=UUID(row.id),
        name=row.name,
        language=row.language,
        repository_path=row.repository_path,
        is_public_dataset=row.is_public_dataset,
        execution_count=executions,
        created_at=row.created_at,
    )


@router.get("", response_model=list[ProjectResponse])
async def list_projects(session: SessionDep, user: UserDep) -> list[ProjectResponse]:
    """Los proyectos de quien pregunta, el más reciente primero.

    Los públicos entran en la lista de todos; los ajenos no aparecen.
    """
    mios = ProjectRow.owner_id == str(user.user_id) if user.user_id else False
    rows = (
        await session.execute(
            select(ProjectRow)
            .where(or_(mios, ProjectRow.is_public_dataset.is_(True)))
            .order_by(ProjectRow.created_at.desc())
        )
    ).scalars().all()

    # Un solo agrupamiento en lugar de una consulta por proyecto.
    conteos = dict(
        (
            await session.execute(
                select(ExecutionRow.project_id, func.count(ExecutionRow.id)).group_by(
                    ExecutionRow.project_id
                )
            )
        ).all()
    )
    return [_to_response(r, conteos.get(r.id, 0)) for r in rows]


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    body: ProjectRequest, session: SessionDep, user: UserDep
) -> ProjectResponse:
    """Crea el proyecto, o devuelve el que ya cubre esa ruta de repositorio."""
    user.require("investigador", "lider_tecnico")

    ruta = body.repository_path.strip() or body.name.strip()
    existente = (
        await session.execute(
            select(ProjectRow).where(
                ProjectRow.repository_path == ruta,
                ProjectRow.owner_id == str(user.user_id) if user.user_id else
                ProjectRow.owner_id.is_(None),
            )
        )
    ).scalar_one_or_none()
    if existente is not None:
        return _to_response(existente, 0)

    if not body.name.strip():
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "El proyecto necesita un nombre"
        )

    row = ProjectRow(
        id=str(uuid4()),
        name=body.name.strip(),
        language=body.language,
        repository_path=ruta,
        is_public_dataset=body.is_public_dataset,
        # Un conjunto publico no es de nadie: lo ve todo el mundo y por eso no
        # lleva dueno. Lo demas pertenece a quien lo creo.
        owner_id=None if body.is_public_dataset else (
            str(user.user_id) if user.user_id else None
        ),
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return _to_response(row, 0)
