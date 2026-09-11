"""Proyectos, que es lo que agrupa las ejecuciones.

Se identifican por ruta de repositorio, que es única: volver a cargarla devuelve
el proyecto que ya existe, para que las corridas de un mismo código no queden
repartidas entre dos filas.
"""

from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import func, select

from ....shared.database import ExecutionRow, ProjectRow
from ..schemas.schemas import ProjectRequest, ProjectResponse
from .dependencies import SessionDep, UserDep

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
    """Proyectos con su número de ejecuciones, el más reciente primero."""
    rows = (
        await session.execute(select(ProjectRow).order_by(ProjectRow.created_at.desc()))
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
            select(ProjectRow).where(ProjectRow.repository_path == ruta)
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
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return _to_response(row, 0)
