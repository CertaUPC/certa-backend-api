"""Proyectos, que es lo que agrupa las ejecuciones.

Se identifican por ruta de repositorio dentro de su dueño: volver a cargarla
devuelve el proyecto que ya existe, para que las corridas de un mismo código no
queden repartidas entre dos filas.

Dentro de su dueño, y ahí está la diferencia: la ruta era única globalmente, de
modo que dos clientes que analizaran «/repos/mi-app» compartían proyecto y con
él los hallazgos del otro. Los conjuntos públicos no tienen dueño y los ve todo
el mundo, que es lo que se espera de OWASP Benchmark.
"""

from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import func, or_, select

from ....shared.database import ExecutionRow, ProjectRow
from ...domain.entities.membership import Membership, MemberRole
from ...infrastructure.persistence.membership_repository import (
    SqlMembershipRepository,
)
from ..schemas.schemas import ProjectRequest, ProjectResponse
from ....iam.infrastructure.persistence.models import UserRow
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

    Exige una cuenta de persona. Una credencial de participación solo veía los
    conjuntos públicos, de modo que no había fuga, pero quien entra a resolver
    su lote no tiene nada que hacer en un listado de proyectos: dárselo es
    ampliar su credencial sin motivo.
    """
    user.require()
    miembros = SqlMembershipRepository(session)
    rows = (
        await session.execute(
            select(ProjectRow)
            .where(miembros.visible_para(user.user_id))
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
    """Crea el proyecto, o devuelve el que ya cubre esa ruta de repositorio.

    Cualquier cuenta puede crear el suyo, y al crearlo queda como su
    administrador. Antes hacia falta un rango, de modo que quien se registraba
    no podia ni empezar: el permiso venia de lo que eras en el sistema en vez
    de lo que eres en tu proyecto.
    """
    if user.user_id is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Crear un proyecto exige una cuenta de persona",
        )

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

    # Quien lo crea entra como administrador, sin que nadie lo invite. Es lo
    # que hace que el alta sea util desde el primer minuto.
    await SqlMembershipRepository(session).add(
        Membership(
            project_id=UUID(row.id),
            user_id=user.user_id,
            role=MemberRole.ADMIN,
        )
    )
    return _to_response(row, 0)


@router.get("/{project_id}/members")
async def list_members(
    project_id: UUID, session: SessionDep, user: UserDep
) -> list[dict]:
    """Quién está en el proyecto. Solo lo ven sus miembros.

    Con el correo de cada uno. Sin él la lista son identificadores de treinta y
    seis caracteres, y no hay pantalla que se pueda construir con eso.
    """
    miembros = SqlMembershipRepository(session)
    if await miembros.role_of(project_id, user.user_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No existe ese proyecto")
    filas = await miembros.members_of(project_id)
    correos = dict(
        (
            await session.execute(
                select(UserRow.id, UserRow.email).where(
                    UserRow.id.in_([str(m.user_id) for m in filas] or [""])
                )
            )
        ).all()
    )
    return [
        {
            "user_id": str(m.user_id),
            "email": correos.get(str(m.user_id), ""),
            "role": m.role.value,
            "invited_by": str(m.invited_by) if m.invited_by else None,
        }
        for m in filas
    ]


@router.post("/{project_id}/members", status_code=status.HTTP_201_CREATED)
async def invite_member(
    project_id: UUID,
    session: SessionDep,
    user: UserDep,
    user_id: UUID | None = None,
    email: str | None = None,
) -> dict:
    """Invita a alguien al proyecto, como miembro.

    Por correo o por identificador. Por correo porque es lo que quien invita
    tiene a mano: nadie conoce de memoria el identificador de un compañero.

    Solo el administrador. Y no se responde «no eres administrador» a quien no
    pertenece al proyecto: eso ya confirmaría que existe, así que se responde
    lo mismo que si no existiera.
    """
    if (user_id is None) == (email is None):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Hace falta el correo de a quién invitar, o su identificador",
        )
    miembros = SqlMembershipRepository(session)
    mio = await miembros.role_of(project_id, user.user_id)
    if mio is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No existe ese proyecto")
    if not mio.manages:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Invitar al proyecto es cosa de su administrador",
        )
    if email is not None:
        fila = (
            await session.execute(
                select(UserRow.id).where(UserRow.email == email.strip().lower())
            )
        ).scalar_one_or_none()
        if fila is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                f"No hay ninguna cuenta con el correo {email}. Pídele que se "
                "registre primero.",
            )
        user_id = UUID(fila)
    if await miembros.role_of(project_id, user_id) is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Esa persona ya está en el proyecto"
        )
    await miembros.add(
        Membership(
            project_id=project_id,
            user_id=user_id,
            role=MemberRole.MEMBER,
            invited_by=user.user_id,
        )
    )
    return {"project_id": str(project_id), "user_id": str(user_id), "role": "miembro"}


@router.delete("/{project_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    project_id: UUID, user_id: UUID, session: SessionDep, user: UserDep
) -> None:
    """Retira a alguien. Solo el administrador, y nunca a sí mismo.

    Un proyecto sin administrador no lo podría gestionar nadie, y recuperarlo
    exigiría tocar la base.
    """
    miembros = SqlMembershipRepository(session)
    mio = await miembros.role_of(project_id, user.user_id)
    if mio is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No existe ese proyecto")
    if not mio.manages:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Retirar del proyecto es cosa de su administrador",
        )
    if str(user_id) == str(user.user_id):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "El administrador no se retira a sí mismo: el proyecto quedaría sin quien lo gestione",
        )
    if not await miembros.remove(project_id, user_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Esa persona no está en el proyecto")
