"""Quién es quién dentro de un proyecto, y qué puede hacer."""

from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ....shared.database import ProjectMemberRow, ProjectRow
from ...domain.entities.membership import Membership, MemberRole


class SqlMembershipRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    @staticmethod
    def _to_entity(r: ProjectMemberRow) -> Membership:
        return Membership(
            id=UUID(r.id),
            project_id=UUID(r.project_id),
            user_id=UUID(r.user_id),
            role=MemberRole(r.role),
            invited_by=UUID(r.invited_by) if r.invited_by else None,
            created_at=r.created_at,
        )

    async def add(self, membership: Membership) -> None:
        self._session.add(
            ProjectMemberRow(
                id=str(membership.id),
                project_id=str(membership.project_id),
                user_id=str(membership.user_id),
                role=membership.role.value,
                invited_by=(
                    str(membership.invited_by) if membership.invited_by else None
                ),
                created_at=membership.created_at,
            )
        )
        await self._session.commit()

    async def role_of(self, project_id, user_id) -> MemberRole | None:
        """Qué es esta persona en este proyecto, o None si no es nada.

        Devolver el papel y no un booleano permite que quien llama distinga
        «no pertenece» de «pertenece pero no administra», que producen
        respuestas distintas: la primera es un 404 en la practica, porque
        revelar que el proyecto existe ya dice algo.
        """
        valor = await self._session.scalar(
            select(ProjectMemberRow.role).where(
                ProjectMemberRow.project_id == str(project_id),
                ProjectMemberRow.user_id == str(user_id),
            )
        )
        return MemberRole(valor) if valor else None

    async def members_of(self, project_id) -> list[Membership]:
        filas = (
            await self._session.execute(
                select(ProjectMemberRow)
                .where(ProjectMemberRow.project_id == str(project_id))
                .order_by(ProjectMemberRow.created_at)
            )
        ).scalars()
        return [self._to_entity(f) for f in filas]

    async def remove(self, project_id, user_id) -> bool:
        fila = (
            await self._session.execute(
                select(ProjectMemberRow).where(
                    ProjectMemberRow.project_id == str(project_id),
                    ProjectMemberRow.user_id == str(user_id),
                )
            )
        ).scalar_one_or_none()
        if fila is None:
            return False
        await self._session.delete(fila)
        await self._session.commit()
        return True

    def visible_para(self, user_id):
        """Condición de visibilidad: lo mío y lo público.

        Se devuelve la condición y no el resultado para que quien consulta la
        componga con lo suyo en una sola consulta, en vez de traer todo y
        filtrar en memoria.
        """
        if user_id is None:
            return ProjectRow.is_public_dataset.is_(True)
        pertenezco = ProjectRow.id.in_(
            select(ProjectMemberRow.project_id).where(
                ProjectMemberRow.user_id == str(user_id)
            )
        )
        return or_(pertenezco, ProjectRow.is_public_dataset.is_(True))
