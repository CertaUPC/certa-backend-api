"""Persistencia de las credenciales acotadas."""

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...domain.access_grant import AccessGrant, GrantKind
from .models import AccessGrantRow


class SqlAccessGrantRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    @staticmethod
    def _to_entity(r: AccessGrantRow) -> AccessGrant:
        return AccessGrant(
            id=r.id,
            subject_kind=GrantKind(r.subject_kind),
            subject_id=r.subject_id,
            secret_hash=r.secret_hash,
            issued_by=r.issued_by,
            label=r.label,
            created_at=r.created_at,
            expires_at=r.expires_at,
            revoked_at=r.revoked_at,
            last_used_at=r.last_used_at,
        )

    async def save(self, grant: AccessGrant) -> None:
        self._session.add(
            AccessGrantRow(
                id=grant.id,
                subject_kind=grant.subject_kind.value,
                subject_id=grant.subject_id,
                secret_hash=grant.secret_hash,
                issued_by=grant.issued_by,
                label=grant.label,
                created_at=grant.created_at,
                expires_at=grant.expires_at,
            )
        )
        await self._session.commit()

    async def get(self, grant_id: str) -> AccessGrant | None:
        row = await self._session.get(AccessGrantRow, grant_id)
        return self._to_entity(row) if row else None

    async def list_for(self, kind: GrantKind, subject_id: str) -> list[AccessGrant]:
        """Las credenciales de un sujeto, vigentes y caducadas.

        Se devuelven todas y no solo las vigentes: para revocar hay que ver lo
        que existe, y una credencial vencida que sigue en la lista dice algo
        distinto de una que nunca se emitió.
        """
        rows = (
            await self._session.execute(
                select(AccessGrantRow)
                .where(
                    AccessGrantRow.subject_kind == kind.value,
                    AccessGrantRow.subject_id == subject_id,
                )
                .order_by(AccessGrantRow.created_at.desc())
            )
        ).scalars()
        return [self._to_entity(f) for f in rows]

    async def touch(self, grant_id: str) -> None:
        """Anota que se usó.

        No entra en la transacción de la operación que la usó: si esa falla, el
        intento ocurrió igual, y el registro de uso sirve precisamente para ver
        una credencial activa que nadie esperaba.
        """
        fila = await self._session.get(AccessGrantRow, grant_id)
        if fila is not None:
            fila.last_used_at = datetime.now(timezone.utc)
            await self._session.commit()

    async def revoke(self, grant_id: str) -> bool:
        fila = await self._session.get(AccessGrantRow, grant_id)
        if fila is None:
            return False
        if fila.revoked_at is None:
            fila.revoked_at = datetime.now(timezone.utc)
            await self._session.commit()
        return True
