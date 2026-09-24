"""Persistencia del contexto de experimentación."""

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ....shared.database import FindingRow, WorklistItemRow, WorklistRow
from ....shared.database_experiment import (
    ParticipantRow,
    SessionRow,
    TransformationRow,
)
from ...domain.entities.participant import Participant
from ...domain.services.counterbalancer import Assignment
from ...domain.value_objects.condition import Condition


class SqlParticipantRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    @staticmethod
    def _to_entity(r: ParticipantRow) -> Participant:
        return Participant(
            id=UUID(r.id),
            anonymous_code=r.anonymous_code,
            experience_band=r.experience_band,
            main_language=r.main_language,
            alert_frequency=r.alert_frequency,
            security_training=r.security_training,
            consented_at=r.consented_at,
            has_security_role=r.has_security_role,
            is_pilot=r.is_pilot,
        )

    async def save(self, participant: Participant) -> None:
        self._session.add(
            ParticipantRow(
                id=str(participant.id),
                anonymous_code=participant.anonymous_code,
                experience_band=participant.experience_band,
                main_language=participant.main_language,
                alert_frequency=participant.alert_frequency,
                security_training=participant.security_training,
                has_security_role=participant.has_security_role,
                is_pilot=participant.is_pilot,
                consented_at=participant.consented_at,
            )
        )
        await self._session.commit()

    async def get(self, participant_id: UUID) -> Participant | None:
        row = await self._session.get(ParticipantRow, str(participant_id))
        return self._to_entity(row) if row else None

    async def get_by_code(self, code: str) -> Participant | None:
        row = (
            await self._session.execute(
                select(ParticipantRow).where(ParticipantRow.anonymous_code == code)
            )
        ).scalar_one_or_none()
        return self._to_entity(row) if row else None

    async def list_all(self) -> list[Participant]:
        rows = (
            await self._session.execute(
                select(ParticipantRow).order_by(ParticipantRow.created_at)
            )
        ).scalars()
        return [self._to_entity(r) for r in rows]


class SqlSessionRepository:
    """Sesiones y el historial de órdenes que alimenta el contrabalanceo."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, participant_id: UUID, assignment: Assignment) -> UUID:
        session_id = uuid4()
        self._session.add(
            SessionRow(
                id=str(session_id),
                participant_id=str(participant_id),
                condition_order=[c.value for c in assignment.order],
                first_batch=assignment.first_batch,
                second_batch=assignment.second_batch,
            )
        )
        await self._session.commit()
        return session_id

    async def record_theme(self, participant_id: UUID, theme: str) -> bool:
        """Anota con qué presentación resolvió la tarea este participante.

        Se escribe una sola vez, al empezar. Un segundo intento con otro valor
        se rechaza: si el tema hubiera cambiado a mitad de sesión, dejarlo
        registrar el último valor ocultaría justamente el problema que US032
        existe para impedir.
        """
        fila = (
            await self._session.execute(
                select(SessionRow).where(
                    SessionRow.participant_id == str(participant_id)
                )
            )
        ).scalars().first()
        if fila is None:
            return False
        if fila.theme is not None and fila.theme != theme:
            return False
        fila.theme = theme
        await self._session.commit()
        return True

    async def theme_of(self, participant_id: UUID) -> str | None:
        fila = (
            await self._session.execute(
                select(SessionRow).where(
                    SessionRow.participant_id == str(participant_id)
                )
            )
        ).scalars().first()
        return fila.theme if fila else None

    async def assignments(self) -> dict[UUID, dict]:
        """El reparto de cada participante, por participante.

        El listado los emparejaba por posicion contra la lista de ordenes, que
        ademas excluye a los pilotos: con un piloto de por medio, cada persona
        aparecia con el reparto de otra, y esa es la pantalla desde la que se
        comprueba el contrabalanceo antes de convocar al siguiente.
        """
        filas = (
            await self._session.execute(
                select(
                    SessionRow.participant_id,
                    SessionRow.condition_order,
                    SessionRow.first_batch,
                    SessionRow.second_batch,
                ).order_by(SessionRow.started_at)
            )
        ).all()
        return {
            UUID(f.participant_id): {
                "order": list(f.condition_order or []),
                "first_batch": f.first_batch,
                "second_batch": f.second_batch,
            }
            for f in filas
        }

    async def existing_orders(self) -> list[tuple[Condition, Condition]]:
        """Órdenes ya asignadas. Es lo que el contrabalanceo consulta.

        Al derivarse del historial persistido, la asignación es reproducible: dos
        ejecuciones sobre la misma base producen el mismo reparto.
        """
        # Las sesiones del piloto quedan fuera. Si contaran, el primero de
        # los participantes reales recibiría el orden que equilibra una
        # cuenta que incluye a alguien cuyos datos el protocolo excluye, y
        # el reparto de la muestra saldría desviado sin que nada lo delatara.
        rows = (
            await self._session.execute(
                select(SessionRow.condition_order)
                .join(ParticipantRow,
                      ParticipantRow.id == SessionRow.participant_id)
                .where(ParticipantRow.is_pilot.is_(False))
                .order_by(SessionRow.started_at)
            )
        ).scalars()
        ordenes: list[tuple[Condition, Condition]] = []
        for valores in rows:
            if valores and len(valores) == 2:
                ordenes.append((Condition(valores[0]), Condition(valores[1])))
        return ordenes

    async def close(self, session_id: UUID, complete: bool) -> None:
        """Cierra la sesión marcando si quedó completa.

        Una sesión incompleta conserva sus decisiones y se marca, de modo que el
        análisis pueda excluirla de forma explícita en lugar de descubrirla como
        un hueco en los datos.
        """
        await self._session.execute(
            update(SessionRow)
            .where(SessionRow.id == str(session_id))
            .values(is_complete=complete, finished_at=datetime.now(timezone.utc))
        )
        await self._session.commit()




class SqlTransformationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def record_pair(
        self,
        original_id: UUID,
        transformed_id: UUID,
        transformation_type: str,
        anchoring_enabled: bool,
        original_verdict: str | None = None,
        transformed_verdict: str | None = None,
        description: str | None = None,
    ) -> None:
        self._session.add(
            TransformationRow(
                id=str(uuid4()),
                original_finding_id=str(original_id),
                transformed_finding_id=str(transformed_id),
                kind=transformation_type,
                anchoring_enabled=anchoring_enabled,
                original_verdict=original_verdict,
                transformed_verdict=transformed_verdict,
                description=description,
            )
        )
        await self._session.commit()

    async def list_by_anchoring(self, anchoring_enabled: bool) -> list[TransformationRow]:
        return list(
            (
                await self._session.execute(
                    select(TransformationRow).where(
                        TransformationRow.anchoring_enabled.is_(anchoring_enabled)
                    )
                )
            ).scalars()
        )


class SqlBatchRepository:
    """El lote congelado de las sesiones, mitad por mitad.

    Vive en `worklists`, que es la lista de trabajo del producto, y no en una
    tabla propia del estudio. Lo que distingue al lote es `frozen_at`: el
    protocolo exige fijarlo antes de reclutar, y una lista del producto se
    reordena cuando quiera.
    """

    NOMBRE = "Lote del estudio"

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def _frozen(self) -> WorklistRow | None:
        return (
            await self._session.execute(
                select(WorklistRow)
                .where(WorklistRow.frozen_at.is_not(None))
                .order_by(WorklistRow.frozen_at.desc())
            )
        ).scalars().first()

    async def execution_id(self) -> UUID | None:
        """Sobre qué ejecución corre el estudio. La pantalla de sesión la
        necesita para pedir los hallazgos, y el participante no la sabe."""
        lista = await self._frozen()
        return UUID(lista.execution_id) if lista else None

    async def finding_ids(self, batch: str) -> list[UUID]:
        """Los hallazgos de una mitad, en el orden registrado."""
        lista = await self._frozen()
        if lista is None:
            return []
        filas = (
            await self._session.execute(
                select(WorklistItemRow)
                .where(
                    WorklistItemRow.worklist_id == lista.id,
                    WorklistItemRow.bucket == batch,
                )
                .order_by(WorklistItemRow.position)
            )
        ).scalars()
        return [UUID(f.finding_id) for f in filas]

    async def batches(self) -> dict[str, int]:
        """Cuantos hallazgos tiene cada mitad. Sirve para comprobar de un
        vistazo que el lote esta cargado antes de convocar a nadie."""
        lista = await self._frozen()
        if lista is None:
            return {}
        filas = (
            await self._session.execute(
                select(WorklistItemRow).where(
                    WorklistItemRow.worklist_id == lista.id
                )
            )
        ).scalars()
        cuenta: dict[str, int] = {}
        for f in filas:
            if f.bucket:
                cuenta[f.bucket] = cuenta.get(f.bucket, 0) + 1
        return dict(sorted(cuenta.items()))

    async def replace_all(self, items: list[tuple[str, str, int]]) -> int:
        """Sustituye el lote entero. Recibe (finding_id, batch, position).

        Se reemplaza y no se anade: el lote es uno solo y dejar restos de una
        carga anterior produciria mitades de tamano equivocado sin que nada lo
        delate. La ejecucion sale de los propios hallazgos, que es de donde el
        que llama la sabe.
        """
        await self._session.execute(delete(WorklistRow))
        if not items:
            await self._session.commit()
            return 0

        execution_id = (
            await self._session.execute(
                select(FindingRow.execution_id).where(
                    FindingRow.id == items[0][0]
                )
            )
        ).scalar_one_or_none()
        if execution_id is None:
            raise ValueError(
                f"El hallazgo {items[0][0]} no esta en esta base, de modo que "
                "no se sabe sobre que ejecucion se congela el lote"
            )

        lista = WorklistRow(
            id=str(uuid4()),
            execution_id=execution_id,
            name=self.NOMBRE,
            frozen_at=datetime.now(timezone.utc),
        )
        self._session.add(lista)
        for finding_id, batch, position in items:
            self._session.add(
                WorklistItemRow(
                    id=str(uuid4()),
                    worklist_id=lista.id,
                    finding_id=finding_id,
                    bucket=batch,
                    position=position,
                )
            )
        await self._session.commit()
        return len(items)
