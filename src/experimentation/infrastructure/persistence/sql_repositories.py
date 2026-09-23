"""Persistencia del contexto de experimentación."""

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ....shared.database import FindingRow
from ....shared.database_experiment import (
    BatchItemRow,
    DecisionRow,
    ParticipantRow,
    SessionRow,
    TransformationRow,
)
from ...domain.entities.decision import Decision
from ...domain.entities.participant import Participant
from ...domain.services.counterbalancer import Assignment
from ...domain.value_objects.condition import Condition, DecisionValue


class SqlParticipantRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    @staticmethod
    def _to_entity(r: ParticipantRow) -> Participant:
        return Participant(
            id=UUID(r.id),
            anonymous_code=r.anonymous_code,
            years_of_experience=r.years_of_experience,
            consented_at=r.consented_at,
            has_security_role=r.has_security_role,
            is_pilot=r.is_pilot,
        )

    async def save(self, participant: Participant) -> None:
        self._session.add(
            ParticipantRow(
                id=str(participant.id),
                anonymous_code=participant.anonymous_code,
                years_of_experience=participant.years_of_experience,
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


class SqlDecisionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    @staticmethod
    def _to_entity(r: DecisionRow) -> Decision:
        return Decision(
            id=UUID(r.id),
            finding_id=UUID(r.finding_id),
            participant_id=UUID(r.participant_id),
            value=DecisionValue(r.value),
            seconds=r.seconds,
            condition=Condition(r.condition),
            is_current=r.is_current,
            comment=r.comment,
        )

    async def record(self, decision: Decision, session_id: UUID | None = None) -> None:
        """Guarda la decisión y jubila la anterior sobre el mismo hallazgo.

        No se borra la anterior: se marca como no vigente. Conservarla permite
        distinguir un cambio de opinión de un dato ausente, y un cambio de
        opinión es información sobre la tarea.
        """
        await self._session.execute(
            update(DecisionRow)
            .where(
                DecisionRow.finding_id == str(decision.finding_id),
                DecisionRow.participant_id == str(decision.participant_id),
                DecisionRow.condition == decision.condition.value,
                DecisionRow.is_current.is_(True),
            )
            .values(is_current=False)
        )
        self._session.add(
            DecisionRow(
                id=str(decision.id),
                session_id=str(session_id) if session_id else None,
                finding_id=str(decision.finding_id),
                participant_id=str(decision.participant_id),
                value=decision.value.value,
                seconds=decision.seconds,
                condition=decision.condition.value,
                is_current=decision.is_current,
                comment=decision.comment,
            )
        )
        await self._session.commit()

    async def list_current_by_execution(self, execution_id: UUID) -> list[Decision]:
        """Las decisiones vigentes sobre los hallazgos de una ejecución.

        Se unen por el hallazgo porque la decisión no guarda la ejecución: la
        guarda el hallazgo, y duplicar ese dato abriría la puerta a que los dos
        dejaran de coincidir.
        """
        rows = (
            await self._session.execute(
                select(DecisionRow)
                .join(FindingRow, FindingRow.id == DecisionRow.finding_id)
                .where(
                    FindingRow.execution_id == str(execution_id),
                    DecisionRow.is_current.is_(True),
                )
            )
        ).scalars()
        return [self._to_entity(r) for r in rows]

    async def list_current_by_participant(
        self, participant_id: UUID
    ) -> list[Decision]:
        rows = (
            await self._session.execute(
                select(DecisionRow).where(
                    DecisionRow.participant_id == str(participant_id),
                    DecisionRow.is_current.is_(True),
                )
            )
        ).scalars()
        return [self._to_entity(r) for r in rows]

    async def list_all_current(self) -> list[Decision]:
        rows = (
            await self._session.execute(
                select(DecisionRow)
                .where(DecisionRow.is_current.is_(True))
                .order_by(DecisionRow.created_at)
            )
        ).scalars()
        return [self._to_entity(r) for r in rows]

    async def history_for(self, finding_id: UUID) -> list[Decision]:
        rows = (
            await self._session.execute(
                select(DecisionRow)
                .where(DecisionRow.finding_id == str(finding_id))
                .order_by(DecisionRow.created_at)
            )
        ).scalars()
        return [self._to_entity(r) for r in rows]


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
    """El lote congelado de las sesiones, mitad por mitad."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def finding_ids(self, batch: str) -> list[UUID]:
        """Los hallazgos de una mitad, en el orden registrado."""
        filas = (
            await self._session.execute(
                select(BatchItemRow)
                .where(BatchItemRow.batch == batch)
                .order_by(BatchItemRow.position)
            )
        ).scalars()
        return [UUID(f.finding_id) for f in filas]

    async def batches(self) -> dict[str, int]:
        """Cuantos hallazgos tiene cada mitad. Sirve para comprobar de un
        vistazo que el lote esta cargado antes de convocar a nadie."""
        filas = (await self._session.execute(select(BatchItemRow))).scalars()
        cuenta: dict[str, int] = {}
        for f in filas:
            cuenta[f.batch] = cuenta.get(f.batch, 0) + 1
        return dict(sorted(cuenta.items()))

    async def replace_all(self, items: list[tuple[str, str, int]]) -> int:
        """Sustituye el lote entero. Recibe (finding_id, batch, position).

        Se reemplaza y no se anade: el lote es uno solo y dejar restos de una
        carga anterior produciria mitades de tamano equivocado sin que nada lo
        delate.
        """
        await self._session.execute(delete(BatchItemRow))
        for finding_id, batch, position in items:
            self._session.add(
                BatchItemRow(
                    finding_id=finding_id, batch=batch, position=position
                )
            )
        await self._session.commit()
        return len(items)
