"""Persistencia del contexto de experimentación."""

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ....shared.database_experiment import (
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
            anonymous_code=r.codigo_anonimo,
            years_of_experience=r.anios_experiencia,
            consented_at=r.consentimiento_en,
            has_security_role=r.tiene_rol_seguridad,
        )

    async def save(self, participant: Participant) -> None:
        self._session.add(
            ParticipantRow(
                id=str(participant.id),
                codigo_anonimo=participant.anonymous_code,
                anios_experiencia=participant.years_of_experience,
                tiene_rol_seguridad=participant.has_security_role,
                consentimiento_en=participant.consented_at,
            )
        )
        await self._session.commit()

    async def get(self, participant_id: UUID) -> Participant | None:
        row = await self._session.get(ParticipantRow, str(participant_id))
        return self._to_entity(row) if row else None

    async def get_by_code(self, code: str) -> Participant | None:
        row = (
            await self._session.execute(
                select(ParticipantRow).where(ParticipantRow.codigo_anonimo == code)
            )
        ).scalar_one_or_none()
        return self._to_entity(row) if row else None

    async def list_all(self) -> list[Participant]:
        rows = (
            await self._session.execute(
                select(ParticipantRow).order_by(ParticipantRow.creado_en)
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
                participante_id=str(participant_id),
                orden_condiciones=[c.value for c in assignment.order],
                lote_primero=assignment.first_batch,
                lote_segundo=assignment.second_batch,
            )
        )
        await self._session.commit()
        return session_id

    async def existing_orders(self) -> list[tuple[Condition, Condition]]:
        """Órdenes ya asignadas. Es lo que el contrabalanceo consulta.

        Al derivarse del historial persistido, la asignación es reproducible: dos
        ejecuciones sobre la misma base producen el mismo reparto.
        """
        rows = (
            await self._session.execute(
                select(SessionRow.orden_condiciones).order_by(SessionRow.iniciada_en)
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
            .values(completa=complete, finalizada_en=datetime.now(timezone.utc))
        )
        await self._session.commit()


class SqlDecisionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    @staticmethod
    def _to_entity(r: DecisionRow) -> Decision:
        return Decision(
            id=UUID(r.id),
            finding_id=UUID(r.hallazgo_id),
            participant_id=UUID(r.participante_id),
            value=DecisionValue(r.valor),
            seconds=r.segundos,
            condition=Condition(r.condicion),
            is_current=r.es_vigente,
            comment=r.comentario,
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
                DecisionRow.hallazgo_id == str(decision.finding_id),
                DecisionRow.participante_id == str(decision.participant_id),
                DecisionRow.condicion == decision.condition.value,
                DecisionRow.es_vigente.is_(True),
            )
            .values(es_vigente=False)
        )
        self._session.add(
            DecisionRow(
                id=str(decision.id),
                sesion_id=str(session_id) if session_id else None,
                hallazgo_id=str(decision.finding_id),
                participante_id=str(decision.participant_id),
                valor=decision.value.value,
                segundos=decision.seconds,
                condicion=decision.condition.value,
                es_vigente=decision.is_current,
                comentario=decision.comment,
            )
        )
        await self._session.commit()

    async def list_current_by_participant(
        self, participant_id: UUID
    ) -> list[Decision]:
        rows = (
            await self._session.execute(
                select(DecisionRow).where(
                    DecisionRow.participante_id == str(participant_id),
                    DecisionRow.es_vigente.is_(True),
                )
            )
        ).scalars()
        return [self._to_entity(r) for r in rows]

    async def list_all_current(self) -> list[Decision]:
        rows = (
            await self._session.execute(
                select(DecisionRow)
                .where(DecisionRow.es_vigente.is_(True))
                .order_by(DecisionRow.creada_en)
            )
        ).scalars()
        return [self._to_entity(r) for r in rows]

    async def history_for(self, finding_id: UUID) -> list[Decision]:
        rows = (
            await self._session.execute(
                select(DecisionRow)
                .where(DecisionRow.hallazgo_id == str(finding_id))
                .order_by(DecisionRow.creada_en)
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
                hallazgo_original_id=str(original_id),
                hallazgo_transformado_id=str(transformed_id),
                tipo=transformation_type,
                anclaje_activo=anchoring_enabled,
                veredicto_original=original_verdict,
                veredicto_transformado=transformed_verdict,
                descripcion=description,
            )
        )
        await self._session.commit()

    async def list_by_anchoring(self, anchoring_enabled: bool) -> list[TransformationRow]:
        return list(
            (
                await self._session.execute(
                    select(TransformationRow).where(
                        TransformationRow.anclaje_activo.is_(anchoring_enabled)
                    )
                )
            ).scalars()
        )
