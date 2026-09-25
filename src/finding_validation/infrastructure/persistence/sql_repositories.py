"""Los puertos de persistencia sobre SQLAlchemy.

Traducen entre entidades y filas. El dominio nunca ve una fila, y la fila nunca
lleva lógica.
"""

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ....shared.database import (
    DecisionRow,
    ContextRow,
    ExecutionRow,
    FindingRow,
    VerdictRow,
)
from ...domain.entities.decision import Decision, DecisionValue
from ...domain.entities.code_context import CodeContext
from ...domain.entities.execution import Execution, ExecutionStatus
from ...domain.entities.finding import Finding
from ...domain.entities.verdict import Verdict, VerdictValue
from ...domain.value_objects.code_location import CodeLocation
from ...domain.value_objects.fingerprint import Fingerprint
from ...domain.value_objects.justification import Justification
from ...domain.value_objects.scope_filter import ScopeFilter


# --------------------------------------------------------------- ejecuciones
class SqlExecutionRepository:
    """Persistencia de ejecuciones y reclamo de la cola."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    @staticmethod
    def _to_row(e: Execution) -> ExecutionRow:
        return ExecutionRow(
            id=str(e.id),
            project_id=str(e.project_id),
            tool_name=e.tool_name,
            ruleset_version=e.ruleset_version,
            status=e.status.value,
            scope=e.scope.describe(),
            total_findings=e.total_findings,
            validated_findings=e.validated_findings,
            claimed_by=e.claimed_by,
            failure_reason=e.failure_reason,
            last_attempt_note=e.last_attempt_note,
            last_attempt_at=e.last_attempt_at,
            context_purged=e.context_purged,
            created_by=str(e.created_by) if e.created_by else None,
            started_at=e.started_at,
            finished_at=e.finished_at,
            created_at=e.created_at,
        )

    @staticmethod
    def _to_entity(r: ExecutionRow) -> Execution:
        return Execution(
            id=UUID(r.id),
            project_id=UUID(r.project_id),
            tool_name=r.tool_name,
            ruleset_version=r.ruleset_version,
            status=ExecutionStatus(r.status),
            total_findings=r.total_findings,
            validated_findings=r.validated_findings,
            scope=ScopeFilter.unrestricted(),
            claimed_by=r.claimed_by,
            failure_reason=r.failure_reason,
            last_attempt_note=r.last_attempt_note,
            last_attempt_at=r.last_attempt_at,
            context_purged=r.context_purged,
            created_by=UUID(r.created_by) if r.created_by else None,
            started_at=r.started_at,
            finished_at=r.finished_at,
            created_at=r.created_at,
        )

    async def save(self, execution: Execution) -> None:
        existing = await self._session.get(ExecutionRow, str(execution.id))
        if existing is None:
            self._session.add(self._to_row(execution))
        else:
            existing.status = execution.status.value
            existing.total_findings = execution.total_findings
            existing.validated_findings = execution.validated_findings
            existing.claimed_by = execution.claimed_by
            existing.failure_reason = execution.failure_reason
            existing.last_attempt_note = execution.last_attempt_note
            existing.last_attempt_at = execution.last_attempt_at
            existing.context_purged = execution.context_purged
            existing.started_at = execution.started_at
            existing.finished_at = execution.finished_at
        await self._session.commit()

    async def get(self, execution_id: UUID) -> Execution | None:
        row = await self._session.get(ExecutionRow, str(execution_id))
        return self._to_entity(row) if row else None

    async def claim_next_pending(
        self, worker: str, project_id: UUID | None = None
    ) -> Execution | None:
        """La pendiente más antigua, sin que otro trabajador la tome.

        En PostgreSQL, bloqueo de fila con SKIP LOCKED: los demás saltan la que
        ya está tomada en vez de esperarla. En el resto de motores se cae a una
        actualización condicionada, que da la misma garantía con contención.
        """
        dialect = self._session.bind.dialect.name if self._session.bind else ""

        # El filtro por proyecto no es un lujo. El trabajador lee el codigo de
        # SU disco, de modo que reclamar una ejecucion de otro repositorio la
        # consume entera marcandolo todo como fallo, y el trabajador que si
        # tenia ese codigo ya no la encuentra porque dejo de estar pendiente.
        # Sin el filtro, una sola base solo puede servir a un repositorio.
        condiciones = [ExecutionRow.status == ExecutionStatus.PENDING.value]
        if project_id is not None:
            condiciones.append(ExecutionRow.project_id == str(project_id))

        stmt = (
            select(ExecutionRow)
            .where(*condiciones)
            .order_by(ExecutionRow.created_at)
            .limit(1)
        )
        if dialect == "postgresql":
            stmt = stmt.with_for_update(skip_locked=True)

        row = (await self._session.execute(stmt)).scalar_one_or_none()
        if row is None:
            return None

        if dialect != "postgresql":
            # Garantiza la exclusión comprobando el estado en el propio UPDATE:
            # si otro lo tomó entre el SELECT y el UPDATE, no afecta filas.
            result = await self._session.execute(
                update(ExecutionRow)
                .where(
                    ExecutionRow.id == row.id,
                    ExecutionRow.status == ExecutionStatus.PENDING.value,
                )
                .values(
                    status=ExecutionStatus.IN_PROGRESS.value,
                    claimed_by=worker,
                    started_at=datetime.now(timezone.utc),
                )
            )
            if result.rowcount == 0:
                await self._session.commit()
                return None
            await self._session.commit()
            await self._session.refresh(row)
            return self._to_entity(row)

        row.status = ExecutionStatus.IN_PROGRESS.value
        row.claimed_by = worker
        row.started_at = datetime.now(timezone.utc)
        await self._session.commit()
        return self._to_entity(row)

    async def list_by_project(self, project_id: UUID) -> list[Execution]:
        rows = (
            await self._session.execute(
                select(ExecutionRow)
                .where(ExecutionRow.project_id == str(project_id))
                .order_by(ExecutionRow.created_at.desc())
            )
        ).scalars()
        return [self._to_entity(r) for r in rows]


# ----------------------------------------------------------------- hallazgos
class SqlFindingRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    @staticmethod
    def _to_entity(r: FindingRow) -> Finding:
        return Finding(
            id=UUID(r.id),
            rule_id=r.rule_id,
            severity=r.rule_severity,
            location=CodeLocation(r.file_path, r.start_line, r.end_line),
            fingerprint=Fingerprint(r.fingerprint),
            cwe=r.cwe,
            message=r.message,
            known_truth=r.known_truth,
        )

    async def save_all(self, findings: list[Finding], execution_id: UUID) -> None:
        self._session.add_all(
            FindingRow(
                id=str(f.id),
                execution_id=str(execution_id),
                rule_id=f.rule_id,
                cwe=f.cwe,
                rule_severity=f.severity,
                file_path=f.location.file_path,
                start_line=f.location.start_line,
                end_line=f.location.end_line,
                message=f.message,
                fingerprint=f.fingerprint.value,
                known_truth=f.known_truth,
            )
            for f in findings
        )
        await self._session.commit()

    async def get(self, finding_id: UUID) -> Finding | None:
        row = await self._session.get(FindingRow, str(finding_id))
        return self._to_entity(row) if row else None

    async def list_by_execution(self, execution_id: UUID) -> list[Finding]:
        rows = (
            await self._session.execute(
                select(FindingRow)
                .where(FindingRow.execution_id == str(execution_id))
                .order_by(FindingRow.priority.desc().nullslast(), FindingRow.fingerprint)
            )
        ).scalars()
        return [self._to_entity(r) for r in rows]

    async def list_pending_validation(
        self, execution_id: UUID, limit: int | None = None
    ) -> list[Finding]:
        """Los que no tienen ningún veredicto todavía.

        Es lo que permite reanudar sin repetir: al retomar una ejecución
        interrumpida, no se vuelve a pagar por lo ya validado.
        """
        con_veredicto = select(VerdictRow.finding_id).distinct()
        stmt = (
            select(FindingRow)
            .where(
                FindingRow.execution_id == str(execution_id),
                FindingRow.id.not_in(con_veredicto),
            )
            .order_by(FindingRow.created_at)
        )
        if limit:
            stmt = stmt.limit(limit)
        rows = (await self._session.execute(stmt)).scalars()
        return [self._to_entity(r) for r in rows]

    async def set_priority(self, finding_id: UUID, score: float, reason: str) -> None:
        await self._session.execute(
            update(FindingRow)
            .where(FindingRow.id == str(finding_id))
            .values(priority=score, priority_reason=reason)
        )
        await self._session.commit()


# ----------------------------------------------------------------- contextos
class SqlCodeContextRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, context: CodeContext) -> None:
        self._session.add(
            ContextRow(
                id=str(context.id),
                finding_id=str(context.finding_id),
                enclosing_function=context.enclosing_function,
                callers=list(context.callers),
                callees=list(context.callees),
                sanitizers=list(context.sanitizers),
                available_lines=sorted(context.available_lines),
                source_expression=context.source_expression,
                caller_depth=context.caller_depth,
                callee_depth=context.callee_depth,
                degraded_to_file=context.degraded_to_file,
                context_text=context.text,
            )
        )
        await self._session.commit()

    async def get_by_finding(self, finding_id: UUID) -> CodeContext | None:
        row = (
            await self._session.execute(
                select(ContextRow).where(ContextRow.finding_id == str(finding_id))
            )
        ).scalar_one_or_none()
        if row is None or row.context_text is None:
            # Sin texto, el contexto fue purgado: no se puede reconstruir ni se
            # debe fingir que sí.
            return None
        return CodeContext(
            id=UUID(row.id),
            finding_id=UUID(row.finding_id),
            enclosing_function=row.enclosing_function,
            text=row.context_text,
            available_lines=frozenset(row.available_lines or []),
            callers=tuple(row.callers or ()),
            callees=tuple(row.callees or ()),
            sanitizers=tuple(row.sanitizers or ()),
            source_expression=row.source_expression,
            caller_depth=row.caller_depth,
            callee_depth=row.callee_depth,
            degraded_to_file=row.degraded_to_file,
        )

    async def purge_by_execution(self, execution_id: UUID) -> int:
        """Borra el texto y conserva el resto.

        Las métricas no dependen del contenido del código, de modo que purgarlo
        no destruye ningún resultado del estudio.
        """
        de_la_ejecucion = select(FindingRow.id).where(
            FindingRow.execution_id == str(execution_id)
        )
        result = await self._session.execute(
            update(ContextRow)
            .where(
                ContextRow.finding_id.in_(de_la_ejecucion),
                ContextRow.context_text.is_not(None),
            )
            .values(context_text=None)
        )
        await self._session.commit()
        return result.rowcount or 0


# ---------------------------------------------------------------- veredictos
class SqlVerdictRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    @staticmethod
    def _to_entity(r: VerdictRow) -> Verdict:
        return Verdict(
            id=UUID(r.id),
            finding_id=UUID(r.finding_id),
            model=r.model,
            model_version=r.model_version,
            value=VerdictValue(r.value),
            justification=Justification(
                text=r.justification or "(sin justificación registrada)",
                cited_lines=frozenset(r.cited_lines or []),
            ),
            anchor_verified=r.anchor_verified,
            confidence=r.confidence,
            temperature=r.temperature,
            repetition=r.repetition,
            attempts=r.attempts,
            reused_from=UUID(r.reused_from) if r.reused_from else None,
            latency_ms=r.latency_ms,
            input_tokens=r.input_tokens,
            output_tokens=r.output_tokens,
        )

    async def save(self, verdict: Verdict, prompt_version: str | None = None) -> None:
        """Guarda el veredicto, reemplazando el que hubiera para esa corrida.

        La clave es hallazgo, modelo, versión y repetición. Sin reemplazo, una
        corrida que muere a la mitad deja la medición bloqueada: repetirla choca
        contra los veredictos ya escritos y no hay manera de terminarla sin
        borrar a mano. Reemplazar deja el procedimiento repetible, que es
        condición declarada del anexo, y hace que valga siempre el último
        veredicto obtenido con esos mismos parámetros.
        """
        await self._session.execute(
            delete(VerdictRow).where(
                VerdictRow.finding_id == str(verdict.finding_id),
                VerdictRow.model == verdict.model,
                VerdictRow.model_version == verdict.model_version,
                VerdictRow.repetition == verdict.repetition,
            )
        )
        self._session.add(
            VerdictRow(
                id=str(verdict.id),
                finding_id=str(verdict.finding_id),
                model=verdict.model,
                model_version=verdict.model_version,
                prompt_version=prompt_version,
                temperature=verdict.temperature,
                repetition=verdict.repetition,
                value=verdict.value.value,
                confidence=verdict.confidence,
                cited_lines=sorted(verdict.justification.cited_lines),
                anchor_verified=verdict.anchor_verified,
                attempts=verdict.attempts,
                justification=verdict.justification.text,
                latency_ms=verdict.latency_ms,
                input_tokens=verdict.input_tokens,
                output_tokens=verdict.output_tokens,
                reused_from=str(verdict.reused_from) if verdict.reused_from else None,
            )
        )
        await self._session.commit()

    async def get_by_finding(self, finding_id: UUID) -> list[Verdict]:
        rows = (
            await self._session.execute(
                select(VerdictRow)
                .where(VerdictRow.finding_id == str(finding_id))
                .order_by(VerdictRow.created_at)
            )
        ).scalars()
        return [self._to_entity(r) for r in rows]

    async def get_for_run(
        self, finding_id: UUID, model: str, model_version: str, repetition: int
    ) -> Verdict | None:
        """El veredicto de esa corrida exacta, si ya se obtuvo.

        Sirve para reanudar una comparación interrumpida sin volver a pagar lo
        ya medido. Las cuatro condiciones son necesarias: cambiar cualquiera
        describe una corrida distinta.
        """
        row = (
            await self._session.execute(
                select(VerdictRow).where(
                    VerdictRow.finding_id == str(finding_id),
                    VerdictRow.model == model,
                    VerdictRow.model_version == model_version,
                    VerdictRow.repetition == repetition,
                )
            )
        ).scalar_one_or_none()
        return self._to_entity(row) if row else None

    async def find_reusable(
        self, fingerprint: Fingerprint, model: str, model_version: str
    ) -> Verdict | None:
        """Las tres condiciones son necesarias.

        Un veredicto de otro modelo, o de otra versión del mismo, no responde
        por este: por eso la versión entra en la búsqueda y no solo la huella.
        """
        row = (
            await self._session.execute(
                select(VerdictRow)
                .join(FindingRow, FindingRow.id == VerdictRow.finding_id)
                .where(
                    FindingRow.fingerprint == fingerprint.value,
                    VerdictRow.model == model,
                    VerdictRow.model_version == model_version,
                    VerdictRow.reused_from.is_(None),
                )
                .order_by(VerdictRow.created_at)
                .limit(1)
            )
        ).scalar_one_or_none()
        return self._to_entity(row) if row else None

    async def list_by_execution(self, execution_id: UUID) -> list[Verdict]:
        rows = (
            await self._session.execute(
                select(VerdictRow)
                .join(FindingRow, FindingRow.id == VerdictRow.finding_id)
                .where(FindingRow.execution_id == str(execution_id))
            )
        ).scalars()
        return [self._to_entity(r) for r in rows]


class SqlDecisionRepository:
    """Las decisiones, las del producto y las del estudio.

    Guardar una nueva retira la vigencia de las anteriores en la misma
    operacion. Hacerlo en dos pasos dejaria, ante un fallo entre medias, dos
    decisiones vigentes sobre el mismo hallazgo, y entonces cual vale seria una
    cuestion de suerte.

    La vigencia se retira por autor y no por hallazgo. El repositorio anterior
    miraba solo el hallazgo, de modo que si dos personas revisaban el mismo, la
    segunda anulaba a la primera sin quererlo.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    @staticmethod
    def _to_entity(r: DecisionRow) -> Decision:
        return Decision(
            id=UUID(r.id),
            finding_id=UUID(r.finding_id),
            user_id=UUID(r.user_id) if r.user_id else None,
            participant_id=UUID(r.participant_id) if r.participant_id else None,
            session_id=UUID(r.session_id) if r.session_id else None,
            worklist_id=UUID(r.worklist_id) if r.worklist_id else None,
            condition=r.condition,
            value=DecisionValue(r.value),
            seconds=r.seconds,
            is_current=r.is_current,
            comment=r.comment,
            created_at=r.created_at,
        )

    async def save(self, decision: Decision) -> None:
        condiciones = [
            DecisionRow.finding_id == str(decision.finding_id),
            DecisionRow.is_current.is_(True),
        ]
        if decision.user_id is not None:
            condiciones.append(DecisionRow.user_id == str(decision.user_id))
        else:
            condiciones.append(
                DecisionRow.participant_id == str(decision.participant_id)
            )
        # La condicion forma parte de la identidad de la medida: el mismo
        # participante resuelve lotes distintos bajo condiciones distintas, y
        # una no rectifica a la otra.
        if decision.condition is not None:
            condiciones.append(DecisionRow.condition == decision.condition)

        await self._session.execute(
            update(DecisionRow).where(*condiciones).values(is_current=False)
        )
        self._session.add(
            DecisionRow(
                id=str(decision.id),
                finding_id=str(decision.finding_id),
                user_id=str(decision.user_id) if decision.user_id else None,
                participant_id=(
                    str(decision.participant_id) if decision.participant_id else None
                ),
                session_id=str(decision.session_id) if decision.session_id else None,
                worklist_id=(
                    str(decision.worklist_id) if decision.worklist_id else None
                ),
                condition=decision.condition,
                value=decision.value.value,
                seconds=decision.seconds,
                is_current=decision.is_current,
                comment=decision.comment,
                created_at=decision.created_at,
            )
        )
        await self._session.commit()

    async def list_by_finding(self, finding_id: UUID) -> list[Decision]:
        """Historial completo, incluidas las rectificadas.

        Conservarlas permite distinguir un cambio de opinion de un dato
        ausente.
        """
        filas = (
            await self._session.execute(
                select(DecisionRow)
                .where(DecisionRow.finding_id == str(finding_id))
                .order_by(DecisionRow.created_at.desc())
            )
        ).scalars()
        return [self._to_entity(f) for f in filas]

    async def list_current_by_execution(self, execution_id: UUID) -> list[Decision]:
        """Las decisiones vigentes sobre los hallazgos de una ejecucion.

        Se unen por el hallazgo porque la decision no guarda la ejecucion: la
        guarda el hallazgo, y duplicar ese dato abriria la puerta a que los dos
        dejaran de coincidir.
        """
        filas = (
            await self._session.execute(
                select(DecisionRow)
                .join(FindingRow, FindingRow.id == DecisionRow.finding_id)
                .where(
                    FindingRow.execution_id == str(execution_id),
                    DecisionRow.is_current.is_(True),
                )
            )
        ).scalars()
        return [self._to_entity(f) for f in filas]

    async def list_current_by_participant(
        self, participant_id: UUID
    ) -> list[Decision]:
        filas = (
            await self._session.execute(
                select(DecisionRow).where(
                    DecisionRow.participant_id == str(participant_id),
                    DecisionRow.is_current.is_(True),
                )
            )
        ).scalars()
        return [self._to_entity(f) for f in filas]

    async def list_all_current(self) -> list[Decision]:
        filas = (
            await self._session.execute(
                select(DecisionRow)
                .where(DecisionRow.is_current.is_(True))
                .order_by(DecisionRow.created_at)
            )
        ).scalars()
        return [self._to_entity(f) for f in filas]