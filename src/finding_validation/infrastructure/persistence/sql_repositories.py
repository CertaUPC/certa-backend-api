"""Los puertos de persistencia sobre SQLAlchemy.

Traducen entre entidades y filas. El dominio nunca ve una fila, y la fila nunca
lleva lógica.
"""

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ....shared.database import (
    ContextRow,
    ExecutionRow,
    FindingRow,
    VerdictRow,
)
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
            proyecto_id=str(e.project_id),
            herramienta=e.tool_name,
            version_reglas=e.ruleset_version,
            estado=e.status.value,
            alcance=e.scope.describe(),
            total_hallazgos=e.total_findings,
            validados=e.validated_findings,
            tomada_por=e.claimed_by,
            motivo_fallo=e.failure_reason,
            contexto_purgado=e.context_purged,
            iniciada_en=e.started_at,
            finalizada_en=e.finished_at,
            creada_en=e.created_at,
        )

    @staticmethod
    def _to_entity(r: ExecutionRow) -> Execution:
        return Execution(
            id=UUID(r.id),
            project_id=UUID(r.proyecto_id),
            tool_name=r.herramienta,
            ruleset_version=r.version_reglas,
            status=ExecutionStatus(r.estado),
            total_findings=r.total_hallazgos,
            validated_findings=r.validados,
            scope=ScopeFilter.unrestricted(),
            claimed_by=r.tomada_por,
            failure_reason=r.motivo_fallo,
            context_purged=r.contexto_purgado,
            started_at=r.iniciada_en,
            finished_at=r.finalizada_en,
            created_at=r.creada_en,
        )

    async def save(self, execution: Execution) -> None:
        existing = await self._session.get(ExecutionRow, str(execution.id))
        if existing is None:
            self._session.add(self._to_row(execution))
        else:
            existing.estado = execution.status.value
            existing.total_hallazgos = execution.total_findings
            existing.validados = execution.validated_findings
            existing.tomada_por = execution.claimed_by
            existing.motivo_fallo = execution.failure_reason
            existing.contexto_purgado = execution.context_purged
            existing.iniciada_en = execution.started_at
            existing.finalizada_en = execution.finished_at
        await self._session.commit()

    async def get(self, execution_id: UUID) -> Execution | None:
        row = await self._session.get(ExecutionRow, str(execution_id))
        return self._to_entity(row) if row else None

    async def claim_next_pending(self, worker: str) -> Execution | None:
        """La pendiente más antigua, sin que otro trabajador la tome.

        En PostgreSQL, bloqueo de fila con SKIP LOCKED: los demás saltan la que
        ya está tomada en vez de esperarla. En el resto de motores se cae a una
        actualización condicionada, que da la misma garantía con contención.
        """
        dialect = self._session.bind.dialect.name if self._session.bind else ""

        stmt = (
            select(ExecutionRow)
            .where(ExecutionRow.estado == ExecutionStatus.PENDING.value)
            .order_by(ExecutionRow.creada_en)
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
                    ExecutionRow.estado == ExecutionStatus.PENDING.value,
                )
                .values(
                    estado=ExecutionStatus.IN_PROGRESS.value,
                    tomada_por=worker,
                    iniciada_en=datetime.now(timezone.utc),
                )
            )
            if result.rowcount == 0:
                await self._session.commit()
                return None
            await self._session.commit()
            await self._session.refresh(row)
            return self._to_entity(row)

        row.estado = ExecutionStatus.IN_PROGRESS.value
        row.tomada_por = worker
        row.iniciada_en = datetime.now(timezone.utc)
        await self._session.commit()
        return self._to_entity(row)

    async def list_by_project(self, project_id: UUID) -> list[Execution]:
        rows = (
            await self._session.execute(
                select(ExecutionRow)
                .where(ExecutionRow.proyecto_id == str(project_id))
                .order_by(ExecutionRow.creada_en.desc())
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
            rule_id=r.regla_id,
            severity=r.severidad_regla,
            location=CodeLocation(r.archivo, r.linea_inicio, r.linea_fin),
            fingerprint=Fingerprint(r.huella),
            cwe=r.cwe,
            message=r.mensaje,
            known_truth=r.verdad_conocida,
        )

    async def save_all(self, findings: list[Finding], execution_id: UUID) -> None:
        self._session.add_all(
            FindingRow(
                id=str(f.id),
                ejecucion_id=str(execution_id),
                regla_id=f.rule_id,
                cwe=f.cwe,
                severidad_regla=f.severity,
                archivo=f.location.file_path,
                linea_inicio=f.location.start_line,
                linea_fin=f.location.end_line,
                mensaje=f.message,
                huella=f.fingerprint.value,
                verdad_conocida=f.known_truth,
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
                .where(FindingRow.ejecucion_id == str(execution_id))
                .order_by(FindingRow.prioridad.desc().nullslast(), FindingRow.huella)
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
        con_veredicto = select(VerdictRow.hallazgo_id).distinct()
        stmt = (
            select(FindingRow)
            .where(
                FindingRow.ejecucion_id == str(execution_id),
                FindingRow.id.not_in(con_veredicto),
            )
            .order_by(FindingRow.creado_en)
        )
        if limit:
            stmt = stmt.limit(limit)
        rows = (await self._session.execute(stmt)).scalars()
        return [self._to_entity(r) for r in rows]

    async def set_priority(self, finding_id: UUID, score: float, reason: str) -> None:
        await self._session.execute(
            update(FindingRow)
            .where(FindingRow.id == str(finding_id))
            .values(prioridad=score, motivo_prioridad=reason)
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
                hallazgo_id=str(context.finding_id),
                funcion_contenedora=context.enclosing_function,
                llamadores=list(context.callers),
                saneadores=list(context.sanitizers),
                lineas_disponibles=sorted(context.available_lines),
                fuente_identificada=context.source_expression,
                profundidad_llamadores=context.caller_depth,
                degradado_a_archivo=context.degraded_to_file,
                texto_contexto=context.text,
            )
        )
        await self._session.commit()

    async def get_by_finding(self, finding_id: UUID) -> CodeContext | None:
        row = (
            await self._session.execute(
                select(ContextRow).where(ContextRow.hallazgo_id == str(finding_id))
            )
        ).scalar_one_or_none()
        if row is None or row.texto_contexto is None:
            # Sin texto, el contexto fue purgado: no se puede reconstruir ni se
            # debe fingir que sí.
            return None
        return CodeContext(
            id=UUID(row.id),
            finding_id=UUID(row.hallazgo_id),
            enclosing_function=row.funcion_contenedora,
            text=row.texto_contexto,
            available_lines=frozenset(row.lineas_disponibles or []),
            callers=tuple(row.llamadores or ()),
            sanitizers=tuple(row.saneadores or ()),
            source_expression=row.fuente_identificada,
            caller_depth=row.profundidad_llamadores,
            degraded_to_file=row.degradado_a_archivo,
        )

    async def purge_by_execution(self, execution_id: UUID) -> int:
        """Borra el texto y conserva el resto.

        Las métricas no dependen del contenido del código, de modo que purgarlo
        no destruye ningún resultado del estudio.
        """
        de_la_ejecucion = select(FindingRow.id).where(
            FindingRow.ejecucion_id == str(execution_id)
        )
        result = await self._session.execute(
            update(ContextRow)
            .where(
                ContextRow.hallazgo_id.in_(de_la_ejecucion),
                ContextRow.texto_contexto.is_not(None),
            )
            .values(texto_contexto=None)
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
            finding_id=UUID(r.hallazgo_id),
            model=r.modelo,
            model_version=r.version_modelo,
            value=VerdictValue(r.valor),
            justification=Justification(
                text=r.justificacion or "(sin justificación registrada)",
                cited_lines=frozenset(r.lineas_citadas or []),
            ),
            anchor_verified=r.anclaje_verificado,
            confidence=r.confianza,
            temperature=r.temperatura,
            repetition=r.repeticion,
            attempts=r.intentos,
            reused_from=UUID(r.reutilizado_de) if r.reutilizado_de else None,
            latency_ms=r.latencia_ms,
            input_tokens=r.tokens_entrada,
            output_tokens=r.tokens_salida,
        )

    async def save(self, verdict: Verdict, prompt_version: str | None = None) -> None:
        self._session.add(
            VerdictRow(
                id=str(verdict.id),
                hallazgo_id=str(verdict.finding_id),
                modelo=verdict.model,
                version_modelo=verdict.model_version,
                version_consulta=prompt_version,
                temperatura=verdict.temperature,
                repeticion=verdict.repetition,
                valor=verdict.value.value,
                confianza=verdict.confidence,
                lineas_citadas=sorted(verdict.justification.cited_lines),
                anclaje_verificado=verdict.anchor_verified,
                intentos=verdict.attempts,
                justificacion=verdict.justification.text,
                latencia_ms=verdict.latency_ms,
                tokens_entrada=verdict.input_tokens,
                tokens_salida=verdict.output_tokens,
                reutilizado_de=str(verdict.reused_from) if verdict.reused_from else None,
            )
        )
        await self._session.commit()

    async def get_by_finding(self, finding_id: UUID) -> list[Verdict]:
        rows = (
            await self._session.execute(
                select(VerdictRow)
                .where(VerdictRow.hallazgo_id == str(finding_id))
                .order_by(VerdictRow.creado_en)
            )
        ).scalars()
        return [self._to_entity(r) for r in rows]

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
                .join(FindingRow, FindingRow.id == VerdictRow.hallazgo_id)
                .where(
                    FindingRow.huella == fingerprint.value,
                    VerdictRow.modelo == model,
                    VerdictRow.version_modelo == model_version,
                    VerdictRow.reutilizado_de.is_(None),
                )
                .order_by(VerdictRow.creado_en)
                .limit(1)
            )
        ).scalar_one_or_none()
        return self._to_entity(row) if row else None

    async def list_by_execution(self, execution_id: UUID) -> list[Verdict]:
        rows = (
            await self._session.execute(
                select(VerdictRow)
                .join(FindingRow, FindingRow.id == VerdictRow.hallazgo_id)
                .where(FindingRow.ejecucion_id == str(execution_id))
            )
        ).scalars()
        return [self._to_entity(r) for r in rows]
