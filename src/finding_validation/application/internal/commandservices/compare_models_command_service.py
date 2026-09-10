"""Corre el mismo lote con varios modelos y contrasta.

Lo único que cambia entre corridas es el adaptador del proveedor: mismo lote,
mismo contexto ya recuperado, mismo verificador, misma consulta. Sin eso la
comparación no diría nada.

Cada modelo lleva su propio presupuesto, para que uno caro no se coma el cupo
de otro.
"""

import logging
from dataclasses import dataclass, field
from uuid import UUID

from .....shared.tracing import Stage, correlate, emit
from ....domain.entities.execution import Execution
from ....domain.entities.verdict import VerdictValue
from ....domain.repositories.repositories import (
    FindingRepository,
    VerdictRepository,
)
from ....domain.services.anchor_verifier import AnchorVerifier
from ....domain.services.budget_guard import BudgetGuard
from ....domain.services.code_reader_port import CodeReaderPort
from ....domain.services.deterministic_prefilter import DeterministicPrefilter
from ....domain.services.language_model_port import LanguageModelPort
from ....domain.value_objects.prompt_version import PromptVersion
from .validate_finding_command_service import ValidateFindingCommandService

logger = logging.getLogger(__name__)


@dataclass
class ModelRun:
    """Resultado de una clase de modelo sobre el lote."""

    model: str
    model_version: str
    repetition: int
    verdicts: dict[UUID, VerdictValue] = field(default_factory=dict)
    anchored_first_try: int = 0
    retries: int = 0
    not_verifiable: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    usd: float = 0.0
    queries: int = 0

    @property
    def anchor_rate(self) -> float:
        return self.anchored_first_try / len(self.verdicts) if self.verdicts else 0.0


@dataclass
class Comparison:
    execution_id: UUID
    runs: list[ModelRun] = field(default_factory=list)

    def agreement(self) -> float:
        """Proporción de hallazgos en que todas las corridas coinciden."""
        if len(self.runs) < 2:
            return 1.0
        comunes = set(self.runs[0].verdicts)
        for r in self.runs[1:]:
            comunes &= set(r.verdicts)
        if not comunes:
            return 0.0
        iguales = sum(
            1 for fid in comunes
            if len({r.verdicts[fid] for r in self.runs}) == 1
        )
        return iguales / len(comunes)

    def disagreements(self) -> list[dict]:
        """Hallazgos donde los modelos no coinciden.

        Son los interesantes: donde el juicio depende del modelo y no del código,
        que es exactamente lo que el estudio quiere caracterizar.
        """
        if len(self.runs) < 2:
            return []
        comunes = set(self.runs[0].verdicts)
        for r in self.runs[1:]:
            comunes &= set(r.verdicts)
        salida = []
        for fid in comunes:
            valores = {r.model: r.verdicts[fid].value for r in self.runs}
            if len(set(valores.values())) > 1:
                salida.append({"finding_id": str(fid), "por_modelo": valores})
        return salida

    def report(self) -> dict:
        return {
            "execution_id": str(self.execution_id),
            "acuerdo": round(self.agreement(), 4),
            "desacuerdos": len(self.disagreements()),
            "modelos": [
                {
                    "modelo": r.model,
                    "version": r.model_version,
                    "repeticion": r.repetition,
                    "veredictos": len(r.verdicts),
                    "anclaje_primera": round(r.anchor_rate, 4),
                    "reintentos": r.retries,
                    "no_verificables": r.not_verifiable,
                    "consultas": r.queries,
                    "usd": round(r.usd, 2),
                }
                for r in self.runs
            ],
        }


class CompareModelsCommandService:
    def __init__(
        self,
        finding_repository: FindingRepository,
        verdict_repository: VerdictRepository,
        code_reader: CodeReaderPort,
        anchor_verifier: AnchorVerifier,
        prefilter: DeterministicPrefilter,
        prompt_version: PromptVersion,
    ) -> None:
        self._findings = finding_repository
        self._verdicts = verdict_repository
        self._reader = code_reader
        self._verifier = anchor_verifier
        self._prefilter = prefilter
        self._prompt_version = prompt_version

    async def compare(
        self,
        execution: Execution,
        models: list[LanguageModelPort],
        repetitions: int = 1,
        max_queries_per_model: int = 1000,
        usd_per_1k_input: float = 0.0,
        usd_per_1k_output: float = 0.0,
        batch_size: int | None = None,
    ) -> Comparison:
        if len(models) < 2:
            raise ValueError(
                "Comparar exige al menos dos modelos. Con uno solo no hay "
                "contraste que medir."
            )

        findings = await self._findings.list_by_execution(execution.id)
        if batch_size:
            findings = findings[:batch_size]

        comparison = Comparison(execution_id=execution.id)

        for model in models:
            for rep in range(1, repetitions + 1):
                # Presupuesto propio: un modelo caro no puede dejar a otro sin
                # cupo y con la medición a medias.
                budget = BudgetGuard(
                    max_queries=max_queries_per_model,
                    usd_per_1k_input=usd_per_1k_input,
                    usd_per_1k_output=usd_per_1k_output,
                )
                # Caché propia por corrida: reutilizar entre repeticiones
                # anularía justo lo que la repetición mide, que es la
                # estabilidad del veredicto.
                validator = ValidateFindingCommandService(
                    code_reader=self._reader,
                    language_model=model,
                    anchor_verifier=self._verifier,
                    prefilter=self._prefilter,
                    budget=budget,
                    prompt_version=self._prompt_version,
                    verdict_cache={},
                )

                run = ModelRun(
                    model=model.model_name,
                    model_version=model.model_version,
                    repetition=rep,
                )

                for finding in findings:
                    with correlate():
                        outcome = await validator.execute(finding, repetition=rep)
                    if not outcome.succeeded or outcome.verdict is None:
                        continue
                    v = outcome.verdict
                    run.verdicts[finding.id] = v.value
                    if v.anchor_verified and v.attempts == 1:
                        run.anchored_first_try += 1
                    if v.needed_retry:
                        run.retries += 1
                    if v.value is VerdictValue.NOT_VERIFIABLE:
                        run.not_verifiable += 1
                    run.input_tokens += v.input_tokens or 0
                    run.output_tokens += v.output_tokens or 0
                    await self._verdicts.save(v)

                run.queries = budget.spent_queries
                run.usd = budget.spent_usd
                comparison.runs.append(run)

                emit(
                    Stage.MODEL,
                    "corrida_completa",
                    modelo=run.model,
                    version=run.model_version,
                    repeticion=rep,
                    veredictos=len(run.verdicts),
                    anclaje=round(run.anchor_rate, 4),
                    consultas=run.queries,
                )

        return comparison
