"""Las cuatro etapas sobre un hallazgo.

Coordina, no decide: las reglas están en el dominio. Por eso se pueden probar
sin proveedor y sin base de datos.
"""

import logging
from dataclasses import dataclass, field

from ....domain.entities.code_context import CodeContext
from ....domain.entities.finding import Finding
from ....domain.entities.verdict import Verdict, VerdictValue
from ....domain.services.anchor_verifier import AnchorVerifier
from ....domain.services.budget_guard import BudgetExhausted, BudgetGuard
from ....domain.services.code_reader_port import CodeReaderPort
from ....domain.services.deterministic_prefilter import (
    DeterministicPrefilter,
    PrefilterOutcome,
)
from ....domain.services.language_model_port import LanguageModelPort
from ....domain.value_objects.justification import Justification
from ....domain.value_objects.prompt_version import PromptVersion

logger = logging.getLogger(__name__)

MAX_ATTEMPTS = 2


@dataclass
class ValidationOutcome:
    """Resultado de validar un hallazgo, con la traza de cómo se llegó a él."""

    finding: Finding
    context: CodeContext | None
    verdict: Verdict | None
    trace: list[str] = field(default_factory=list)
    error: str | None = None
    # Se declara en vez de deducirse del texto del error. Quien decide si
    # aborta el lote necesita distinguir «no encuentro el codigo» de «el
    # proveedor fallo», y mirar dentro de una cadena para averiguarlo rompe en
    # cuanto alguien reescribe el mensaje.
    context_failed: bool = False

    @property
    def succeeded(self) -> bool:
        return self.verdict is not None


class ValidateFindingCommandService:
    """Servicio de aplicación de la cadena de validación."""

    def __init__(
        self,
        code_reader: CodeReaderPort,
        language_model: LanguageModelPort,
        anchor_verifier: AnchorVerifier,
        prefilter: DeterministicPrefilter,
        budget: BudgetGuard,
        prompt_version: PromptVersion,
        verdict_cache: dict[str, Verdict] | None = None,
    ) -> None:
        self._reader = code_reader
        self._model = language_model
        self._verifier = anchor_verifier
        self._prefilter = prefilter
        self._budget = budget
        self._prompt_version = prompt_version
        # Clave: huella + modelo + versión. Reutilizar exige que las tres
        # coincidan: un veredicto de otro modelo no responde por este.
        self._cache: dict[str, Verdict] = verdict_cache if verdict_cache is not None else {}

    def _cache_key(self, finding: Finding) -> str:
        return (
            f"{finding.fingerprint.value}|{self._model.model_name}"
            f"|{self._model.model_version}"
        )

    async def execute(
        self, finding: Finding, caller_depth: int = 2, repetition: int = 1
    ) -> ValidationOutcome:
        outcome = ValidationOutcome(finding=finding, context=None, verdict=None)

        # --- Nivel 1 de la cascada: reutilización por huella ---------------
        cached = self._cache.get(self._cache_key(finding))
        if cached is not None:
            self._budget.record_reuse()
            outcome.trace.append(
                f"Reutilizado del veredicto {cached.id} por coincidencia de huella "
                f"{finding.fingerprint.short}. Costo cero."
            )
            outcome.verdict = self._clone_reused(cached, finding, repetition)
            return outcome

        # --- Etapa 1: recuperación de contexto ------------------------------
        try:
            context = await self._reader.recover_context(finding, caller_depth)
        except Exception as exc:  # noqa: BLE001 - el adaptador define sus fallos
            outcome.error = f"No se pudo recuperar el contexto: {exc}"
            outcome.context_failed = True
            outcome.trace.append(outcome.error)
            return outcome

        outcome.context = context
        outcome.trace.append(
            f"Contexto recuperado: {context.recovered_line_count} líneas, "
            f"función {context.enclosing_function}"
            + (", degradado a archivo" if context.degraded_to_file else "")
        )

        # --- Nivel 2 de la cascada: filtro determinista ----------------------
        decision = self._prefilter.decide(finding, context)
        outcome.trace.append(decision.reason)
        if decision.outcome is PrefilterOutcome.RESOLVED_BY_RULE:
            self._budget.record_rule_resolution()
            outcome.verdict = self._verdict_by_rule(finding, decision.reason, repetition)
            self._cache[self._cache_key(finding)] = outcome.verdict
            return outcome

        # --- Etapas 2 y 3: juicio del modelo y verificación de anclaje -------
        retry_hint: str | None = None
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                self._budget.reserve()
            except BudgetExhausted as exc:
                outcome.error = str(exc)
                outcome.trace.append(outcome.error)
                return outcome

            try:
                judgement = await self._model.judge(finding, context, retry_hint)
            except Exception as exc:  # noqa: BLE001 - el adaptador define sus fallos
                # Una consulta fallida es de este hallazgo y no del lote. Antes
                # subia sin atrapar y se llevaba por delante la corrida entera:
                # una sola respuesta fuera de contrato entre decenas dejaba el
                # lote sin ordenar y la ejecucion sin contar lo ya validado,
                # aunque todos los veredictos anteriores estuvieran guardados.
                # Se registra como fallo, el hallazgo queda pendiente y el
                # siguiente intento lo retoma sin volver a pagar por los demas.
                outcome.error = f"La consulta al modelo falló: {exc}"
                outcome.trace.append(outcome.error)
                return outcome
            self._budget.record_usage(judgement.input_tokens, judgement.output_tokens)

            justification = Justification.from_model_output(
                judgement.justification_text, judgement.cited_lines
            )
            anchor = self._verifier.verify(justification, context)
            outcome.trace.append(f"Intento {attempt}: {anchor.reason}")

            if anchor.verified or attempt == MAX_ATTEMPTS:
                value = self._verifier.resolve_value(
                    self._parse_value(judgement.value), anchor, attempts=attempt
                )
                if not anchor.verified:
                    outcome.trace.append(
                        "Anclaje no verificado tras el reintento: el hallazgo se "
                        "marca como no verificable y asciende en el orden."
                    )
                outcome.verdict = Verdict(
                    finding_id=finding.id,
                    model=self._model.model_name,
                    model_version=self._model.model_version,
                    value=value,
                    justification=justification,
                    anchor_verified=anchor.verified,
                    confidence=judgement.confidence,
                    repetition=repetition,
                    attempts=attempt,
                    latency_ms=judgement.latency_ms,
                    input_tokens=judgement.input_tokens,
                    output_tokens=judgement.output_tokens,
                )
                self._cache[self._cache_key(finding)] = outcome.verdict
                return outcome

            retry_hint = anchor.as_retry_hint()
            outcome.trace.append(f"Reintento dirigido: {retry_hint}")

        return outcome  # inalcanzable, el bucle siempre retorna

    @staticmethod
    def _parse_value(raw: str) -> VerdictValue:
        try:
            return VerdictValue(str(raw).strip().lower())
        except ValueError:
            # Una respuesta fuera del contrato no se interpreta ni se adivina.
            return VerdictValue.UNDETERMINED

    def _verdict_by_rule(
        self, finding: Finding, reason: str, repetition: int
    ) -> Verdict:
        """Veredicto emitido sin consultar al modelo.

        Se marca con el modelo `regla-determinista` para que la medición pueda
        separar lo resuelto por regla de lo resuelto por juicio del modelo.
        """
        return Verdict(
            finding_id=finding.id,
            model="regla-determinista",
            model_version=self._prompt_version.identifier,
            value=VerdictValue.NOT_EXPLOITABLE,
            justification=Justification(
                text=reason,
                cited_lines=frozenset({finding.location.start_line}),
            ),
            anchor_verified=True,
            confidence=None,
            repetition=repetition,
        )

    @staticmethod
    def _clone_reused(source: Verdict, finding: Finding, repetition: int) -> Verdict:
        return Verdict(
            finding_id=finding.id,
            model=source.model,
            model_version=source.model_version,
            value=source.value,
            justification=source.justification,
            anchor_verified=source.anchor_verified,
            confidence=source.confidence,
            repetition=repetition,
            attempts=source.attempts,
            reused_from=source.id,
        )
