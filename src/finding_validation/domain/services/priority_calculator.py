from ..entities.finding import Finding
from ..entities.verdict import Verdict, VerdictValue
from ..value_objects.priority import Priority

# Peso de cada señal en el puntaje final. Suman 1.0.
_W_VERDICT = 0.50
_W_CONFIDENCE = 0.20
_W_SEVERITY = 0.20
_W_ANCHOR = 0.10

_VERDICT_WEIGHT = {
    # Lo que no se pudo justificar sube, no baja: no poder justificar es señal
    # de riesgo, no prueba de que no lo haya.
    VerdictValue.NOT_VERIFIABLE: 0.90,
    VerdictValue.EXPLOITABLE: 1.00,
    VerdictValue.UNDETERMINED: 0.55,
    VerdictValue.NOT_EXPLOITABLE: 0.10,
}

_SEVERITY_WEIGHT = {"error": 1.00, "warning": 0.60, "note": 0.25}


class PriorityCalculator:
    """Ordena, nunca suprime.

    Un hallazgo mal ordenado sigue ahí para que alguien lo encuentre; uno
    suprimido no.
    """

    def calculate(self, finding: Finding, verdict: Verdict) -> Priority:
        verdict_weight = _VERDICT_WEIGHT[verdict.value]
        severity_weight = _SEVERITY_WEIGHT.get(finding.severity.lower(), 0.60)

        # Sin confianza declarada se asume el punto medio: no premia ni castiga.
        confidence = verdict.confidence if verdict.confidence is not None else 0.5

        # Señal débil a propósito: el anclaje ya pesa por el lado del veredicto
        # cuando el hallazgo pasa a no verificable.
        anchor = 1.0 if verdict.anchor_verified else 0.4

        score = (
            _W_VERDICT * verdict_weight
            + _W_CONFIDENCE * confidence
            + _W_SEVERITY * severity_weight
            + _W_ANCHOR * anchor
        )

        return Priority(score=round(score, 4), reason=self._explain(finding, verdict))

    def _explain(self, finding: Finding, verdict: Verdict) -> str:
        if verdict.value is VerdictValue.NOT_VERIFIABLE:
            return (
                "El modelo no logró sostener su conclusión con líneas existentes. "
                "Se eleva por precaución: requiere revisión humana."
            )
        partes = [f"veredicto {verdict.value.value}"]
        if verdict.confidence is not None:
            partes.append(f"confianza {verdict.confidence:.2f}")
        partes.append(f"severidad {finding.severity}")
        if not verdict.anchor_verified:
            partes.append("sin anclaje verificado")
        return ", ".join(partes)

    def rank(
        self, pairs: list[tuple[Finding, Verdict]]
    ) -> list[tuple[Finding, Verdict, Priority]]:
        """Devuelve tantos elementos como recibió. Empata por huella para que el
        orden no dependa del de llegada."""
        scored = [(f, v, self.calculate(f, v)) for f, v in pairs]
        scored.sort(key=lambda t: (-t[2].score, t[0].fingerprint.value))
        return scored
