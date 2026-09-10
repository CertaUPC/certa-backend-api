"""Métricas de la evaluación funcional.

La matriz entera y no solo la exactitud: un modelo que declare explotable todo
saca buena exactitud sobre un conjunto desbalanceado, y solo la matriz lo delata.
"""

from dataclasses import dataclass

# Declarado en el Project Charter. Por encima de esta proporción en una sola
# clase, la corrida no vale para comparar.
DEGENERATE_THRESHOLD = 0.90


@dataclass(frozen=True)
class ConfusionMatrix:
    """Conteos frente a la verdad conocida del conjunto de referencia."""

    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0

    @property
    def total(self) -> int:
        return (
            self.true_positives
            + self.false_positives
            + self.true_negatives
            + self.false_negatives
        )

    @property
    def accuracy(self) -> float:
        if not self.total:
            return 0.0
        return (self.true_positives + self.true_negatives) / self.total

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.false_positives + self.true_negatives
        return self.false_positives / denom if denom else 0.0

    def report(self) -> dict[str, float | int]:
        return {
            "verdaderos_positivos": self.true_positives,
            "falsos_positivos": self.false_positives,
            "verdaderos_negativos": self.true_negatives,
            "falsos_negativos": self.false_negatives,
            "exactitud": round(self.accuracy, 4),
            "precision": round(self.precision, 4),
            "exhaustividad": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "tasa_falsos_positivos": round(self.false_positive_rate, 4),
        }


@dataclass(frozen=True)
class RunQuality:
    """Veredicto sobre la validez de una corrida completa."""

    is_valid: bool
    dominant_share: float
    dominant_label: str
    reason: str


class MetricsCalculator:
    """Servicio de dominio. Agrega resultados sin conocer tecnología alguna."""

    def confusion(
        self, pairs: list[tuple[bool | None, bool]]
    ) -> ConfusionMatrix:
        """Construye la matriz desde pares (verdad conocida, predicho explotable).

        Los hallazgos sin verdad conocida se omiten: no hay contra qué
        contrastarlos, e incluirlos como aciertos o fallos inventaría datos.
        """
        tp = fp = tn = fn = 0
        for truth, predicted_exploitable in pairs:
            if truth is None:
                continue
            if truth and predicted_exploitable:
                tp += 1
            elif not truth and predicted_exploitable:
                fp += 1
            elif not truth and not predicted_exploitable:
                tn += 1
            else:
                fn += 1
        return ConfusionMatrix(tp, fp, tn, fn)

    def anchor_rate(self, verified_first_try: int, total: int) -> float:
        """Proporción de veredictos anclados a la primera consulta.

        Es el umbral de diseño del 85%: por debajo, el reintento domina el costo
        de operación y el mecanismo deja de ser viable.
        """
        return verified_first_try / total if total else 0.0

    def assess_run(self, verdict_labels: list[str]) -> RunQuality:
        """Detecta la respuesta degenerada antes de dar la corrida por buena."""
        if not verdict_labels:
            return RunQuality(False, 0.0, "", "La corrida no produjo veredictos")

        counts: dict[str, int] = {}
        for label in verdict_labels:
            counts[label] = counts.get(label, 0) + 1
        dominant_label = max(counts, key=lambda k: counts[k])
        share = counts[dominant_label] / len(verdict_labels)

        if share > DEGENERATE_THRESHOLD:
            return RunQuality(
                is_valid=False,
                dominant_share=round(share, 4),
                dominant_label=dominant_label,
                reason=(
                    f"El {share:.1%} de los veredictos es {dominant_label!r}, por "
                    f"encima del umbral de rechazo del {DEGENERATE_THRESHOLD:.0%}. "
                    f"La corrida no es válida para la comparación."
                ),
            )
        return RunQuality(
            is_valid=True,
            dominant_share=round(share, 4),
            dominant_label=dominant_label,
            reason=f"Distribución admisible, la clase mayoritaria cubre el {share:.1%}",
        )

    def agreement(self, runs: list[list[str]]) -> float:
        """Acuerdo entre ejecuciones repetidas con parámetros idénticos.

        Proporción de hallazgos en que las tres corridas coinciden por completo.
        Es la estabilidad del veredicto, cuyo umbral declarado es 0.80.
        """
        if len(runs) < 2:
            raise ValueError("La estabilidad exige al menos dos ejecuciones")
        largos = {len(r) for r in runs}
        if len(largos) != 1:
            raise ValueError("Las ejecuciones comparadas deben cubrir los mismos hallazgos")
        total = largos.pop()
        if not total:
            return 0.0
        coincidencias = sum(
            1 for valores in zip(*runs) if len(set(valores)) == 1
        )
        return coincidencias / total
