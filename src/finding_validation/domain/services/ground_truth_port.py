from typing import Protocol

from ..entities.finding import Finding


class GroundTruthPort(Protocol):
    """La etiqueta que trae un conjunto de referencia.

    Solo existe en conjuntos construidos con verdad conocida. Un proyecto real
    no la tiene, y ahí el puerto sencillamente no se inyecta.
    """

    def truth_for(self, finding: Finding) -> bool | None:
        """None cuando el conjunto no afirma nada sobre este hallazgo.

        Es distinto de afirmar que es falso: el analizador puede disparar una
        regla de otra categoría sobre el mismo archivo, y el conjunto no dice
        si eso es correcto. Etiquetarlo como falso positivo inventaría una
        verdad que nadie midió.
        """
        ...
