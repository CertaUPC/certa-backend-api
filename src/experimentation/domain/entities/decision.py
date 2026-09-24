"""La decisión vive ahora en el contexto de validación.

Estaba aquí porque el estudio la medía, pero el acto es del producto: alguien
decide sobre un hallazgo, lo haga dentro o fuera de un experimento. Sostenerla
en dos sitios hacía que el estudio corriera por un camino paralelo en lugar de
ser un caso del producto.

Lo propio del estudio se queda en este contexto: la condición asignada, el
contrabalanceo que la reparte y la sesión que las agrupa.

    from ....finding_validation.domain.entities.decision import Decision
"""

from ....finding_validation.domain.entities.decision import (  # noqa: F401
    Decision,
    DecisionValue,
)
