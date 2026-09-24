from collections.abc import Sequence
from dataclasses import dataclass

from ..value_objects.condition import Condition

# Los dos órdenes posibles en un diseño intra-sujeto de dos condiciones.
#
# El control va primero en la lista, y eso decide por dónde empieza quien se
# sienta el primero: el desempate de `assign` es el índice, de modo que con el
# historial vacío toca el orden que aquí aparece antes. Qué lado arranca no
# afecta al equilibrio, que lo produce la alternancia, pero sí a qué queda
# medido si una sesión se corta a la mitad. Empezando por el control, lo que
# sobrevive a una sesión interrumpida es la línea base, que es el término de
# comparación y el que no se puede reconstruir después.
ORDERS: tuple[tuple[Condition, Condition], ...] = (
    (Condition.CONTROL, Condition.WITH_ASSISTANT),
    (Condition.WITH_ASSISTANT, Condition.CONTROL),
)


@dataclass(frozen=True)
class Assignment:
    """Orden de condiciones y lotes que le tocan a un participante."""

    order: tuple[Condition, Condition]
    first_batch: str
    second_batch: str

    def condition_for(self, batch: str) -> Condition:
        if batch == self.first_batch:
            return self.order[0]
        if batch == self.second_batch:
            return self.order[1]
        raise ValueError(f"El lote {batch!r} no pertenece a esta asignación")


class Counterbalancer:
    """Reparte el orden de las condiciones.

    Cada persona pasa por las dos, y la segunda se beneficia de haber practicado
    en la primera. Si todos empezaran igual, ese aprendizaje se confundiría con
    el efecto del asistente.

    Determinista y no aleatorio: con muestras pequeñas el azar desequilibra.
    """

    def __init__(self, batches: Sequence[str] = ("A", "B")) -> None:
        if len(batches) != 2 or batches[0] == batches[1]:
            raise ValueError("El diseño exige exactamente dos lotes distintos")
        self._batches = tuple(batches)

    def assign(self, existing_orders: Sequence[tuple[Condition, Condition]]) -> Assignment:
        """El orden que equilibra el reparto. Empata por el primero, para que el
        resultado se pueda reconstruir desde el historial."""
        counts = {order: 0 for order in ORDERS}
        for order in existing_orders:
            key = tuple(order)
            if key in counts:
                counts[key] += 1
        chosen = min(ORDERS, key=lambda o: (counts[o], ORDERS.index(o)))
        first, second = self._batches
        return Assignment(order=chosen, first_batch=first, second_batch=second)

    @staticmethod
    def is_balanced(
        existing_orders: Sequence[tuple[Condition, Condition]], tolerance: int = 1
    ) -> bool:
        """Que ningún orden domine más allá de la tolerancia."""
        counts = [0, 0]
        for order in existing_orders:
            key = tuple(order)
            if key in ORDERS:
                counts[ORDERS.index(key)] += 1
        return abs(counts[0] - counts[1]) <= tolerance
