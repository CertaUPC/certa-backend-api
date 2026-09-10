from dataclasses import dataclass


@dataclass(frozen=True)
class Priority:
    """Puesto del hallazgo en la lista. `reason` es lo que se le muestra a
    quien revisa para explicar por qué quedó ahí."""

    score: float
    reason: str

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0:
            raise ValueError(f"La prioridad vive en [0, 1], llegó {self.score}")
        if not self.reason:
            raise ValueError("La prioridad exige la razón que la explica")

    def __lt__(self, other: "Priority") -> bool:
        # Invertido: mayor puntaje va primero.
        return self.score > other.score
