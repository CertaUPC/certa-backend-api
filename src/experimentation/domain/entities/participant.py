from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID, uuid4


@dataclass
class Participant:
    """Raíz del agregado de experimentación.

    Sin nombre ni correo: el análisis nunca los necesita, y no tenerlos es la
    salvaguarda más simple.
    """

    anonymous_code: str
    years_of_experience: int
    consented_at: datetime
    has_security_role: bool = False
    id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not self.anonymous_code or not self.anonymous_code.strip():
            raise ValueError("El participante exige un código anónimo")
        if self.years_of_experience < 0:
            raise ValueError("Los años de experiencia no pueden ser negativos")
        if self.has_security_role:
            # Criterio de exclusión. En el dominio y no solo en la interfaz,
            # porque de esto depende que la muestra sea la que se declaró.
            raise ValueError(
                "El estudio excluye a quienes tienen rol formal en seguridad de "
                "aplicaciones: son la competencia que la herramienta sustituye"
            )

    @property
    def experience_band(self) -> str:
        """Entra como factor en el análisis."""
        if self.years_of_experience < 2:
            return "inicial"
        if self.years_of_experience < 5:
            return "intermedio"
        return "senior"
