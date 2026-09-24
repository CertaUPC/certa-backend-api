"""Quien participa en el estudio, con la ficha que lo caracteriza.

NO ES UNA CUENTA. El participante se identifica por un codigo anonimo y no
tiene credenciales de persona: el consentimiento promete que no se recoge su
nombre, su correo ni el de su empleador. La ficha describe al grupo, no a
nadie.
"""

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID, uuid4

# Las bandas son las del formulario, y esa es la correccion. El modelo guardaba
# un entero de anios y derivaba tres bandas propias, «inicial» por debajo de
# dos, «intermedio» por debajo de cinco y «senior» el resto, mientras que la
# ficha preguntaba en cuatro tramos distintos. Quien respondiera «De 1 a 3»
# podia caer en dos bandas y no habia manera de saber en cual, porque el numero
# exacto nunca se preguntaba. Guardar la banda que se pregunto deja el factor
# del analisis identico a lo que la persona respondio.
BANDAS_DE_EXPERIENCIA = ("menos_de_1", "de_1_a_3", "de_4_a_7", "mas_de_7")
FRECUENCIAS_DE_ALERTA = ("nunca", "alguna_vez", "mensual", "semanal", "diaria")
FORMACIONES = ("ninguna", "autodidacta", "curso")


@dataclass
class Participant:
    anonymous_code: str
    experience_band: str
    consented_at: datetime
    has_security_role: bool = False
    main_language: str | None = None
    alert_frequency: str | None = None
    security_training: str | None = None
    is_pilot: bool = False
    id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not self.anonymous_code or not self.anonymous_code.strip():
            raise ValueError("El participante exige un código anónimo")
        if self.experience_band not in BANDAS_DE_EXPERIENCIA:
            raise ValueError(
                f"Banda de experiencia desconocida: {self.experience_band!r}. "
                f"Se admiten {', '.join(BANDAS_DE_EXPERIENCIA)}"
            )
        if (
            self.alert_frequency is not None
            and self.alert_frequency not in FRECUENCIAS_DE_ALERTA
        ):
            raise ValueError(
                f"Frecuencia desconocida: {self.alert_frequency!r}. Se admiten "
                f"{', '.join(FRECUENCIAS_DE_ALERTA)}"
            )
        if (
            self.security_training is not None
            and self.security_training not in FORMACIONES
        ):
            raise ValueError(
                f"Formación desconocida: {self.security_training!r}. Se admiten "
                f"{', '.join(FORMACIONES)}"
            )
        if self.has_security_role:
            # Criterio de exclusión del apartado 4.4. En el dominio y no solo
            # en la interfaz, porque de esto depende que la muestra sea la que
            # se declaró. Hasta que la ficha se recogió por la herramienta esta
            # regla no podía dispararse: el campo nunca llegaba, siempre valía
            # falso, y la exclusión dependía de que alguien leyera a tiempo una
            # hoja de respuestas.
            raise ValueError(
                "El estudio excluye a quienes tienen rol formal en seguridad de "
                "aplicaciones: son la competencia que la herramienta sustituye"
            )
