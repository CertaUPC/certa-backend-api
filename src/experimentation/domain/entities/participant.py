"""Quien participa en el estudio, con la ficha que lo caracteriza.

No es una cuenta: se identifica por un codigo anonimo y no tiene
credenciales, porque el consentimiento promete que no se recoge su nombre ni
su correo. La ficha describe al grupo, no a nadie.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID, uuid4

# El acta de consentimiento que la persona firma lleva el codigo con guion,
# «P-04», y el campo de la pantalla lo pedia sin el. Quien dicta lee lo que
# tiene delante, de modo que las dos formas tenian que resolver a la misma o
# el acceso fallaba por un caracter.
_CODIGO = re.compile(r"^([A-Z]+)[\s\-_]*([0-9]+)$")


def normalizar_codigo(codigo: str) -> str:
    """Devuelve el codigo en su forma canonica: mayusculas y con guion.

    «p04», «P 04» y «P-4» son el mismo participante que «P-04». Lo que no
    encaje en letras seguidas de digitos se devuelve solo en mayusculas,
    porque el dominio no decide como se llaman los codigos de otro estudio.
    """
    limpio = codigo.strip().upper()
    m = _CODIGO.match(limpio)
    if not m:
        return limpio
    letras, numero = m.groups()
    return f"{letras}-{int(numero):02d}"

# Las bandas son las del formulario. Antes se guardaba un entero de anios y se
# derivaban tres bandas propias que no coincidian con los cuatro tramos de la
# ficha, de modo que «De 1 a 3» podia caer en dos y no habia como saber en cual.
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
        self.anonymous_code = normalizar_codigo(self.anonymous_code)
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
            # Criterio de exclusión del apartado 4.4, en el dominio y no solo
            # en la interfaz: de esto depende que la muestra sea la declarada.
            raise ValueError(
                "El estudio excluye a quienes tienen rol formal en seguridad de "
                "aplicaciones: son la competencia que la herramienta sustituye"
            )
