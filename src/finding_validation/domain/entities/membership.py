"""Quién es quién dentro de un proyecto.

EL PERMISO VIENE DE LA RELACIÓN CON EL PROYECTO, NO DE UN RANGO GLOBAL. Antes
había tres roles de cuenta, `desarrollador`, `investigador` y `lider_tecnico`,
y de dieciséis comprobaciones del sistema trece admitían indistintamente a los
dos últimos. La distinción no existía de verdad, y el primero no podía siquiera
crear un proyecto, de modo que quien se registraba no podía usar la
herramienta.

El propio documento de arquitectura ya describía membresía sin llamarla así:
del líder técnico dice que «registra el proyecto, lanza el análisis y consulta
en qué quedó el trabajo de su equipo», y del desarrollador que «recibe la lista
ordenada y decide sobre cada uno». Eso no es un rango: es lo que uno hace en su
proyecto y lo que hace quien fue invitado a él.

DOS PAPELES Y NO MÁS. Quien crea el proyecto es su administrador. A quien
invita es miembro. Los dos revisan hallazgos y deciden, porque decidir es para
lo que existe la herramienta. Lo que solo puede el administrador es lo que
afecta al proyecto entero: invitar, retirar, lanzar análisis, purgar el
contexto y exportar el registro.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4


class MemberRole(str, Enum):
    """Papel dentro de un proyecto.

    En los diagramas el administrador se etiqueta así y el resto como miembros
    invitados, sin detallar ahí quién puede qué: el detalle vive en el código,
    que es donde se comprueba.
    """

    ADMIN = "administrador"
    MEMBER = "miembro"

    @property
    def administra(self) -> bool:
        return self is MemberRole.ADMIN


@dataclass
class Membership:
    project_id: UUID
    user_id: UUID
    role: MemberRole = MemberRole.MEMBER
    invited_by: UUID | None = None
    id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        if self.invited_by is not None and self.invited_by == self.user_id:
            raise ValueError(
                "Nadie se invita a sí mismo: quien crea el proyecto entra como "
                "administrador sin invitación, y el resto entra invitado por otro"
            )
