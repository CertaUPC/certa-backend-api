"""Quién es quién dentro de un proyecto.

El permiso viene de la relación con el proyecto y no de un rango global. Antes
había tres roles de cuenta y de dieciséis comprobaciones trece admitían
indistintamente a dos de ellos, mientras que el tercero no podía ni crear un
proyecto: quien se registraba no podía usar la herramienta.

Quien crea el proyecto es su administrador y a quien invita es miembro. Los
dos deciden sobre hallazgos, que es para lo que existe la herramienta; lo que
solo puede el administrador es lo que afecta al proyecto entero, invitar,
retirar, lanzar análisis, purgar el contexto y exportar el registro.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4


class MemberRole(str, Enum):
    """Papel dentro de un proyecto."""

    ADMIN = "administrador"
    MEMBER = "miembro"

    @property
    def manages(self) -> bool:
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
