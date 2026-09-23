"""Puerto de persistencia de los pares adversariales.

El dominio declara qué necesita guardar y no cómo. Lo declara aquí y no en la
infraestructura porque el servicio que mide la robustez pertenece al dominio y
no puede depender de SQLAlchemy sin romper la regla de dependencia que este
proyecto comprueba en cada corrida.
"""

from typing import Protocol
from uuid import UUID


class TransformationRepositoryPort(Protocol):
    """Registra el par original y transformado con sus dos veredictos."""

    async def record_pair(
        self,
        original_id: UUID,
        transformed_id: UUID,
        transformation_type: str,
        anchoring_enabled: bool,
        original_verdict: str | None = None,
        transformed_verdict: str | None = None,
        description: str | None = None,
    ) -> None:
        """Deja constancia de un par medido.

        El régimen de anclaje forma parte de la identidad del par: el mismo
        original y el mismo transformado medidos con anclaje y sin él son dos
        observaciones distintas, y es justamente su diferencia lo que el
        estudio de robustez reporta.
        """
        ...
