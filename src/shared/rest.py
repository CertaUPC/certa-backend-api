"""Cableado que todos los enrutadores necesitan, sea cual sea su contexto.

Obtener el contenedor y abrir una sesión de base de datos no pertenece al
contexto de validación ni al de experimentación: los dos lo usan y ninguno lo
define. Vivía dentro de validación, y por eso el enrutador del experimento
importaba desde validación algo que no tiene que ver con hallazgos.

La identidad de quien llama no está aquí: eso lo declara el contexto de acceso.
"""

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from .composition import Container


def get_container(request: Request) -> Container:
    return request.app.state.container


async def get_session(
    container: Annotated[Container, Depends(get_container)],
) -> AsyncIterator[AsyncSession]:
    async with container.sessions() as session:
        yield session


ContainerDep = Annotated[Container, Depends(get_container)]
SessionDep = Annotated[AsyncSession, Depends(get_session)]
