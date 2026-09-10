from typing import Protocol

from ..entities.code_context import CodeContext
from ..entities.finding import Finding


class CodeReaderPort(Protocol):
    """Recupera del código la función contenedora, sus llamadores y los
    saneadores de la ruta.

    Nunca falla: si un llamador no se resuelve, cae al contexto del archivo y lo
    marca como degradado.
    """

    async def recover_context(
        self, finding: Finding, caller_depth: int = 2
    ) -> CodeContext:
        ...

    @property
    def language(self) -> str:
        ...
