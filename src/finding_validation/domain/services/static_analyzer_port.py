from typing import Protocol

from ..entities.finding import Finding


class StaticAnalyzerPort(Protocol):
    """El analizador externo que detecta. Declarado sobre SARIF y no sobre una
    herramienta concreta."""

    async def analyze(self, repository_path: str) -> list[Finding]:
        ...

    @property
    def tool_name(self) -> str:
        ...

    @property
    def ruleset_version(self) -> str:
        """Sin la versión de las reglas, dos ejecuciones no son comparables."""
        ...
