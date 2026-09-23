"""Elige el recuperador según el archivo del hallazgo, y delega.

Tres escalones, ninguno falla: perfil con gramática instalada va por árbol
sintáctico; perfil sin gramática cae a ventana y lo anota; sin perfil, ventana.

Por eso un lenguaje nuevo no detiene la cadena. Declarar un perfil no habilita
el lenguaje, mejora el contexto con que ya se juzgaba.
"""

import logging
from pathlib import Path

from ...domain.entities.code_context import CodeContext
from ...domain.entities.finding import Finding
from .language_profile import LanguageProfile, profile_for
from .tree_sitter_code_reader import TreeSitterCodeReader
from .window_code_reader import WindowCodeReader

logger = logging.getLogger(__name__)


class CodeReaderRegistry:

    def __init__(
        self,
        repository_root: Path,
        max_context_lines: int = 250,
        callee_depth: int = 2,
    ) -> None:
        self._root = Path(repository_root)
        self._max_lines = max_context_lines
        self._callee_depth = callee_depth
        self._fallback = WindowCodeReader(self._root, max_context_lines)
        self._readers: dict[str, TreeSitterCodeReader] = {}
        self._unavailable: dict[str, str] = {}

    @property
    def language(self) -> str:
        return "(según el archivo)"

    def _reader_for(self, file_path: str) -> TreeSitterCodeReader | None:
        profile: LanguageProfile | None = profile_for(file_path)
        if profile is None:
            return None
        if profile.name in self._unavailable:
            return None
        cached = self._readers.get(profile.name)
        if cached is not None:
            return cached
        try:
            reader = TreeSitterCodeReader(
                self._root, profile, self._max_lines, self._callee_depth
            )
        except (ImportError, Exception) as exc:  # noqa: BLE001
            # Falta la gramática, o la consulta no compila contra ella. Se anota
            # una vez y se sigue: un perfil roto no puede parar el lote entero.
            self._unavailable[profile.name] = str(exc)
            logger.warning(
                "Perfil %s no disponible (%s). Se recupera por ventana.",
                profile.name,
                exc,
            )
            return None
        self._readers[profile.name] = reader
        return reader

    async def recover_context(
        self, finding: Finding, caller_depth: int = 2
    ) -> CodeContext:
        reader = self._reader_for(finding.location.file_path)
        if reader is None:
            return await self._fallback.recover_context(finding, caller_depth)
        return await reader.recover_context(finding, caller_depth)

    @property
    def active_languages(self) -> tuple[str, ...]:
        return tuple(sorted(self._readers))

    @property
    def unavailable_profiles(self) -> dict[str, str]:
        """Gramáticas que no cargaron. Es un problema de instalación, distinto de
        no tener perfil, y por eso se informa aparte."""
        return dict(self._unavailable)
