"""Retención del código fuente recuperado.

Se borra el contenido y se conservan las métricas: las métricas no dependen de
él, así que borrarlo no destruye ningún resultado.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum

DEFAULT_RETENTION_DAYS = 30


class RetentionOutcome(str, Enum):
    PURGE = "purgar"
    KEEP_IN_USE = "conservar_en_uso"
    KEEP_WITHIN_WINDOW = "conservar_en_ventana"
    ALREADY_PURGED = "ya_purgado"


@dataclass(frozen=True)
class RetentionDecision:
    outcome: RetentionOutcome
    reason: str

    @property
    def should_purge(self) -> bool:
        return self.outcome is RetentionOutcome.PURGE


@dataclass(frozen=True)
class ExecutionRetentionState:
    """Lo que la política necesita saber de una ejecución para decidir."""

    closed_at: datetime | None
    context_purged: bool
    used_in_active_session: bool


class RetentionPolicy:
    """Servicio de dominio. Decide qué contexto se puede borrar y cuándo."""

    def __init__(self, retention_days: int = DEFAULT_RETENTION_DAYS) -> None:
        if retention_days < 0:
            raise ValueError("La ventana de retención no puede ser negativa")
        self._window = timedelta(days=retention_days)

    def decide_on_request(
        self, state: ExecutionRetentionState
    ) -> RetentionDecision:
        """Lo que se decide cuando alguien pide el borrado, no cuando toca.

        La ventana gobierna el barrido automático: pasados los días, el texto
        se va solo. Pero quien cargó el código puede soltarlo antes, y esa es
        justamente la contrapartida de habérselo guardado. Exigirle esperar la
        ventana entera convertía el botón de la pantalla en una promesa que el
        servicio no cumplía: decía «puedes soltarlo cuando quieras» y el
        servicio respondía que faltaban veintitantos días.
        """
        if state.context_purged:
            return RetentionDecision(
                RetentionOutcome.ALREADY_PURGED,
                "El contexto de esta ejecución ya fue eliminado",
            )

        if state.used_in_active_session:
            return RetentionDecision(
                RetentionOutcome.KEEP_IN_USE,
                "La ejecución participa en una sesión con participantes en curso",
            )

        return RetentionDecision(
            RetentionOutcome.PURGE,
            "Borrado a petición de quien cargó el código. Se elimina el texto "
            "del contexto y se conservan las métricas y los veredictos, que no "
            "dependen del contenido del código",
        )

    def decide(
        self, state: ExecutionRetentionState, now: datetime | None = None
    ) -> RetentionDecision:
        reference = now or datetime.now(timezone.utc)

        if state.context_purged:
            return RetentionDecision(
                RetentionOutcome.ALREADY_PURGED,
                "El contexto de esta ejecución ya fue eliminado",
            )

        if state.used_in_active_session:
            # Precede a cualquier otra consideración: borrar el contexto de una
            # ejecución en uso rompería la sesión de un participante en curso, y
            # esa sesión no se puede repetir.
            return RetentionDecision(
                RetentionOutcome.KEEP_IN_USE,
                "La ejecución participa en una sesión con participantes en curso",
            )

        if state.closed_at is None:
            return RetentionDecision(
                RetentionOutcome.KEEP_WITHIN_WINDOW,
                "La ejecución sigue abierta",
            )

        # SQLite devuelve la fecha sin zona, PostgreSQL con ella. Comparar una
        # con «ahora» reventaba con un 500 en la base local, y el dominio no
        # tiene por qué saber en qué motor está guardado: se da por UTC, que es
        # como se escribió.
        cerrada = state.closed_at
        if cerrada.tzinfo is None:
            cerrada = cerrada.replace(tzinfo=timezone.utc)

        vencimiento = cerrada + self._window
        if reference < vencimiento:
            restantes = (vencimiento - reference).days
            return RetentionDecision(
                RetentionOutcome.KEEP_WITHIN_WINDOW,
                f"Dentro de la ventana de retención, faltan {restantes} días",
            )

        return RetentionDecision(
            RetentionOutcome.PURGE,
            "Cumplida la ventana de retención. Se elimina el texto del contexto "
            "y se conservan las métricas y los veredictos, que no dependen del "
            "contenido del código",
        )
