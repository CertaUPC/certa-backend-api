"""Traza de eventos con identificador de correlación.

Sirve para reconstruir qué pasó con un hallazgo sin volver a correr el lote.

Nunca registra código ni credenciales: solo identificadores, duraciones y
resultados. El código ya tiene su propia tabla, con retención, y duplicarlo en
los registros lo dejaría fuera de esa política.
"""

import logging
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger("certa.trace")

# El identificador viaja por contexto y no como argumento: atravesar cuatro
# etapas pasándolo a mano ensuciaría cada firma del dominio.
_correlation: ContextVar[str | None] = ContextVar("certa_correlation", default=None)

# Claves que nunca se registran, por si alguna llega en los datos del evento.
_FORBIDDEN = frozenset(
    {"code", "codigo", "text", "texto", "texto_contexto", "source", "api_key",
     "authorization", "token", "password", "contrasena", "justification",
     "justificacion", "prompt", "content"}
)


class Stage(str, Enum):
    """Las cuatro etapas de la cadena, más los desvíos que puede tomar."""

    INGEST = "ingesta"
    CONTEXT = "contexto"
    PREFILTER = "filtro_determinista"
    REUSE = "reutilizacion"
    MODEL = "consulta_modelo"
    ANCHOR = "verificacion_anclaje"
    RETRY = "reintento"
    PRIORITY = "priorizacion"
    PERSIST = "persistencia"


@dataclass
class Event:
    stage: Stage
    correlation_id: str
    outcome: str
    duration_ms: int | None = None
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def as_log(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "correlacion": self.correlation_id,
            "etapa": self.stage.value,
            "resultado": self.outcome,
        }
        if self.duration_ms is not None:
            payload["ms"] = self.duration_ms
        if self.error:
            payload["error"] = self.error
        payload.update(self.data)
        return payload


def new_correlation_id() -> str:
    return uuid.uuid4().hex[:16]


def current_correlation_id() -> str | None:
    return _correlation.get()


@contextmanager
def correlate(correlation_id: str | None = None) -> Iterator[str]:
    """Abre un ámbito de correlación. Todo evento emitido dentro lo hereda."""
    cid = correlation_id or new_correlation_id()
    token = _correlation.set(cid)
    try:
        yield cid
    finally:
        _correlation.reset(token)


def _scrub(data: dict[str, Any]) -> dict[str, Any]:
    """Descarta cualquier clave sensible antes de que llegue al registro."""
    limpio: dict[str, Any] = {}
    for k, v in data.items():
        if k.lower() in _FORBIDDEN:
            continue
        # Un valor largo casi siempre es texto que no debería estar aquí.
        if isinstance(v, str) and len(v) > 200:
            limpio[k] = f"<{len(v)} caracteres omitidos>"
        else:
            limpio[k] = v
    return limpio


def emit(
    stage: Stage,
    outcome: str,
    duration_ms: int | None = None,
    error: str | None = None,
    **data: Any,
) -> Event:
    event = Event(
        stage=stage,
        correlation_id=current_correlation_id() or "sin-correlacion",
        outcome=outcome,
        duration_ms=duration_ms,
        data=_scrub(data),
        error=error,
    )
    nivel = logging.ERROR if error else logging.INFO
    logger.log(nivel, "%s", event.as_log(), extra={"certa_event": event})
    return event


@contextmanager
def timed(stage: Stage, **data: Any) -> Iterator[dict[str, Any]]:
    """Mide una etapa y emite su evento, tanto si termina bien como si falla.

    El diccionario que entrega admite datos que solo se conocen al final, como
    el número de líneas recuperadas o los tokens consumidos.
    """
    extra: dict[str, Any] = {}
    inicio = time.perf_counter()
    try:
        yield extra
    except Exception as exc:
        emit(
            stage,
            "fallo",
            duration_ms=int((time.perf_counter() - inicio) * 1000),
            error=f"{type(exc).__name__}: {exc}",
            **{**data, **extra},
        )
        raise
    emit(
        stage,
        extra.pop("resultado", "ok"),
        duration_ms=int((time.perf_counter() - inicio) * 1000),
        **{**data, **extra},
    )


class MemoryTraceSink(logging.Handler):
    """Conserva los eventos en memoria para consultarlos por correlación.

    Es lo que permite responder "qué pasó con este hallazgo" sin depender de que
    alguien haya conservado la salida del proceso.
    """

    def __init__(self, capacity: int = 5000) -> None:
        super().__init__(level=logging.INFO)
        self._events: list[Event] = []
        self._capacity = capacity

    def emit(self, record: logging.LogRecord) -> None:
        event = getattr(record, "certa_event", None)
        if isinstance(event, Event):
            self._events.append(event)
            if len(self._events) > self._capacity:
                del self._events[: len(self._events) - self._capacity]

    def by_correlation(self, correlation_id: str) -> list[Event]:
        return [e for e in self._events if e.correlation_id == correlation_id]

    def clear(self) -> None:
        self._events.clear()

    @property
    def count(self) -> int:
        return len(self._events)


def install_memory_sink(capacity: int = 5000) -> MemoryTraceSink:
    sink = MemoryTraceSink(capacity)
    logger.addHandler(sink)
    logger.setLevel(logging.INFO)
    return sink
