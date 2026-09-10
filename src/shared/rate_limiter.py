"""Control de tasa y retroceso ante error transitorio del proveedor.

Una saturación momentánea no debería costar un lote entero de medición.

El cálculo del retraso va separado de la espera, para poder probarlo sin dormir
el reloj.
"""

import asyncio
import random
from dataclasses import dataclass, field

DEFAULT_BASE_DELAY = 1.0
DEFAULT_MAX_DELAY = 60.0


class ProviderUnavailable(RuntimeError):
    """El proveedor sigue fallando tras agotar los reintentos previstos."""


@dataclass
class BackoffPolicy:
    """Retroceso exponencial con dispersión aleatoria.

    La dispersión evita que varios trabajadores que fallaron a la vez reintenten
    en el mismo instante y vuelvan a saturar al proveedor, que es como una
    interrupción breve se convierte en una larga.
    """

    max_attempts: int = 4
    base_delay: float = DEFAULT_BASE_DELAY
    max_delay: float = DEFAULT_MAX_DELAY
    jitter: float = 0.25

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("Se requiere al menos un intento")
        if self.base_delay <= 0:
            raise ValueError("El retraso base debe ser positivo")
        if not 0.0 <= self.jitter < 1.0:
            raise ValueError("La dispersión es una fracción en [0, 1)")

    def delay_for(self, attempt: int, rng: random.Random | None = None) -> float:
        """Retraso antes del intento indicado, base 1.

        El primer intento no espera. A partir del segundo, el retraso se duplica
        y se acota al máximo.
        """
        if attempt < 1:
            raise ValueError("Los intentos se numeran desde 1")
        if attempt == 1:
            return 0.0
        crudo = min(self.base_delay * (2 ** (attempt - 2)), self.max_delay)
        if not self.jitter:
            return crudo
        generador = rng or random
        factor = 1.0 + generador.uniform(-self.jitter, self.jitter)
        return round(min(crudo * factor, self.max_delay), 3)

    def should_retry(self, attempt: int) -> bool:
        return attempt < self.max_attempts


@dataclass
class RateLimiter:
    """Mantiene el ritmo por debajo del límite declarado por el proveedor.

    Se expresa en consultas por minuto porque es la unidad en que los
    proveedores publican su límite.
    """

    queries_per_minute: int
    _timestamps: list[float] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.queries_per_minute < 1:
            raise ValueError("El límite debe admitir al menos una consulta")

    @property
    def window_seconds(self) -> float:
        return 60.0

    def wait_seconds(self, now: float) -> float:
        """Cuánto hay que esperar para no exceder el límite.

        Devuelve cero si hay cupo. No duerme: quien llama decide si espera, lo
        que permite probar la política con un reloj simulado.
        """
        umbral = now - self.window_seconds
        self._timestamps = [t for t in self._timestamps if t > umbral]
        if len(self._timestamps) < self.queries_per_minute:
            return 0.0
        mas_antigua = min(self._timestamps)
        return max(0.0, mas_antigua + self.window_seconds - now)

    def record(self, now: float) -> None:
        self._timestamps.append(now)

    @property
    def in_window(self) -> int:
        return len(self._timestamps)


async def with_backoff(operation, policy: BackoffPolicy, is_transient=None):
    """Ejecuta `operation` reintentando ante fallo transitorio.

    Un fallo permanente no se reintenta: gastar cuatro intentos en una clave
    inválida solo retrasa el diagnóstico. `is_transient` decide cuál es cuál; si
    no se provee, todo fallo se considera transitorio.
    """
    transitorio = is_transient or (lambda _exc: True)
    ultimo: Exception | None = None

    for attempt in range(1, policy.max_attempts + 1):
        espera = policy.delay_for(attempt)
        if espera:
            await asyncio.sleep(espera)
        try:
            return await operation()
        except Exception as exc:
            if not transitorio(exc):
                raise
            ultimo = exc
            if not policy.should_retry(attempt):
                break

    raise ProviderUnavailable(
        f"El proveedor falló en los {policy.max_attempts} intentos previstos. "
        f"El lote se detiene y lo ya validado se conserva."
    ) from ultimo
