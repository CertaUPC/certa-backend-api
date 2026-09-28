"""US039. Que el proveedor se sature un momento no puede costar el lote.

La historia pide dos cosas y son distintas. Una es el ritmo: no pasarse del
límite de consultas por minuto que el proveedor publica. La otra es el
retroceso: cuando aun así responde que no puede, esperar y volver a intentar,
cada vez un poco más, en lugar de dar la alerta por perdida.

Y pide una tercera que es la que de verdad ahorra dinero: distinguir el fallo
que pasa del que no. Gastar cuatro intentos y un minuto de espera en una clave
inválida no arregla nada, solo retrasa el diagnóstico.

El cálculo del retraso está separado de la espera, así que todo esto se
comprueba sin dormir el reloj.
"""

import asyncio

import pytest

from src.shared.rate_limiter import (
    BackoffPolicy,
    ProviderUnavailable,
    RateLimiter,
    with_backoff,
)


class TestElRitmo:
    """Cuántas consultas caben en la ventana y cuánto hay que esperar."""

    def test_con_cupo_no_se_espera(self):
        limitador = RateLimiter(queries_per_minute=3)
        assert limitador.wait_seconds(now=0.0) == 0.0

    def test_alcanzado_el_limite_se_espera_lo_que_falta_de_la_ventana(self):
        limitador = RateLimiter(queries_per_minute=2)
        limitador.record(now=0.0)
        limitador.record(now=10.0)
        # La ventana de la primera vence en el segundo 60.
        assert limitador.wait_seconds(now=20.0) == pytest.approx(40.0)

    def test_pasada_la_ventana_vuelve_a_haber_cupo(self):
        limitador = RateLimiter(queries_per_minute=1)
        limitador.record(now=0.0)
        assert limitador.wait_seconds(now=61.0) == 0.0
        assert limitador.in_window == 0, "la consulta vieja ya no cuenta"

    def test_un_limite_por_debajo_de_uno_no_tiene_sentido(self):
        with pytest.raises(ValueError):
            RateLimiter(queries_per_minute=0)


class TestElRetroceso:
    """Cuánto se espera entre intento e intento."""

    def test_el_primer_intento_no_espera(self):
        assert BackoffPolicy().delay_for(1) == 0.0

    def test_la_espera_se_duplica(self):
        politica = BackoffPolicy(base_delay=1.0, jitter=0.0)
        assert [politica.delay_for(n) for n in (2, 3, 4)] == [1.0, 2.0, 4.0]

    def test_la_espera_tiene_techo(self):
        politica = BackoffPolicy(base_delay=1.0, max_delay=3.0, jitter=0.0)
        assert politica.delay_for(9) == 3.0

    def test_la_dispersion_mueve_la_espera_sin_pasarse_del_techo(self):
        """Sin dispersión, dos trabajadores que fallan a la vez reintentan en
        el mismo instante y vuelven a saturar al proveedor: así es como una
        interrupción breve se vuelve larga."""
        politica = BackoffPolicy(base_delay=10.0, max_delay=12.0, jitter=0.25)
        esperas = {politica.delay_for(2) for _ in range(40)}
        assert len(esperas) > 1, "la dispersión no está moviendo nada"
        assert all(7.5 <= e <= 12.0 for e in esperas)

    def test_deja_de_reintentar_al_llegar_al_tope(self):
        politica = BackoffPolicy(max_attempts=3)
        assert politica.should_retry(2)
        assert not politica.should_retry(3)


class TestReintentar:
    """Qué se reintenta, qué no, y qué pasa cuando se acaban los intentos."""

    @staticmethod
    def _sin_esperas() -> BackoffPolicy:
        # base_delay mínimo: lo que se comprueba aquí es la decisión, no el reloj.
        return BackoffPolicy(max_attempts=3, base_delay=0.001, jitter=0.0)

    async def test_un_fallo_que_pasa_se_reintenta_y_la_consulta_sale(self):
        intentos = {"n": 0}

        async def operacion():
            intentos["n"] += 1
            if intentos["n"] < 3:
                raise TimeoutError("el proveedor tardó demasiado")
            return "veredicto"

        resultado = await with_backoff(operacion, self._sin_esperas())
        assert resultado == "veredicto"
        assert intentos["n"] == 3

    async def test_un_fallo_que_no_pasa_no_se_reintenta(self):
        """Una clave inválida no mejora esperando. Reintentarla cuatro veces
        solo retrasa el diagnóstico."""
        intentos = {"n": 0}

        async def operacion():
            intentos["n"] += 1
            raise PermissionError("credencial rechazada")

        with pytest.raises(PermissionError):
            await with_backoff(
                operacion,
                self._sin_esperas(),
                is_transient=lambda exc: not isinstance(exc, PermissionError),
            )
        assert intentos["n"] == 1, "lo reintentó y no debía"

    async def test_agotados_los_intentos_se_detiene_diciendo_por_que(self):
        async def operacion():
            raise TimeoutError("sigue caído")

        with pytest.raises(ProviderUnavailable) as caido:
            await with_backoff(operacion, self._sin_esperas())
        assert "3 intentos" in str(caido.value)
        assert isinstance(caido.value.__cause__, TimeoutError), (
            "se pierde la causa original y el registro no sirve para diagnosticar"
        )

    async def test_no_espera_antes_del_primer_intento(self):
        """Si esperara, toda consulta pagaría el retraso aunque el proveedor
        esté perfecto."""
        politica = BackoffPolicy(max_attempts=2, base_delay=5.0, jitter=0.0)

        async def operacion():
            return "listo"

        antes = asyncio.get_running_loop().time()
        assert await with_backoff(operacion, politica) == "listo"
        assert asyncio.get_running_loop().time() - antes < 1.0
