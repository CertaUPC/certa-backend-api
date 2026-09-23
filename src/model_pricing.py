"""Costo real por modelo, a partir del catálogo del proveedor.

El guardia de presupuesto del dominio lleva un solo par de precios, porque su
trabajo es cortar una corrida desbocada y para eso le basta una cifra
aproximada. Pero el cuadro de resultados usa el costo para elegir modelo, y ahí
un precio único los vuelve incomparables: aplicar la tarifa del más caro a todos
multiplica por cinco la cuenta del más barato y puede invertir el orden.

Los precios se piden al proveedor y no se escriben aquí: los mueve él, y una
tabla copiada a mano envejece sin avisar.
"""

from __future__ import annotations

import os

import httpx

_POR_MILLON = 1_000_000


class PriceUnavailable(RuntimeError):
    """El catálogo no se pudo consultar o no trae el modelo pedido."""


def _verificacion(settings) -> object:
    ruta = settings.ssl_cert_file
    return ruta if ruta and os.path.isfile(ruta) else True


def fetch_prices(settings, models: list[str]) -> dict[str, tuple[float, float]]:
    """Precio por millón de tokens de entrada y de salida, por modelo.

    Devuelve solo los modelos que el catálogo reconoce. Quien llama decide qué
    hacer con los que falten: aquí no se inventa una tarifa, porque un costo
    inventado en el cuadro de resultados es peor que un hueco declarado.
    """
    try:
        respuesta = httpx.get(
            settings.llm_base_url.rstrip("/") + "/models",
            verify=_verificacion(settings),
            timeout=60,
        )
        respuesta.raise_for_status()
        catalogo = respuesta.json()["data"]
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        raise PriceUnavailable(
            f"No se pudo consultar el catálogo de precios: {exc}"
        ) from exc

    tarifas = {}
    for entrada in catalogo:
        if entrada.get("id") not in models:
            continue
        precios = entrada.get("pricing") or {}
        try:
            tarifas[entrada["id"]] = (
                float(precios["prompt"]) * _POR_MILLON,
                float(precios["completion"]) * _POR_MILLON,
            )
        except (KeyError, TypeError, ValueError):
            continue
    return tarifas


def cost_of(tarifa: tuple[float, float], input_tokens: int, output_tokens: int) -> float:
    entrada, salida = tarifa
    return (input_tokens * entrada + output_tokens * salida) / _POR_MILLON


def costs_by_run(verdicts, tarifas: dict[str, tuple[float, float]]) -> dict:
    """Tokens y costo de cada corrida, leídos de los veredictos guardados.

    Se cuenta sobre lo guardado y no sobre lo gastado en esta invocación: al
    reanudar, lo ya medido no se vuelve a pagar, pero el lote sigue costando lo
    que cuesta y es esa cifra la que sirve para comparar modelos.
    """
    acumulado: dict[tuple[str, str, int], dict] = {}
    for v in verdicts:
        clave = (v.model, v.model_version, v.repetition)
        fila = acumulado.setdefault(
            clave, {"tokens_entrada": 0, "tokens_salida": 0, "usd": None}
        )
        fila["tokens_entrada"] += v.input_tokens or 0
        fila["tokens_salida"] += v.output_tokens or 0

    for (modelo, _, _), fila in acumulado.items():
        tarifa = tarifas.get(modelo)
        if tarifa is None:
            continue
        fila["usd"] = round(
            cost_of(tarifa, fila["tokens_entrada"], fila["tokens_salida"]), 4
        )
    return acumulado


__all__ = ["PriceUnavailable", "cost_of", "costs_by_run", "fetch_prices"]
