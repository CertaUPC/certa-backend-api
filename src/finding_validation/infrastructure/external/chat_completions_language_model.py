"""El puerto de modelo sobre el contrato de completado de chat.

Lo hablan casi todos los proveedores comerciales y también los servidores
locales de pesos abiertos, así que cambiar de proveedor es cambiar
`llm_base_url` y `llm_model`.
"""

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field

import httpx

from ....shared.rate_limiter import BackoffPolicy, RateLimiter, with_backoff
from ...domain.entities.code_context import CodeContext
from ...domain.entities.finding import Finding
from ...domain.services.language_model_port import ModelJudgement
from . import prompt_builder

logger = logging.getLogger(__name__)


def _verificacion_tls(path: str = ""):
    """Certificado con el que verificar al proveedor.

    httpx valida contra el almacen de certifi, que no incluye las autoridades
    que instalan los antivirus y las redes corporativas cuando interceptan TLS.
    En esas maquinas toda llamada al proveedor falla con
    CERTIFICATE_VERIFY_FAILED, el reintento la toma por transitoria y el lote
    muere tras agotar los intentos sin decir cual es la causa.

    Se admite un paquete propio por entorno. Devolver True mantiene el
    comportamiento habitual donde no hay interceptacion.
    """
    path = path or os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE")
    if path and os.path.isfile(path):
        return path
    if path:
        logger.warning(
            "El certificado indicado no existe: %s. Se usa la verificación "
            "por omisión.", path,
        )
    return True

# Saturación y fallos de servidor. Un 401 o un 400 no: gastar cuatro intentos en
# una clave inválida solo retrasa el diagnóstico.
TRANSIENT_STATUS = frozenset({408, 409, 425, 429, 500, 502, 503, 504})

_JSON_BLOCK = re.compile(r"\{.*\}", re.DOTALL)


class ModelContractViolation(ValueError):
    """La respuesta no cumple el contrato. Reintenta en vez de interpretarla:
    adivinar metería en la medición una decisión del adaptador."""


class ProviderRefused(RuntimeError):
    """Fallo permanente del proveedor: credencial, cuota o petición inválida."""


class ProviderEmptyResponse(RuntimeError):
    """El proveedor respondió sin contenido.

    No es lo mismo que un contrato incumplido. Un modelo que devuelve JSON
    malformado seguirá devolviéndolo, de modo que reintentar solo gasta; una
    respuesta vacía viene de un fallo del proveedor en esa llamada concreta y
    la siguiente suele resolverla. Por eso lleva su propia clase y se trata
    como transitoria.
    """


def _extract_json(raw: str | None) -> dict:
    """Saca el objeto aunque venga envuelto en texto o en vallas. Recorta lo de
    alrededor; no completa campos ni corrige valores."""
    if not isinstance(raw, str) or not raw.strip():
        # Algunos proveedores devuelven contenido nulo: el modelo se quedó sin
        # espacio, filtró la respuesta o contestó solo con su razonamiento
        # interno. Es un incumplimiento del contrato, no un fallo del programa:
        # tratarlo como excepción de atributo mataba el lote entero y con él
        # todo lo ya pagado.
        raise ProviderEmptyResponse(
            "El proveedor no devolvió contenido en la respuesta"
        )
    text = raw.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = _JSON_BLOCK.search(text)
        if not match:
            raise ModelContractViolation(
                "La respuesta no contiene ningún objeto JSON"
            ) from None
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError as exc:
            raise ModelContractViolation(
                f"El objeto JSON de la respuesta no se pudo interpretar: {exc}"
            ) from exc


def parse_judgement(
    raw: str, input_tokens: int, output_tokens: int, latency_ms: int
) -> ModelJudgement:
    """Valida contra el contrato antes de dejar entrar nada."""
    data = _extract_json(raw)

    if isinstance(data, list):
        # Algún proveedor devuelve el veredicto envuelto en un arreglo de un
        # solo elemento. Se acepta ese caso porque el contenido sí cumple el
        # contrato; cualquier otro arreglo se rechaza como incumplimiento, que
        # es una falla contada y no una excepción que tumbe el lote.
        if len(data) == 1 and isinstance(data[0], dict):
            data = data[0]
        else:
            raise ModelContractViolation(
                f"La respuesta es un arreglo de {len(data)} elementos y el "
                f"contrato pide un objeto"
            )
    if not isinstance(data, dict):
        raise ModelContractViolation(
            f"La respuesta no es un objeto sino {type(data).__name__}"
        )

    value = data.get("value")
    if not isinstance(value, str) or not value.strip():
        raise ModelContractViolation("Falta el campo 'value' o no es texto")

    text = data.get("justification_text")
    if not isinstance(text, str) or not text.strip():
        raise ModelContractViolation("Falta el campo 'justification_text'")

    lineas_crudas = data.get("cited_lines", [])
    if not isinstance(lineas_crudas, list):
        raise ModelContractViolation("'cited_lines' debe ser una lista")
    try:
        lineas = tuple(int(n) for n in lineas_crudas)
    except (TypeError, ValueError) as exc:
        raise ModelContractViolation(f"'cited_lines' trae un valor no entero: {exc}") from exc

    confianza = data.get("confidence")
    if confianza is not None:
        try:
            confianza = float(confianza)
        except (TypeError, ValueError):
            confianza = None
        else:
            if not 0.0 <= confianza <= 1.0:
                confianza = None

    return ModelJudgement(
        value=value.strip().lower(),
        justification_text=text.strip(),
        cited_lines=lineas,
        confidence=confianza,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        latency_ms=latency_ms,
    )


@dataclass
class ChatCompletionsLanguageModel:
    """Implementa `LanguageModelPort` sobre HTTP."""

    base_url: str
    api_key: str
    model: str
    version: str
    temperature: float = 0.0
    timeout_seconds: int = 120
    queries_per_minute: int = 60
    ca_bundle: str = ""
    max_output_tokens: int = 2000
    backoff: BackoffPolicy = field(default_factory=BackoffPolicy)
    _limiter: RateLimiter = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.base_url or not self.api_key or not self.model:
            raise ValueError(
                "El adaptador exige dirección, credencial y modelo. La credencial "
                "se toma del entorno, nunca del repositorio."
            )
        if self.temperature != 0.0:
            raise ValueError("La temperatura debe ser cero para poder reproducir")
        self._limiter = RateLimiter(self.queries_per_minute)

    @property
    def model_name(self) -> str:
        return self.model

    @property
    def model_version(self) -> str:
        return self.version

    async def judge(
        self, finding: Finding, context: CodeContext, retry_hint: str | None = None
    ) -> ModelJudgement:
        payload = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": [
                {"role": "system", "content": prompt_builder.system_prompt()},
                {
                    "role": "user",
                    "content": prompt_builder.build_user_prompt(
                        finding, context, retry_hint
                    ),
                },
            ],
            "response_format": {"type": "json_object"},
            # Sin tope, la pasarela reserva crédito por el máximo del modelo y
            # rechaza la petición con 402 aunque el saldo sobre. El contrato de
            # salida ocupa unos cientos de tokens, de modo que el tope no
            # recorta nada legítimo.
            "max_tokens": self.max_output_tokens,
        }

        async def _call() -> ModelJudgement:
            espera = self._limiter.wait_seconds(time.monotonic())
            if espera:
                import asyncio

                await asyncio.sleep(espera)
            self._limiter.record(time.monotonic())

            inicio = time.perf_counter()
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds,
                verify=_verificacion_tls(self.ca_bundle),
            ) as client:
                response = await client.post(
                    f"{self.base_url.rstrip('/')}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
            latencia = int((time.perf_counter() - inicio) * 1000)

            if response.status_code in TRANSIENT_STATUS:
                response.raise_for_status()
            if response.status_code >= 400:
                raise ProviderRefused(
                    f"El proveedor respondió {response.status_code}: "
                    f"{response.text[:200]}"
                )

            cuerpo = response.json()
            opciones = cuerpo.get("choices") or []
            if not opciones:
                raise ProviderEmptyResponse(
                    "La respuesta del proveedor no trae ninguna opción"
                )
            mensaje = opciones[0].get("message") or {}
            contenido = mensaje.get("content")
            if not contenido:
                motivo = opciones[0].get("finish_reason") or "sin motivo declarado"
                logger.warning(
                    "Contenido vacío del modelo %s, motivo declarado: %s",
                    self.model, motivo,
                )
            uso = cuerpo.get("usage") or {}
            return parse_judgement(
                contenido,
                int(uso.get("prompt_tokens") or 0),
                int(uso.get("completion_tokens") or 0),
                latencia,
            )

        def _is_transient(exc: Exception) -> bool:
            if isinstance(exc, (ProviderRefused, ModelContractViolation)):
                return False
            if isinstance(exc, httpx.HTTPStatusError):
                return exc.response.status_code in TRANSIENT_STATUS
            if isinstance(exc, ProviderEmptyResponse):
                return True
            return isinstance(exc, (httpx.TimeoutException, httpx.TransportError))

        return await with_backoff(_call, self.backoff, _is_transient)
