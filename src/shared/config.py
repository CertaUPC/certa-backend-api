"""Configuración del servicio. Todo por entorno, nada versionado.

Las credenciales del proveedor viven fuera del repositorio y se rotan cambiando
la variable de entorno, sin tocar el código ni volver a desplegar.
"""

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # -- servicio ---------------------------------------------------------
    app_name: str = "certa-backend-api"
    debug: bool = False
    cors_origins: str = "http://localhost:5173"

    # -- persistencia -----------------------------------------------------
    database_url: str = Field(
        default="sqlite+aiosqlite:///./certa.db",
        description="Cadena asíncrona. En despliegue, postgresql+asyncpg://...",
    )

    # -- autenticación ----------------------------------------------------
    jwt_secret: str = Field(default="cambiar-en-despliegue", min_length=8)
    jwt_algorithm: str = "HS256"
    jwt_expiration_minutes: int = 480

    # -- proveedor de modelo ----------------------------------------------
    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_model: str = ""
    llm_model_version: str = ""
    llm_temperature: float = 0.0
    llm_timeout_seconds: int = 120
    # Tope de tokens de la respuesta. El contrato de salida son unos cientos;
    # sin tope, la pasarela reserva crédito por el máximo del modelo, que llega
    # a 65 536, y rechaza la petición con 402 aunque el saldo sobre de largo.
    # Los modelos que razonan gastan parte del tope en su razonamiento: con 2 000
    # truncaban una de cada nueve respuestas y el contenido llegaba vacío.
    llm_max_output_tokens: int = 4000
    # Paquete de certificados con el que verificar al proveedor. Hace falta en
    # redes o antivirus que interceptan TLS, donde el almacén por omisión no
    # incluye la autoridad que firma la conexión.
    ssl_cert_file: str = ""
    llm_queries_per_minute: int = 60

    # -- presupuesto ------------------------------------------------------
    budget_max_queries: int = 3000
    usd_per_1k_input: float = 0.003
    usd_per_1k_output: float = 0.015

    # -- análisis ---------------------------------------------------------
    repository_root: str = "./repos"
    # Ata al trabajador a un proyecto. Vacio significa que toma cualquier
    # ejecucion pendiente, que solo es seguro cuando todos los trabajadores de
    # esa base ven el mismo repositorio: el trabajador lee el codigo de SU
    # disco, y reclamar el de otro consume el lote sin poder procesarlo.
    worker_project_id: str = ""
    caller_depth: int = 2
    # Eslabones de delegación que se siguen al recuperar el contexto. El
    # saneamiento casi nunca está en el método que contiene la línea señalada,
    # sino en el auxiliar al que ese método le pasa el dato. Sin su cuerpo el
    # modelo ve el origen y el sumidero pero no la transformación intermedia, y
    # se abstiene con razón.
    callee_depth: int = 2
    max_context_lines: int = 250
    retention_days: int = 30

    # Resultados esperados del conjunto de referencia. Vacío en un despliegue
    # normal: solo la prueba de concepto mide contra verdad conocida.
    ground_truth_path: str = ""

    @field_validator("llm_temperature")
    @classmethod
    def _temperature_must_be_zero(cls, v: float) -> float:
        if v != 0.0:
            raise ValueError(
                "La temperatura debe ser cero: la reproducibilidad del "
                "experimento depende de ello"
            )
        return v

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def llm_configured(self) -> bool:
        """Si no hay proveedor configurado, el servicio arranca igual.

        Permite levantar la interfaz de programación para revisar ejecuciones
        pasadas sin exponer una clave, y hace que la ausencia de credencial se
        detecte al usarla y no al desplegar.
        """
        return bool(self.llm_base_url and self.llm_api_key and self.llm_model)


@lru_cache
def get_settings() -> Settings:
    return Settings()
