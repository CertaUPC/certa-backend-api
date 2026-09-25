"""Esquemas de entrada y salida. Traducen entre el mundo exterior y el dominio.

Ningún esquema lleva lógica: son forma, no regla. Si una validación aquí decide
algo del negocio, está en el sitio equivocado.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


# --------------------------------------------------------------- entrada
class ScopeRequest(BaseModel):
    cwes: list[str] = Field(default_factory=list)
    min_severity: str | None = Field(
        default=None, description="error, warning o note"
    )


class IngestSarifRequest(BaseModel):
    project_id: UUID
    sarif: dict
    scope: ScopeRequest | None = None
    # Opcional a propósito: quien carga desde la línea de órdenes no pone
    # nombre, y la pantalla resuelve con la fecha.
    label: str | None = Field(default=None, max_length=120)


class AuditRequest(BaseModel):
    """Decision de auditoria del producto.

    No pide participante ni condicion, a diferencia de DecisionRequest. Esas
    dos son instrumentacion del estudio: exigirlas obligaba a inventar un
    participante cada vez que alguien usara la herramienta fuera de el.
    """

    value: str = Field(description="confirmado, descartado o dudoso")
    seconds: float = Field(gt=0, description="Tiempo empleado en la revision")
    comment: str | None = None


class AuditResponse(BaseModel):
    id: UUID
    finding_id: UUID
    value: str
    seconds: float
    is_current: bool
    comment: str | None
    created_at: datetime


class DecisionRequest(BaseModel):
    finding_id: UUID
    participant_id: UUID
    value: str = Field(description="confirmado, descartado o dudoso")
    seconds: float = Field(gt=0)
    condition: str = Field(description="con_asistente o sin_asistente")
    session_id: UUID | None = None
    comment: str | None = None


class ParticipantRequest(BaseModel):
    anonymous_code: str = Field(min_length=1, max_length=20)
    # La ficha del anexo B, que antes vivia en un formulario aparte. Entra
    # aqui porque la pregunta del rol de seguridad decide si la sesion se
    # habilita, y porque la experiencia es factor de control del analisis:
    # cruzarla despues por un codigo tecleado a mano es donde se pierden filas.
    experience_band: str = Field(
        description="menos_de_1, de_1_a_3, de_4_a_7 o mas_de_7"
    )
    has_security_role: bool = Field(
        default=False,
        description=(
            "Rol formal de seguridad de aplicaciones. Una respuesta afirmativa "
            "activa el criterio de exclusion y la sesion no se habilita."
        ),
    )
    main_language: str | None = None
    alert_frequency: str | None = Field(
        default=None,
        description="nunca, alguna_vez, mensual, semanal o diaria",
    )
    security_training: str | None = Field(
        default=None, description="ninguna, autodidacta o curso"
    )
    consented: bool = Field(
        description="Debe ser verdadero. Sin consentimiento no se registra nada."
    )
    is_pilot: bool = Field(
        default=False,
        description=(
            "Participa en la sesión piloto. Sus datos quedan fuera del "
            "análisis y no cuentan para el contrabalanceo."
        ),
    )


class SessionThemeRequest(BaseModel):
    """Con qué presentación resolvió la tarea un participante.

    Solo dos valores, y cerrados a propósito: un tema libre dejaría entrar
    cualquier cadena en una columna que el análisis va a usar como factor.
    """

    participant_id: UUID
    theme: Literal["light", "dark"]


class ProjectRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    repository_path: str = Field(
        default="",
        description="Ruta o URL del repositorio. Identifica al proyecto de forma "
        "única; si se omite se usa el nombre.",
    )
    language: str = Field(default="java", max_length=50)
    is_public_dataset: bool = Field(
        default=False,
        description="Marca los conjuntos con etiqueta conocida, como OWASP "
        "Benchmark, que sirven de referencia y no de código en producción.",
    )


# ---------------------------------------------------------------- salida
class ProjectResponse(BaseModel):
    id: UUID
    name: str
    language: str
    repository_path: str
    is_public_dataset: bool
    execution_count: int
    created_at: datetime


class ExecutionResponse(BaseModel):
    id: UUID
    project_id: UUID
    project_name: str = ""
    tool_name: str
    ruleset_version: str
    label: str | None = None
    status: str
    total_findings: int
    validated_findings: int
    pending_findings: int
    progress: float
    progress_text: str
    failure_reason: str | None = None
    # Quién la tomó y desde cuándo. Sin esto, una corrida que se quedó en
    # proceso porque el trabajador murió no se distingue de una que avanza, y
    # decidir si devolverla a la cola sería a ciegas.
    claimed_by: str | None = None
    started_at: datetime | None = None
    # Lo que el último intento dejó dicho. Es la señal del trabajador hacia la
    # pantalla: sin ella, una corrida que vuelve a la cola porque el
    # repositorio no está se ve igual que una que espera su turno.
    last_attempt_note: str | None = None
    last_attempt_at: datetime | None = None
    created_at: datetime


class IngestResponse(BaseModel):
    execution: ExecutionResponse
    ingested: int
    filtered_out: int
    skipped: list[str]
    labeled: int = 0
    message: str


class VerdictResponse(BaseModel):
    model: str
    model_version: str
    value: str
    confidence: float | None
    anchor_verified: bool
    attempts: int
    reused: bool
    justification: str | None
    cited_lines: list[int]


class StabilityResponse(BaseModel):
    """Cuántas veces se preguntó lo mismo y en cuántas coincidió la respuesta.

    Con temperatura cero la respuesta debería ser idéntica siempre. Que no lo
    sea es un dato del resultado, no un detalle de implementación, y por eso
    viaja junto al hallazgo en lugar de quedarse en la base.
    """

    runs: int
    agree: int


class FindingResponse(BaseModel):
    id: UUID
    rule_id: str
    cwe: str | None
    severity: str
    file_path: str
    start_line: int
    end_line: int
    message: str | None
    fingerprint: str
    priority: float | None = None
    priority_reason: str | None = None
    verdict: VerdictResponse | None = None
    stability: StabilityResponse | None = None


class ContextResponse(BaseModel):
    enclosing_function: str
    first_line: int = Field(
        default=1,
        description="Número real de la primera línea del texto. Sin él, quien "
        "muestre el contexto lo numeraría desde uno y las líneas citadas por el "
        "modelo señalarían al lugar equivocado.",
    )
    callers: list[str]
    sanitizers: list[str]
    degraded_to_file: bool
    recovered_lines: int
    text: str | None = Field(
        default=None,
        description="Nulo si el contexto fue purgado por la política de retención",
    )


class RunReportResponse(BaseModel):
    execution_id: UUID
    validated: int
    failed: int
    interrupted: bool
    interruption_reason: str | None
    budget: str


class EnqueuedResponse(BaseModel):
    """Acuse de que el trabajo quedó en la cola.

    No lleva resultados porque no los hay todavía: el trabajador aún no la ha
    tomado. El avance se consulta en el recorrido de la ejecución.
    """

    execution_id: UUID
    status: str
    pending_findings: int
    message: str


class MetricsResponse(BaseModel):
    execution_id: UUID
    total_verdicts: int
    confusion: dict
    anchor_rate_first_try: float
    run_is_valid: bool
    run_quality_reason: str
    # Hallazgos en que el veredicto contradice la verdad conocida, y proporción
    # de ellos que el participante adoptó en lugar de rectificar. Condiciona la
    # lectura de la exactitud: una mejora acompañada de seguimiento alto indica
    # traslado de la decisión y no mejor juicio.
    misleading_verdicts: int
    misleading_follow_rate: float | None
    budget: str
