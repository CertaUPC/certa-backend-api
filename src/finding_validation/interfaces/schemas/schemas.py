"""Esquemas de entrada y salida. Traducen entre el mundo exterior y el dominio.

Ningún esquema lleva lógica: son forma, no regla. Si una validación aquí decide
algo del negocio, está en el sitio equivocado.
"""

from datetime import datetime
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
    years_of_experience: int = Field(ge=0, le=60)
    consented: bool = Field(
        description="Debe ser verdadero. Sin consentimiento no se registra nada."
    )


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


class LoginRequest(BaseModel):
    email: str
    password: str


# ---------------------------------------------------------------- salida
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


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
    status: str
    total_findings: int
    validated_findings: int
    pending_findings: int
    progress: float
    progress_text: str
    failure_reason: str | None = None
    created_at: datetime


class IngestResponse(BaseModel):
    execution: ExecutionResponse
    ingested: int
    filtered_out: int
    skipped: list[str]
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


class MetricsResponse(BaseModel):
    execution_id: UUID
    total_verdicts: int
    confusion: dict
    anchor_rate_first_try: float
    run_is_valid: bool
    run_quality_reason: str
    budget: str
