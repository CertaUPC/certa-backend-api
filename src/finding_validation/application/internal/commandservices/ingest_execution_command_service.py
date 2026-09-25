"""Ingesta de hallazgos y creación de la ejecución."""

import logging
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from ....domain.entities.execution import Execution
from ....domain.entities.finding import Finding
from ....domain.repositories.repositories import (
    ExecutionRepository,
    FindingRepository,
)
from ....domain.services.ground_truth_port import GroundTruthPort
from ....domain.value_objects.scope_filter import ScopeFilter
from ....infrastructure.external.sarif_parser import (
    SarifError,
    SarifIngestion,
    parse_sarif,
    parse_sarif_file,
)

logger = logging.getLogger(__name__)


@dataclass
class IngestResult:
    execution: Execution
    ingested: int
    filtered_out: int
    skipped: list[str]
    labeled: int = 0

    @property
    def is_empty(self) -> bool:
        """Un análisis sin hallazgos que procesar.

        No es un fallo, pero debe informarse de manera explícita en lugar de
        dejar una ejecución en silencio que nadie sabe interpretar.
        """
        return self.ingested == 0

    def describe(self) -> str:
        if self.is_empty and self.filtered_out:
            return (
                f"El archivo traía {self.filtered_out} hallazgos, pero ninguno "
                f"cumple el alcance declarado. No se consumirá presupuesto."
            )
        if self.is_empty:
            return "El análisis no encontró hallazgos"
        detalle = f"{self.ingested} hallazgos ingeridos"
        if self.filtered_out:
            detalle += f", {self.filtered_out} fuera del alcance"
        if self.skipped:
            detalle += f", {len(self.skipped)} omitidos por datos incompletos"
        if self.labeled:
            detalle += f", {self.labeled} con verdad conocida"
        return detalle


class IngestExecutionCommandService:
    """Crea la ejecución y persiste sus hallazgos normalizados."""

    def __init__(
        self,
        execution_repository: ExecutionRepository,
        finding_repository: FindingRepository,
        ground_truth: GroundTruthPort | None = None,
    ) -> None:
        self._executions = execution_repository
        self._findings = finding_repository
        # Solo los conjuntos de referencia traen etiqueta. Un proyecto real
        # ingresa sin ella y el resto del flujo no cambia.
        self._ground_truth = ground_truth

    async def from_payload(
        self,
        project_id: UUID,
        payload: dict,
        scope: ScopeFilter | None = None,
        created_by: UUID | None = None,
        label: str | None = None,
    ) -> IngestResult:
        return await self._ingest(
            project_id, parse_sarif(payload), scope, created_by, label
        )

    async def from_file(
        self,
        project_id: UUID,
        path: str | Path,
        scope: ScopeFilter | None = None,
        created_by: UUID | None = None,
    ) -> IngestResult:
        # Sin autor cuando entra por linea de ordenes: ahi no hay sesion, y
        # atribuirla a alguien seria inventar el dato.
        return await self._ingest(
            project_id, parse_sarif_file(path), scope, created_by
        )

    async def _ingest(
        self,
        project_id: UUID,
        ingestion: SarifIngestion,
        scope: ScopeFilter | None,
        created_by: UUID | None = None,
        label: str | None = None,
    ) -> IngestResult:
        alcance = scope or ScopeFilter.unrestricted()
        admitidos = alcance.apply(ingestion.findings)
        descartados = len(ingestion.findings) - len(admitidos)
        etiquetados = self._label(admitidos)

        if not ingestion.ruleset_version:
            # La versión del conjunto de reglas es condición para comparar dos
            # ejecuciones. Si la herramienta no la declara, se registra como
            # desconocida en lugar de inventarla.
            logger.warning(
                "El archivo SARIF no declara versión de reglas; se registra como "
                "desconocida"
            )

        execution = Execution(
            project_id=project_id,
            tool_name=ingestion.tool_name or "desconocida",
            ruleset_version=ingestion.ruleset_version or "desconocida",
            total_findings=len(admitidos),
            scope=alcance,
            created_by=created_by,
            # Un nombre de espacios no es un nombre. Se guarda nulo para que la
            # pantalla caiga a la fecha en vez de enseñar un título vacío.
            label=(label or "").strip() or None,
        )
        await self._executions.save(execution)
        if admitidos:
            await self._findings.save_all(admitidos, execution.id)

        return IngestResult(
            execution=execution,
            ingested=len(admitidos),
            filtered_out=descartados,
            skipped=ingestion.skipped,
            labeled=etiquetados,
        )

    def _label(self, findings: list[Finding]) -> int:
        """Adjunta la verdad conocida y devuelve cuántos la recibieron."""
        if self._ground_truth is None:
            return 0
        etiquetados = 0
        for finding in findings:
            verdad = self._ground_truth.truth_for(finding)
            if verdad is not None:
                finding.known_truth = verdad
                etiquetados += 1
        if not etiquetados and findings:
            logger.warning(
                "Ningún hallazgo coincidió con el conjunto de referencia. "
                "Revisa que las rutas del SARIF apunten a los casos de prueba."
            )
        return etiquetados


__all__ = ["IngestExecutionCommandService", "IngestResult", "SarifError"]
