"""Arma el grafo de objetos en un solo lugar.

Aparte de `main.py`: si el cableado vive en el arranque, ese archivo crece con
cada contexto nuevo. Es además el único sitio donde se nombra una tecnología
concreta.
"""

import logging
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from ..finding_validation.application.internal.commandservices.compare_models_command_service import (
    CompareModelsCommandService,
)
from ..finding_validation.application.internal.commandservices.ingest_execution_command_service import (
    IngestExecutionCommandService,
)
from ..finding_validation.application.internal.commandservices.run_execution_command_service import (
    RunExecutionCommandService,
)
from ..finding_validation.application.internal.commandservices.validate_finding_command_service import (
    ValidateFindingCommandService,
)
from ..finding_validation.domain.services.anchor_verifier import AnchorVerifier
from ..finding_validation.domain.services.budget_guard import BudgetGuard
from ..finding_validation.domain.services.deterministic_prefilter import (
    DeterministicPrefilter,
)
from ..finding_validation.domain.services.priority_calculator import PriorityCalculator
from ..finding_validation.infrastructure.external.code_reader_registry import (
    CodeReaderRegistry,
)
from ..finding_validation.infrastructure.external.owasp_benchmark_ground_truth import (
    OwaspBenchmarkGroundTruth,
)
from ..finding_validation.infrastructure.external.prompt_builder import CURRENT_VERSION
from ..finding_validation.infrastructure.persistence.sql_repositories import (
    SqlCodeContextRepository,
    SqlExecutionRepository,
    SqlFindingRepository,
    SqlVerdictRepository,
)
from .config import Settings
from .database import create_engine, session_factory

logger = logging.getLogger(__name__)


class Container:
    """Contiene lo que vive mientras vive el proceso."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.engine: AsyncEngine = create_engine(settings.database_url, settings.debug)
        self.sessions: async_sessionmaker[AsyncSession] = session_factory(self.engine)

        # Servicios de dominio: sin estado por petición, se comparten.
        self.anchor_verifier = AnchorVerifier()
        self.prefilter = DeterministicPrefilter()
        self.priority_calculator = PriorityCalculator()
        self.code_reader = CodeReaderRegistry(
            Path(settings.repository_root), settings.max_context_lines
        )
        self.prompt_version = CURRENT_VERSION

        self.language_model = self._build_language_model()
        self.ground_truth = self._build_ground_truth()

    def _build_ground_truth(self):
        """Carga la verdad conocida del conjunto de referencia, si la hay.

        Un despliegue normal no la tiene y no debe tenerla. Solo la prueba de
        concepto del primer objetivo mide contra etiquetas.
        """
        if not self.settings.ground_truth_path:
            return None
        cargador = OwaspBenchmarkGroundTruth(self.settings.ground_truth_path)
        logger.info("Verdad conocida cargada: %d casos de prueba", len(cargador))
        return cargador

    def _build_language_model(self):
        """Construye el adaptador del proveedor, o None si no está configurado.

        Que el servicio arranque sin proveedor es deliberado: permite revisar
        ejecuciones pasadas sin exponer una credencial, y hace que la ausencia se
        detecte al usarla y no al desplegar.
        """
        if not self.settings.llm_configured:
            logger.warning(
                "Sin proveedor de modelo configurado. La ingesta y la consulta "
                "funcionan; lanzar una validación devolverá error explícito."
            )
            return None

        from ..finding_validation.infrastructure.external.chat_completions_language_model import (
            ChatCompletionsLanguageModel,
        )

        return ChatCompletionsLanguageModel(
            base_url=self.settings.llm_base_url,
            api_key=self.settings.llm_api_key,
            model=self.settings.llm_model,
            version=self.settings.llm_model_version or self.settings.llm_model,
            temperature=self.settings.llm_temperature,
            timeout_seconds=self.settings.llm_timeout_seconds,
            queries_per_minute=self.settings.llm_queries_per_minute,
            ca_bundle=self.settings.ssl_cert_file,
            max_output_tokens=self.settings.llm_max_output_tokens,
        )

    def new_budget(self) -> BudgetGuard:
        """Un presupuesto por ejecución, no compartido entre ellas."""
        return BudgetGuard(
            max_queries=self.settings.budget_max_queries,
            usd_per_1k_input=self.settings.usd_per_1k_input,
            usd_per_1k_output=self.settings.usd_per_1k_output,
        )

    # -- servicios por petición -------------------------------------------
    def ingest_service(self, session: AsyncSession) -> IngestExecutionCommandService:
        return IngestExecutionCommandService(
            SqlExecutionRepository(session),
            SqlFindingRepository(session),
            self.ground_truth,
        )

    def language_model_named(self, model: str):
        """Un adaptador para el modelo indicado, con el resto de la configuración
        intacta.

        Lo emplea el benchmarking, que compara clases de modelo entre sí. Entre
        corridas solo puede cambiar el identificador: si cambiara la temperatura,
        el tiempo de espera o el ritmo de consulta, la diferencia medida dejaría
        de ser atribuible al modelo.
        """
        if not (self.settings.llm_base_url and self.settings.llm_api_key):
            raise RuntimeError(
                "Falta el proveedor. Define llm_base_url y llm_api_key en el "
                "entorno. El identificador del modelo llega por argumento."
            )

        from ..finding_validation.infrastructure.external.chat_completions_language_model import (
            ChatCompletionsLanguageModel,
        )

        return ChatCompletionsLanguageModel(
            base_url=self.settings.llm_base_url,
            api_key=self.settings.llm_api_key,
            model=model,
            version=model,
            temperature=self.settings.llm_temperature,
            timeout_seconds=self.settings.llm_timeout_seconds,
            queries_per_minute=self.settings.llm_queries_per_minute,
            ca_bundle=self.settings.ssl_cert_file,
            max_output_tokens=self.settings.llm_max_output_tokens,
        )

    def comparator(self, session: AsyncSession) -> CompareModelsCommandService:
        return CompareModelsCommandService(
            finding_repository=SqlFindingRepository(session),
            verdict_repository=SqlVerdictRepository(session),
            code_reader=self.code_reader,
            anchor_verifier=self.anchor_verifier,
            prefilter=self.prefilter,
            prompt_version=self.prompt_version,
        )

    def validator(
        self, session: AsyncSession, budget: BudgetGuard, language_model=None
    ) -> ValidateFindingCommandService:
        model = language_model or self.language_model
        if model is None:
            raise RuntimeError(
                "No hay proveedor de modelo configurado. Define llm_base_url, "
                "llm_api_key y llm_model en el entorno."
            )
        return ValidateFindingCommandService(
            code_reader=self.code_reader,
            language_model=model,
            anchor_verifier=self.anchor_verifier,
            prefilter=self.prefilter,
            budget=budget,
            prompt_version=self.prompt_version,
        )

    def runner(
        self, session: AsyncSession, budget: BudgetGuard, language_model=None
    ) -> RunExecutionCommandService:
        return RunExecutionCommandService(
            execution_repository=SqlExecutionRepository(session),
            finding_repository=SqlFindingRepository(session),
            context_repository=SqlCodeContextRepository(session),
            verdict_repository=SqlVerdictRepository(session),
            validator=self.validator(session, budget, language_model),
            budget=budget,
            priority_calculator=self.priority_calculator,
            prompt_version=self.prompt_version.identifier,
        )

    async def dispose(self) -> None:
        await self.engine.dispose()
