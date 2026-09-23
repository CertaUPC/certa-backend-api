"""Mide qué le pasa al veredicto cuando el código cambia de aspecto y no de fondo.

El transformador producía los pares y el repositorio sabía guardarlos, pero
nadie los unía: la tabla de transformaciones no la escribía nadie y la tasa de
descarte incorrecto no se calculaba nunca. Este servicio es esa unión.

Qué mide, en una frase: si el modelo cambia de "explotable" a "no explotable"
porque una variable pasó a llamarse validatedInput, no está leyendo el código,
está leyendo el nombre. Y si con el anclaje activo deja de hacerlo, el anclaje
no es un adorno del informe sino la pieza que sostiene el veredicto.

Por eso cada par se mide DOS veces, con anclaje y sin él, sobre el mismo modelo
y el mismo código. La diferencia entre ambos regímenes es el resultado; una sola
corrida no responde a nada.
"""

from dataclasses import dataclass, replace
from uuid import uuid4

from src.experimentation.domain.repositories.transformation_repository import (
    TransformationRepositoryPort,
)
from src.experimentation.domain.services.semantic_preserving_transformer import (
    AdversarialResult,
    Transformation,
)
from src.finding_validation.domain.entities.code_context import CodeContext
from src.finding_validation.domain.entities.finding import Finding
from src.finding_validation.domain.entities.verdict import VerdictValue
from src.finding_validation.domain.services.anchor_verifier import AnchorVerifier
from src.finding_validation.domain.services.budget_guard import BudgetGuard
from src.finding_validation.domain.services.language_model_port import (
    LanguageModelPort,
)
from src.finding_validation.domain.value_objects.justification import Justification


@dataclass(frozen=True)
class ParMedido:
    """Un par adversarial con todo lo que hizo falta para juzgarlo.

    Se devuelve entero y no solo su veredicto porque al analizar la corrida
    hace falta saber si el modelo llegó a citar líneas existentes: un cambio
    de veredicto acompañado de una cita que no se sostiene no es lo mismo que
    un cambio de veredicto bien argumentado.
    """

    transformacion: Transformation
    anclaje_activo: bool
    veredicto_original: str
    veredicto_transformado: str
    anclaje_original_verificado: bool
    anclaje_transformado_verificado: bool

    def como_resultado(self) -> AdversarialResult:
        return AdversarialResult(
            type=self.transformacion.type,
            anchoring_enabled=self.anclaje_activo,
            original_verdict=self.veredicto_original,
            transformed_verdict=self.veredicto_transformado,
        )


class MeasureAdversarialRobustnessCommandService:
    """Ejecuta los pares adversariales de un hallazgo y los deja registrados."""

    def __init__(
        self,
        language_model: LanguageModelPort,
        anchor_verifier: AnchorVerifier,
        repository: TransformationRepositoryPort,
        budget: BudgetGuard | None = None,
    ) -> None:
        self._model = language_model
        self._verifier = anchor_verifier
        self._repository = repository
        self._budget = budget

    async def execute(
        self,
        finding: Finding,
        context: CodeContext,
        transformaciones: list[Transformation],
        anclaje_activo: bool,
    ) -> list[ParMedido]:
        if not transformaciones:
            return []

        # El original se juzga una sola vez por régimen y no una por
        # transformación: es el mismo código y la misma consulta, de modo que
        # repetirlo gastaría presupuesto sin añadir información.
        veredicto_original, anclaje_original = await self._juzgar(
            finding, context, anclaje_activo
        )

        medidos: list[ParMedido] = []
        for transformacion in transformaciones:
            contexto = self._contexto_transformado(context, transformacion)
            veredicto, anclado = await self._juzgar(
                finding, contexto, anclaje_activo
            )
            par = ParMedido(
                transformacion=transformacion,
                anclaje_activo=anclaje_activo,
                veredicto_original=veredicto_original,
                veredicto_transformado=veredicto,
                anclaje_original_verificado=anclaje_original,
                anclaje_transformado_verificado=anclado,
            )
            await self._repository.record_pair(
                original_id=context.id,
                transformed_id=contexto.id,
                transformation_type=transformacion.type.value,
                anchoring_enabled=anclaje_activo,
                original_verdict=veredicto_original,
                transformed_verdict=veredicto,
                description=transformacion.signal,
            )
            medidos.append(par)
        return medidos

    async def _juzgar(
        self, finding: Finding, context: CodeContext, anclaje_activo: bool
    ) -> tuple[str, bool]:
        """Devuelve el veredicto y si el anclaje se verificó.

        Sin reintento, a diferencia de la cadena de producción. El reintento
        existe para darle al modelo una segunda oportunidad de citar bien, y
        aquí se mide justamente su primera reacción ante el código alterado:
        concedérsela contaminaría la medida.
        """
        if self._budget is not None:
            self._budget.consume()

        juicio = await self._model.judge(finding, context)
        propuesto = VerdictValue(juicio.value)

        justificacion = Justification(
            text=juicio.justification_text,
            cited_lines=frozenset(juicio.cited_lines),
        )
        anclaje = self._verifier.verify(justificacion, context)

        if not anclaje_activo:
            # El régimen sin anclaje toma la respuesta tal como llega. Es la
            # condición de control: lo que haría una herramienta que confía en
            # el modelo y no comprueba sus citas.
            return propuesto.value, anclaje.verified

        # Con anclaje y sin reintento: una cita que no se sostiene retira el
        # veredicto en lugar de corregirlo. attempts=2 fuerza esa resolución
        # inmediata en resolve_value.
        resuelto = self._verifier.resolve_value(propuesto, anclaje, attempts=2)
        return resuelto.value, anclaje.verified

    @staticmethod
    def _contexto_transformado(
        context: CodeContext, transformacion: Transformation
    ) -> CodeContext:
        """Contexto con el código alterado y su numeración recalculada.

        Recalcularla no es un detalle: dos de las tres transformaciones añaden
        líneas. Reutilizar la numeración del original haría que el verificador
        de anclaje comprobase las citas contra un rango que ya no corresponde,
        y toda la medida de robustez quedaría midiendo el desajuste en vez del
        comportamiento del modelo.
        """
        lineas = sorted(context.available_lines)
        esperado = list(range(lineas[0], lineas[0] + len(lineas)))
        if lineas != esperado:
            raise ValueError(
                "El contexto original no cubre un rango continuo de líneas "
                f"({lineas[0]} a {lineas[-1]} con {len(lineas)} líneas), de modo "
                "que la numeración del transformado no se puede derivar. Medir "
                "así daría una tasa de anclaje falsa."
            )
        primera = lineas[0]
        total = len(transformacion.transformed.splitlines())
        return replace(
            context,
            id=uuid4(),
            text=transformacion.transformed,
            available_lines=frozenset(range(primera, primera + total)),
        )
