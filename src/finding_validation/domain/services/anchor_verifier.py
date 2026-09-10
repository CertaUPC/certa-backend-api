from dataclasses import dataclass

from ..entities.code_context import CodeContext
from ..entities.verdict import VerdictValue
from ..value_objects.justification import Justification


@dataclass(frozen=True)
class AnchorResult:
    """Resultado de comprobar una justificación contra el contexto entregado."""

    verified: bool
    cited_lines: frozenset[int]
    missing_lines: frozenset[int]
    reason: str

    @property
    def failed(self) -> bool:
        return not self.verified

    def as_retry_hint(self) -> str:
        """Qué estuvo mal en el intento anterior, para no repetir a ciegas."""
        if self.verified:
            raise ValueError("Un anclaje verificado no genera pista de reintento")
        if not self.cited_lines:
            return (
                "La respuesta anterior no citó ninguna línea. Cita los números de "
                "línea concretos del fragmento entregado en los que apoyas tu "
                "conclusión."
            )
        faltantes = ", ".join(str(n) for n in sorted(self.missing_lines))
        return (
            f"La respuesta anterior citó las líneas {faltantes}, que no existen en "
            f"el fragmento entregado. Cita únicamente líneas presentes en ese "
            f"fragmento."
        )


class AnchorVerifier:
    """Comprueba que cada línea que el modelo cita exista en el contexto que se
    le entregó.

    Es lo que separa una justificación de una opinión: un modelo que descarta un
    hallazgo porque la función se llama validateInput no puede señalar la línea
    donde valida, porque no la hay.

    Servicio y no método de una entidad porque necesita el veredicto y el
    contexto a la vez.
    """

    def verify(
        self, justification: Justification, context: CodeContext
    ) -> AnchorResult:
        cited = justification.cited_lines

        if not cited:
            return AnchorResult(
                verified=False,
                cited_lines=frozenset(),
                missing_lines=frozenset(),
                reason="La justificación no cita ninguna línea",
            )

        missing = frozenset(n for n in cited if not context.contains_line(n))

        if missing:
            return AnchorResult(
                verified=False,
                cited_lines=cited,
                missing_lines=missing,
                reason=(
                    f"{len(missing)} de {len(cited)} líneas citadas no existen "
                    f"en el contexto entregado"
                ),
            )

        return AnchorResult(
            verified=True,
            cited_lines=cited,
            missing_lines=frozenset(),
            reason=f"Las {len(cited)} líneas citadas existen en el contexto",
        )

    def resolve_value(
        self, proposed: VerdictValue, result: AnchorResult, attempts: int
    ) -> VerdictValue:
        """Si el anclaje falla tras el reintento, el veredicto propuesto se
        descarta y el hallazgo pasa a no verificable."""
        if result.verified:
            return proposed
        if attempts >= 2:
            return VerdictValue.NOT_VERIFIABLE
        return proposed
