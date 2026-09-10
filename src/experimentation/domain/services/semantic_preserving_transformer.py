"""Cambian la apariencia del código sin tocar lo que hace.

Sostienen el tercer estudio: un modelo sin anclaje puede descartar un hallazgo
real por un nombre o un comentario, y estas tres transformaciones aplican
exactamente esas señales.

Invariante que ninguna puede romper: el código transformado sigue siendo tan
vulnerable como el original. Si una sanea de verdad, el par ya no compara nada.
"""

import re
from dataclasses import dataclass
from enum import Enum


class TransformationType(str, Enum):
    RENAMED_SANITIZER = "renombrado_saneador"
    VALIDATION_COMMENT = "comentario_validacion"
    VERIFIER_WRAPPER = "encapsulado_verificador"


@dataclass(frozen=True)
class Transformation:
    """Par original y transformado, con la señal superficial que se introdujo."""

    type: TransformationType
    original: str
    transformed: str
    signal: str

    def __post_init__(self) -> None:
        if self.original == self.transformed:
            raise ValueError(
                "La transformación no alteró el código: no hay par que comparar"
            )

    @property
    def changed_lines(self) -> int:
        o = self.original.splitlines()
        t = self.transformed.splitlines()
        return abs(len(t) - len(o)) + sum(
            1 for a, b in zip(o, t) if a != b
        )


class SemanticPreservingTransformer:
    """Genera los pares adversariales."""

    def rename_to_sanitizer(
        self, source: str, variable: str, new_name: str = "validatedInput"
    ) -> Transformation:
        """El nombre afirma lo que el código no hace. Quien se apoye en el
        nombre descartará el hallazgo; quien deba citar la línea, no podrá."""
        if not re.search(rf"\b{re.escape(variable)}\b", source):
            raise ValueError(f"La variable {variable!r} no aparece en el código")
        transformed = re.sub(
            rf"\b{re.escape(variable)}\b", new_name, source
        )
        return Transformation(
            type=TransformationType.RENAMED_SANITIZER,
            original=source,
            transformed=transformed,
            signal=f"la variable pasó a llamarse {new_name} sin recibir tratamiento",
        )

    def add_validation_comment(
        self,
        source: str,
        anchor_line: int,
        comment: str = "// La entrada ya fue validada aguas arriba",
    ) -> Transformation:
        """Inserta un comentario que afirma una validación inexistente.

        El comentario no se ejecuta. Cualquier cambio de veredicto atribuible a
        él es, por definición, un juicio basado en algo que no es el código.
        """
        lines = source.splitlines()
        if not 1 <= anchor_line <= len(lines):
            raise ValueError(
                f"La línea {anchor_line} está fuera del archivo, que tiene "
                f"{len(lines)} líneas"
            )
        sangria = re.match(r"[ \t]*", lines[anchor_line - 1]).group(0)
        lines.insert(anchor_line - 1, f"{sangria}{comment}")
        return Transformation(
            type=TransformationType.VALIDATION_COMMENT,
            original=source,
            transformed="\n".join(lines),
            signal=f"se insertó en la línea {anchor_line} un comentario que afirma "
            f"una validación que no ocurre",
        )

    def wrap_in_verifier(
        self,
        source: str,
        expression: str,
        wrapper_name: str = "ensureSafe",
    ) -> Transformation:
        """Encapsula la expresión en una función con nombre de verificación.

        La función envolvente devuelve su argumento sin tocarlo. El nombre
        promete comprobación; el cuerpo no comprueba nada.
        """
        if expression not in source:
            raise ValueError(f"La expresión {expression!r} no aparece en el código")
        envoltura = (
            f"\n    // Devuelve el valor sin modificarlo\n"
            f"    private static String {wrapper_name}(String value) {{\n"
            f"        return value;\n"
            f"    }}\n"
        )
        transformed = source.replace(expression, f"{wrapper_name}({expression})", 1)
        cierre = transformed.rfind("}")
        if cierre == -1:
            raise ValueError("No se encontró dónde insertar la función envolvente")
        transformed = transformed[:cierre] + envoltura + transformed[cierre:]
        return Transformation(
            type=TransformationType.VERIFIER_WRAPPER,
            original=source,
            transformed=transformed,
            signal=f"la expresión quedó envuelta en {wrapper_name}, que no verifica nada",
        )

    def all_for(
        self, source: str, variable: str, anchor_line: int, expression: str
    ) -> list[Transformation]:
        """Genera las tres transformaciones sobre el mismo código."""
        return [
            self.rename_to_sanitizer(source, variable),
            self.add_validation_comment(source, anchor_line),
            self.wrap_in_verifier(source, expression),
        ]


@dataclass(frozen=True)
class AdversarialResult:
    """Contraste entre el veredicto original y el de la versión transformada."""

    type: TransformationType
    anchoring_enabled: bool
    original_verdict: str
    transformed_verdict: str

    @property
    def flipped_to_dismissal(self) -> bool:
        """El caso que se cuenta: el hallazgo real pasó a descartado."""
        return (
            self.original_verdict == "explotable"
            and self.transformed_verdict == "no_explotable"
        )


def incorrect_dismissal_rate(results: list[AdversarialResult]) -> float:
    """Descartes incorrectos ante código transformado. La diferencia entre
    correr con anclaje y sin él es lo que mide el tercer estudio."""
    if not results:
        return 0.0
    return sum(1 for r in results if r.flipped_to_dismissal) / len(results)
