import hashlib
import re
from dataclasses import dataclass

# Comentarios de línea y de bloque de Java, C, JavaScript y familia.
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT = re.compile(r"//[^\n]*")
_WHITESPACE = re.compile(r"\s+")

_HEX_LENGTH = 64


def normalize(body: str) -> str:
    """Quita comentarios y colapsa espacios: reindentar no debe producir otro
    hallazgo."""
    without_comments = _LINE_COMMENT.sub(" ", _BLOCK_COMMENT.sub(" ", body))
    return _WHITESPACE.sub(" ", without_comments).strip()


@dataclass(frozen=True)
class Fingerprint:
    """Identidad del hallazgo entre ejecuciones.

    No incluye el número de línea: insertar código más arriba lo desplaza sin
    cambiar nada, y tratarlo como nuevo obligaría a pagar otra vez la consulta.
    """

    value: str

    def __post_init__(self) -> None:
        if len(self.value) != _HEX_LENGTH:
            raise ValueError(
                f"Una huella tiene {_HEX_LENGTH} caracteres hexadecimales, "
                f"llegaron {len(self.value)}"
            )

    @classmethod
    def compute(cls, rule_id: str, file_path: str, body: str) -> "Fingerprint":
        if not rule_id or not file_path:
            raise ValueError("La regla y el archivo son obligatorios para la huella")
        material = "".join((rule_id, file_path.replace("\\", "/"), normalize(body)))
        return cls(hashlib.sha256(material.encode("utf-8")).hexdigest())

    @property
    def short(self) -> str:
        return self.value[:12]

    def __str__(self) -> str:
        return self.value
