import hashlib
from dataclasses import dataclass

# Se versiona junto con la consulta: cambiar uno sin el otro invalida la
# comparación.
OUTPUT_CONTRACT_V1 = {
    "value": "explotable | no_explotable | indeterminado",
    "justification_text": "str",
    "cited_lines": "list[int]",
    "confidence": "float en [0, 1]",
}


@dataclass(frozen=True)
class PromptVersion:
    """Con qué consulta y qué contrato se obtuvo un veredicto.

    Se guarda con cada veredicto. Tocar la consulta crea una versión nueva; los
    veredictos viejos siguen apuntando a la suya.
    """

    label: str
    template_digest: str
    contract_digest: str

    def __post_init__(self) -> None:
        if not self.label:
            raise ValueError("La versión de la consulta exige una etiqueta legible")

    @classmethod
    def of(cls, label: str, template: str, contract: dict[str, str]) -> "PromptVersion":
        if not template.strip():
            raise ValueError("Una consulta vacía no se puede versionar")
        contrato = "|".join(f"{k}={v}" for k, v in sorted(contract.items()))
        return cls(
            label=label,
            template_digest=hashlib.sha256(template.encode("utf-8")).hexdigest()[:16],
            contract_digest=hashlib.sha256(contrato.encode("utf-8")).hexdigest()[:16],
        )

    @property
    def identifier(self) -> str:
        return f"{self.label}+{self.template_digest}+{self.contract_digest}"

    def __str__(self) -> str:
        return self.identifier
