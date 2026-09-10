from dataclasses import dataclass, field

# Perfil declarado en el Project Charter.
AVG_INPUT_TOKENS = 3_500
AVG_OUTPUT_TOKENS = 450


class BudgetExhausted(RuntimeError):
    """Se alcanzó el límite. Lo validado se conserva; el resto queda pendiente."""


@dataclass(frozen=True)
class CostEstimate:
    """Previsión de consumo antes de emitir la primera consulta."""

    queries: int
    input_tokens: int
    output_tokens: int
    usd: float

    def describe(self) -> str:
        return (
            f"{self.queries} consultas previstas, "
            f"{self.input_tokens:,} tokens de entrada y "
            f"{self.output_tokens:,} de salida, "
            f"unos US$ {self.usd:.2f}"
        )


@dataclass
class BudgetGuard:
    """Impide que una configuración mal puesta se lleve el presupuesto en una
    corrida.

    Cuenta consultas, no dinero: el precio por token lo mueve el proveedor.
    """

    max_queries: int
    usd_per_1k_input: float = 0.0
    usd_per_1k_output: float = 0.0
    spent_queries: int = 0
    spent_input_tokens: int = 0
    spent_output_tokens: int = 0
    reused_queries: int = field(default=0)
    resolved_by_rule: int = field(default=0)

    def __post_init__(self) -> None:
        if self.max_queries < 1:
            raise ValueError("El límite se expresa en consultas y debe ser positivo")

    def estimate(self, pending_findings: int, repetitions: int = 1) -> CostEstimate:
        queries = pending_findings * repetitions
        entrada = queries * AVG_INPUT_TOKENS
        salida = queries * AVG_OUTPUT_TOKENS
        usd = (entrada / 1_000) * self.usd_per_1k_input + (
            salida / 1_000
        ) * self.usd_per_1k_output
        return CostEstimate(queries, entrada, salida, round(usd, 2))

    @property
    def remaining(self) -> int:
        return max(0, self.max_queries - self.spent_queries)

    @property
    def is_exhausted(self) -> bool:
        return self.spent_queries >= self.max_queries

    def reserve(self) -> None:
        if self.is_exhausted:
            raise BudgetExhausted(
                f"Se alcanzó el límite de {self.max_queries} consultas. "
                f"Lo validado se conserva y el resto queda pendiente."
            )
        self.spent_queries += 1

    def record_usage(self, input_tokens: int, output_tokens: int) -> None:
        self.spent_input_tokens += max(0, input_tokens)
        self.spent_output_tokens += max(0, output_tokens)

    def record_reuse(self) -> None:
        self.reused_queries += 1

    def record_rule_resolution(self) -> None:
        self.resolved_by_rule += 1

    @property
    def spent_usd(self) -> float:
        return round(
            (self.spent_input_tokens / 1_000) * self.usd_per_1k_input
            + (self.spent_output_tokens / 1_000) * self.usd_per_1k_output,
            2,
        )

    @property
    def avoided_queries(self) -> int:
        """Lo que la cascada ahorró."""
        return self.reused_queries + self.resolved_by_rule

    def report(self) -> str:
        return (
            f"{self.spent_queries} de {self.max_queries} consultas empleadas "
            f"(US$ {self.spent_usd:.2f}). "
            f"{self.avoided_queries} evitadas: {self.reused_queries} por huella "
            f"repetida y {self.resolved_by_rule} por filtro determinista."
        )
