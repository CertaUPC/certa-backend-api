"""US017. Una ejecución no puede llevarse el presupuesto entero.

El tope se cuenta en consultas y no en dólares, porque el precio por token lo
mueve el proveedor cuando quiere y el número de consultas es lo único que
depende de nosotros.

Lo que la historia exige son tres cosas: que se pueda saber cuánto va a costar
antes de emitir la primera consulta, que al llegar al tope la corrida se
detenga conservando lo ya validado, y que quede registrado lo que la cascada
ahorró, porque una consulta evitada por huella repetida o resuelta por regla es
dinero que no se gastó.
"""

import pytest

from src.finding_validation.domain.services.budget_guard import (
    BudgetExhausted,
    BudgetGuard,
)


class TestLaPrevision:
    """Cuánto va a costar, dicho antes de gastar nada."""

    def test_estima_consultas_y_gasto_antes_de_la_primera(self):
        guarda = BudgetGuard(
            max_queries=100, usd_per_1k_input=0.001, usd_per_1k_output=0.002
        )
        previsión = guarda.estimate(pending_findings=10)
        assert previsión.queries == 10
        # Diez consultas a 3 500 tokens de entrada y 450 de salida: 0.035 más
        # 0.009. La cifra se redondea a centavos, que es como se presupuesta.
        assert previsión.usd == pytest.approx(0.04)

    def test_las_repeticiones_multiplican_la_previsión(self):
        """Comparar tres modelos tres veces son nueve corridas del mismo lote,
        y eso hay que saberlo antes y no después."""
        guarda = BudgetGuard(max_queries=100)
        assert guarda.estimate(pending_findings=10, repetitions=3).queries == 30

    def test_la_previsión_se_puede_leer_en_una_línea(self):
        guarda = BudgetGuard(max_queries=10, usd_per_1k_input=0.001)
        assert "consultas previstas" in guarda.estimate(5).describe()

    def test_un_tope_por_debajo_de_una_consulta_no_tiene_sentido(self):
        with pytest.raises(ValueError):
            BudgetGuard(max_queries=0)


class TestElTope:
    """Qué pasa cuando se alcanza."""

    def test_cada_consulta_descuenta(self):
        guarda = BudgetGuard(max_queries=3)
        guarda.reserve()
        assert guarda.remaining == 2
        assert not guarda.is_exhausted

    def test_al_llegar_al_tope_se_detiene(self):
        guarda = BudgetGuard(max_queries=2)
        guarda.reserve()
        guarda.reserve()
        assert guarda.is_exhausted
        with pytest.raises(BudgetExhausted):
            guarda.reserve()

    def test_el_mensaje_dice_que_lo_validado_se_conserva(self):
        """Es la diferencia entre un tope y una pérdida: quien lea esto tiene
        que saber que puede retomar sin volver a pagar lo anterior."""
        guarda = BudgetGuard(max_queries=1)
        guarda.reserve()
        with pytest.raises(BudgetExhausted) as tope:
            guarda.reserve()
        assert "Lo validado se conserva" in str(tope.value)

    def test_agotado_no_queda_nada_por_gastar(self):
        guarda = BudgetGuard(max_queries=1)
        guarda.reserve()
        assert guarda.remaining == 0


class TestLoQueSeAhorró:
    """La cascada existe para no preguntar. Eso también se cuenta."""

    def test_cuenta_aparte_lo_reutilizado_y_lo_resuelto_por_regla(self):
        guarda = BudgetGuard(max_queries=10)
        guarda.record_reuse()
        guarda.record_reuse()
        guarda.record_rule_resolution()
        assert guarda.avoided_queries == 3
        assert guarda.spent_queries == 0, "evitar una consulta no puede gastarla"

    def test_el_informe_separa_lo_gastado_de_lo_evitado(self):
        guarda = BudgetGuard(max_queries=10, usd_per_1k_input=0.001)
        guarda.reserve()
        guarda.record_usage(input_tokens=3_500, output_tokens=450)
        guarda.record_reuse()
        informe = guarda.report()
        assert "1 de 10 consultas" in informe
        assert "1 evitadas" in informe

    def test_el_gasto_sale_de_los_tokens_de_verdad_y_no_de_la_previsión(self):
        """La previsión usa un promedio declarado en el charter. Lo que se
        informa como gastado tiene que ser lo que el proveedor cobró."""
        guarda = BudgetGuard(
            max_queries=1_000, usd_per_1k_input=0.002, usd_per_1k_output=0.004
        )
        guarda.record_usage(input_tokens=350_000, output_tokens=45_000)
        assert guarda.spent_usd == pytest.approx(0.88)

    def test_el_gasto_se_informa_en_centavos(self):
        """Una corrida de dos consultas puede costar menos de medio centavo y
        entonces se informa como cero. Conviene saberlo antes de leer un cero
        como si no se hubiera consultado nada."""
        guarda = BudgetGuard(max_queries=10, usd_per_1k_input=0.002)
        guarda.record_usage(input_tokens=1_000, output_tokens=0)
        assert guarda.spent_usd == 0.0

    def test_un_uso_negativo_no_descuenta_gasto(self):
        guarda = BudgetGuard(max_queries=10, usd_per_1k_input=0.002)
        guarda.record_usage(input_tokens=-5_000, output_tokens=0)
        assert guarda.spent_usd == 0.0
