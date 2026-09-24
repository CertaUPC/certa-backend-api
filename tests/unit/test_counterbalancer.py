"""El reparto del orden de condiciones.

Vivía sin pruebas propias, comprobado de refilón desde la API. Lo que no
estaba sujeto por ninguna parte es por dónde empieza el primero, que depende
del orden en que están escritas las dos alternativas y que por tanto un
reordenado inocente puede invertir sin que nada se queje.
"""

from src.experimentation.domain.services.counterbalancer import Counterbalancer
from src.experimentation.domain.value_objects.condition import Condition

CONTROL_PRIMERO = (Condition.CONTROL, Condition.WITH_ASSISTANT)
ASISTIDO_PRIMERO = (Condition.WITH_ASSISTANT, Condition.CONTROL)


class TestPorDondeEmpiezaElPrimero:
    def test_sin_historial_toca_la_condicion_de_control(self):
        """Lo que sobrevive a una sesión que se corta a la mitad es entonces
        la línea base, que es el término de comparación."""
        asignado = Counterbalancer().assign([])
        assert asignado.order == CONTROL_PRIMERO

    def test_el_segundo_recibe_el_orden_contrario(self):
        primero = Counterbalancer().assign([])
        segundo = Counterbalancer().assign([primero.order])
        assert segundo.order == ASISTIDO_PRIMERO


class TestElRepartoSeEquilibra:
    def test_alterna_a_lo_largo_de_seis(self):
        historial = []
        for _ in range(6):
            historial.append(Counterbalancer().assign(historial).order)
        assert historial.count(CONTROL_PRIMERO) == 3
        assert historial.count(ASISTIDO_PRIMERO) == 3
        assert Counterbalancer.is_balanced(historial)

    def test_corrige_un_historial_torcido(self):
        """Si una sesión se descarta, el reparto queda desviado y el siguiente
        alta lo endereza."""
        historial = [ASISTIDO_PRIMERO, ASISTIDO_PRIMERO]
        assert not Counterbalancer.is_balanced(historial)
        siguiente = Counterbalancer().assign(historial)
        assert siguiente.order == CONTROL_PRIMERO

    def test_las_dos_mitades_van_en_el_mismo_orden_siempre(self):
        """El lote A es el primero para todos. Lo que rota es la condición, no
        la mitad: rotar las dos a la vez las volvería indistinguibles."""
        for historial in ([], [CONTROL_PRIMERO], [CONTROL_PRIMERO] * 2):
            asignado = Counterbalancer().assign(historial)
            assert (asignado.first_batch, asignado.second_batch) == ("A", "B")


class TestQueCondicionLeTocaACadaMitad:
    def test_la_primera_mitad_lleva_la_primera_condicion(self):
        asignado = Counterbalancer().assign([])
        assert asignado.condition_for("A") == Condition.CONTROL
        assert asignado.condition_for("B") == Condition.WITH_ASSISTANT
