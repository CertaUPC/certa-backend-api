"""El costo es uno de los criterios con los que se elige modelo.

El guardia de presupuesto lleva un solo par de precios porque su trabajo es
cortar una corrida desbocada, y para eso basta una cifra aproximada. Aplicar ese
par a los tres modelos en el cuadro de resultados es otra cosa: multiplica por
cinco la cuenta del barato y puede invertir el orden de la elección.
"""

from dataclasses import dataclass

import pytest

from src.model_pricing import cost_of, costs_by_run

CARO = (5.0, 25.0)       # dólares por millón, entrada y salida
BARATO = (0.214, 2.55)


@dataclass
class FakeVerdict:
    model: str
    repetition: int
    input_tokens: int
    output_tokens: int
    model_version: str = "v"


class TestCostOf:
    def test_charges_input_and_output_apart(self):
        # 1000 de entrada a 5 por millón, 1000 de salida a 25 por millón.
        assert cost_of(CARO, 1000, 1000) == pytest.approx(0.030)

    def test_no_tokens_costs_nothing(self):
        assert cost_of(CARO, 0, 0) == 0.0


class TestCostsByRun:
    @pytest.fixture
    def veredictos(self):
        return [
            FakeVerdict("caro", 1, 1800, 600),
            FakeVerdict("caro", 1, 1800, 600),
            FakeVerdict("barato", 1, 1200, 1900),
            FakeVerdict("caro", 2, 1800, 600),
        ]

    def test_each_model_pays_its_own_price(self, veredictos):
        filas = costs_by_run(veredictos, {"caro": CARO, "barato": BARATO})
        caro = filas[("caro", "v", 1)]["usd"]
        barato = filas[("barato", "v", 1)]["usd"]
        assert caro == pytest.approx(cost_of(CARO, 3600, 1200), abs=1e-4)
        assert barato == pytest.approx(cost_of(BARATO, 1200, 1900), abs=1e-4)
        assert caro > barato, "con un precio único el barato salía más caro"

    def test_repetitions_are_counted_apart(self, veredictos):
        filas = costs_by_run(veredictos, {"caro": CARO, "barato": BARATO})
        assert filas[("caro", "v", 1)]["tokens_entrada"] == 3600
        assert filas[("caro", "v", 2)]["tokens_entrada"] == 1800

    def test_a_model_without_price_is_left_blank(self, veredictos):
        """Un hueco declarado es preferible a un costo inventado."""
        filas = costs_by_run(veredictos, {"caro": CARO})
        assert filas[("barato", "v", 1)]["usd"] is None
        assert filas[("barato", "v", 1)]["tokens_entrada"] == 1200

    def test_verdicts_without_tokens_do_not_break_it(self):
        """Los veredictos del filtro determinista no consultan al modelo."""
        filas = costs_by_run(
            [FakeVerdict("regla", 1, 0, 0)], {"regla": CARO}
        )
        assert filas[("regla", "v", 1)]["usd"] == 0.0


class TestEtiquetasBreves:
    """Las etiquetas que van al encabezado de la diapositiva.

    Se comprueban aquí y no al exportar la presentación porque el defecto que
    causaron era invisible en el archivo: el encabezado largo se guardaba entero
    y solo se veía partido a media palabra al renderizar la imagen.
    """

    def test_todo_criterio_tiene_etiqueta(self):
        from tools.benchmarking_scores import CAPAS, etiqueta

        for capa in CAPAS:
            for criterio in capa.criterios:
                assert etiqueta(criterio)

    def test_la_etiqueta_cabe_en_una_columna(self):
        from tools.benchmarking_scores import CAPAS, etiqueta

        # Veintiocho caracteres es lo que entra en dos líneas de un encabezado
        # de la plantilla sin reducir el cuerpo de letra.
        for capa in CAPAS:
            for criterio in capa.criterios:
                assert len(etiqueta(criterio)) <= 28, criterio.nombre

    def test_un_criterio_sin_etiqueta_falla_en_vez_de_callar(self):
        from tools.benchmarking_scores import Criterio, Nivel, etiqueta

        inventado = Criterio("Criterio que nadie declaró", 100, "",
                             (Nivel(100, "Sí"),))
        with pytest.raises(KeyError, match="etiqueta breve"):
            etiqueta(inventado)


class TestCapaDeModelo:
    """La capa de modelo no se decide por tabla, y eso debe quedar impuesto.

    El defecto que estas pruebas impiden volver: ponderar los atributos que el
    proveedor declara producía un total que ordenaba por precio, coronaba al
    modelo más barato y dejaba último al seleccionado. Esa tabla contradecía a
    la medición del anexo A, que es la que de verdad decide.
    """

    def test_no_lleva_total_ponderado(self):
        from tools.benchmarking_scores import MODELO

        assert MODELO.criterios == ()

    def test_declara_la_regla_con_la_que_acota_la_muestra(self):
        from tools.benchmarking_scores import MODELO

        assert MODELO.reglas_de_muestreo
        assert MODELO.finalistas

    def test_cada_finalista_supera_los_requisitos(self):
        from tools.benchmarking_scores import MODELO

        vivos = MODELO.supervivientes()
        for finalista in MODELO.finalistas:
            assert finalista in vivos, finalista

    def test_un_finalista_por_regimen(self):
        from tools.benchmarking_scores import MODELO, REGIMEN

        regimenes = {REGIMEN[f] for f in MODELO.finalistas}
        assert len(regimenes) == len(MODELO.finalistas)

    def test_proveedores_distintos_entre_finalistas(self):
        from tools.benchmarking_scores import MODELO

        proveedores = {f.split("/")[0] for f in MODELO.finalistas}
        assert len(proveedores) == len(MODELO.finalistas)


class TestReglaDeRepresentacion:
    """Quién representa a cada régimen no se afirma: se deriva y se comprueba.

    El documento declaraba "un finalista por régimen" y luego nombraba tres sin
    decir cuál de los tres candidatos del régimen de gran escala tomaba ni por
    qué. Es la primera pregunta que cabe hacerle a esa tabla.
    """

    def test_los_finalistas_se_derivan_de_la_regla(self):
        from tools.benchmarking_scores import MODELO, finalistas_derivados

        assert MODELO.finalistas == finalistas_derivados()

    def test_toma_el_de_mayor_gama_de_cada_regimen(self):
        from tools.benchmarking_scores import (
            MODELO,
            REGIMEN,
            costo_por_cien,
            finalistas_derivados,
        )

        for elegido in finalistas_derivados():
            hermanos = [m for m in MODELO.supervivientes()
                        if REGIMEN[m] == REGIMEN[elegido]
                        and m.split("/")[0] == elegido.split("/")[0]]
            assert costo_por_cien(elegido) == max(
                costo_por_cien(m) for m in hermanos)

    def test_cubre_los_tres_regimenes(self):
        from tools.benchmarking_scores import (
            ORDEN_DE_REGIMENES,
            REGIMEN,
            finalistas_derivados,
        )

        cubiertos = {REGIMEN[m] for m in finalistas_derivados()}
        assert cubiertos == set(ORDEN_DE_REGIMENES)

    def test_el_regimen_caro_lo_representa_su_modelo_mas_caro(self):
        # El sesgo de la regla debe jugar en contra de la hipótesis: si el
        # régimen caro estuviera representado por su opción barata, la falta de
        # diferencia en exactitud no probaría nada.
        from tools.benchmarking_scores import (
            MODELO,
            REGIMEN,
            costo_por_cien,
            finalistas_derivados,
        )

        caros = [m for m in MODELO.supervivientes()
                 if REGIMEN[m] == "Comercial, gran escala"]
        elegido = next(m for m in finalistas_derivados()
                       if REGIMEN[m] == "Comercial, gran escala")
        assert costo_por_cien(elegido) == max(costo_por_cien(m) for m in caros)


class TestPuntuacionCompleta:
    """Todo candidato se puntúa, también el que un requisito deja fuera.

    Sin esto la tabla no deja ver si el eliminado cayó por el requisito o por
    ser peor en todo, que son dos afirmaciones muy distintas y solo una es la
    que el trabajo sostiene.
    """

    def test_todo_candidato_tiene_niveles(self):
        from tools.benchmarking_scores import CAPAS

        for capa in CAPAS:
            if not capa.criterios:
                continue
            for candidato in capa.cumplimiento:
                assert candidato in capa.niveles, f"{capa.nombre}: {candidato}"

    def test_todo_nivel_existe_en_su_rubrica(self):
        from tools.benchmarking_scores import CAPAS

        for capa in CAPAS:
            for candidato in capa.niveles:
                # puntos_de levanta KeyError si el nivel no está declarado.
                capa.total(candidato)

    def test_el_seleccionado_encabeza_su_capa(self):
        from tools.benchmarking_scores import CAPAS

        for capa in CAPAS:
            if not capa.criterios:
                continue
            vivos = [c for c in capa.supervivientes() if c in capa.niveles]
            mejor = max(capa.cumplimiento, key=capa.total)
            elegido = max(vivos, key=capa.total)
            assert elegido == mejor, (
                f"{capa.nombre}: gana {elegido} entre los admisibles pero "
                f"{mejor} puntúa más y quedó fuera por requisito"
            )

    def test_la_cola_distingue_tomar_de_enterarse(self):
        # MySQL 8 admite bloqueo de fila con omisión de las tomadas, de modo
        # que puntuarlo a cero en este criterio era falso. Lo que de verdad lo
        # separa es el aviso entre sesiones.
        from tools.benchmarking_scores import PERSISTENCIA

        criterio = next(c for c in PERSISTENCIA.criterios
                        if c.nombre == "Cola de trabajos sobre el propio motor")
        niveles = {n.descripcion: n.puntos for n in criterio.rubrica}
        assert niveles["Toma con bloqueo de fila, sin aviso entre sesiones"] == 70
        assert PERSISTENCIA.niveles["MySQL"][criterio.nombre] == (
            "Toma con bloqueo de fila, sin aviso entre sesiones")
