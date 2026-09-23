"""El bucle del trabajador: qué toma, cuándo para y qué hace al fallar.

El trabajador es el proceso que sostiene la propiedad que la arquitectura
declara: que la interrupción es el caso normal y no la excepción. De poco sirve
que la cadena sea reanudable si el proceso que la ejecuta se cae con el primer
imprevisto, o si al morir deja el trabajo tomado para siempre.

Lo que se comprueba aquí es el bucle, no la cadena. La cadena tiene sus propias
pruebas.
"""

import asyncio

from src.worker import WorkerLoop


class ColaFalsa:
    """Entrega trabajos en orden y cuenta cuántas veces se le preguntó."""

    def __init__(self, trabajos):
        self.pendientes = list(trabajos)
        self.consultas = 0
        self.procesados = []
        self.fallo_en = None
        self.ultimo_proyecto = None

    async def claim_and_run(self, worker, batch_size=None, project_id=None):
        self.consultas += 1
        self.ultimo_proyecto = project_id
        if not self.pendientes:
            return None
        trabajo = self.pendientes.pop(0)
        if self.fallo_en is not None and trabajo == self.fallo_en:
            raise RuntimeError(f"el proveedor se cayó procesando {trabajo}")
        self.procesados.append(trabajo)
        return trabajo


def bucle(cola, **kwargs):
    kwargs.setdefault("idle_seconds", 0)
    kwargs.setdefault("error_seconds", 0)
    return WorkerLoop(lambda: cola, nombre="prueba", **kwargs)


class TestLoQueToma:
    async def test_procesa_todo_lo_pendiente(self):
        cola = ColaFalsa(["a", "b", "c"])
        await bucle(cola, max_cycles=5).run()
        assert cola.procesados == ["a", "b", "c"]

    async def test_con_la_cola_vacia_no_procesa_nada(self):
        cola = ColaFalsa([])
        await bucle(cola, max_cycles=3).run()
        assert cola.procesados == []
        assert cola.consultas == 3

    async def test_sigue_preguntando_cuando_la_cola_se_vacia(self):
        """La cola vacía no es el final: el trabajador espera más trabajo."""
        cola = ColaFalsa(["a"])
        await bucle(cola, max_cycles=4).run()
        assert cola.procesados == ["a"]
        assert cola.consultas == 4


class TestCuandoFalla:
    async def test_un_trabajo_que_revienta_no_tumba_el_bucle(self):
        """Es la razón de existir de este bucle.

        Un fallo del proveedor sobre un trabajo no puede dejar sin atender a
        los que vienen detrás, que es lo que ocurriría si la excepción subiera
        hasta el punto de entrada y terminara el proceso.
        """
        cola = ColaFalsa(["a", "malo", "c"])
        cola.fallo_en = "malo"
        b = bucle(cola, max_cycles=5)
        await b.run()
        assert cola.procesados == ["a", "c"]
        assert b.failures == 1

    async def test_el_fallo_queda_contado(self):
        cola = ColaFalsa(["malo"])
        cola.fallo_en = "malo"
        b = bucle(cola, max_cycles=2)
        await b.run()
        assert b.failures == 1
        assert b.processed == 0


class TestCuandoSePideQuePare:
    async def test_para_al_pedirselo(self):
        cola = ColaFalsa(["a"] * 100)
        b = bucle(cola)

        async def parar():
            await asyncio.sleep(0.01)
            b.stop()

        await asyncio.gather(b.run(), parar())
        assert b.stopping
        assert len(cola.procesados) < 100

    async def test_termina_el_trabajo_en_curso_antes_de_parar(self):
        """Parar en medio de un hallazgo desperdiciaría la consulta ya pagada."""
        cola = ColaFalsa(["a", "b"])
        b = bucle(cola, max_cycles=1)
        await b.run()
        assert cola.procesados == ["a"]


class TestCuentas:
    async def test_lleva_la_cuenta_de_lo_hecho(self):
        cola = ColaFalsa(["a", "b"])
        b = bucle(cola, max_cycles=4)
        await b.run()
        assert b.processed == 2
        assert b.idle_cycles == 2
