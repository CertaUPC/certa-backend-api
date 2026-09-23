"""Proceso desatendido que toma trabajos de la cola y ejecuta la validación.

Existe separado del servicio web por una razón medida y no de estilo: validar un
hallazgo tarda entre diez y veinticinco segundos según el modelo, y un lote de
cien con tres repeticiones son horas. Ninguna petición HTTP sobrevive a eso, y
menos en una plataforma que duerme el servicio por inactividad. Mezclarlos
obliga a que la unidad que debe responder en milisegundos cargue con el ciclo de
vida de la que tarda horas.

El bucle no reimplementa nada: llama a los servicios de aplicación que ya
existen. Su único trabajo es tomar de la cola, seguir vivo y no llevarse el
proceso por delante cuando algo falla.

    py -m src.worker
    py -m src.worker --lote 50 --espera 15
"""

import argparse
import asyncio
import logging
import os
import signal
import sys
from collections.abc import Callable
from uuid import UUID

# Registra la tabla de cuentas, que executions referencia. Ver cli.py.
from .iam.infrastructure.persistence import models as _cuentas  # noqa: F401
from .shared.composition import Container
from .shared.config import get_settings
from .shared.tracing import correlate, install_memory_sink

logger = logging.getLogger("certa.worker")

# Tiempo de espera entre consultas a la cola cuando no hay nada que hacer. Ni
# tan corto que castigue a la base con preguntas inútiles, ni tan largo que un
# trabajo recién encolado se quede esperando.
ESPERA_SIN_TRABAJO = 10.0

# Tras un fallo se espera un poco más: si el proveedor está caído, insistir de
# inmediato solo consume el presupuesto de reintentos.
ESPERA_TRAS_FALLO = 30.0


class WorkerLoop:
    """Toma trabajos y los ejecuta hasta que le pidan parar.

    `fabrica` devuelve el objeto que sabe tomar y ejecutar un trabajo. Se recibe
    como función y no como instancia porque cada ciclo necesita su propia sesión
    de base de datos: reutilizar una sola a lo largo de horas acumularía estado
    y dejaría transacciones abiertas.
    """

    def __init__(
        self,
        fabrica: Callable,
        nombre: str = "worker",
        batch_size: int | None = None,
        idle_seconds: float = ESPERA_SIN_TRABAJO,
        error_seconds: float = ESPERA_TRAS_FALLO,
        max_cycles: int | None = None,
        project_id=None,
    ) -> None:
        self._fabrica = fabrica
        self.nombre = nombre
        self.batch_size = batch_size
        self.idle_seconds = idle_seconds
        self.error_seconds = error_seconds
        self.max_cycles = max_cycles
        self.project_id = project_id

        self.stopping = False
        self.processed = 0
        self.failures = 0
        self.idle_cycles = 0

    def stop(self) -> None:
        """Pide parar. El trabajo en curso se termina antes de salir.

        Cortar a mitad de un hallazgo desperdiciaría una consulta ya pagada, y
        el veredicto se perdería sin haberse guardado.
        """
        if not self.stopping:
            logger.info("Se pidió parar. Se termina el trabajo en curso.")
        self.stopping = True

    async def run(self) -> None:
        ciclos = 0
        while not self.stopping:
            if self.max_cycles is not None and ciclos >= self.max_cycles:
                break
            ciclos += 1

            # Se cede el control en cada vuelta. Sin esto, un bucle con espera
            # cero nunca regresa al planificador y deja sin atender a quien
            # pide parar: el proceso queda girando y solo lo tumba una señal.
            await asyncio.sleep(0)

            try:
                runner = self._fabrica()
                with correlate():
                    resultado = await runner.claim_and_run(
                        self.nombre, self.batch_size, self.project_id
                    )
            except Exception as exc:
                # Se atrapa cualquier excepción y no solo las previstas. Las
                # previstas son las que ya se conocen; las que tumban un proceso
                # de horas son las otras, y la lista de formas en que un
                # servicio ajeno puede fallar no se cierra de antemano. El
                # trabajo queda en la cola y otro ciclo lo intentará.
                self.failures += 1
                # logger.exception ya adjunta la traza y el objeto; nombrar solo
                # el tipo deja la línea legible sin perder el detalle.
                logger.exception("El ciclo falló con %s", type(exc).__name__)
                await self._esperar(self.error_seconds)
                continue

            if resultado is None:
                self.idle_cycles += 1
                await self._esperar(self.idle_seconds)
                continue

            self.processed += 1
            logger.info("Trabajo terminado. Acumulado: %d", self.processed)

    async def _esperar(self, segundos: float) -> None:
        """Espera en tramos cortos para atender la orden de parar sin demora."""
        if segundos <= 0 or self.stopping:
            return
        restante = segundos
        while restante > 0 and not self.stopping:
            paso = min(0.5, restante)
            await asyncio.sleep(paso)
            restante -= paso


def _instalar_senales(bucle: WorkerLoop) -> None:
    """Una parada ordenada ante la señal de la plataforma.

    Render y cualquier orquestador envían la señal antes de terminar el
    proceso. Sin atenderla, el trabajo en curso se corta a la mitad.
    """
    def _manejar(_sig, _frame):
        bucle.stop()

    for nombre in ("SIGTERM", "SIGINT"):
        senal = getattr(signal, nombre, None)
        if senal is not None:
            try:
                signal.signal(senal, _manejar)
            except (ValueError, OSError):
                # Fuera del hilo principal no se pueden instalar; no es motivo
                # para no arrancar.
                pass


async def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nombre", default=os.environ.get("WORKER_NAME", ""),
                        help="Identifica al trabajador en la cola. Por omisión, el del proceso")
    parser.add_argument("--lote", type=int, default=None,
                        help="Hallazgos por ciclo. Sin valor, todos los pendientes")
    parser.add_argument("--espera", type=float, default=ESPERA_SIN_TRABAJO,
                        help="Segundos entre consultas cuando la cola está vacía")
    parser.add_argument("--ciclos", type=int, default=None,
                        help="Tope de ciclos. Sirve para comprobar el arranque sin dejarlo vivo")
    parser.add_argument("--proyecto", default=None,
                        help="Solo toma ejecuciones de este proyecto. Por omisión, "
                             "el de WORKER_PROJECT_ID")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    install_memory_sink()

    settings = get_settings()
    if not settings.llm_configured:
        logger.error(
            "No hay proveedor de modelo configurado. El trabajador no tiene "
            "nada que hacer sin él."
        )
        return 2

    container = Container(settings)
    nombre = args.nombre or f"worker-{os.getpid()}"

    def fabrica():
        # Sesión y presupuesto propios por ciclo: el presupuesto acota una
        # ejecución y no la vida entera del proceso.
        sesion = container.sessions()
        return _RunnerPorCiclo(container, sesion)

    # Sin proyecto el trabajador toma cualquier cosa pendiente, que solo es
    # seguro si todos los trabajadores de esta base ven el mismo repositorio.
    proyecto = args.proyecto or settings.worker_project_id or None
    if proyecto:
        try:
            proyecto = UUID(str(proyecto))
        except ValueError:
            logger.error("WORKER_PROJECT_ID no es un identificador válido: %r", proyecto)
            return 2
    else:
        logger.warning(
            "Sin proyecto asignado: este trabajador tomará cualquier ejecución "
            "pendiente. Solo es seguro si todos los trabajadores de esta base "
            "ven el mismo repositorio."
        )

    bucle = WorkerLoop(
        fabrica,
        nombre=nombre,
        batch_size=args.lote,
        idle_seconds=args.espera,
        max_cycles=args.ciclos,
        project_id=proyecto,
    )
    _instalar_senales(bucle)

    logger.info(
        "Trabajador %s en marcha. Modelo %s. Espera de %.0f s sin trabajo.",
        nombre, settings.llm_model, args.espera,
    )
    try:
        await bucle.run()
    finally:
        await container.dispose()

    logger.info(
        "Trabajador detenido. %d trabajos, %d fallos, %d ciclos sin trabajo.",
        bucle.processed, bucle.failures, bucle.idle_cycles,
    )
    return 0


class _RunnerPorCiclo:
    """Abre la sesión al tomar el trabajo y la cierra al terminarlo."""

    def __init__(self, container: Container, sesion) -> None:
        self._container = container
        self._sesion = sesion

    async def claim_and_run(
        self, worker: str, batch_size: int | None, project_id=None
    ):
        async with self._sesion as s:
            budget = self._container.new_budget()
            runner = self._container.runner(s, budget)
            return await runner.claim_and_run(worker, batch_size, project_id)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
