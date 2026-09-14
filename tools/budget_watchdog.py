"""Vigila el saldo del proveedor y detiene la corrida antes de agotarlo.

El guardia de presupuesto del dominio limita por numero de consultas, que es lo
que puede conocer sin salir del sistema. No conoce el saldo real de la cuenta,
y el saldo es lo que de verdad se agota: una corrida que lo consume entero deja
la medicion a medias y el dinero gastado sin resultado utilizable.

Esto consulta el saldo cada cierto tiempo y mata el proceso indicado en cuanto
baja del piso declarado. Prefiere detener de mas: lo ya validado se conserva en
la base y la corrida se puede reanudar, mientras que el dinero no vuelve.

    py tools/budget_watchdog.py --pid 1234 --piso 1.50

Sin --pid solo informa, que sirve para seguir una corrida sin poder cortarla.
"""

import argparse
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

import httpx

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.shared.config import get_settings


def saldo(ajustes) -> tuple[float, float]:
    """Devuelve saldo restante y consumo total, en dólares."""
    r = httpx.get(
        ajustes.llm_base_url.rstrip("/").replace("/api/v1", "/api/v1") + "/credits",
        headers={"Authorization": f"Bearer {ajustes.llm_api_key}"},
        timeout=30,
        verify=ajustes.ssl_cert_file or True,
    )
    r.raise_for_status()
    d = r.json()["data"]
    return d["total_credits"] - d["total_usage"], d["total_usage"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, help="Proceso a detener al tocar el piso")
    parser.add_argument("--piso", type=float, default=1.50,
                        help="Saldo por debajo del cual se detiene, en dólares")
    parser.add_argument("--cada", type=int, default=60, help="Segundos entre consultas")
    parser.add_argument("--log", help="Archivo donde anotar cada lectura")
    args = parser.parse_args()

    ajustes = get_settings()
    inicial, usado_inicial = saldo(ajustes)
    print(f"saldo inicial {inicial:.2f} | piso {args.piso:.2f} | "
          f"vigilando pid {args.pid or 'ninguno'}")

    while True:
        try:
            actual, usado = saldo(ajustes)
        except Exception as exc:  # noqa: BLE001
            # Una consulta fallida no debe matar al vigilante: si se cae, la
            # corrida se queda sin red.
            print(f"aviso: no se pudo leer el saldo ({type(exc).__name__})")
            time.sleep(args.cada)
            continue

        gastado = usado - usado_inicial
        linea = (f"{datetime.now(tz=timezone.utc).astimezone():%H:%M:%S}  saldo {actual:6.2f}  "
                 f"gastado en esta corrida {gastado:5.2f}")
        print(linea, flush=True)
        if args.log:
            with open(args.log, "a", encoding="utf-8") as f:
                f.write(linea + "\n")

        if actual <= args.piso:
            print(f"PISO ALCANZADO: saldo {actual:.2f} <= {args.piso:.2f}")
            if args.pid:
                try:
                    if sys.platform == "win32":
                        subprocess.run(["taskkill", "/PID", str(args.pid), "/F"],
                                       capture_output=True, check=False)
                    else:
                        os.kill(args.pid, signal.SIGTERM)
                    print(f"proceso {args.pid} detenido")
                except OSError as exc:
                    print(f"no se pudo detener el proceso: {exc}")
            return 1

        if args.pid and not _vive(args.pid):
            print("la corrida terminó; el vigilante se retira")
            return 0

        time.sleep(args.cada)


def _vive(pid: int) -> bool:
    """Comprueba si el proceso sigue en marcha, sin tocarlo.

    En Windows os.kill con senal 0 no es la comprobacion inocua que es en los
    sistemas de tipo Unix: intenta terminar el proceso. Usarla para saber si
    seguia vivo mataba justo aquello que este vigilante existe para proteger.
    """
    if sys.platform == "win32":
        salida = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
            capture_output=True, text=True, check=False,
        )
        return str(pid) in salida.stdout
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


if __name__ == "__main__":
    sys.exit(main())
