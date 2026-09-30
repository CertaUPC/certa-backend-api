"""Carga proyectos de ejemplo para ver la interfaz con datos.

La cuenta tenía un solo proyecto, el conjunto de referencia, y con eso no se
puede juzgar cómo se comporta la aplicación cuando hay varias cosas a la vez:
el desplegable con una sola opción, la lista de una fila, la pantalla de una
corrida sin nada con qué compararla.

Lo que crea es material de trabajo, no del estudio. Va aparte del proyecto que
el trabajador tiene atado por `WORKER_PROJECT_ID`, así que nadie lo procesa y
no consume presupuesto. Los identificadores creados quedan escritos en un
archivo al lado, y `--borrar` los usa para deshacer exactamente esto y nada
más.

    py tools/seed_demo_projects.py --crear --despliegue
    py tools/seed_demo_projects.py --borrar --despliegue
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from dotenv import load_dotenv
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.demo_fragments import fragmento  # noqa: E402

from src.iam.infrastructure.persistence import models as _cuentas  # noqa: F401,E402
from src.shared import database_experiment as _estudio  # noqa: F401,E402
from src.shared.database import (  # noqa: E402
    ContextRow,
    ExecutionRow,
    FindingRow,
    ProjectMemberRow,
    ProjectRow,
    VerdictRow,
)

RAIZ = Path(__file__).resolve().parents[1]
def _registro(despliegue: bool) -> Path:
    """Un registro por base: lo cargado en local no es lo cargado afuera."""
    return RAIZ / (
        "demo-proyectos-despliegue.json" if despliegue else "demo-proyectos.json"
    )
CORREO = "u202211399@upc.edu.pe"

# La semilla fija hace que dos corridas del script produzcan lo mismo, de modo
# que una captura de pantalla de ayer sigue coincidiendo con lo que hay hoy.
SEMILLA = 20260925

MODELO = "google/gemini-3.8-flash"
VERSION_MODELO = "gemini-3.8-flash-20260901"

# Reglas de Semgrep con el aspecto que tienen de verdad: identificador con
# puntos, su CWE y su severidad declarada.
REGLAS = [
    ("java.lang.security.audit.sqli.jdbc-sqli", "CWE-89", "error",
     "Concatenación de entrada del usuario en una consulta JDBC"),
    ("java.lang.security.audit.xss.no-direct-response-writer", "CWE-79", "error",
     "Se escribe en la respuesta sin escapar el contenido"),
    ("java.lang.security.audit.crypto.weak-hash", "CWE-327", "warning",
     "Resumen criptográfico débil para credenciales"),
    ("java.lang.security.audit.xxe.documentbuilder-xxe", "CWE-611", "error",
     "El lector de XML admite entidades externas"),
    ("java.lang.security.audit.path-traversal.file-access", "CWE-22", "error",
     "Ruta construida con datos de la petición"),
    ("java.lang.security.audit.deserialization.object-input-stream", "CWE-502", "error",
     "Deserialización de datos que llegan de fuera"),
    ("java.lang.security.audit.hardcoded.secret", "CWE-798", "warning",
     "Credencial escrita en el código"),
    ("java.lang.security.audit.logging.sensitive-data", "CWE-532", "note",
     "Se registra un dato sensible en la bitácora"),
    ("java.lang.security.audit.ssrf.request-from-input", "CWE-918", "error",
     "Petición saliente con destino que viene del usuario"),
    ("java.lang.security.audit.cookie.missing-httponly", "CWE-1004", "note",
     "Cookie de sesión sin la marca HttpOnly"),
]

CLASES = [
    "controller/ClienteController",
    "controller/FacturaController",
    "service/AutenticacionService",
    "service/PagoService",
    "service/ReporteService",
    "repository/ClienteRepository",
    "repository/MovimientoRepository",
    "web/SesionFilter",
    "web/ArchivoServlet",
    "batch/ConciliacionJob",
    "integration/PasarelaCliente",
    "util/PlantillaRenderer",
]

JUSTIFICA = {
    "explotable": (
        "El dato entra por la petición y llega al punto marcado sin pasar por "
        "nada que lo valide. Las líneas citadas muestran el recorrido completo."
    ),
    "no_explotable": (
        "El valor viene de una constante del propio código y no de la "
        "petición, así que quien llama no puede cambiarlo."
    ),
    "indeterminado": (
        "El método que podría estar saneando el dato queda fuera del fragmento "
        "recuperado, así que no alcanza para afirmar ni descartar."
    ),
}


def _huella(ruta: str, linea: int, regla: str) -> str:
    """La huella es del contenido, no de la corrida.

    Llevaba dentro el identificador de la ejecución, así que dos corridas del
    mismo proyecto no compartían ni un hallazgo y compararlas daba «todo
    aparece, todo desaparece, cero sigue ahí», que es justo lo que la pantalla
    de comparar avisa como configuración mal hecha.
    """
    # Entera, sin recortar: el dominio exige sesenta y cuatro hexadecimales y
    # con cuarenta reventaba al leer los hallazgos, que es lo que hace el
    # exportador. El CSV devolvía un error del servicio.
    return hashlib.sha256(f"{ruta}|{linea}|{regla}".encode()).hexdigest()


def _proyectos(owner_id: str, ahora: datetime) -> list[dict]:
    """Lo que se va a crear, descrito de una sola vez."""
    return [
        {
            "nombre": "Portal de clientes",
            "ruta": "/repos/portal-clientes",
            "paquete": "com.portal.clientes",
            "corridas": [
                {
                    "label": "Barrido semanal, reglas 1.96",
                    "reglas": "1.96.0",
                    "estado": "completada",
                    "hallazgos": 78,
                    "juzgados": 78,
                    "hace": timedelta(days=2, hours=3),
                },
                {
                    "label": "Antes del pase a producción",
                    "reglas": "1.96.0",
                    "estado": "en_proceso",
                    "hallazgos": 54,
                    "juzgados": 31,
                    "hace": timedelta(hours=5),
                },
            ],
        },
        {
            "nombre": "API de pagos",
            "ruta": "/repos/api-pagos",
            "paquete": "com.pagos.api",
            "corridas": [
                {
                    "label": "Revisión de seguridad del trimestre",
                    "reglas": "1.95.0",
                    "estado": "completada",
                    "hallazgos": 96,
                    "juzgados": 96,
                    "hace": timedelta(days=9),
                },
            ],
        },
        {
            "nombre": "Backoffice de recursos humanos",
            "ruta": "/repos/backoffice-rrhh",
            "paquete": "com.rrhh.backoffice",
            "corridas": [
                {
                    "label": None,
                    "reglas": "1.96.0",
                    "estado": "pendiente",
                    "hallazgos": 23,
                    "juzgados": 0,
                    "hace": timedelta(minutes=40),
                },
            ],
        },
    ]


def _catalogo(p: dict, cuantas: int, azar: random.Random) -> list[tuple]:
    """Las alertas que ese repositorio tiene, sin repetir sitio.

    Una corrida no inventa hallazgos nuevos cada vez: encuentra los que el
    código tiene. Dos corridas seguidas comparten casi todo, y lo poco que
    cambia es lo que se arregló o lo que se acaba de escribir.
    """
    vistas: set[tuple[str, int]] = set()
    catalogo: list[tuple] = []
    while len(catalogo) < cuantas:
        regla, cwe, severidad, mensaje = REGLAS[azar.randrange(len(REGLAS))]
        clase = CLASES[azar.randrange(len(CLASES))]
        ruta = f"src/main/java/{p['paquete'].replace('.', '/')}/{clase}.java"
        linea = azar.randint(12, 240)
        if (ruta, linea) in vistas:
            continue
        vistas.add((ruta, linea))
        catalogo.append((regla, cwe, severidad, mensaje, ruta, linea))
    return catalogo


# Cuántas alertas se corrigen entre una corrida y la siguiente. Al desplazar
# la ventana sobre el catálogo, las de abajo desaparecen y asoman otras nuevas,
# que es lo que pasa en un repositorio vivo.
CORREGIDAS_ENTRE_CORRIDAS = 30


def _alertas_de(cuantas: int, catalogo: list[tuple], orden: int) -> list[tuple]:
    """Las de esta corrida: casi las mismas que la anterior, no otras.

    Las primeras del catálogo son las que ya se arreglaron cuando llega la
    corrida siguiente, y las últimas son código escrito desde entonces.
    """
    desde = orden * CORREGIDAS_ENTRE_CORRIDAS
    return catalogo[desde : desde + cuantas]


async def crear(sesion, owner_id: str) -> dict:
    azar = random.Random(SEMILLA)
    ahora = datetime.now(timezone.utc)
    creado: dict[str, list[str]] = {"proyectos": [], "ejecuciones": []}

    for p in _proyectos(owner_id, ahora):
        proyecto_id = str(uuid4())
        sesion.add(
            ProjectRow(
                id=proyecto_id,
                name=p["nombre"],
                language="java",
                repository_path=p["ruta"],
                owner_id=owner_id,
                is_public_dataset=False,
                created_at=ahora - timedelta(days=30),
            )
        )
        # Se vuelca el proyecto solo, antes de lo que lo referencia: en
        # PostgreSQL la clave foránea se comprueba en el acto.
        await sesion.flush()

        # El permiso no vive en `owner_id`, que solo dice quién lo creó: sin
        # esta fila el proyecto no se lista, porque la visibilidad se resuelve
        # por pertenencia.
        sesion.add(
            ProjectMemberRow(
                id=str(uuid4()),
                project_id=proyecto_id,
                user_id=owner_id,
                role="administrador",
                invited_by=None,
                created_at=ahora - timedelta(days=30),
            )
        )
        creado["proyectos"].append(proyecto_id)
        # Se vuelca antes de seguir: en PostgreSQL la clave foránea se
        # comprueba en el acto, y sin esto la fila de pertenencia salía antes
        # que el proyecto al que apunta.
        await sesion.flush()

        # Un solo catálogo por proyecto, del tamaño de la corrida más larga.
        catalogo = _catalogo(
            p,
            max(c["hallazgos"] for c in p["corridas"])
            + CORREGIDAS_ENTRE_CORRIDAS * len(p["corridas"]),
            azar,
        )

        for orden, c in enumerate(p["corridas"]):
            ejecucion_id = str(uuid4())
            nacida = ahora - c["hace"]
            sesion.add(
                ExecutionRow(
                    id=ejecucion_id,
                    project_id=proyecto_id,
                    tool_name="semgrep-oss",
                    ruleset_version=c["reglas"],
                    label=c["label"],
                    status=c["estado"],
                    total_findings=c["hallazgos"],
                    validated_findings=c["juzgados"],
                    created_by=owner_id,
                    created_at=nacida,
                    started_at=None if c["estado"] == "pendiente" else nacida,
                    finished_at=(
                        nacida + timedelta(hours=1)
                        if c["estado"] == "completada"
                        else None
                    ),
                    claimed_by=(
                        None if c["estado"] == "pendiente" else "trabajador-local"
                    ),
                )
            )
            creado["ejecuciones"].append(ejecucion_id)
            await sesion.flush()

            for i, (regla, cwe, severidad, mensaje, ruta, linea) in enumerate(
                _alertas_de(c["hallazgos"], catalogo, orden)
            ):
                hallazgo_id = str(uuid4())
                juzgado = i < c["juzgados"]

                sesion.add(
                    FindingRow(
                        id=hallazgo_id,
                        execution_id=ejecucion_id,
                        rule_id=regla,
                        cwe=cwe,
                        rule_severity=severidad,
                        file_path=ruta,
                        start_line=linea,
                        end_line=linea + azar.randint(0, 3),
                        message=mensaje,
                        fingerprint=_huella(ruta, linea, regla),
                        known_truth=None,
                        created_at=nacida,
                    )
                )

                if not juzgado:
                    continue

                # La mezcla imita lo medido: la mayoría se descarta, una parte
                # se confirma y unas pocas no alcanzan a determinarse.
                sorteo = azar.random()
                if sorteo < 0.28:
                    valor, confianza = "explotable", azar.uniform(0.72, 0.97)
                elif sorteo < 0.88:
                    valor, confianza = "no_explotable", azar.uniform(0.6, 0.95)
                else:
                    valor, confianza = "indeterminado", azar.uniform(0.3, 0.55)

                anclado = valor != "indeterminado" and azar.random() < 0.92

                # El fragmento que el asistente miró, que es la mitad de la
                # pantalla de revisión. Sembrado sin él, el visor salía en
                # negro y vacío mientras el panel de al lado prometía unas
                # marcas que no estaban en ninguna parte.
                frag = fragmento(cwe, linea, valor, azar)
                sesion.add(
                    ContextRow(
                        id=str(uuid4()),
                        finding_id=hallazgo_id,
                        enclosing_function=frag["enclosing"],
                        callers=frag["callers"],
                        callees=frag["callees"],
                        sanitizers=frag["sanitizers"],
                        available_lines=frag["lineas"],
                        source_expression=frag["expresion"],
                        caller_depth=0 if frag["degradado"] else 1,
                        callee_depth=0 if frag["degradado"] else 1,
                        degraded_to_file=frag["degradado"],
                        context_text=frag["texto"],
                        created_at=nacida + timedelta(minutes=azar.randint(1, 40)),
                    )
                )
                prioridad = round(
                    (0.7 if valor == "explotable" else 0.2)
                    + (0.2 if severidad == "error" else 0.0)
                    + confianza * 0.1,
                    4,
                )
                sesion.add(
                    VerdictRow(
                        id=str(uuid4()),
                        finding_id=hallazgo_id,
                        model=MODELO,
                        model_version=VERSION_MODELO,
                        prompt_version="v3",
                        temperature=0.0,
                        repetition=1,
                        value=valor,
                        confidence=round(confianza, 3),
                        cited_lines=frag["citadas"] if anclado else [],
                        anchor_verified=anclado,
                        attempts=1 if anclado else 2,
                        justification=JUSTIFICA[valor],
                        latency_ms=azar.randint(4200, 21000),
                        input_tokens=azar.randint(900, 2600),
                        output_tokens=azar.randint(120, 420),
                        created_at=nacida + timedelta(minutes=azar.randint(1, 55)),
                    )
                )
                await sesion.flush()
                fila = await sesion.get(FindingRow, hallazgo_id)
                fila.priority = prioridad
                fila.priority_reason = (
                    "Parece real y la regla es de severidad alta"
                    if valor == "explotable" and severidad == "error"
                    else "Queda por detrás de lo que sí parece explotable"
                )

    await sesion.commit()
    return creado


async def borrar(sesion, registro: dict) -> tuple[int, int]:
    """Deshace exactamente lo que este script creó, ni una fila más."""
    ejecuciones = registro.get("ejecuciones", [])
    proyectos = registro.get("proyectos", [])
    if ejecuciones:
        await sesion.execute(
            delete(ExecutionRow).where(ExecutionRow.id.in_(ejecuciones))
        )
    if proyectos:
        await sesion.execute(delete(ProjectRow).where(ProjectRow.id.in_(proyectos)))
    await sesion.commit()
    return len(proyectos), len(ejecuciones)


async def principal() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--crear", action="store_true")
    p.add_argument("--borrar", action="store_true")
    p.add_argument(
        "--despliegue",
        action="store_true",
        help="Contra la base del servicio desplegado en lugar de la local.",
    )
    args = p.parse_args()
    if args.crear == args.borrar:
        p.error("elige --crear o --borrar")

    load_dotenv(RAIZ / ".env")
    REGISTRO = _registro(args.despliegue)
    if args.despliegue:
        url = os.environ["DATABASE_URL_DESPLIEGUE"]
        url = url.replace("postgresql://", "postgresql+asyncpg://")
        # asyncpg no entiende estos parámetros en la dirección; van por TLS
        # igual, que es lo que Neon exige.
        for sobra in ("?sslmode=require&channel_binding=require", "?sslmode=require"):
            url = url.replace(sobra, "")
    else:
        url = "sqlite+aiosqlite:///./certa.db"

    motor = create_async_engine(url, echo=False)
    Sesion = async_sessionmaker(motor, expire_on_commit=False)

    async with Sesion() as sesion:
        if args.borrar:
            if not REGISTRO.exists():
                print("No hay registro de qué crear, así que no hay qué borrar.")
                return 1
            registro = json.loads(REGISTRO.read_text(encoding="utf-8"))
            proyectos, ejecuciones = await borrar(sesion, registro)
            REGISTRO.unlink()
            print(f"Borrados {proyectos} proyectos y {ejecuciones} ejecuciones.")
            return 0

        from src.iam.infrastructure.persistence.models import UserRow

        usuario = (
            await sesion.execute(select(UserRow).where(UserRow.email == CORREO))
        ).scalar_one_or_none()
        if usuario is None:
            print(f"No existe la cuenta {CORREO} en esa base.")
            return 1

        if REGISTRO.exists():
            print("Ya hay material cargado. Bórralo primero con --borrar.")
            return 1

        creado = await crear(sesion, usuario.id)
        REGISTRO.write_text(
            json.dumps(creado, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(
            f"Creados {len(creado['proyectos'])} proyectos y "
            f"{len(creado['ejecuciones'])} ejecuciones."
        )
        print(f"Registro en {REGISTRO.name}, que es lo que --borrar deshace.")
    await motor.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(principal()))
