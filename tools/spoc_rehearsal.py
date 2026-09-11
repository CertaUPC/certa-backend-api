"""Ensayo general de la prueba de concepto, sin gastar en el proveedor.

    py tools/spoc_rehearsal.py

Correr esto ANTES de pagar. Una corrida real que falle a la mitad cuesta dinero
que no se recupera, y los fallos que de verdad ocurren no son de logica sino de
cableado: una variable de entorno mal puesta, un contrato que cambio de nombres,
una dependencia que falta en el entorno.

Levanta un servidor que habla el mismo contrato que el proveedor real y corre
contra el la cadena entera, con el codigo de produccion y sin parches: adaptador
HTTP, constructor de consulta, verificador de anclaje, guarda de presupuesto,
persistencia, cuadro de resultados, paquete reproducible y figuras.

Lo unico simulado es lo que hay al otro lado del cable. Todo lo demas es lo que
correra el dia que se pague.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
RAIZ = Path(__file__).resolve().parents[1]
PY = Path(sys.executable)

JAVA = """package org.owasp.benchmark.testcode;
import java.sql.*;
import javax.servlet.http.*;

public class {clase} extends HttpServlet {{
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws java.io.IOException {{
        String param = request.getParameter("dato");
        String consulta = "SELECT * FROM usuarios WHERE nombre = '" + param + "'";
        try {{
            Connection c = org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
            Statement s = c.createStatement();
            s.execute(consulta);
        }} catch (SQLException e) {{
            response.getWriter().println("error");
        }}
    }}
}}
"""

CASOS = [("BenchmarkTest00001", "sqli", "true", "89"),
         ("BenchmarkTest00002", "sqli", "false", "89"),
         ("BenchmarkTest00003", "sqli", "true", "89"),
         ("BenchmarkTest00004", "sqli", "false", "89"),
         ("BenchmarkTest00005", "sqli", "true", "89"),
         ("BenchmarkTest00006", "sqli", "false", "89")]


# --------------------------------------------------- servidor del proveedor
class Proveedor(BaseHTTPRequestHandler):
    """Responde el contrato de completado de chat. Varia el veredicto segun el
    modelo pedido, para que el cuadro no salga degenerado."""

    llamadas: ClassVar[list] = []

    def do_POST(self):
        cuerpo = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        modelo = cuerpo.get("model", "?")
        consulta = cuerpo["messages"][-1]["content"]
        Proveedor.llamadas.append((modelo, cuerpo.get("temperature")))

        # Se cita una linea que de verdad exista en el contexto recibido.
        # El lector numera como "9: codigo", con dos puntos.
        lineas = [int(n) for n in __import__("re").findall(r"^\s*(\d+):", consulta, 8)]
        cita = lineas[len(lineas) // 2] if lineas else 1
        # Cada modelo acierta en distinta proporcion.
        idx = len(Proveedor.llamadas)
        if "alto" in modelo:
            valor = "explotable" if idx % 2 else "no_explotable"
        elif "medio" in modelo:
            valor = "explotable" if idx % 3 else "no_explotable"
        else:
            valor = "explotable"

        respuesta = {
            "id": "prueba", "object": "chat.completion", "model": modelo,
            "choices": [{"index": 0, "finish_reason": "stop", "message": {
                "role": "assistant",
                "content": json.dumps({
                    "value": valor,
                    "justification_text": "El dato llega sin sanear al punto sensible.",
                    "cited_lines": [cita],
                    "confidence": 0.8,
                }, ensure_ascii=False)}}],
            "usage": {"prompt_tokens": 1700, "completion_tokens": 350},
        }
        datos = json.dumps(respuesta).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(datos)))
        self.end_headers()
        self.wfile.write(datos)

    def log_message(self, *a):
        pass


def puerto_libre():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def main():
    tmp = Path(tempfile.mkdtemp(prefix="ensayo_spoc_"))
    corpus = tmp / "corpus"
    corpus.mkdir()
    for clase, _, _, _ in CASOS:
        (corpus / f"{clase}.java").write_text(JAVA.format(clase=clase), encoding="utf-8")

    esperados = tmp / "expectedresults-1.2.csv"
    esperados.write_text(
        "# test name, category, real vulnerability, cwe\n"
        + "\n".join(",".join(c) for c in CASOS) + "\n", encoding="utf-8")

    sarif = {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "semgrep", "semanticVersion": "1.90.0", "rules": [
            {"id": "java.lang.security.audit.sqli",
             "properties": {"tags": ["CWE-89: SQL Injection"]}}]}},
        "results": [{
            "ruleId": "java.lang.security.audit.sqli", "level": "error",
            "message": {"text": "Consulta construida por concatenación"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f"{clase}.java"},
                "region": {"startLine": 9, "endLine": 9}}}]}
            for clase, _, _, _ in CASOS]}]}
    (tmp / "salida.sarif").write_text(json.dumps(sarif), encoding="utf-8")

    puerto = puerto_libre()
    servidor = HTTPServer(("127.0.0.1", puerto), Proveedor)
    threading.Thread(target=servidor.serve_forever, daemon=True).start()

    entorno = dict(os.environ)
    entorno.update({
        "DATABASE_URL": f"sqlite+aiosqlite:///{(tmp / 'spoc.db').as_posix()}",
        "GROUND_TRUTH_PATH": str(esperados),
        "REPOSITORY_ROOT": str(corpus),
        "LLM_BASE_URL": f"http://127.0.0.1:{puerto}/v1",
        "LLM_API_KEY": "clave-de-ensayo",
        "LLM_MODEL": "ensayo/alto",
        "LLM_TEMPERATURE": "0.0",
        "PYTHONIOENCODING": "utf-8",
    })

    def corre(titulo, args, script=None):
        print(f"\n{'=' * 62}\n{titulo}\n{'=' * 62}")
        cmd = [str(PY)] + (["-c", script] if script else ["-m", "src.cli"] + args)
        r = subprocess.run(cmd, cwd=RAIZ, env=entorno, capture_output=True,
                           text=True, encoding="utf-8", errors="replace", check=False)
        print(r.stdout.strip()[:2600])
        if r.returncode != 0:
            print("--- STDERR ---")
            print(r.stderr.strip()[-2200:])
        return r

    # 1. Ingesta con verdad conocida
    ingesta = f'''
import asyncio, json
from uuid import uuid4
from src.shared.config import get_settings
from src.shared.composition import Container
from src.shared.database import Base, ProjectRow

async def main():
    c = Container(get_settings())
    async with c.engine.begin() as cn:
        await cn.run_sync(Base.metadata.create_all)
    pid = uuid4()
    async with c.sessions() as s:
        s.add(ProjectRow(id=str(pid), name="Ensayo", repository_path=r"{corpus}"))
        await s.commit()
    payload = json.load(open(r"{tmp / 'salida.sarif'}", encoding="utf-8"))
    async with c.sessions() as s:
        r = await c.ingest_service(s).from_payload(pid, payload)
        print("ingeridos:", r.ingested, "| etiquetados:", r.labeled)
        print("mensaje:", r.describe())
        print("EXECUTION_ID=" + str(r.execution.id))
    await c.dispose()

asyncio.run(main())
'''
    r = corre("PASO 1  Ingesta y etiquetado contra verdad conocida", [], ingesta)
    if "EXECUTION_ID=" not in r.stdout:
        print("\nFALLA: la ingesta no produjo ejecución")
        return 1
    ejec = r.stdout.split("EXECUTION_ID=")[1].strip().splitlines()[0]

    # 2. Comparacion de tres modelos, dos repeticiones
    paquete = tmp / "spoc"
    corre("PASO 2  compare con tres modelos y dos repeticiones",
          ["compare", ejec, "--model", "ensayo/alto", "--model", "ensayo/medio",
           "--model", "ensayo/abierto", "--repetitions", "2",
           "--out-dir", str(paquete)])

    # 3. Figuras
    print(f"\n{'=' * 62}\nPASO 3  Figuras del anexo\n{'=' * 62}")
    r = subprocess.run([str(PY), "tools/spoc_figures.py", str(paquete)],
                       cwd=RAIZ, env=entorno, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", check=False)
    print(r.stdout.strip()[:1200])
    if r.returncode != 0:
        print("--- STDERR ---")
        print(r.stderr.strip()[-1500:])

    # 4. Comprobaciones
    print(f"\n{'=' * 62}\nPASO 4  Comprobaciones del paquete\n{'=' * 62}")
    import csv as _csv
    fallos = []
    for nombre in ("scorecard.csv", "verdicts.csv", "manifest.json"):
        ruta = paquete / nombre
        print(f"   {'ok  ' if ruta.is_file() else 'FALTA'} {nombre}"
              f"{'  ' + str(ruta.stat().st_size) + ' bytes' if ruta.is_file() else ''}")
        if not ruta.is_file():
            fallos.append(nombre)
    if (paquete / "scorecard.csv").is_file():
        filas = list(_csv.DictReader((paquete / "scorecard.csv").open(encoding="utf-8")))
        print(f"\n   corridas en el cuadro: {len(filas)} (esperadas 6: 3 modelos x 2 repeticiones)")
        for f in filas:
            print(f"      {f['modelo']:<16} rep {f['repeticion']}  F1={f['f1']}  "
                  f"contrastados={f['contrastados']}  USD={f['usd']}")
        if len(filas) != 6:
            fallos.append("el cuadro no trae 6 corridas")
    if (paquete / "manifest.json").is_file():
        m = json.loads((paquete / "manifest.json").read_text(encoding="utf-8"))
        print(f"\n   manifiesto: huella={m['lote']['huella_del_lote'][:16]} "
              f"etiquetados={m['lote']['con_verdad_conocida']} "
              f"temp={m['consulta']['temperatura']} anfitrion={m['modelos']['anfitrion']}")
        if "clave-de-ensayo" in json.dumps(m):
            fallos.append("LA CLAVE APARECE EN EL MANIFIESTO")
        else:
            print("   ok   la clave del proveedor no aparece en el manifiesto")
    figuras = sorted(p.name for p in paquete.glob("*.png"))
    print(f"\n   figuras: {len(figuras)} -> {figuras}")
    if len(figuras) < 4:
        fallos.append("faltan figuras")
    temps = {t for _, t in Proveedor.llamadas}
    print(f"\n   llamadas al proveedor: {len(Proveedor.llamadas)}")
    print(f"   temperaturas enviadas: {temps}  {'ok' if temps == {0.0} else 'FALLA: no todas en cero'}")
    if temps != {0.0}:
        fallos.append("temperatura distinta de cero")
    modelos = sorted({m for m, _ in Proveedor.llamadas})
    print(f"   modelos solicitados:   {modelos}")
    if len(modelos) != 3:
        fallos.append("no se solicitaron los tres modelos")

    print(f"\n{'=' * 62}")
    if fallos:
        print("FALLOS ENCONTRADOS:")
        for f in fallos:
            print("   -", f)
    else:
        print("CADENA COMPLETA VERIFICADA, sin fallos")
    print(f"paquete en {paquete}")
    servidor.shutdown()
    shutil.rmtree(tmp, ignore_errors=True)
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
