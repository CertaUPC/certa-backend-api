"""El código que acompaña a cada alerta de los proyectos de ejemplo.

La pantalla de revisión no enseña la alerta sola: enseña el fragmento que el
asistente miró, con la función que la contiene, quién la llama y las líneas que
la justificación cita. Los proyectos de ejemplo se sembraron sin nada de eso, y
el resultado era una columna negra vacía con un número de línea suelto,
mientras el panel de al lado seguía prometiendo que las líneas citadas estaban
marcadas ahí.

Así que cada tipo de falla trae aquí su fragmento, con la forma que tiene ese
error en Java de verdad: el dato entrando por la petición, el sumidero cuatro
líneas más abajo y el llamador al final. Las dos líneas que el veredicto cita
son justamente esas dos, de modo que las marcas caen sobre código que existe.

No es código ejecutable ni pretende serlo: es lo que un lector de contexto
habría recortado del repositorio.
"""

from __future__ import annotations

import random

# El sumidero va siempre en el mismo renglón del fragmento, para que la línea
# que el hallazgo declara y la que se pinta sean la misma.
FILA_SUMIDERO = 6
FILA_FUENTE = 2

# Por tipo de falla: cómo se llama el método, qué dato entra, dónde revienta y
# quién lo llama. Es lo que cambia entre una inyección SQL y una ruta
# manipulable; el andamiaje alrededor es el mismo porque en un controlador de
# verdad también lo es.
PLANTILLAS: dict[str, dict] = {
    "CWE-89": {
        "metodo": "buscarPorDocumento",
        "firma": "public List<Cliente> buscarPorDocumento(HttpServletRequest peticion) {",
        "var": "documento",
        "param": "doc",
        "nota": "El filtro viene del buscador del portal.",
        "vacio": "Collections.emptyList()",
        "sumidero": 'String sql = "SELECT * FROM clientes WHERE documento = \'" + documento + "\'";',
        "seguida": "List<Cliente> filas = plantilla.query(sql, MAPEADOR);",
        "retorno": "filas",
        "llamador": "atenderBusqueda",
        "atributo": "clientes",
    },
    "CWE-79": {
        "metodo": "escribirResumen",
        "firma": "public void escribirResumen(HttpServletRequest peticion, HttpServletResponse respuesta) {",
        "var": "comentario",
        "param": "comentario",
        "nota": "El texto lo escribe el propio usuario en el formulario.",
        "vacio": "",
        "sumidero": 'respuesta.getWriter().write("<div class=\\"nota\\">" + comentario + "</div>");',
        "seguida": "respuesta.setContentType(\"text/html\");",
        "retorno": None,
        "llamador": "mostrarFicha",
        "atributo": "resumen",
    },
    "CWE-327": {
        "metodo": "resumirClave",
        "firma": "public String resumirClave(HttpServletRequest peticion) throws Exception {",
        "var": "clave",
        "param": "clave",
        "nota": "Se guarda el resumen, nunca la clave en claro.",
        "vacio": "null",
        "sumidero": 'MessageDigest resumen = MessageDigest.getInstance("MD5");',
        "seguida": "byte[] digerido = resumen.digest(clave.getBytes(StandardCharsets.UTF_8));",
        "retorno": "Base64.getEncoder().encodeToString(digerido)",
        "llamador": "registrarUsuario",
        "atributo": "huellaClave",
    },
    "CWE-611": {
        "metodo": "leerDocumento",
        "firma": "public Document leerDocumento(HttpServletRequest peticion) throws Exception {",
        "var": "xml",
        "param": "cuerpo",
        "nota": "El proveedor manda el reporte como XML plano.",
        "vacio": "null",
        "sumidero": "DocumentBuilderFactory fabrica = DocumentBuilderFactory.newInstance();",
        "seguida": "return fabrica.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));",
        "retorno": None,
        "llamador": "importarReporte",
        "atributo": "documento",
    },
    "CWE-22": {
        "metodo": "abrirAdjunto",
        "firma": "public InputStream abrirAdjunto(HttpServletRequest peticion) throws IOException {",
        "var": "nombre",
        "param": "archivo",
        "nota": "El nombre llega en la dirección del enlace de descarga.",
        "vacio": "null",
        "sumidero": "File adjunto = new File(CARPETA_ADJUNTOS + nombre);",
        "seguida": "return new FileInputStream(adjunto);",
        "retorno": None,
        "llamador": "descargar",
        "atributo": "adjunto",
    },
    "CWE-502": {
        "metodo": "recuperarSesion",
        "firma": "public Sesion recuperarSesion(HttpServletRequest peticion) throws Exception {",
        "var": "estado",
        "param": "estado",
        "nota": "El estado viaja serializado en la galleta de sesión.",
        "vacio": "null",
        "sumidero": "ObjectInputStream flujo = new ObjectInputStream(decodificar(estado));",
        "seguida": "return (Sesion) flujo.readObject();",
        "retorno": None,
        "llamador": "filtrar",
        "atributo": "sesion",
    },
    "CWE-798": {
        "metodo": "conectarPasarela",
        "firma": "public Respuesta conectarPasarela(HttpServletRequest peticion) {",
        "var": "entorno",
        "param": "entorno",
        "nota": "Cada entorno apunta a una pasarela distinta.",
        "vacio": "Respuesta.vacia()",
        "sumidero": 'String llaveApi = "sk_live_51H8vQm2eZvKYlo2C0kQhUq";',
        "seguida": "Pasarela pasarela = new Pasarela(entorno, llaveApi);",
        "retorno": "pasarela.cobrar(peticion)",
        "llamador": "procesarPago",
        "atributo": "cobro",
    },
    "CWE-532": {
        "metodo": "anotarIntento",
        "firma": "public void anotarIntento(HttpServletRequest peticion) {",
        "var": "token",
        "param": "token",
        "nota": "Se deja rastro de cada intento de acceso.",
        "vacio": "",
        "sumidero": 'registro.info("intento con token {} desde {}", token, peticion.getRemoteAddr());',
        "seguida": "intentos.incrementar(peticion.getRemoteAddr());",
        "retorno": None,
        "llamador": "autenticar",
        "atributo": "intento",
    },
    "CWE-918": {
        "metodo": "consultarProveedor",
        "firma": "public String consultarProveedor(HttpServletRequest peticion) throws Exception {",
        "var": "destino",
        "param": "url",
        "nota": "El integrador configura a qué proveedor se pregunta.",
        "vacio": '""',
        "sumidero": "HttpRequest salida = HttpRequest.newBuilder(URI.create(destino)).build();",
        "seguida": "return cliente.send(salida, BodyHandlers.ofString()).body();",
        "retorno": None,
        "llamador": "sincronizar",
        "atributo": "respuestaProveedor",
    },
    "CWE-1004": {
        "metodo": "emitirGalleta",
        "firma": "public void emitirGalleta(HttpServletRequest peticion, HttpServletResponse respuesta) {",
        "var": "identificador",
        "param": "sid",
        "nota": "La sesión se sostiene con esta galleta.",
        "vacio": "",
        "sumidero": 'Cookie sesion = new Cookie("SID", identificador);',
        "seguida": "sesion.setPath(\"/\");",
        "retorno": None,
        "llamador": "iniciarSesion",
        "atributo": "galleta",
    },
}

# Para un tipo de falla que no esté arriba, uno genérico antes que ninguno.
GENERICA = PLANTILLAS["CWE-89"]


def _fuente(p: dict, valor: str) -> str:
    """De dónde sale el dato, según lo que el veredicto acabó diciendo.

    La justificación de un descarte dice que el valor viene de una constante
    del propio código. Si el fragmento enseñara un `getParameter`, el texto y
    el código se contradirían en la misma pantalla.
    """
    if valor == "no_explotable":
        return (
            f'String {p["var"]} = CONFIGURACION.getProperty("{p["param"]}");'
            "  // fijado en el despliegue"
        )
    return f'String {p["var"]} = peticion.getParameter("{p["param"]}");'


def _cuerpo(p: dict, valor: str) -> list[str]:
    """Las catorce líneas del fragmento, en orden.

    El sumidero se queda clavado en `FILA_SUMIDERO` pase lo que pase: si se
    corriera un renglón, la línea que el hallazgo declara dejaría de ser la que
    se pinta marcada.
    """
    var = p["var"]
    if valor == "indeterminado":
        # El saneador se llama, pero su cuerpo vive en otra clase y no entra en
        # el recorte. Es exactamente lo que dice la justificación de un
        # indeterminado, y así el texto y el código no se contradicen.
        guarda = [
            "    // saneador.normalizar vive en otra clase del proyecto",
            f"    {var} = saneador.normalizar({var});",
            f"    if ({var}.isBlank()) {{ return; }}" if not p["vacio"]
            else f'    if ({var}.isBlank()) {{ return {p["vacio"]}; }}',
        ]
    else:
        guarda = [
            f"    if ({var} == null || {var}.isBlank()) {{",
            f'        return {p["vacio"]};' if p["vacio"] else "        return;",
            "    }",
        ]

    # La nota de arriba explica de dónde sale el dato, así que cambia con él:
    # dejar «lo escribe el usuario» encima de una constante del despliegue era
    # contradecirse en dos renglones seguidos.
    nota = (
        "El valor sale de la configuración del despliegue."
        if valor == "no_explotable"
        else p["nota"]
    )

    lineas = [
        p["firma"],
        f"    // {nota}",
        f"    {_fuente(p, valor)}",
        *guarda,
        f'    {p["sumidero"]}',
        f'    {p["seguida"]}',
    ]
    assert lineas[FILA_SUMIDERO] == f'    {p["sumidero"]}'

    # Nada después de un return, que sería código muerto y se nota.
    if p["retorno"]:
        lineas.append(f'    return {p["retorno"]};')
    elif not p["seguida"].startswith("return"):
        lineas.append("    metricas.marcar();")

    devuelve = bool(p["retorno"]) or p["seguida"].startswith("return")
    lineas += [
        "}",
        "",
        "// quien lo llama",
        f'public void {p["llamador"]}(HttpServletRequest peticion) {{',
        (
            f'    modelo.put("{p["atributo"]}", {p["metodo"]}(peticion));'
            if devuelve
            else f'    {p["metodo"]}(peticion);'
        ),
    ]
    return lineas


def fragmento(
    cwe: str, linea: int, valor: str, azar: random.Random
) -> dict:
    """El contexto de una alerta: texto numerado, función, llamadores y líneas.

    `linea` es la del hallazgo, y cae sobre el sumidero. Las citadas son la
    línea por donde entra el dato y esa misma del sumidero, que es el recorrido
    que la justificación describe.
    """
    p = PLANTILLAS.get(cwe, GENERICA)
    cuerpo = _cuerpo(p, valor)
    primera = linea - FILA_SUMIDERO

    # Una de cada doce viene degradada: el lector no logró aislar la función y
    # devuelve una ventana de líneas. La pantalla lo avisa, y conviene que ese
    # aviso se pueda ver con datos de ejemplo.
    degradado = azar.random() < 0.08
    if degradado:
        recorte = 1
        cuerpo = cuerpo[recorte:-2]
        primera += recorte

    texto = "\n".join(
        f"{primera + i}: {l}" for i, l in enumerate(cuerpo)
    )
    lineas = list(range(primera, primera + len(cuerpo)))

    return {
        "texto": texto,
        "enclosing": "(no identificada)" if degradado else p["metodo"],
        "callers": [] if degradado else [p["llamador"]],
        "callees": [] if degradado else ["modelo.put"],
        "sanitizers": [],
        "lineas": lineas,
        "citadas": [linea - (FILA_SUMIDERO - FILA_FUENTE), linea],
        "expresion": p["sumidero"].strip(),
        "degradado": degradado,
    }
