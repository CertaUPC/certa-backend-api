"""Puntuación del benchmarking del objetivo 1, calculada y no escrita a mano.

Por qué existe este archivo y no una tabla tecleada en el documento: una
puntuación que nadie puede recomputar es una opinión con aspecto de medida. Aquí
se declara, para cada capa, qué criterios se usan, cuánto pesa cada uno, qué
hecho concreto activa cada nivel de la rúbrica y de dónde sale ese hecho. El
total se calcula. Quien quiera discutir la decisión tiene que discutir un peso o
un hecho, que es como debe ser.

Dos reglas de método que condicionan toda la estructura:

1. Los requisitos eliminatorios NO entran en la media ponderada. Un requisito
   que el proyecto no puede ceder no admite compensación: permitir que un
   candidato supla con buena puntuación en otro criterio lo que incumple aquí
   convertiría la tabla en un adorno. Se filtran primero y se puntúa después,
   solo entre los que sobreviven.

2. Donde el filtro deja un único superviviente se dice así, sin fabricar una
   carrera. Una puntuación ponderada entre un candidato y ninguno no informa de
   nada y aparenta una precisión que no existe.

    py tools/benchmarking_scores.py
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


@dataclass(frozen=True)
class Nivel:
    """Un escalón de la rúbrica: qué puntúa y qué hecho lo activa."""

    puntos: int
    descripcion: str


@dataclass(frozen=True)
class Criterio:
    """Criterio ponderado, con su rúbrica y la razón de su peso."""

    nombre: str
    peso: int
    porque_pesa: str
    rubrica: tuple[Nivel, ...]

    def puntos_de(self, nivel: str) -> int:
        for n in self.rubrica:
            if n.descripcion == nivel:
                return n.puntos
        raise KeyError(
            f"El nivel {nivel!r} no está en la rúbrica de {self.nombre!r}. "
            f"Niveles válidos: {[n.descripcion for n in self.rubrica]}"
        )


@dataclass(frozen=True)
class Requisito:
    """Condición sin la cual el candidato queda fuera, sin puntuación."""

    nombre: str
    porque_elimina: str
    # Frase breve para la celda de la tabla. El texto largo sustenta; la celda
    # solo informa de en qué quedó. Vacío cuando el efecto se calcula.
    resumen: str = ""


@dataclass
class Capa:
    nombre: str
    requisitos: tuple[Requisito, ...]
    criterios: tuple[Criterio, ...]
    # candidato -> {requisito: bool}
    cumplimiento: dict[str, dict[str, bool]] = field(default_factory=dict)
    # candidato -> {criterio: nivel}
    niveles: dict[str, dict[str, str]] = field(default_factory=dict)
    # candidato -> {requisito: hecho que lo resuelve}. Sustituye al sí o no:
    # informa de por qué el candidato pasa o cae, que es lo que se discute.
    hechos: dict[str, dict[str, str]] = field(default_factory=dict)
    # La misma informacion en forma breve, para la celda de una diapositiva.
    hechos_breves: dict[str, dict[str, str]] = field(default_factory=dict)
    # Reglas que eligen cuáles de los supervivientes pasan a medirse, cuando la
    # capa no se decide por tabla. No puntúan ni ordenan: acotan la muestra.
    reglas_de_muestreo: tuple[Requisito, ...] = ()
    finalistas: tuple[str, ...] = ()
    fuente: str = ""

    def __post_init__(self) -> None:
        suma = sum(c.peso for c in self.criterios)
        if self.criterios and suma != 100:
            raise ValueError(
                f"Los pesos de {self.nombre!r} suman {suma} y deben sumar 100"
            )

    def hecho(self, candidato: str, requisito: str) -> str:
        """El dato verificable que resuelve el requisito para ese candidato."""
        declarado = self.hechos.get(candidato, {}).get(requisito)
        if declarado:
            return declarado
        return "Cumple" if self.cumplimiento[candidato][requisito] else "No cumple"

    def hecho_breve(self, candidato: str, requisito: str) -> str:
        """El mismo dato que hecho(), en la forma corta que cabe en una celda."""
        breve = self.hechos_breves.get(candidato, {}).get(requisito)
        return breve if breve else self.hecho(candidato, requisito)

    def supervivientes(self) -> list[str]:
        return [c for c, r in self.cumplimiento.items() if all(r.values())]

    def eliminado_por(self, candidato: str) -> list[str]:
        return [r for r, ok in self.cumplimiento[candidato].items() if not ok]

    def total(self, candidato: str) -> float:
        niveles = self.niveles[candidato]
        return round(
            sum(c.peso * c.puntos_de(niveles[c.nombre]) / 100 for c in self.criterios),
            1,
        )

    def detalle(self, candidato: str) -> list[tuple[str, int, int, float]]:
        """Por criterio: peso, puntos y aporte al total."""
        niveles = self.niveles[candidato]
        salida = []
        for c in self.criterios:
            p = c.puntos_de(niveles[c.nombre])
            salida.append((c.nombre, c.peso, p, round(c.peso * p / 100, 1)))
        return salida


# ═══════════════════════════════════════════ Capa 1. Analizador estático
#
# Los tres requisitos salen del Project Charter y no de una preferencia: el
# proyecto analiza código privado de equipos peruanos, consume la salida en
# SARIF para no acoplarse al analizador, y se incorpora a la línea de
# integración continua, donde exigir una compilación previa lo deja fuera.

ANALIZADOR = Capa(
    nombre="Analizadores estáticos de seguridad",
    requisitos=(
        Requisito(
            "Opera sobre código privado sin licencia comercial",
            "El proyecto analiza código privado y no dispone de presupuesto de "
            "licencias. Un candidato que exija repositorio público no puede "
            "usarse, por bueno que sea en lo demás.",
        ),
        Requisito(
            "Emite SARIF 2.1.0 de manera nativa",
            "El desacoplamiento del analizador descansa en un formato común. "
            "Un conversor añadido sería una pieza más que mantener y una "
            "fuente de pérdida de información.",
        ),
        Requisito(
            "Analiza sin compilar el proyecto",
            "La herramienta se incorpora a la línea de integración continua "
            "sobre repositorios ajenos. Exigir una compilación previa traslada "
            "al usuario el problema de reproducir su construcción.",
        ),
    ),
    criterios=(
        Criterio(
            "Alcance del seguimiento de contaminación", 30,
            "Determina cuántos hallazgos llegan con la ruta del dato completa. "
            "Es el criterio de capacidad y por eso pesa más que ninguno.",
            (Nivel(100, "Interprocedural entre archivos"),
             Nivel(50, "Dentro del archivo"),
             Nivel(25, "Por patrones, sin seguimiento")),
        ),
        Criterio(
            "Configurabilidad y auditabilidad de reglas", 25,
            "El trabajo debe declarar con qué reglas midió y permitir que otro "
            "lo repita. Un catálogo cerrado impide ambas cosas.",
            (Nivel(100, "Reglas declarativas legibles y propias"),
             Nivel(60, "Lenguaje de consulta propio"),
             Nivel(30, "Perfiles configurables sobre catálogo fijo"),
             Nivel(0, "Catálogo cerrado")),
        ),
        Criterio(
            "Ausencia de tope de uso", 25,
            "El corpus de referencia tiene 2 740 casos y la medición se repite. "
            "Un tope mensual convierte la reproducibilidad en un problema de "
            "calendario.",
            (Nivel(100, "Sin tope"),
             Nivel(25, "Tope mensual en el plan gratuito"),
             Nivel(0, "Sin plan gratuito")),
        ),
        Criterio(
            "Invocación apta para integración continua", 20,
            "La ejecución desatendida es un requisito declarado del producto.",
            (Nivel(100, "Línea de órdenes sin cuenta"),
             Nivel(75, "Línea de órdenes con cuenta"),
             Nivel(40, "Servidor propio o complemento de construcción")),
        ),
    ),
    fuente="Documentación de cada producto, consultada el 11 de setiembre del "
           "2026; tasas de detección de Bennett et al. (2024a).",
)

ANALIZADOR.cumplimiento = {
    "Semgrep OSS": {
        "Opera sobre código privado sin licencia comercial": True,
        "Emite SARIF 2.1.0 de manera nativa": True,
        "Analiza sin compilar el proyecto": True,
    },
    "SonarQube Community": {
        "Opera sobre código privado sin licencia comercial": True,
        "Emite SARIF 2.1.0 de manera nativa": False,
        "Analiza sin compilar el proyecto": True,
    },
    "CodeQL": {
        "Opera sobre código privado sin licencia comercial": False,
        "Emite SARIF 2.1.0 de manera nativa": True,
        "Analiza sin compilar el proyecto": False,
    },
    "Snyk Code": {
        "Opera sobre código privado sin licencia comercial": True,
        "Emite SARIF 2.1.0 de manera nativa": True,
        "Analiza sin compilar el proyecto": True,
    },
    "SpotBugs con FindSecBugs": {
        "Opera sobre código privado sin licencia comercial": True,
        "Emite SARIF 2.1.0 de manera nativa": False,
        "Analiza sin compilar el proyecto": False,
    },
}

ANALIZADOR.niveles = {
    "Semgrep OSS": {
        "Alcance del seguimiento de contaminación": "Dentro del archivo",
        "Configurabilidad y auditabilidad de reglas": "Reglas declarativas legibles y propias",
        "Ausencia de tope de uso": "Sin tope",
        "Invocación apta para integración continua": "Línea de órdenes sin cuenta",
    },
    "Snyk Code": {
        "Alcance del seguimiento de contaminación": "Interprocedural entre archivos",
        "Configurabilidad y auditabilidad de reglas": "Catálogo cerrado",
        "Ausencia de tope de uso": "Tope mensual en el plan gratuito",
        "Invocación apta para integración continua": "Línea de órdenes con cuenta",
    },
}


# ═══════════════════════════════════════ Capa 2. Modelo de lenguaje
#
# Esta capa NO se decide por tabla, y el documento lo sostiene: ningún atributo
# verificable en la documentación del proveedor anticipa si un modelo distingue
# un hallazgo real de uno espurio sobre código concreto. La tabla filtra; decide
# la prueba de concepto. Por eso aquí solo hay requisitos, y la puntuación de
# los finalistas sale de la medición y no de una rúbrica.

# El costo se calcula con el perfil de tokens que la corrida midió de verdad,
# 1 800 de entrada y 700 de salida por consulta, y no con una estimación. Los
# precios salen del catálogo del proveedor.
PERFIL_ENTRADA, PERFIL_SALIDA = 1800, 700

PRECIOS = {
    "anthropic/claude-opus-5": (5.00, 25.00),
    "openai/gpt-5.4": (2.50, 15.00),
    "google/gemini-2.5-pro": (1.25, 10.00),
    "anthropic/claude-sonnet-5": (2.00, 10.00),
    "google/gemini-3.8-flash": (0.75, 3.75),
    "qwen/qwen3.8-27b": (0.42, 3.00),
    "google/gemma-4-31b-it": (0.09, 0.34),
}
VENTANAS = {
    "anthropic/claude-opus-5": 1.00, "openai/gpt-5.4": 1.05,
    "google/gemini-2.5-pro": 1.05, "anthropic/claude-sonnet-5": 1.00,
    "google/gemini-3.8-flash": 1.05, "qwen/qwen3.8-27b": 1.00,
    "google/gemma-4-31b-it": 0.262,
}
REGIMEN = {
    "anthropic/claude-opus-5": "Comercial, gran escala",
    "openai/gpt-5.4": "Comercial, gran escala",
    "google/gemini-2.5-pro": "Comercial, gran escala",
    "anthropic/claude-sonnet-5": "Comercial, escala media",
    "google/gemini-3.8-flash": "Comercial, escala media",
    "qwen/qwen3.8-27b": "Pesos abiertos",
    "google/gemma-4-31b-it": "Pesos abiertos",
}


def costo_por_cien(modelo: str) -> float:
    """USD por 100 hallazgos, con el perfil de tokens medido en la corrida."""
    entrada, salida = PRECIOS[modelo]
    return round((PERFIL_ENTRADA * entrada + PERFIL_SALIDA * salida) / 1e6 * 100, 2)


def _banda_costo(modelo: str) -> str:
    c = costo_por_cien(modelo)
    if c <= 0.50:
        return "Hasta 0.50 USD por 100 hallazgos"
    if c <= 1.50:
        return "Hasta 1.50 USD por 100 hallazgos"
    if c <= 3.00:
        return "Hasta 3.00 USD por 100 hallazgos"
    return "Más de 3.00 USD por 100 hallazgos"


def _banda_ventana(modelo: str) -> str:
    v = VENTANAS[modelo]
    if v >= 1.0:
        return "Un millón de tokens o más"
    if v >= 0.5:
        return "Entre medio millón y un millón"
    return "Menos de medio millón"


MODELO = Capa(
    nombre="Modelos de lenguaje",
    requisitos=(
        Requisito(
            "Contrato de salida validable por esquema",
            "Sin respuesta estructurada no hay veredicto que verificar ni "
            "anclaje que comprobar.",
        ),
        Requisito(
            "Temperatura fijable en cero",
            "La reproducibilidad del experimento depende de ello.",
        ),
        Requisito(
            "Ventana suficiente para la consulta",
            "El fragmento, el contexto recuperado y la instrucción rondan los "
            "2 500 tokens. Una ventana menor obligaría a recortar el contexto, "
            "que es justamente la variable que la propuesta manipula.",
        ),
        Requisito(
            "Identificador de versión anclable",
            "Un identificador que el proveedor puede sustituir sin aviso "
            "invalida la repetición de la medida.",
        ),
    ),
    # Esta capa no lleva criterios ponderados, y la ausencia es deliberada.
    #
    # Ponderar aquí los atributos que el proveedor declara (precio, ventana,
    # régimen) produce un total que ordena por precio y lo presenta como si
    # midiera aptitud: el modelo más barato encabeza la tabla y el más caro la
    # cierra, cualquiera que sea su acierto sobre código real. Ese total entra
    # en contradicción directa con la medición del anexo A, que es la que de
    # verdad decide, y deja al lector con dos respuestas distintas a la misma
    # pregunta.
    #
    # Ningún atributo publicado por un proveedor anticipa si un modelo
    # distingue un hallazgo explotable de uno espurio sobre código concreto.
    # De modo que la capa filtra por requisitos, acota la muestra con reglas
    # declaradas y remite la decisión a la prueba de concepto.
    criterios=(),
    reglas_de_muestreo=(
        Requisito(
            "Un finalista por régimen de ejecución",
            "Los tres regímenes (pesos abiertos, comercial de escala media y "
            "comercial de gran escala) imponen restricciones distintas sobre "
            "dónde reside el código. Medir uno de cada uno responde qué "
            "cuesta, en acierto, quedarse dentro de la organización.",
            resumen="Reduce a tres: el régimen es la variable que la "
                    "comparación aísla",
        ),
        Requisito(
            "Proveedores distintos entre finalistas",
            "Dos modelos del mismo proveedor comparten datos de entrenamiento "
            "y decisiones de alineamiento, de modo que su acuerdo no sería "
            "evidencia independiente.",
            resumen="Evita confundir el efecto del régimen con el del "
                    "proveedor",
        ),
        Requisito(
            "El de mayor gama dentro de cada régimen",
            "La gama se identifica por el precio que el propio proveedor "
            "asigna, que es dato publicado. El sesgo de la regla juega en "
            "contra de la hipótesis: se compara contra el exponente más caro "
            "que el régimen caro ofrece, de modo que la ausencia de diferencia "
            "en exactitud no puede atribuirse a haber elegido un rival débil.",
            resumen="Fija el techo de cada régimen; el sesgo juega contra la "
                    "hipótesis",
        ),
    ),
    # Los finalistas no se enumeran a mano: los deriva finalistas_derivados()
    # aplicando las reglas de arriba, y una prueba comprueba que coinciden.
    finalistas=(),
    fuente="Catálogo del proveedor, consultado el 11 de setiembre del 2026. El "
           "costo se calcula con el perfil de tokens medido en la corrida del "
           "anexo A: 1 800 de entrada y 700 de salida por consulta.",
)

MODELO.cumplimiento = {
    m: {r.nombre: True for r in MODELO.requisitos} for m in PRECIOS
}
MODELO.hechos = {
    m: {
        "Contrato de salida validable por esquema": "Formato JSON forzado",
        "Temperatura fijable en cero": "Parámetro admitido",
        "Ventana suficiente para la consulta": _banda_ventana(m),
        "Identificador de versión anclable": "Versión explícita",
    }
    for m in PRECIOS
}

# ═══════════════════════════════ Quién representa a cada régimen
#
# Declarar "un finalista por régimen" no basta: en el régimen comercial de gran
# escala hay tres candidatos y el documento tomaba uno sin decir por qué. Es la
# primera pregunta que cabe hacerle a la tabla, y la respuesta no puede ser una
# medida de acierto, porque el acierto es justamente lo que aún no se ha medido.
#
# La regla es entonces ésta: dentro de cada régimen se toma el modelo de mayor
# gama, y se identifica la gama por el precio que el propio proveedor le asigna,
# que es un dato publicado y comprobable. Se resuelve primero el régimen de gran
# escala, porque es aquel cuya necesidad la tesis pone en duda, y los demás se
# eligen después evitando repetir proveedor.
#
# El sesgo de la regla juega en contra de la hipótesis, que es como debe ser: se
# compara contra el exponente más caro que el régimen caro ofrece. Si aun así la
# exactitud no se separa, la conclusión no se sostiene sobre haber elegido un
# rival débil.

ORDEN_DE_REGIMENES = ("Comercial, gran escala", "Comercial, escala media",
                      "Pesos abiertos")


def finalistas_derivados() -> tuple[str, ...]:
    """Aplica las reglas de muestreo y devuelve los tres representantes."""
    elegidos: list[str] = []
    proveedores: set[str] = set()
    for regimen in ORDEN_DE_REGIMENES:
        candidatos = [
            m for m in MODELO.supervivientes()
            if REGIMEN[m] == regimen and m.split("/")[0] not in proveedores
        ]
        if not candidatos:
            raise ValueError(
                f"El régimen {regimen!r} se queda sin representante con "
                f"proveedor distinto de {sorted(proveedores)}"
            )
        elegido = max(candidatos, key=costo_por_cien)
        elegidos.append(elegido)
        proveedores.add(elegido.split("/")[0])
    return tuple(elegidos)


MODELO.finalistas = finalistas_derivados()


# Resultado medido de la prueba de concepto. No es una rúbrica: son las cifras
# que produjo la corrida sobre 92 hallazgos con verdad conocida.
PRUEBA_DE_CONCEPTO = {
    "encabezado": ["Finalista", "F1", "Precisión", "Exhaustividad",
                   "Cobertura", "Estabilidad", "Latencia mediana",
                   "USD por 100 hallazgos"],
    "filas": [
        ["anthropic/claude-opus-5", 0.973, 0.962, 0.983, 0.949, 0.946, "9.9 s", 2.33],
        ["qwen/qwen3.8-27b", 0.969, 0.946, 0.994, 0.856, 0.874, "24.7 s", 0.43],
        ["google/gemini-3.8-flash", 0.953, 0.969, 0.939, 0.885, 0.931, "20.0 s", 0.45],
        ["Analizador sin asistencia", 0.821, 0.696, 1.000, 1.000, 1.000, "No aplica", 0.00],
    ],
    "nota": "Medias de tres repeticiones sobre los 92 hallazgos que los tres "
            "resolvieron. La exactitud no separa a los finalistas: la prueba de "
            "McNemar no detecta diferencia entre ninguna pareja y los "
            "intervalos de confianza se solapan. Lo que sí resulta "
            "significativo es la cobertura, con p = 0.004 y p = 0.016 contra "
            "el primero.",
}


# ═══════════════════════════════════ Capa 3. Motor de análisis sintáctico

SINTACTICO = Capa(
    nombre="Motores de análisis sintáctico",
    requisitos=(
        Requisito(
            "Se ejecuta en el proceso del trabajador",
            "Un proceso auxiliar en otra máquina virtual duplica el despliegue "
            "y añade un modo de fallo que no aporta nada al problema.",
        ),
        Requisito(
            "Tolera archivos que no compilan",
            "El analizador señala archivos de repositorios ajenos, en cualquier "
            "estado. Un recorrido que exija código correcto deja fuera justo "
            "los casos que más interesan.",
        ),
    ),
    criterios=(
        Criterio(
            "Extensión a otros lenguajes", 35,
            "El alcance actual es Java por disponibilidad de corpus con verdad "
            "conocida, no por diseño. La capacidad de ampliarlo sin reescribir "
            "el recuperador es lo que sostiene esa afirmación.",
            (Nivel(100, "Perfil declarativo por lenguaje"),
             Nivel(60, "Gramática propia por lenguaje"),
             Nivel(0, "Atado a un solo lenguaje")),
        ),
        Criterio(
            "Esfuerzo de resolución de llamadores y llamados", 30,
            "Es la operación central del recuperador de contexto.",
            (Nivel(100, "Grafo de llamadas incorporado"),
             Nivel(70, "Consulta sobre el árbol"),
             Nivel(30, "Implementación propia desde cero")),
        ),
        Criterio(
            "Consumo de recursos", 20,
            "El trabajador corre en capa gratuita con memoria acotada.",
            (Nivel(100, "Bajo"), Nivel(60, "Medio"), Nivel(20, "Alto")),
        ),
        Criterio(
            "Complejidad de integración", 15,
            "Cada pieza añadida es una que desplegar, vigilar y explicar.",
            (Nivel(100, "Ruedas precompiladas"),
             Nivel(50, "Proceso auxiliar"),
             Nivel(20, "Generación previa")),
        ),
    ),
    fuente="Documentación de cada proyecto, consultada el 11 de setiembre del 2026.",
)

SINTACTICO.cumplimiento = {
    "Tree-sitter": {"Se ejecuta en el proceso del trabajador": True,
                    "Tolera archivos que no compilan": True},
    "JavaParser": {"Se ejecuta en el proceso del trabajador": False,
                   "Tolera archivos que no compilan": True},
    "Eclipse JDT Core": {"Se ejecuta en el proceso del trabajador": False,
                         "Tolera archivos que no compilan": True},
    "Spoon": {"Se ejecuta en el proceso del trabajador": False,
              "Tolera archivos que no compilan": False},
    "ANTLR": {"Se ejecuta en el proceso del trabajador": True,
              "Tolera archivos que no compilan": False},
}
SINTACTICO.niveles = {
    "Tree-sitter": {
        "Extensión a otros lenguajes": "Perfil declarativo por lenguaje",
        "Esfuerzo de resolución de llamadores y llamados": "Consulta sobre el árbol",
        "Consumo de recursos": "Bajo",
        "Complejidad de integración": "Ruedas precompiladas",
    },
}


# ═══════════════════════════════════ Capa 4. Marco del servidor

SERVIDOR = Capa(
    nombre="Marcos de trabajo del servidor",
    requisitos=(
        Requisito(
            "Mismo lenguaje que la cadena de análisis",
            "El recuperador de contexto, el adaptador de modelo y el "
            "verificador de anclaje están en Python. Otro lenguaje obligaría a "
            "exportar la cadena a un servicio aparte, con su frontera, su "
            "protocolo y su modo de fallo, sin ganar nada a cambio.",
        ),
    ),
    criterios=(
        Criterio(
            "Validación por esquema del contrato de salida", 30,
            "El contrato de salida del modelo se valida en cada respuesta. Que "
            "el marco lo traiga evita una biblioteca más y un punto de "
            "divergencia entre lo declarado y lo comprobado.",
            (Nivel(100, "Integrada en el marco"),
             Nivel(60, "Por biblioteca añadida"),
             Nivel(40, "Por anotaciones")),
        ),
        Criterio(
            "Ejecución asíncrona nativa", 25,
            "Las consultas al proveedor tardan entre diez y veinticinco "
            "segundos. Sin asincronía, cada una bloquea un hilo entero.",
            (Nivel(100, "Nativa"),
             Nivel(50, "Con extensión"),
             Nivel(0, "No disponible")),
        ),
        Criterio(
            "Tipado del cliente generado desde el esquema", 20,
            "Evita que el cliente y el servicio se desincronicen sin que nada "
            "lo detecte.",
            (Nivel(100, "Generado desde el esquema publicado"),
             Nivel(70, "Compartido por ser el mismo lenguaje"),
             Nivel(0, "Manual")),
        ),
        Criterio(
            "Consumo de memoria por instancia", 10,
            "El despliegue es sobre capa gratuita con memoria acotada.",
            (Nivel(100, "Bajo"), Nivel(50, "Medio"), Nivel(20, "Alto")),
        ),
        Criterio(
            "Estabilidad histórica de la interfaz pública", 15,
            "Un marco joven traslada al proyecto el coste de sus cambios de "
            "interfaz. Se incluye precisamente porque es el criterio en que la "
            "alternativa aventaja a la opción elegida: una tabla donde el "
            "ganador encabeza todo suele significar que la rúbrica se escribió "
            "alrededor de él.",
            (Nivel(100, "Más de una década sin rupturas"),
             Nivel(60, "Varios años, con cambios acotados"),
             Nivel(30, "Menos de cinco años")),
        ),
    ),
    fuente="Documentación de cada marco, consultada el 11 de setiembre del 2026.",
)
SERVIDOR.cumplimiento = {
    "FastAPI": {"Mismo lenguaje que la cadena de análisis": True},
    "Flask": {"Mismo lenguaje que la cadena de análisis": True},
    "NestJS": {"Mismo lenguaje que la cadena de análisis": False},
    "Express": {"Mismo lenguaje que la cadena de análisis": False},
    "Spring Boot": {"Mismo lenguaje que la cadena de análisis": False},
}
SERVIDOR.niveles = {
    "FastAPI": {
        "Validación por esquema del contrato de salida": "Integrada en el marco",
        "Ejecución asíncrona nativa": "Nativa",
        "Tipado del cliente generado desde el esquema": "Generado desde el esquema publicado",
        "Consumo de memoria por instancia": "Bajo",
        "Estabilidad histórica de la interfaz pública": "Varios años, con cambios acotados",
    },
    "Flask": {
        "Validación por esquema del contrato de salida": "Por biblioteca añadida",
        "Ejecución asíncrona nativa": "Con extensión",
        "Tipado del cliente generado desde el esquema": "Manual",
        "Consumo de memoria por instancia": "Bajo",
        "Estabilidad histórica de la interfaz pública": "Más de una década sin rupturas",
    },
}


# ═══════════════════════════════════ Capa 5. Marco del cliente

CLIENTE = Capa(
    nombre="Marcos de trabajo del cliente",
    requisitos=(
        Requisito(
            "Visor de código con marcado de rangos de línea integrable",
            "Sin marcar las líneas que el modelo cita, la verificación de "
            "anclaje deja de ser observable y el experimento pierde su "
            "instrumento de medida.",
        ),
    ),
    criterios=(
        Criterio(
            "Madurez de los visores disponibles", 55,
            "Es la única pieza de interfaz que el proyecto no puede escribir "
            "por su cuenta sin desviar el esfuerzo del objetivo. Sube de 40 a "
            "55 al medir la descarga: el visor y sus gramáticas son el 95.3% de "
            "lo que pesa el cliente construido, y se cargan bajo demanda, de "
            "modo que la decisión sobre el visor gobierna a la vez la calidad "
            "de la lectura y el tamaño de lo que se descarga.",
            (Nivel(100, "Varias opciones maduras"),
             Nivel(60, "Disponible con adaptación"),
             Nivel(20, "Implementación propia")),
        ),
        Criterio(
            "Tipado compartido con el servicio", 25,
            "Los tipos se generan desde el esquema que publica el servicio.",
            (Nivel(100, "Sí"), Nivel(0, "No")),
        ),
        Criterio(
            "Tamaño de la descarga inicial", 5,
            "Pesaba 20 y baja a 5 tras medirlo, no antes. La justificación "
            "original decía que una espera larga se come el tiempo de una "
            "sesión de sesenta minutos. El cliente construido pide 159 KB "
            "comprimidos en el arranque, que sobre banda ancha son unas "
            "décimas de segundo: el 0.004% de la sesión. La premisa no se "
            "sostiene y el peso sobraba. Se deja en 5 porque el tamaño no es "
            "irrelevante, solo mucho menos relevante de lo que se supuso. "
            "Bajarlo no cambia la alternativa seleccionada, solo su margen.",
            (Nivel(100, "Menos de 100 KB comprimidos"),
             Nivel(80, "Entre 100 y 200 KB"),
             Nivel(60, "Entre 200 y 400 KB"),
             Nivel(30, "Más de 400 KB")),
        ),
        Criterio(
            "Madurez del ecosistema", 15,
            "Un componente abandonado a mitad del ciclo es un riesgo del "
            "cronograma.",
            (Nivel(100, "Alta"), Nivel(60, "Media"), Nivel(20, "Baja")),
        ),
    ),
    fuente="Documentación de cada marco y de sus visores, consultada el 11 de "
           "setiembre del 2026.",
)
CLIENTE.cumplimiento = {
    "React": {"Visor de código con marcado de rangos de línea integrable": True},
    "Vue.js": {"Visor de código con marcado de rangos de línea integrable": True},
    "Angular": {"Visor de código con marcado de rangos de línea integrable": True},
    "Svelte": {"Visor de código con marcado de rangos de línea integrable": False},
    "Solid.js": {"Visor de código con marcado de rangos de línea integrable": False},
}
CLIENTE.niveles = {
    "React": {
        "Madurez de los visores disponibles": "Varias opciones maduras",
        "Tipado compartido con el servicio": "Sí",
        "Tamaño de la descarga inicial": "Entre 100 y 200 KB",
        "Madurez del ecosistema": "Alta",
    },
    "Vue.js": {
        "Madurez de los visores disponibles": "Disponible con adaptación",
        "Tipado compartido con el servicio": "Sí",
        "Tamaño de la descarga inicial": "Menos de 100 KB comprimidos",
        "Madurez del ecosistema": "Media",
    },
    "Angular": {
        "Madurez de los visores disponibles": "Disponible con adaptación",
        "Tipado compartido con el servicio": "Sí",
        "Tamaño de la descarga inicial": "Entre 200 y 400 KB",
        "Madurez del ecosistema": "Media",
    },
}


# ═══════════════════════════════════ Capa 6. Motor de persistencia

PERSISTENCIA = Capa(
    nombre="Motores de persistencia",
    requisitos=(
        Requisito(
            "Integridad referencial garantizada por el motor",
            "La cadena experimental encadena participante, sesión, decisión, "
            "hallazgo y veredicto. Dejar esa integridad a cargo de la "
            "aplicación admite datos huérfanos, y un dato huérfano dentro de un "
            "experimento es un resultado que no se puede defender.",
        ),
        Requisito(
            "Servicio gestionado con capa gratuita sin vencimiento",
            "El despliegue del piloto y de la sustentación no dispone de "
            "presupuesto de infraestructura.",
        ),
    ),
    criterios=(
        Criterio(
            "Cola de trabajos sobre el propio motor", 30,
            "Resolverla aquí elimina un componente del despliegue. Cada pieza "
            "que se evita es una menos que desplegar, vigilar y explicar. La "
            "rúbrica distingue tomar el trabajo de enterarse de que lo hay: "
            "sin aviso entre sesiones el trabajador sondea en bucle, lo que "
            "sobre una capa gratuita con cómputo medido no es gratis.",
            (Nivel(100, "Toma con bloqueo de fila y aviso entre sesiones"),
             Nivel(70, "Toma con bloqueo de fila, sin aviso entre sesiones"),
             Nivel(0, "Exige un servicio de cola aparte")),
        ),
        Criterio(
            "Ajuste al dato de forma variable", 25,
            "La salida SARIF y la respuesta íntegra del modelo cambian de forma "
            "según el proveedor. Imponerles un esquema fijo obligaría a migrar "
            "con cada cambio ajeno.",
            (Nivel(100, "Columnas documentales con índice"),
             Nivel(80, "Documentos anidados"),
             Nivel(50, "Tipo documental sin índice")),
        ),
        Criterio(
            "Agregación para las métricas del experimento", 20,
            "La matriz de confusión por modelo, repetición y categoría se "
            "calcula sobre la base.",
            (Nivel(100, "Consultas declarativas completas"),
             Nivel(70, "Suficiente"),
             Nivel(30, "Limitada")),
        ),
        Criterio(
            "Componentes que añade al despliegue", 10,
            "El despliegue completo debe caber en capa gratuita.",
            (Nivel(100, "Ninguno"), Nivel(50, "Uno"), Nivel(20, "Dos")),
        ),
        Criterio(
            "Consulta de alcanzabilidad sobre el grafo de llamadas", 15,
            "El techo de este criterio lo marca un motor de grafos y no el "
            "candidato elegido. Se conserva justamente por eso: deja a la vista "
            "en qué cede la opción seleccionada, y evita una tabla en la que el "
            "ganador encabece todas las filas.",
            (Nivel(100, "Recorrido de relaciones nativo"),
             Nivel(60, "Consulta recursiva"),
             Nivel(20, "Sin soporte")),
        ),
    ),
    fuente="Documentación de cada motor y de sus servicios gestionados, "
           "consultada el 11 de setiembre del 2026.",
)
PERSISTENCIA.cumplimiento = {
    "PostgreSQL con JSONB": {
        "Integridad referencial garantizada por el motor": True,
        "Servicio gestionado con capa gratuita sin vencimiento": True},
    "MySQL": {
        "Integridad referencial garantizada por el motor": True,
        "Servicio gestionado con capa gratuita sin vencimiento": True},
    "MongoDB": {
        "Integridad referencial garantizada por el motor": False,
        "Servicio gestionado con capa gratuita sin vencimiento": True},
    "Neo4j": {
        "Integridad referencial garantizada por el motor": True,
        "Servicio gestionado con capa gratuita sin vencimiento": False},
    "SQLite": {
        "Integridad referencial garantizada por el motor": True,
        "Servicio gestionado con capa gratuita sin vencimiento": False},
}
PERSISTENCIA.niveles = {
    "PostgreSQL con JSONB": {
        "Cola de trabajos sobre el propio motor": "Toma con bloqueo de fila y aviso entre sesiones",
        "Ajuste al dato de forma variable": "Columnas documentales con índice",
        "Agregación para las métricas del experimento": "Consultas declarativas completas",
        "Componentes que añade al despliegue": "Ninguno",
        "Consulta de alcanzabilidad sobre el grafo de llamadas": "Consulta recursiva",
    },
    "MySQL": {
        "Cola de trabajos sobre el propio motor": "Toma con bloqueo de fila, sin aviso entre sesiones",
        "Ajuste al dato de forma variable": "Tipo documental sin índice",
        "Agregación para las métricas del experimento": "Suficiente",
        "Componentes que añade al despliegue": "Uno",
        "Consulta de alcanzabilidad sobre el grafo de llamadas": "Consulta recursiva",
    },
}



# ═══════════════════════════════ Los hechos que resuelven cada requisito
#
# No se escribe "Sí" ni "No": se escribe el dato que lo decide. Un sí no se
# puede discutir; un hecho sí, y esa es la diferencia entre una tabla que se
# defiende y una que se cree.

ANALIZADOR.hechos = {
    "Semgrep OSS": {
        "Opera sobre código privado sin licencia comercial": "Sin costo, sin restricción de repositorio",
        "Emite SARIF 2.1.0 de manera nativa": "Nativo, --sarif",
        "Analiza sin compilar el proyecto": "Opera sobre el fuente",
    },
    "SonarQube Community": {
        "Opera sobre código privado sin licencia comercial": "Sin costo",
        "Emite SARIF 2.1.0 de manera nativa": "No, exige extracción de la interfaz",
        "Analiza sin compilar el proyecto": "Opera sobre el fuente",
    },
    "CodeQL": {
        "Opera sobre código privado sin licencia comercial": "Gratuito solo en repositorios públicos",
        "Emite SARIF 2.1.0 de manera nativa": "Nativo, es su formato de origen",
        "Analiza sin compilar el proyecto": "Exige construir la base de datos",
    },
    "Snyk Code": {
        "Opera sobre código privado sin licencia comercial": "Plan gratuito con tope mensual",
        "Emite SARIF 2.1.0 de manera nativa": "Nativo",
        "Analiza sin compilar el proyecto": "Opera sobre el fuente",
    },
    "SpotBugs con FindSecBugs": {
        "Opera sobre código privado sin licencia comercial": "Sin costo",
        "Emite SARIF 2.1.0 de manera nativa": "No, exige complemento de conversión",
        "Analiza sin compilar el proyecto": "Opera sobre bytecode",
    },
}

SINTACTICO.hechos = {
    "Tree-sitter": {
        "Se ejecuta en el proceso del trabajador": "Ruedas precompiladas, sin proceso auxiliar",
        "Tolera archivos que no compilan": "Recuperación ante error, árbol parcial",
    },
    "JavaParser": {
        "Se ejecuta en el proceso del trabajador": "Exige máquina virtual de Java",
        "Tolera archivos que no compilan": "Tolerancia media",
    },
    "Eclipse JDT Core": {
        "Se ejecuta en el proceso del trabajador": "Exige máquina virtual de Java",
        "Tolera archivos que no compilan": "Tolerancia media",
    },
    "Spoon": {
        "Se ejecuta en el proceso del trabajador": "Exige máquina virtual de Java",
        "Tolera archivos que no compilan": "Exige código que compile",
    },
    "ANTLR": {
        "Se ejecuta en el proceso del trabajador": "Destino generado, sin proceso auxiliar",
        "Tolera archivos que no compilan": "Falla ante entrada no conforme",
    },
}

SERVIDOR.hechos = {
    "FastAPI": {"Mismo lenguaje que la cadena de análisis": "Python, igual que la cadena"},
    "Flask": {"Mismo lenguaje que la cadena de análisis": "Python, igual que la cadena"},
    "NestJS": {"Mismo lenguaje que la cadena de análisis": "TypeScript, exige exportar la cadena"},
    "Express": {"Mismo lenguaje que la cadena de análisis": "JavaScript, exige exportar la cadena"},
    "Spring Boot": {"Mismo lenguaje que la cadena de análisis": "Java, exige exportar la cadena"},
}

CLIENTE.hechos = {
    "React": {"Visor de código con marcado de rangos de línea integrable": "Varios visores con marcado admitido"},
    "Vue.js": {"Visor de código con marcado de rangos de línea integrable": "Disponible, requiere adaptación"},
    "Angular": {"Visor de código con marcado de rangos de línea integrable": "Disponible, requiere adaptación"},
    "Svelte": {"Visor de código con marcado de rangos de línea integrable": "Exige implementación propia"},
    "Solid.js": {"Visor de código con marcado de rangos de línea integrable": "Exige implementación propia"},
}

PERSISTENCIA.hechos = {
    "PostgreSQL con JSONB": {
        "Integridad referencial garantizada por el motor": "Claves foráneas del motor",
        "Servicio gestionado con capa gratuita sin vencimiento": "Neon, sin vencimiento",
    },
    "MySQL": {
        "Integridad referencial garantizada por el motor": "Claves foráneas del motor",
        "Servicio gestionado con capa gratuita sin vencimiento": "Disponible",
    },
    "MongoDB": {
        "Integridad referencial garantizada por el motor": "A cargo de la aplicación",
        "Servicio gestionado con capa gratuita sin vencimiento": "Disponible",
    },
    "Neo4j": {
        "Integridad referencial garantizada por el motor": "Relaciones del motor",
        "Servicio gestionado con capa gratuita sin vencimiento": "Con límite de nodos",
    },
    "SQLite": {
        "Integridad referencial garantizada por el motor": "Claves foráneas del motor",
        "Servicio gestionado con capa gratuita sin vencimiento": "No aplica, es de archivo",
    },
}


# ═══════════════════ Puntuación de los candidatos que un requisito deja fuera
#
# Se puntúan igual que los demás, y la razón no es de forma. Una tabla que solo
# puntúa a los supervivientes deja al lector sin saber si el eliminado cayó por
# el requisito o por ser peor en todo. Puntuarlo entero separa las dos cosas:
# CodeQL alcanza el nivel máximo en profundidad de análisis y cae por licencia;
# NestJS obtiene 71 y cae por lenguaje. El filtro hace un trabajo visible, que
# es justo lo que una decisión de arquitectura tiene que poder mostrar.
#
# El total del eliminado no compite: la columna de decisión lo dice. Se publica
# para que la eliminación quede expuesta a discusión y no escondida.

ANALIZADOR.niveles.update({
    # Community Edition no incluye el seguimiento de contaminación, que en ese
    # producto pertenece a las ediciones de pago.
    "SonarQube Community": {
        "Alcance del seguimiento de contaminación": "Por patrones, sin seguimiento",
        "Configurabilidad y auditabilidad de reglas": "Perfiles configurables sobre catálogo fijo",
        "Ausencia de tope de uso": "Sin tope",
        "Invocación apta para integración continua": "Servidor propio o complemento de construcción",
    },
    # El más capaz del conjunto en lo que mide el criterio de mayor peso. Cae
    # por licencia, no por capacidad, y la tabla debe dejarlo ver.
    "CodeQL": {
        "Alcance del seguimiento de contaminación": "Interprocedural entre archivos",
        "Configurabilidad y auditabilidad de reglas": "Lenguaje de consulta propio",
        "Ausencia de tope de uso": "Sin plan gratuito",
        "Invocación apta para integración continua": "Línea de órdenes con cuenta",
    },
    "SpotBugs con FindSecBugs": {
        "Alcance del seguimiento de contaminación": "Dentro del archivo",
        "Configurabilidad y auditabilidad de reglas": "Perfiles configurables sobre catálogo fijo",
        "Ausencia de tope de uso": "Sin tope",
        "Invocación apta para integración continua": "Servidor propio o complemento de construcción",
    },
})

SINTACTICO.niveles.update({
    "JavaParser": {
        "Extensión a otros lenguajes": "Atado a un solo lenguaje",
        "Esfuerzo de resolución de llamadores y llamados": "Consulta sobre el árbol",
        "Consumo de recursos": "Medio",
        "Complejidad de integración": "Proceso auxiliar",
    },
    # Resuelve enlaces y jerarquía de llamadas de fábrica, que es el máximo del
    # criterio, y lo paga en consumo y en integración.
    "Eclipse JDT Core": {
        "Extensión a otros lenguajes": "Atado a un solo lenguaje",
        "Esfuerzo de resolución de llamadores y llamados": "Grafo de llamadas incorporado",
        "Consumo de recursos": "Alto",
        "Complejidad de integración": "Proceso auxiliar",
    },
    "Spoon": {
        "Extensión a otros lenguajes": "Atado a un solo lenguaje",
        "Esfuerzo de resolución de llamadores y llamados": "Grafo de llamadas incorporado",
        "Consumo de recursos": "Alto",
        "Complejidad de integración": "Proceso auxiliar",
    },
    "ANTLR": {
        "Extensión a otros lenguajes": "Gramática propia por lenguaje",
        "Esfuerzo de resolución de llamadores y llamados": "Implementación propia desde cero",
        "Consumo de recursos": "Bajo",
        "Complejidad de integración": "Generación previa",
    },
})

SERVIDOR.niveles.update({
    "NestJS": {
        "Validación por esquema del contrato de salida": "Por anotaciones",
        "Ejecución asíncrona nativa": "Nativa",
        "Tipado del cliente generado desde el esquema": "Generado desde el esquema publicado",
        "Consumo de memoria por instancia": "Medio",
        "Estabilidad histórica de la interfaz pública": "Varios años, con cambios acotados",
    },
    "Express": {
        "Validación por esquema del contrato de salida": "Por biblioteca añadida",
        "Ejecución asíncrona nativa": "Nativa",
        "Tipado del cliente generado desde el esquema": "Manual",
        "Consumo de memoria por instancia": "Bajo",
        "Estabilidad histórica de la interfaz pública": "Más de una década sin rupturas",
    },
    # La asincronía no es nativa del modelo servlet: exige el marco reactivo.
    "Spring Boot": {
        "Validación por esquema del contrato de salida": "Por anotaciones",
        "Ejecución asíncrona nativa": "Con extensión",
        "Tipado del cliente generado desde el esquema": "Generado desde el esquema publicado",
        "Consumo de memoria por instancia": "Alto",
        "Estabilidad histórica de la interfaz pública": "Más de una década sin rupturas",
    },
})

CLIENTE.niveles.update({
    "Svelte": {
        "Madurez de los visores disponibles": "Implementación propia",
        "Tipado compartido con el servicio": "Sí",
        "Tamaño de la descarga inicial": "Menos de 100 KB comprimidos",
        "Madurez del ecosistema": "Media",
    },
    "Solid.js": {
        "Madurez de los visores disponibles": "Implementación propia",
        "Tipado compartido con el servicio": "Sí",
        "Tamaño de la descarga inicial": "Menos de 100 KB comprimidos",
        "Madurez del ecosistema": "Baja",
    },
})

PERSISTENCIA.niveles.update({
    # Toma el trabajo de forma atómica y avisa por flujo de cambios, de modo
    # que en la cola no cede nada. Cae por integridad referencial, que es un
    # requisito y no admite compensación.
    "MongoDB": {
        "Cola de trabajos sobre el propio motor": "Toma con bloqueo de fila y aviso entre sesiones",
        "Ajuste al dato de forma variable": "Columnas documentales con índice",
        "Agregación para las métricas del experimento": "Suficiente",
        "Componentes que añade al despliegue": "Ninguno",
        "Consulta de alcanzabilidad sobre el grafo de llamadas": "Consulta recursiva",
    },
    "Neo4j": {
        "Cola de trabajos sobre el propio motor": "Exige un servicio de cola aparte",
        "Ajuste al dato de forma variable": "Tipo documental sin índice",
        "Agregación para las métricas del experimento": "Suficiente",
        "Componentes que añade al despliegue": "Ninguno",
        "Consulta de alcanzabilidad sobre el grafo de llamadas": "Recorrido de relaciones nativo",
    },
    # Un solo escritor: la toma concurrente de trabajos no tiene solución en el
    # motor.
    "SQLite": {
        "Cola de trabajos sobre el propio motor": "Exige un servicio de cola aparte",
        "Ajuste al dato de forma variable": "Tipo documental sin índice",
        "Agregación para las métricas del experimento": "Consultas declarativas completas",
        "Componentes que añade al despliegue": "Ninguno",
        "Consulta de alcanzabilidad sobre el grafo de llamadas": "Consulta recursiva",
    },
})


CAPAS = (ANALIZADOR, MODELO, SINTACTICO, SERVIDOR, CLIENTE, PERSISTENCIA)


# ═══════════════════════════════════ Etiquetas breves para la exposición
#
# El nombre largo de un criterio es el que se defiende en el documento, porque
# ahí se lee despacio y cada palabra hace falta. En una diapositiva ese mismo
# nombre no cabe en el encabezado de una columna, y recortarlo por caracteres
# parte palabras a la mitad: "Tipado del cliente generad". Se declara entonces
# una etiqueta breve por criterio, escrita a propósito, que dice lo mismo en
# menos. El documento sigue usando el nombre largo; solo cambia la diapositiva.

ETIQUETAS_CORTAS = {
    "Alcance del seguimiento de contaminación": "Alcance del rastreo",
    "Configurabilidad y auditabilidad de reglas": "Reglas auditables",
    "Ausencia de tope de uso": "Sin tope de uso",
    "Invocación apta para integración continua": "Invocación automatizable",
    "Costo por 100 hallazgos": "Costo por 100 hallazgos",
    "Régimen de ejecución": "Régimen de ejecución",
    "Ventana de contexto": "Ventana de contexto",
    "Anclaje del identificador de versión": "Anclaje de versión",
    "Extensión a otros lenguajes": "Extensión a otros lenguajes",
    "Esfuerzo de resolución de llamadores y llamados": "Llamadores y llamados",
    "Consumo de recursos": "Consumo de recursos",
    "Complejidad de integración": "Complejidad de integración",
    "Validación por esquema del contrato de salida": "Validación por esquema",
    "Ejecución asíncrona nativa": "Ejecución asíncrona",
    "Tipado del cliente generado desde el esquema": "Tipado del cliente",
    "Consumo de memoria por instancia": "Memoria por instancia",
    "Estabilidad histórica de la interfaz pública": "Estabilidad de la interfaz",
    "Madurez de los visores disponibles": "Madurez de los visores",
    "Tipado compartido con el servicio": "Tipado compartido",
    "Tamaño de la descarga inicial": "Descarga inicial",
    "Madurez del ecosistema": "Madurez del ecosistema",
    "Cola de trabajos sobre el propio motor": "Cola en el propio motor",
    "Ajuste al dato de forma variable": "Dato de forma variable",
    "Agregación para las métricas del experimento": "Agregación de métricas",
    "Componentes que añade al despliegue": "Componentes añadidos",
    "Consulta de alcanzabilidad sobre el grafo de llamadas": "Alcanzabilidad del grafo",
}


def etiqueta(criterio: Criterio) -> str:
    """Nombre breve del criterio para el encabezado de una columna.

    Falla si el criterio no tiene etiqueta declarada, en lugar de devolver el
    nombre largo. Un respaldo silencioso volvería a colar en la diapositiva el
    encabezado que no cabe, y el defecto solo se vería al exportar la imagen.
    """
    try:
        return ETIQUETAS_CORTAS[criterio.nombre]
    except KeyError:
        raise KeyError(
            f"El criterio {criterio.nombre!r} no tiene etiqueta breve declarada "
            f"en ETIQUETAS_CORTAS"
        ) from None



# ═══════ Forma breve de los requisitos y de los hechos
#
# El documento usa el nombre entero del requisito y el hecho entero, porque se
# lee despacio y cada matiz cuenta. En una diapositiva esa misma celda mide
# pulgada y media: el nombre largo se parte a media palabra y el hecho largo
# empuja el alto de la fila hasta sacar la tabla de la lámina.
#
# Se declara entonces una forma breve, escrita a propósito, que dice lo mismo
# en menos. Ninguna sustituye a la otra: el documento sigue con la larga.

ETIQUETAS_REQUISITOS = {
    "Opera sobre código privado sin licencia comercial": "Código privado sin licencia",
    "Emite SARIF 2.1.0 de manera nativa": "SARIF 2.1.0 nativo",
    "Analiza sin compilar el proyecto": "Analiza sin compilar",
    "Contrato de salida validable por esquema": "Salida validable por esquema",
    "Temperatura fijable en cero": "Temperatura fijable en cero",
    "Ventana suficiente para la consulta": "Ventana suficiente",
    "Identificador de versión anclable": "Versión anclable",
    "Se ejecuta en el proceso del trabajador": "En el proceso del trabajador",
    "Tolera archivos que no compilan": "Tolera código que no compila",
    "Mismo lenguaje que la cadena de análisis": "Mismo lenguaje que la cadena",
    "Visor de código con marcado de rangos de línea integrable": "Visor con marcado de líneas",
    "Integridad referencial garantizada por el motor": "Integridad en el motor",
    "Servicio gestionado con capa gratuita sin vencimiento": "Capa gratuita sin vencimiento",
}

ANALIZADOR.hechos_breves = {
    "Semgrep OSS": {
        "Opera sobre código privado sin licencia comercial": "Sin costo ni restricción",
        "Emite SARIF 2.1.0 de manera nativa": "Nativo",
        "Analiza sin compilar el proyecto": "Sobre el fuente",
    },
    "SonarQube Community": {
        "Opera sobre código privado sin licencia comercial": "Sin costo",
        "Emite SARIF 2.1.0 de manera nativa": "Exige extraer de la interfaz",
        "Analiza sin compilar el proyecto": "Sobre el fuente",
    },
    "CodeQL": {
        "Opera sobre código privado sin licencia comercial": "Solo repositorios públicos",
        "Emite SARIF 2.1.0 de manera nativa": "Nativo, es su formato",
        "Analiza sin compilar el proyecto": "Exige construir la base",
    },
    "Snyk Code": {
        "Opera sobre código privado sin licencia comercial": "Tope mensual gratuito",
        "Emite SARIF 2.1.0 de manera nativa": "Nativo",
        "Analiza sin compilar el proyecto": "Sobre el fuente",
    },
    "SpotBugs con FindSecBugs": {
        "Opera sobre código privado sin licencia comercial": "Sin costo",
        "Emite SARIF 2.1.0 de manera nativa": "Exige conversor",
        "Analiza sin compilar el proyecto": "Sobre bytecode",
    },
}

SINTACTICO.hechos_breves = {
    "Tree-sitter": {
        "Se ejecuta en el proceso del trabajador": "Ruedas precompiladas",
        "Tolera archivos que no compilan": "Árbol parcial ante error",
    },
    "JavaParser": {
        "Se ejecuta en el proceso del trabajador": "Exige máquina virtual Java",
        "Tolera archivos que no compilan": "Tolerancia media",
    },
    "Eclipse JDT Core": {
        "Se ejecuta en el proceso del trabajador": "Exige máquina virtual Java",
        "Tolera archivos que no compilan": "Tolerancia media",
    },
    "Spoon": {
        "Se ejecuta en el proceso del trabajador": "Exige máquina virtual Java",
        "Tolera archivos que no compilan": "Exige código que compile",
    },
    "ANTLR": {
        "Se ejecuta en el proceso del trabajador": "Destino generado",
        "Tolera archivos que no compilan": "Falla ante entrada no conforme",
    },
}

SERVIDOR.hechos_breves = {
    "FastAPI": {"Mismo lenguaje que la cadena de análisis": "Python, igual que la cadena"},
    "Flask": {"Mismo lenguaje que la cadena de análisis": "Python, igual que la cadena"},
    "NestJS": {"Mismo lenguaje que la cadena de análisis": "TypeScript, exige exportarla"},
    "Express": {"Mismo lenguaje que la cadena de análisis": "JavaScript, exige exportarla"},
    "Spring Boot": {"Mismo lenguaje que la cadena de análisis": "Java, exige exportarla"},
}

CLIENTE.hechos_breves = {
    "React": {"Visor de código con marcado de rangos de línea integrable": "Varios visores maduros"},
    "Vue.js": {"Visor de código con marcado de rangos de línea integrable": "Disponible con adaptación"},
    "Angular": {"Visor de código con marcado de rangos de línea integrable": "Disponible con adaptación"},
    "Svelte": {"Visor de código con marcado de rangos de línea integrable": "Exige implementación propia"},
    "Solid.js": {"Visor de código con marcado de rangos de línea integrable": "Exige implementación propia"},
}

PERSISTENCIA.hechos_breves = {
    "PostgreSQL con JSONB": {
        "Integridad referencial garantizada por el motor": "Claves foráneas del motor",
        "Servicio gestionado con capa gratuita sin vencimiento": "Neon, sin vencimiento",
    },
    "MySQL": {
        "Integridad referencial garantizada por el motor": "Claves foráneas del motor",
        "Servicio gestionado con capa gratuita sin vencimiento": "Disponible",
    },
    "MongoDB": {
        "Integridad referencial garantizada por el motor": "A cargo de la aplicación",
        "Servicio gestionado con capa gratuita sin vencimiento": "Disponible",
    },
    "Neo4j": {
        "Integridad referencial garantizada por el motor": "Relaciones del motor",
        "Servicio gestionado con capa gratuita sin vencimiento": "Con límite de nodos",
    },
    "SQLite": {
        "Integridad referencial garantizada por el motor": "Claves foráneas del motor",
        "Servicio gestionado con capa gratuita sin vencimiento": "No aplica, es de archivo",
    },
}


def etiqueta_requisito(requisito: Requisito) -> str:
    """Nombre breve del requisito para la primera columna de la diapositiva."""
    try:
        return ETIQUETAS_REQUISITOS[requisito.nombre]
    except KeyError:
        raise KeyError(
            f"El requisito {requisito.nombre!r} no tiene etiqueta breve "
            f"declarada en ETIQUETAS_REQUISITOS"
        ) from None


def informe() -> None:
    """Imprime el cálculo entero, para poder revisarlo sin abrir el documento."""
    for capa in CAPAS:
        print("=" * 78)
        print(capa.nombre.upper())
        print("=" * 78)
        print(f"Fuente: {capa.fuente}\n")

        print("Requisitos eliminatorios")
        for r in capa.requisitos:
            print(f"  · {r.nombre}")
        print()

        vivos = capa.supervivientes()
        for cand in capa.cumplimiento:
            fallos = capa.eliminado_por(cand)
            if fallos:
                print(f"  ELIMINADO  {cand:26s} incumple: {'; '.join(fallos)}")
        print()

        if not capa.criterios:
            print("  Esta capa no se decide por tabla. La resuelve la prueba de")
            print("  concepto del anexo A, porque ningún atributo declarado por")
            print("  el proveedor anticipa el acierto sobre código concreto.")
            print(f"  Superan los requisitos: {len(vivos)} de "
                  f"{len(capa.cumplimiento)}")
            if capa.reglas_de_muestreo:
                print("\n  Reglas que acotan la muestra que se mide")
                for regla in capa.reglas_de_muestreo:
                    print(f"    · {regla.nombre}")
            if capa.finalistas:
                print(f"\n  Finalistas medidos: {', '.join(capa.finalistas)}")
            print()
            continue

        if len(vivos) == 1:
            print(f"  Sobrevive uno solo: {vivos[0]}. Se puntúa igualmente para")
            print("  dejar constancia de en qué cede, no para simular una carrera.\n")

        for cand in vivos:
            if cand not in capa.niveles:
                continue
            print(f"  {cand}")
            for nombre, peso, puntos, aporte in capa.detalle(cand):
                print(f"     {nombre[:46]:48s} peso {peso:3d}  {puntos:3d} pts  ->{aporte:6.1f}")
            print(f"     {'TOTAL PONDERADO':48s} {capa.total(cand):>22.1f}")
            print()


if __name__ == "__main__":
    informe()
