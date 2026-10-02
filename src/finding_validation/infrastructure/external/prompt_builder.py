"""La consulta que se le envía al modelo.

Está en infraestructura porque es la forma de hablar con un proveedor, no una
regla. Se versiona con `PromptVersion` y esa versión se guarda con cada
veredicto.
"""

from ...domain.entities.code_context import CodeContext
from ...domain.entities.finding import Finding
from ...domain.value_objects.prompt_version import OUTPUT_CONTRACT_V1, PromptVersion

SYSTEM_PROMPT = """Eres un analista de seguridad de aplicaciones. Recibes un \
hallazgo que produjo una herramienta de análisis estático y un fragmento de \
código numerado por líneas. Tu tarea es determinar si el hallazgo corresponde a \
una vulnerabilidad realmente explotable.

Reglas que debes cumplir sin excepción:

1. Juzga ÚNICAMENTE con el fragmento que se te entrega. No supongas la \
existencia de validaciones, saneadores ni controles que no aparezcan en él.
2. Toda conclusión debe apoyarse en líneas concretas del fragmento. Cita sus \
números en el campo cited_lines.
3. Cita solo líneas que existan en el fragmento entregado. Una cita a una línea \
ausente invalida tu respuesta completa.
4. Si el fragmento no alcanza para decidir, responde "indeterminado" en lugar de \
adivinar. Es una respuesta legítima y preferible a una conclusión sin respaldo.
5. El nombre de una función no prueba lo que hace. Si una función se llama \
validarEntrada pero su cuerpo no aparece, no puedes afirmar que valide.
6. La regla 5 rige en los dos sentidos. El fragmento incluye el cuerpo de las \
funciones llamadas que figuran en «Llamados incluidos»: búscalo y resuélvelo \
antes de declarar que falta. Afirmar que un cuerpo no aparece cuando sí está \
entregado es tan grave como suponer un saneamiento inexistente, y convierte un \
"indeterminado" en una respuesta sin respaldo.

Responde exclusivamente con un objeto JSON que cumpla este contrato:
{contract}
"""

USER_TEMPLATE = """HALLAZGO
Regla: {rule_id}
Categoría: {cwe}
Severidad declarada por la regla: {severity}
Ubicación: {location}
Mensaje de la herramienta: {message}

CONTEXTO RECUPERADO
Función contenedora: {enclosing}
Llamadores incluidos: {callers}
Llamados incluidos, con su cuerpo entero: {callees}
Funciones cuyo nombre sugiere saneamiento: {sanitizers}
{degraded}
Líneas disponibles: {line_range}

CÓDIGO
{code}
"""

RETRY_TEMPLATE = """{base}

CORRECCIÓN REQUERIDA
{hint}
"""

_CONTRACT_TEXT = "\n".join(f'  "{k}": {v}' for k, v in OUTPUT_CONTRACT_V1.items())

CURRENT_VERSION = PromptVersion.of(
    "v2", SYSTEM_PROMPT + USER_TEMPLATE, OUTPUT_CONTRACT_V1
)


def system_prompt() -> str:
    return SYSTEM_PROMPT.format(contract="{\n" + _CONTRACT_TEXT + "\n}")


def line_ranges(lineas: list[int]) -> str:
    """Las líneas disponibles por tramos, en vez de por sus extremos.

    Antes se anunciaba «32 a 74» y dentro de ese intervalo faltaban la 37 y la
    62, que son las líneas en blanco entre un método y el siguiente. La regla 3
    invalida la respuesta que cite una línea ausente, de modo que el rango
    prometía dos líneas que nadie entregó.
    """
    if not lineas:
        return "ninguna"
    tramos: list[list[int]] = []
    for n in lineas:
        if tramos and n == tramos[-1][1] + 1:
            tramos[-1][1] = n
        else:
            tramos.append([n, n])
    return ", ".join(
        str(a) if a == b else f"{a}-{b}" for a, b in tramos
    )


def build_user_prompt(
    finding: Finding, context: CodeContext, retry_hint: str | None = None
) -> str:
    lineas = sorted(context.available_lines)
    degraded = (
        "AVISO: el contexto se recuperó de forma degradada. No fue posible "
        "identificar la función contenedora, de modo que se entrega una ventana "
        "de código alrededor del hallazgo. Ténlo en cuenta al decidir si la "
        "información alcanza.\n"
        if context.degraded_to_file
        else ""
    )
    base = USER_TEMPLATE.format(
        rule_id=finding.rule_id,
        cwe=finding.cwe or "no declarada",
        severity=finding.severity,
        location=str(finding.location),
        message=finding.message or "sin mensaje",
        enclosing=context.enclosing_function,
        callers=", ".join(context.callers) or "ninguno",
        # El recuperador ya pegaba estos cuerpos en el código y el inventario no
        # los nombraba. El modelo leía «Llamadores incluidos: doGet», no veía
        # mención del llamado y declaraba ausente un cuerpo que tenía delante:
        # once de los veinticuatro hallazgos del lote del estudio salieron así.
        callees=", ".join(context.callees) or "ninguno",
        sanitizers=", ".join(context.sanitizers) or "ninguna",
        degraded=degraded,
        line_range=line_ranges(lineas),
        code=context.text,
    )
    if retry_hint:
        return RETRY_TEMPLATE.format(base=base, hint=retry_hint)
    return base
