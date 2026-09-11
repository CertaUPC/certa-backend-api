# certa-backend-api

Servicio de Certa. Consume los hallazgos que produjo un analizador estático
externo en formato SARIF, recupera del código el contexto necesario para
juzgarlos, consulta a un modelo de lenguaje sobre su explotabilidad, **verifica
que la justificación cite líneas que existen** y presenta el resultado ordenado
sin suprimir nada.

## Estado

Completo y conectado al front.

```
venv\Scripts\python.exe -m pytest       163 pruebas
venv\Scripts\python.exe -m ruff check src tests tools
py tools\check_architecture.py          25 módulos de dominio
py tools\check_all.py                   189 comprobaciones, sin instalar nada
```

Las comprobaciones de `tools/` corren con biblioteca estándar. Nacieron porque
`pip` estuvo bloqueado durante el desarrollo y se quedaron porque sirven para
verificar en una máquina sin entorno preparado.

## Arrancar

```
copy .env.example .env
venv\Scripts\python.exe -m alembic upgrade head
venv\Scripts\python.exe -m uvicorn src.main:app --reload
```

Documentación interactiva en <http://127.0.0.1:8000/docs>.

`REPOSITORY_ROOT` apunta a la carpeta donde vive el código que se analiza, y
las rutas de archivo del SARIF se resuelven contra ella. Esa carpeta no se
versiona: contiene código de terceros.

Arranca **sin proveedor de modelo configurado**: la ingesta y la consulta
funcionan, y lanzar una validación devuelve un error explícito. Así se pueden
revisar ejecuciones pasadas sin exponer una credencial.

## Recorridos

| Método | Ruta | Qué hace |
|---|---|---|
| `POST` | `/api/v1/auth/register` | Alta de usuario con rol |
| `POST` | `/api/v1/auth/login` | Token de acceso |
| `GET` | `/api/v1/projects` | Proyectos con su número de ejecuciones |
| `POST` | `/api/v1/projects` | Crea el proyecto, o devuelve el de esa ruta |
| `POST` | `/api/v1/executions` | Carga un SARIF y crea la ejecución |
| `GET` | `/api/v1/executions` | Lista, con filtro por proyecto |
| `GET` | `/api/v1/executions/{id}` | Estado y avance |
| `POST` | `/api/v1/executions/{id}/run` | Valida los pendientes |
| `POST` | `/api/v1/executions/{id}/resume` | Devuelve a la cola conservando lo validado |
| `GET` | `/api/v1/executions/{id}/findings` | Lista priorizada, con filtros |
| `GET` | `/api/v1/executions/findings/{id}/context` | El contexto exacto que vio el modelo |
| `GET` | `/api/v1/executions/{id}/export` | CSV anónimo para el análisis |
| `POST` | `/api/v1/executions/{id}/purge` | Borra el código, conserva métricas |
| `POST` | `/api/v1/experiment/participants` | Registro y asignación contrabalanceada |
| `GET` | `/api/v1/experiment/participants` | Participantes con su orden asignado |
| `POST` | `/api/v1/experiment/decisions` | Decisión y tiempo |
| `GET` | `/api/v1/experiment/findings/{id}/decisions` | Historial, incluidas las rectificadas |
| `GET` | `/api/v1/experiment/executions/{id}/metrics` | Matriz de confusión y validez de la corrida |
| `GET` | `/health` | Estado del servicio y del proveedor |

## Arquitectura

Diseño guiado por el dominio sobre arquitectura hexagonal, un paquete por
contexto delimitado.

```
src/
  finding_validation/     cadena de análisis: hallazgo, contexto, veredicto
  experimentation/        instrumentación del estudio: participante, decisión
  shared/                 configuración, base, seguridad, traza, control de tasa
```

Cada contexto se organiza igual:

| Capa | Contenido |
|---|---|
| `domain/entities` | Entidades del agregado |
| `domain/value_objects` | Objetos de valor inmutables |
| `domain/repositories` | Interfaces de repositorio |
| `domain/services` | Puertos de salida y servicios de dominio |
| `domain/model/{commands,queries}` | Objetos de comando y de consulta |
| `application/internal/{command,query}services` | Orquestación de casos de uso |
| `infrastructure/{persistence,external}` | Adaptadores concretos |
| `interfaces/{rest,schemas}` | Entrada HTTP |

**La regla que lo sostiene:** el dominio no importa nada de las capas
exteriores. Declara mediante puertos qué necesita del mundo, y la
infraestructura provee la implementación.

No es estética. El proyecto compara clases de modelo de lenguaje entre sí, dos
veces: en la prueba de concepto que elige el modelo y en la evaluación funcional
de la herramienta terminada. Esa comparación solo vale si la lógica sometida a
prueba permanece idéntica al cambiar de proveedor. `tools/check_architecture.py`
recorre el árbol sintáctico de cada módulo del dominio y falla si aparece un
import prohibido; la integración continua lo corre antes que las pruebas.

### Los dos contextos

Se comunican **por identidad, nunca por referencia directa**: `Decision` guarda
el UUID del hallazgo, no el objeto `Finding`. Esa frontera permite retirar la
instrumentación del experimento al terminar la tesis sin tocar la cadena de
análisis, que es el producto.

## La contribución, en código

`domain/services/anchor_verifier.py`. El sistema exige que el modelo cite líneas
concretas del contexto entregado y comprueba que existan. Un modelo que descarta
un hallazgo porque una función se llama `validateInput` no puede sostener esa
conclusión citando la línea donde la validación ocurre, porque esa línea no
existe.

Cuando el anclaje falla, `as_retry_hint()` construye un reintento **dirigido**
que nombra las líneas inexistentes, en lugar de repetir la consulta a ciegas. Si
el segundo intento vuelve a fallar, `resolve_value()` anula el veredicto
propuesto y el hallazgo pasa a `NOT_VERIFIABLE`, que en la priorización
**asciende**. No poder justificar se trata como señal de riesgo, no como prueba
de que no lo haya.

## Cascada de costo

Tres niveles antes de gastar una consulta, en `validate_finding_command_service`:

1. **Reutilización por huella.** Si la huella ya fue resuelta por este modelo y
   versión, se reaprovecha el veredicto. Costo cero.
2. **Filtro determinista.** Si la traza atraviesa un saneador acreditado antes
   del punto sensible, se resuelve por regla. Costo cero, y queda marcado como
   `regla-determinista` para que la medición pueda separarlo del juicio del
   modelo.
3. **Consulta al modelo,** con presupuesto acotado por `BudgetGuard`, que
   detiene el lote al alcanzar el límite conservando lo ya validado.

`BudgetGuard.report()` dice cuántas consultas evitó cada nivel.

## Multilenguaje

**No hay un recorredor por lenguaje.** Hay uno solo,
`TreeSitterCodeReader`, parametrizado por un `LanguageProfile` declarativo.
Incorporar un lenguaje cuesta datos, no código:

```python
PHP = LanguageProfile(
    name="php", extensions=(".php",), grammar_module="tree_sitter_php",
    function_query="(function_definition name: (name) @name) @function",
    call_query="(function_call_expression function: (name) @callee)",
)
```

`CodeReaderRegistry` elige por extensión con tres escalones, y **ninguno falla**:

1. Hay perfil y gramática instalada → árbol sintáctico, contexto completo
2. Hay perfil pero falta la gramática → ventana, y se registra el motivo
3. No hay perfil → ventana

Un hallazgo en PL/SQL o en cualquier otro lenguaje sigue produciendo contexto,
sigue permitiendo citar líneas y sigue verificando el anclaje. Lo que cambia al
declarar un perfil no es **si** Certa puede juzgar, sino la **calidad** del
contexto: sin perfil el modelo ve una ventana; con perfil ve la función
contenedora, sus llamadores y los saneadores.

**El techo real no lo pone Certa, lo pone el analizador.** Si el analizador no
emite hallazgos para un lenguaje, no hay nada que validar por bien resuelto que
esté el contexto.

**Fuera de alcance:** herramientas que no son código fuente, como los flujos de
Apache NiFi. Un flujo se configura en XML con procesadores encadenados; ahí no
hay función contenedora ni llamadores que recuperar.

`java_source_scanner.py` se conserva como respaldo sin dependencias, por conteo
de llaves. Enmascara literales y comentarios antes de contar. Sus límites están
en la constante `LIMITATIONS`.

## Persistencia

Espejo de `certa/arquitectura/modelo-datos`. El mismo motor hace de persistencia
y de cola de trabajos.

`SqlExecutionRepository.claim_next_pending` reclama la ejecución pendiente más
antigua. Sobre PostgreSQL usa bloqueo de fila con `SKIP LOCKED`, de modo que
varios trabajadores avancen en paralelo sin duplicar procesamiento. Sobre otros
motores cae a una actualización condicionada, que da la misma garantía con
contención.

`list_pending_validation` devuelve los hallazgos sin veredicto: es lo que
permite reanudar sin volver a pagar por lo ya validado.

`purge_by_execution` borra el texto del contexto y conserva veredictos y
métricas, que no dependen del contenido del código.

## El proveedor de modelo

`ChatCompletionsLanguageModel` habla el contrato de mensajes compatible con
OpenAI, que es el que exponen casi todos los proveedores comerciales y también
los servidores locales de pesos abiertos. Cambiar de proveedor es cambiar
`LLM_BASE_URL` y `LLM_MODEL`.

Tres reglas que el adaptador hace cumplir:

- **La temperatura debe ser cero.** Se rechaza cualquier otro valor al construir
  el adaptador y al leer la configuración.
- **Una respuesta fuera del contrato es un fallo de la consulta,** no algo que
  se interprete a conveniencia.
- **No todo error se reintenta.** Saturación y fallos de servidor sí, con
  retroceso exponencial. Una credencial inválida o una petición mal formada, no.

La consulta vive en `prompt_builder.py` y se versiona con `PromptVersion`. Esa
versión se persiste junto a cada veredicto.

## Línea de comandos

Para incorporar la validación a la entrega continua sin abrir la aplicación:

```
py -m src.cli analyze ./repo --project "Mi proyecto" --cwe CWE-89
py -m src.cli validate <execution-id>
py -m src.cli check ./repo --fail-on real
```

Códigos de salida pensados para un paso de integración: `0` nada por encima del
umbral, `1` hay hallazgos que lo superan, `2` el análisis o la validación
fallaron.

## Traza

`shared/tracing.py` registra las cuatro etapas de cada hallazgo bajo un
identificador de correlación, que viaja por contexto y no por argumento. Filtrar
por él devuelve la historia completa en orden, sin repetir la ejecución. Nunca
registra código ni credenciales: solo identificadores, duraciones y resultados.

## Comparación entre modelos

`CompareModelsCommandService` corre el mismo lote con varios adaptadores. Entre
corridas solo cambia el proveedor: mismo lote, mismo contexto ya recuperado,
mismo verificador, misma consulta. Cada modelo lleva su propio presupuesto.

`PrepareSessionCommandService` precomputa los veredictos antes de una sesión con
participantes y reparte los hallazgos en dos lotes disjuntos, alternando por
huella para que el reparto sea reproducible.

## Verdad conocida

Un proyecto real no viene etiquetado: si viniera, no haría falta la herramienta.
Los conjuntos de referencia sí, y son los únicos donde se puede medir corrección
funcional sin depender del juicio de nadie.

`OwaspBenchmarkGroundTruth` lee el archivo de resultados esperados del conjunto y
adjunta la etiqueta durante la ingesta. `GROUND_TRUTH_PATH` la activa; vacía en
cualquier despliegue normal.

Etiqueta solo cuando la categoría del hallazgo coincide con la del caso de
prueba. Si el analizador dispara una regla de otra familia sobre el mismo
archivo, el hallazgo queda sin etiqueta: el conjunto no afirma nada al respecto,
y darlo por falso positivo inflaría la exactitud medida.

`tools/poc_baseline.py` mide la línea base del analizador solo, que es contra lo
que hay que competir. No necesita proveedor de modelo.

```
venv\Scripts\python.exe tools\poc_baseline.py ^
    --expected ruta\expectedresults-1.2.csv --sarif salida.sarif
```

El recuento va por caso de prueba y no por hallazgo. Tres reglas disparadas
sobre el mismo archivo son un acierto, no tres; contar hallazgos premiaría a la
herramienta más ruidosa.

## Elegir el modelo

El identificador exacto de un modelo cambia, y escribirlo de memoria produce un
404 a mitad de una corrida. `tools/list_models.py` consulta el catálogo del
proveedor y lista identificador, ventana y precio por millón de tokens.

```
venv\Scripts\python.exe tools\list_models.py --filter claude --filter qwen
venv\Scripts\python.exe tools\list_models.py --filter claude --csv modelos.csv
```

Con `--csv` deja el listado en disco. El benchmarking del objetivo primero
compara clases de modelo, y esa comparación necesita el precio y la ventana
vigentes el día en que se midió, no los que uno recuerde.

Cambiar de modelo es cambiar `LLM_BASE_URL` y `LLM_MODEL`. Si hiciera falta
tocar el dominio, la comparación entre modelos no sería válida, y por eso
`tools/check_architecture.py` falla cuando el dominio importa un adaptador.

## Migraciones

```
venv\Scripts\python.exe -m alembic upgrade head
venv\Scripts\python.exe -m alembic revision --autogenerate -m "descripción"
```

`migrations/env.py` toma la dirección de la base del entorno y no del archivo de
configuración, de modo que la credencial de producción nunca quede versionada.

## Integración continua

`certa/.github/workflows/ci.yml` corre en cada empujón y en cada propuesta de cambio:
regla de dependencia, `ruff`, pruebas con cobertura, comprobaciones sin
dependencias, y compilación del front. Un empujón nuevo cancela la verificación
anterior de la misma rama.

## Despliegue

`render.yaml` describe el servicio en capa gratuita, con `JWT_SECRET` generado
por la plataforma y las credenciales del proveedor marcadas para carga manual.
La comprobación de salud apunta a `/health`. La migración corre en el paso de
construcción: con `DEBUG` en falso el servicio no crea tablas por su cuenta, de
modo que sin ese paso la base quedaría vacía en el primer despliegue.

La versión de Python se fija en `.python-version`. Render no lee `runtime.txt`,
y su valor por omisión para los servicios nuevos va por delante del que se
prueba aquí.

La cadena de conexión de un Postgres gestionado se pega tal cual: viene en
formato libpq, con el controlador síncrono y con `sslmode`, y `create_engine` la
adapta sola antes de construir el motor.

## Entorno

```
py -m venv venv
venv\Scripts\python.exe -m pip install -r requirements-dev.txt
venv\Scripts\python.exe -m pytest
```

Si `pip` falla con `CERTIFICATE_VERIFY_FAILED`, es Kaspersky interceptando TLS
con su propia raíz. La solución está aplicada en esta máquina: la raíz se
exportó y se combinó con el paquete de certificados de Python en
`C:\Users\Chizo\.certs\ca-bundle-kaspersky.pem`, y `PIP_CERT` apunta ahí. Eso
mantiene la verificación activa en lugar de desactivarla.
