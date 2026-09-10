# Cómo se trabaja en este repositorio

## Ramas

Se sigue git flow. Dos ramas viven siempre:

| Rama | Qué contiene |
|---|---|
| `main` | Lo desplegado. Solo recibe fusiones desde `release/*` o `hotfix/*`, y cada fusión lleva etiqueta de versión. |
| `develop` | La integración. De aquí salen las ramas de trabajo y aquí vuelven. |

Y tres tipos de rama temporal:

| Prefijo | Sale de | Vuelve a | Para qué |
|---|---|---|---|
| `feature/<nombre>` | `develop` | `develop` | Una historia de usuario o una parte de ella |
| `release/<versión>` | `develop` | `main` y `develop` | Cierre de sprint: se congela, se corrige y se etiqueta |
| `hotfix/<nombre>` | `main` | `main` y `develop` | Un fallo en lo desplegado que no puede esperar |

El nombre de la rama de trabajo lleva la historia del backlog cuando corresponde
a una: `feature/us012-verificacion-de-anclaje`.

Nada entra a `develop` sin que la verificación pase. La regla de dependencia se
comprueba antes que las pruebas: si el dominio importara infraestructura, la
comparación entre modelos del objetivo específico cuarto dejaría de ser válida
aunque todas las pruebas pasaran.

## Mensajes de commit

Se sigue Conventional Commits. La primera línea, en minúscula y sin punto final,
no pasa de 72 caracteres:

```
<tipo>(<alcance>): <qué hace, en imperativo>

<por qué, si no es evidente. Líneas de 72 caracteres.>

Refs: US012
```

Tipos admitidos:

| Tipo | Cuándo |
|---|---|
| `feat` | Comportamiento nuevo que un usuario nota |
| `fix` | Corrección de un defecto |
| `refactor` | Cambia la forma, no el comportamiento |
| `perf` | Mejora de rendimiento |
| `test` | Pruebas, sin tocar el código de producción |
| `docs` | Documentación |
| `build` | Dependencias, empaquetado, migraciones de esquema |
| `ci` | Integración continua |
| `chore` | Tareas que no encajan arriba |

Alcances de este repositorio: `domain`, `application`, `infrastructure`,
`interfaces`, `shared`, `cli`, `tools`, `migrations`.

Un cambio que rompa el contrato lleva `!` tras el alcance y una línea
`BREAKING CHANGE:` al final explicando qué se rompe y qué hacer.

Ejemplos:

```
feat(domain): verificar que las líneas citadas existan en el contexto
fix(infrastructure): reclamar la ejecución antes de procesarla por la API
refactor(infrastructure): un solo recorredor parametrizado por lenguaje
test(domain): casos límite del verificador de anclaje
```

El commit describe el cambio y nada más: sin firmas de herramientas ni
coautorías automáticas.

## Antes de proponer un cambio

```
venv\Scripts\python.exe -m ruff check src tests tools
py tools\check_architecture.py
venv\Scripts\python.exe -m pytest
py tools\check_all.py
```

Las cuatro corren también en la integración continua, en ese orden.

## Código

Identificadores y nombres de carpeta en inglés. Comentarios, docstrings y
mensajes de error en español. El comentario explica por qué, no qué: si hace
falta para entender qué hace la línea, el problema es la línea.
