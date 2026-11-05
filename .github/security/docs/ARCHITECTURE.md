# Arquitectura GitHub Actions

## Entradas y limites de confianza

`ci.yml` escucha todos los pushes sin filtros, pull requests y dispatch. Llama al
workflow reutilizable con permisos `contents: read`. Las herramientas se instalan
exclusivamente en el runner Ubuntu 24.04, directamente en el bloque `run` del
workflow; no existe un script instalador independiente. Trivy se instala en el
runner y Snyk se ejecuta en su imagen Docker oficial fijada por digest, siguiendo
el patron de la accion de releases de referencia.

El unico selector de cobertura es `scan-types`: `all` o una combinacion de
`sast`, `iac`, `dependencies`. Su parser compartido produce la matriz de jobs
Trivy/Snyk y controla que escaneres ejecuta el motor. Seleccionar SAST
implica ejecutarlo y exigir su finalizacion, sin opt-ins o controles de exigencia
adicionales. Una seleccion invalida falla explicitamente; no se convierte en `all`.

El token de una cuenta personal Snyk es suficiente como credencial. Sin un
ID/slug explicito, no se pasa `--org` y Snyk utiliza el espacio preferido de la
cuenta; sus Organizations no son organizaciones de GitHub. El adaptador omite
valores de contexto vacios y conserva el error nativo depurado cuando el servicio
rechaza Snyk Code. No modifica permisos, planes ni habilita productos de la cuenta.
El contexto explicito acepta el input `snyk-org`, la Variable `SNYK_ORG` o el
Secret opcional `SNYK_ORG`, en ese orden. El caller transmite ese Secret al
workflow reutilizable y el redactor protege su valor tambien en los artefactos.

El checkout del motor esta separado del checkout `target`. En uso central, el
motor proviene del commit del push o de la base confiable en PR; en uso externo,
el consumidor debe especificar repositorio y SHA completo. Un consumidor no
obtiene automaticamente los scripts del repositorio del workflow llamado.

El objetivo se trata como datos: no se importan sus modulos, ejecutan comandos de
su YAML, instalan dependencias o corren sus builds. Los paths son relativos,
validados y confinados al objetivo. No se siguen symlinks. Se copia el alcance
filtrado a un directorio temporal, excluyendo salidas y politica `.snyk` del
objetivo; Trivy recibe configuracion e ignorefile controlados por el motor.

Snyk usa `docker run --rm`, UID/GID del runner, fuente en `/project:ro` y
reportes en un volumen escribible distinto (`/reports`). El token se pasa por
nombre de variable de entorno, no como valor en argumentos. El entrypoint se
sobrescribe con el binario Snyk para evitar ejecutar builds o instalar dependencias
del repositorio. Los contenedores tienen nombre unico y se eliminan al terminar
o explicitamente si el proceso excede el timeout. No se monta el socket Docker
dentro del contenedor.

## Fases

El DAG de Actions separa `prepare` -> `scan` (matriz paralela) -> `consolidate` ->
`gate`. La preparacion resuelve una sola vez el repositorio y commit confiables
del motor y valida la seleccion. Todos los jobs obtienen ese mismo motor; los
que analizan el objetivo obtienen el mismo `github.sha`. Ninguno ejecuta scripts
descargados como parte de un artefacto.

La matriz incluye solo los tipos seleccionados, con `fail-fast: false`. Cada
worker prepara solo su herramienta y ejecuta `cli.py collect`: inventario y
coleccion, sin normalizacion, consultas de inteligencia ni riesgo. Solo el
worker SAST recibe el token Snyk, con las restricciones de forks y Dependabot.

`consolidate` espera a todos los workers y se ejecuta tambien si alguno falla.
Descarga sus artefactos en carpetas separadas, sin fusion ciega, y ejecuta
`cli.py consolidate`. Verifica hashes e identidad antes de aceptar resultados;
despues normaliza, deduplica, enriquece y publica el informe una sola vez.
`gate` descarga el informe final, verifica su manifiesto y aplica el gate. No
aprueba si la consolidacion o publicacion fallaron.

Los workers usan nombres de artefacto estables y `overwrite: true`: reejecutar
uno reemplaza solo su evidencia. Se admite un intento anterior del mismo run
para conservar resultados de jobs no reejecutados; nunca un intento futuro ni
evidencia de otro run, commit, motor o configuracion. Los hashes no constituyen
una firma ni autentican al productor.

| Script | Responsabilidad |
|---|---|
| `configuration.py` | Merge validado de YAML, rechazo de claves desconocidas/duplicadas y validacion de tipos y paths. |
| `inventory.py` | Lenguajes, manifiestos, candidatos IaC, exclusiones y archivos no evaluados. |
| `scanner_runner.py` | Ejecucion sin shell, timeout, versiones, estados, JSON y SARIF por escaner, logs depurados. |
| `parsers.py`, `normalizer.py` | Validacion de entrada, adaptadores, identidades estables y deduplicacion conservadora. |
| `threat_intelligence.py` | Solo identificadores CVE publicos hacia FIRST/CISA, consultas acotadas y cache con fechas. |
| `risk_engine.py` | Reglas deterministas y explicables, manteniendo severidad/CVSS originales. |
| `baseline_comparator.py` | Comparacion explicita, sin interpretar desaparicion como correccion. |
| `report_generator.py` | Markdown, HTML autocontenido, CSV resistente a formulas y resumen JSON. |
| `copilot_prompt_generator.py` | Handoff de remediacion con todos los IDs y detalle acotado de los prioritarios. |
| `artifact_manifest.py` | Inventario SHA-256 y verificacion de archivos, sin seguir symlinks. |
| `scan_artifacts.py` | Contrato y validacion de evidencia entre workers y consolidacion. |
| `write_actions_summary.py` | Resumen Markdown por etapa y final en `GITHUB_STEP_SUMMARY`, sin modificar el artefacto. |
| `cli.py` | Seleccion, coleccion, consolidacion y gate; conserva el comando integral `scan` y el bloqueo de escaneo local. |

## Estados y fallos

`COMPLETED` indica ejecucion y validacion del documento, no cobertura universal.
`FAILED` indica fallo tecnico; `SKIPPED`, herramienta deshabilitada o sin permisos;
`NOT_APPLICABLE`, sin candidatos compatibles detectados.
Si SAST estaba seleccionado, cualquier estado distinto de COMPLETED impide
aprobar el gate. Esto incluye la falta de secretos en PR de forks o Dependabot;
no se relajan las protecciones de secretos para forzar el analisis.

Un fallo de escaner no evita procesar los otros resultados. JSON de Trivy es
autoritativo para conservar paquetes/versiones; SARIF se valida por separado.
Se preservan metadatos de fallos sin fabricar reportes limpios. Los errores de
procesamiento se muestran y fuerzan fallo del gate. Un fallo de configuracion
produce un informe fallido, no escaneos con valores alternativos silenciosos.

Publicacion, resumen y consolidacion usan `always()`. Una coleccion seleccionada
ausente o invalida se convierte en FAILED, conservando los otros resultados.
Los resumenes separan conteos pendientes/no disponibles de ceros comprobados y
exponen fallos del job aunque el gate guardado indique PASSED. El escritor usa
solo la biblioteca estandar y puede explicar la falta de evidencia incluso si
fallo la instalacion de dependencias del motor. El gate se evalua despues del
artefacto y no confunde ausencia de hallazgos con seguridad verificada.

Un fallo de checkout, Python o instalacion de dependencias puede impedir
construir el informe; Actions conserva el fallo y no se promete un artefacto
completo en esos casos. Si no se obtuvo el motor, el workflow publica un resumen
minimo explicito sin intentar ejecutar codigo del objetivo.

Los hashes detectan cambios, no prueban autenticidad. La retencion configura
cuanto tiempo quedan disponibles los artefactos, que pueden contener evidencia de
codigo del repositorio: debe restringirse el acceso como al propio repositorio.
