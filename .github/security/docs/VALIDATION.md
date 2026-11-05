# Validacion y evidencia

## Restricciones de esta entrega

- No se crearon pruebas unitarias. El laboratorio solicitado posteriormente vive
  en `lab/`, dentro del repositorio objetivo y bajo el mismo escaneo de cada push.
  Su evidencia inicial y la validacion del traslado estan en `lab/security/evidence/`.
- No se instalaron paquetes en el sistema ni en el entorno conda.
- Se retiraron los binarios descargados temporalmente dentro del workspace.
- No se ejecutaron escaneres contra el repositorio en esta computadora.
- Python usado para comprobaciones de sintaxis/configuracion y graphify:
  entorno conda existente `security`.

## Comprobaciones ejecutadas

- Parseo AST e importacion de los scripts del motor.
- Comprobacion de esquemas JSON y de la politica de riesgo por defecto.
- Carga del YAML de configuracion e inventario de solo lectura del proyecto real.
- Lectura de workflows YAML y verificacion de que `push` no tiene filtros.
- Resolucion de las siete combinaciones de SAST/IaC/dependencias sin lanzar escaneres.
- Reproduccion en memoria del error real de Snyk Code y comprobacion de que se
  conserva depurado en el gate. Cuenta personal sin `--org`, override explicito,
  diagnosticos no JSON y codigos 0/1 sin cambios; sin ejecutar Snyk localmente.
- Contrato de paso del Secret opcional `SNYK_ORG` y precedencia de input/Variable/Secret;
  contexto personal preferido sin override y redaccion del identificador configurado.
- `bash -n` sobre los bloques `run` del workflow, sin ejecutar sus comandos.
- CLI rechaza un intento local de `scan` antes de crear salidas o lanzar escaneres.
- SHAs de Actions y versiones de Trivy/Snyk verificados en repositorios publicos.
- Digest de la imagen oficial Snyk verificado via metadatos publicos del registro,
  sin descargar ni ejecutar la imagen en esta computadora.
- Esquemas de los workflows de caller, motor por etapas y ejemplo consumidor.
- DAG `prepare` -> matriz `scan` -> `consolidate` -> `gate`, con
  `fail-fast: false`, herramientas aisladas y descarga sin fusion de metadatos.
- Sintaxis Bash de los 15 bloques `run` del workflow por etapas.
- Contrato de referencias SHA confiables en todos los jobs, aislamiento del
  token al worker SAST, publicacion ante fallos y reemplazo de artefactos en
  reintentos. SHA de `actions/download-artifact` verificado contra su tag oficial.
- Reproduccion de `collect` -> `consolidate` -> `gate` para las siete selecciones
  con resultados nativos de un run anterior, sustituyendo la ejecucion de
  escaneres por lectura de esa evidencia: 22 hallazgos SCA y 42 IaC, sin lanzar
  herramientas ni consultar inteligencia online. No es un escaneo del codigo actual.
- Consolidacion sin invocar escaneres, reutilizacion de un intento anterior del
  mismo run y fallo del gate cuando el SAST seleccionado no se completo.
- Ausencia y alteracion de un artefacto IaC: FAILED explicito, gate bloqueado y
  conservacion de los 22 hallazgos SCA validos.
- Contrato de coleccion: rechazo de 26 variantes invalidas de identidad, rutas,
  manifiestos, configuracion y registros; funciones nuevas menores de 50 lineas.
- Resumen con los 64 hallazgos historicos y conteos exactos de severidad/prioridad;
  salida de coleccion pendiente, datos ausentes/corruptos, redaccion/escape,
  estado de job fallido/cancelado y ejecucion con `python -S`, sin site packages.
- Sintaxis compatible con Python 3.12 y bloqueo local de `scan`, `collect` y
  `consolidate`, sin crear salidas ni ejecutar escaneres.

Estas comprobaciones no equivalen a haber completado un escaneo ni a haber
medido cobertura de pruebas. No se declara cobertura unitaria.

## Verificacion E2E pendiente en GitHub Actions

1. Publicar los archivos y hacer un push al repositorio actual.
2. Comprobar que la ejecucion usa el SHA del push y que instala solo en el runner.
3. Configurar el secreto Snyk si `scan-types` incluye SAST; con `all` se requiere
   por defecto. Seleccionar SAST no requiere activar variables adicionales.
4. Verificar que los escaneos seleccionados aparecen como jobs independientes
   y se ejecutan en paralelo. Revisar **Summary** y los enlaces a evidencia.
   Descargar `security-assessment`; abrir HTML y revisar estados por escaner.
5. Verificar JSON/SARIF de escaneres completados, inventario, riesgo, prompt,
   comparacion y manifiesto. Si no existen archivos IaC compatibles, IaC debe
   indicar NOT_APPLICABLE; el YAML de Actions no debe aparecer como seguro.
6. Confirmar que el gate se evalua despues de subir artefactos y falla si hubo
   errores tecnicos o se supero el umbral configurado.
7. Para baseline, proporcionar explicitamente el JSON de una ejecucion anterior
   dentro del repositorio y configurar el input `baseline`.
8. Repetir con las siete selecciones. Solo deben crearse los workers seleccionados.
   Provocar un fallo de SAST: Trivy debe continuar y la consolidacion debe publicar
   su evidencia valida junto al error SAST. No interpretar fallos como ceros.
9. Reejecutar jobs fallidos y comprobar reemplazo de su artefacto, conservacion
   de los workers no reejecutados del mismo run y rechazo de identidades distintas.

Se inspecciono evidencia real del run `42063295848`: Trivy SCA e IaC completaron,
pero Snyk Code fallo. Esa evidencia es anterior a la correccion del paso de
`SNYK_ORG` y a la division en jobs; no demuestra que esos cambios ya hayan
pasado en Actions. No se hizo commit/push automatico ni se ejecuto remotamente
la nueva orquestacion. Su validacion E2E sigue pendiente de publicar los cambios.
