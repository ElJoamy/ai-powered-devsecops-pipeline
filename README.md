# AI-powered DevSecOps Pipeline

Pipeline para **GitHub Actions** que analiza **este mismo repositorio en cada
push de cualquier rama**, ademas de pull requests y ejecuciones manuales.
No hay filtros de rutas o ramas en el workflow principal.

Toda la implementacion del motor vive en `.github/`. No es una aplicacion Python ni
requiere instalar paquetes, contenedores o escaneres en tu computadora.
La instalacion esta definida directamente en el `run` del workflow, sin un
script instalador separado. El comando de escaneo rechaza la ejecucion fuera de Actions.

## Activarlo en este repositorio

1. Publica estos archivos en el repositorio de GitHub con Actions habilitado.
2. Haz un push: [ci.yml](.github/workflows/ci.yml) ejecutara el workflow
   [security-assessment.yml](.github/workflows/security-assessment.yml).
3. En **Actions**, abre la ejecucion y revisa **Summary**. Descarga
   **security-assessment** para consultar el detalle completo.

Cada etapa que procesa el objetivo hace dos checkouts separados: motor confiable
y repositorio objetivo. El gate solo descarga el informe y obtiene el motor.
Analiza el commit del evento de este repositorio, incluido el laboratorio `lab/`.
No instala ni ejecuta dependencias, scripts de construccion o codigo del objetivo.
No remedia, hace commits ni pushes automaticamente.

## Laboratorio incluido

[lab/](lab/) contiene los ejemplos intencionalmente vulnerables para probar el
pipeline: seis CWE, seis CVE verificados y configuraciones Terraform, Kubernetes
y Docker inseguras. Es una carpeta de este mismo repositorio, no otro proyecto
Git ni un repositorio remoto separado.

El workflow principal ya analiza estos archivos en cada push, sin cambiar el
selector `scan-types: all`. Solo necesitas el secreto `SNYK_TOKEN` para SAST;
no debes configurar otro repositorio del motor. Puede haber hallazgos del motor
ademas de los del lab.

Consulta [lab/README.md](lab/README.md),
[la matriz de escenarios](lab/security/expected-findings.json) y
[la evidencia disponible](lab/security/evidence/relocation-validation.json).
No ejecutes las funciones vulnerables ni despliegues la infraestructura.

## Elegir que analizar

Solo se declara `scan-types`; no hay interruptores adicionales para habilitar o
exigir SAST. Los pushes ejecutan `all` por defecto. Para cambiar el alcance
automatico, ajusta el valor de respaldo en la llamada de
[ci.yml](.github/workflows/ci.yml). En ejecuciones manuales se elige en un menu.

| `scan-types` | Analisis |
|---|---|
| `all` | SAST + IaC + dependencias |
| `sast` | Solo codigo con Snyk Code |
| `iac` | Solo infraestructura con Trivy |
| `dependencies` | Solo dependencias (SCA) con Trivy |
| `sast,iac` | Codigo e infraestructura |
| `sast,dependencies` | Codigo y dependencias |
| `iac,dependencies` | Infraestructura y dependencias |

Ejemplo de llamada al workflow reutilizable:

```yaml
with:
  scan-types: sast,iac
```

Solo se preparan las herramientas necesarias. Los analisis no seleccionados
quedan SKIPPED con su motivo; no se crean jobs para ellos. La misma validacion de
seleccion controla la matriz de jobs y el motor de escaneo.

### Snyk Code para analizar codigo fuente

Como en la accion de releases de referencia, el runner hace `docker pull` y
ejecuta Snyk Code con `docker run --rm`, no instala el CLI Snyk en el host.
La imagen oficial `snyk/snyk:linux` se fija por digest. La fuente filtrada se
monta en `/project` en solo lectura y los resultados en `/reports`, por separado.
Se invoca directamente el ejecutable Snyk para evitar los builds o instalaciones
automaticas del entrypoint de la imagen. Trivy se prepara en el runner y genera
JSON una vez; SARIF se obtiene con `trivy convert`.

No se utiliza Semgrep. Al seleccionar `sast` o `all`, Snyk Code se ejecuta
automaticamente sin variables de activacion o confirmaciones adicionales:

1. En **Settings > Secrets and variables > Actions**, agrega el secreto
   **SNYK_TOKEN** de tu cuenta Snyk.
   Puede ser el token de tu **cuenta personal**; no necesitas una organizacion
   de GitHub.
2. Para la cuenta personal, basta ese token: el CLI usa el espacio preferido
   configurado en tu cuenta Snyk. Snyk llama **Organization** a ese espacio,
   incluso en cuentas personales. Debe tener **Snyk Code habilitado**.
3. Solo si deseas cambiar de espacio, configura **SNYK_ORG** como Secret o Variable, o el
   input `snyk-org` con su ID/slug de **Snyk**, no con tu usuario de GitHub.
   Dejalo sin configurar para usar el espacio preferido.
   Precedencia: input `snyk-org`, Variable `SNYK_ORG`, Secret `SNYK_ORG`.
   Si ya guardaste token y espacio en Secrets, ahora ambos se transmiten al motor.

SAST seleccionado siempre debe completarse para aprobar el gate. Sin token,
SAST aparece como **SKIPPED** por autenticacion ausente, los reportes se publican
y el gate falla: nunca se interpreta como un analisis limpio. Si SAST no esta
seleccionado, no se requiere token y su omision no bloquea el gate.
Snyk Code requiere cuenta, autenticacion, disponibilidad y los permisos/limites
del plan contratado; no se promete SAST gratuito o sin servicio externo.
Seleccionar SAST implica procesamiento externo del codigo por Snyk. Los PR de
forks y Dependabot no reciben el secreto; si tienen SAST seleccionado, su
cobertura incompleta tambien bloquea el gate.

Si aparece `Snyk Code is not supported for your current organization`, el CLI
esta rechazando la disponibilidad de Snyk Code para el espacio usado. Revisar
**Settings > Snyk Code** dentro de Snyk para ese mismo espacio. Si ya esta habilitado
en el espacio que ves en la web, seleccionar ese espacio con `SNYK_ORG`: puede
diferir del preferido de la cuenta del token. No usar el nombre de usuario de
GitHub como ID de espacio Snyk. El nombre
vacio en ese mensaje no demuestra que falle la resolucion del espacio: tambien
aparece cuando se usa el preferido sin pasar `--org`. El gate conserva el error
real y esta orientacion; no lo sustituye por un resultado limpio. Activar esa
funcion de la cuenta Snyk no puede hacerse modificando un workflow de GitHub.

## Flujo y artefactos

El workflow tiene etapas independientes, no un unico job:

```text
Preparacion y seleccion
        |
        +--> SAST / Snyk Code -----+
        +--> Dependencias / Trivy -+--> Consolidacion y reportes --> Gate final
        +--> IaC / Trivy ----------+
             en paralelo
```

La matriz contiene solo los escaneos seleccionados y usa `fail-fast: false`:
un fallo de Snyk no cancela Trivy. Cada runner inventaria y recoge evidencia,
sin calcular riesgo ni generar el reporte final. La consolidacion verifica los
artefactos, valida JSON/SARIF, normaliza y deduplica; despues consulta EPSS/KEV,
calcula prioridad, compara el baseline y genera reportes y prompt Copilot.
El gate se ejecuta en otro job, despues de publicar y verificar el manifiesto.

### Resumen visible en Actions

Cada escaner publica su estado, version, motivo y enlace a su evidencia en
`GITHUB_STEP_SUMMARY`. Sus conteos permanecen pendientes hasta la consolidacion.
El resumen consolidado muestra commit y alcance, integridad, hallazgos por
severidad y prioridad, estado por escaner, hallazgos prioritarios, motivos del
gate y enlace de descarga. El job final muestra tambien el resultado del gate.

Un escaneo fallido o sin evidencia se muestra como fallo o no disponible,
**nunca como cero vulnerabilidades**. Una etapa fallida no presenta un estado
verde aunque un informe previo indique que el umbral de riesgo permitiria pasar.

Los artefactos intermedios se llaman **security-scan-sast**,
**security-scan-dependencies** y **security-scan-iac**, segun la seleccion.
Incluyen resultados originales, diagnosticos, identidad de coleccion y hashes;
no sustituyen al informe final. La consolidacion rechaza resultados de otro
commit, ejecucion, motor o configuracion y registra los artefactos ausentes como
fallos. Reejecutar jobs fallidos reemplaza su evidencia y permite reutilizar la
de los jobs completados del mismo run, sin mezclar otras ejecuciones.

El artefacto **security-assessment** contiene:

```text
raw/                           JSON y SARIF originales de escaneres completados
logs/                          Diagnosticos depurados
metadata/project-inventory.json
metadata/execution.json
metadata/scanners.json
metadata/phases.json
metadata/gate.json
normalized/normalized-findings.json
risk/risk-assessment.json
comparison/findings-diff.json
comparison/COMPARISON-REPORT.md
SECURITY-REPORT.md
SECURITY-REPORT.html            Autocontenido; sin JavaScript o recursos externos
findings.csv
summary.json
COPILOT-REMEDIATION.md
manifest.json
```

Los escaneres fallidos u omitidos no generan archivos vacios que aparenten
resultados limpios. Sus estados y motivos quedan en los metadatos. Los errores
tecnicos no se ocultan con `|| true`: publicacion, resumen y consolidacion usan
`always()`, y el gate se ejecuta despues. Si falla la instalacion de escaneres,
se intenta igualmente recoger diagnosticos y generar un informe. Un fallo de
checkout o preparacion del motor puede impedir producir evidencia; se muestra
explicitamente y no se promete un artefacto completo en ese caso.

## Configuracion

Los valores iniciales estan en
[default.yaml](.github/security/config/default.yaml) y la politica en
[risk-policy.yaml](.github/security/config/risk-policy.yaml).
El workflow actual ya funciona con estos valores; no necesita copiar ejemplos.

Para personalizarlo, crea un YAML en el repositorio y pasa su ruta al input
`config` de la llamada de [ci.yml](.github/workflows/ci.yml). Consulta
[consumer-config.yaml](.github/security/examples/consumer-config.yaml).
`scan.types` permite declarar la seleccion en la configuracion del motor; el input
`scan-types` pasado por el workflow siempre tiene precedencia sobre ese YAML.

Los inputs permiten seleccionar los analisis, excluir rutas, elegir politica,
pasar un baseline, definir retencion y gate. `fail-on: P1` bloquea P0 y P1;
el valor vacio no bloquea por hallazgos, pero si por errores tecnicos por defecto.
La falta de un SAST seleccionado siempre bloquea, independientemente de los
umbrales de hallazgos. `REVIEW` bloquea tambien cualquier hallazgo que requiera revision.

## Reutilizar desde otro repositorio

Copia y adapta [consumer-workflow.yml](.github/security/examples/consumer-workflow.yml):
reemplaza organizacion/repositorio y los dos marcadores por **el mismo commit
completo, revisado e inmutable del motor**. No uses una rama mutable para obtener
los scripts centrales. El repositorio central debe ser publico o accesible para
el token del consumidor; el `GITHUB_TOKEN` normal no concede acceso a otros
repositorios privados por defecto.

## Alcance y limites

- Las versiones estan fijadas: Trivy **0.74.0**, imagen oficial Snyk **por digest**,
  Actions por SHA completo y dependencias directas Python por version exacta.
  Trivy se verifica contra checksums publicados. La version efectiva del CLI
  Snyk dentro del contenedor y el digest quedan en los metadatos. Las bases de
  vulnerabilidades y las reglas distribuidas por los servicios pueden cambiar.
- SCA no instala dependencias del objetivo. Sin lockfiles, o cuando el escaner
  necesita artefactos compilados, la cobertura transitiva puede ser parcial.
- Trivy se aplica a formatos IaC compatibles. El YAML de GitHub Actions y otros
  archivos no soportados se registran **NOT_ASSESSED**, no seguros.
- No se afirma alcanzabilidad, explotabilidad ni remediacion por ausencia de evidencia.
- EPSS/KEV sin conectividad son desconocidos, no valores negativos.
- No se crean pruebas unitarias ni proyectos de prueba adicionales al laboratorio
  solicitado en `lab/`. La validacion E2E real queda en el runner, no en tu maquina.

Mas informacion:
[arquitectura](.github/security/docs/ARCHITECTURE.md),
[referencias inspeccionadas](.github/security/docs/EXISTING_IMPLEMENTATION_ANALYSIS.md),
[riesgo](.github/security/docs/RISK-METHODOLOGY.md),
[formatos](.github/security/docs/REPORT-SCHEMA.md),
[validacion real](.github/security/docs/VALIDATION.md).

..... Test