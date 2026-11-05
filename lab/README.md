# devsecops-vulnerable-lab

Laboratorio pequeno, **intencionalmente inseguro**, para probar
`ai-powered-devsecops-pipeline`: SAST, SCA e IaC, reportes y remediacion posterior
con Copilot. No es una aplicacion ni debe usarse en produccion.

## Limites de seguridad

- No ejecutar las funciones vulnerables ni instalar sus dependencias.
- No ejecutar `terraform apply`, `kubectl apply` ni desplegar infraestructura.
- No hay endpoints, conexiones a servicios reales ni credenciales reales.
- Los entrypoints solo imprimen un banner; no importan los ejemplos vulnerables.
- Los Dockerfiles copian unicamente esos entrypoints y no instalan dependencias.
- Compose no publica puertos, deshabilita la red y no monta codigo del host.
- No se ha construido ninguna imagen, iniciado contenedor ni creado recurso cloud.

## Contenido

| Ruta | Proposito |
|---|---|
| [backend/vulnerabilities/](backend/vulnerabilities/) | SQL injection, command injection, traversal, MD5 y password ficticio |
| [frontend/src/vulnerabilities.js](frontend/src/vulnerabilities.js) | XSS mediante `innerHTML`, sin invocacion automatica |
| [backend/requirements.txt](backend/requirements.txt) | Tres paquetes Python con CVE verificables |
| [frontend/package-lock.json](frontend/package-lock.json) | Tres paquetes npm con versiones e integridades oficiales |
| [infrastructure/](infrastructure/) | Terraform y Kubernetes inseguros, solo para analisis |
| [security/expected-findings.json](security/expected-findings.json) | Matriz de 29 escenarios esperados, inicialmente NOT_RUN |
| [security/VULNERABILITIES.md](security/VULNERABILITIES.md) | CWE, CVE, fuentes, reglas locales, limites y correcciones |
| [security/evidence/](security/evidence/) | Evidencia real de validaciones y comparacion inicial |

Los Dockerfiles son fixtures de configuracion; las dependencias vulnerables no
estan instaladas en sus imagenes. Un escaneo de imagen no sustituye al SCA de
los manifiestos del repositorio.

## Integracion en este mismo repositorio

El laboratorio vive en `lab/`, dentro de `ai-powered-devsecops-pipeline`.
No tiene un repositorio Git propio y no hay que publicarlo por separado.

1. Publicar **el repositorio actual completo**, incluyendo `lab/`.
2. Si se selecciona SAST, agregar el secreto Actions `SNYK_TOKEN` con acceso a
   Snyk Code. Opcionalmente configurar la variable `SNYK_ORG`.
3. Hacer push: el [workflow activo](../.github/workflows/ci.yml) llama al
   [motor local](../.github/workflows/security-assessment.yml) y escanea el commit
   completo, incluido `lab/`. No necesita referencias a otro repositorio.
4. Descargar el artefacto **security-assessment** desde Actions.

El archivo [security-scan.yml](.github/workflows/security-scan.yml) se conserva
como ejemplo de llamada local. GitHub **no ejecuta workflows anidados** en `lab/`:
solo los de `.github/workflows/` en la raiz. No es necesario copiar el ejemplo,
porque el workflow activo ya cubre el lab; hacerlo duplicaria las ejecuciones.
No se duplica Trivy, SAST ni Risk Engine.

**Importante:** el pipeline actual usa **Snyk Code**, no Semgrep Community
Edition. Los ejemplos y reglas locales permiten evaluar Semgrep por separado,
pero este lab no cambia ni reemplaza el escaner del motor central.

Por defecto, `scan-types: all`. En ejecuciones manuales se pueden elegir
`sast`, `iac`, `dependencies`, `sast,iac`, `sast,dependencies` o `iac,dependencies`.
El valor de respaldo en el workflow activo de la raiz determina el alcance de cada push.
Sin Snyk disponible, elegir `iac,dependencies` para esa demostracion;
esto no constituye una validacion de SAST.

El ejemplo anidado configura `fail-on: P1`; el gate real depende de los inputs
del workflow activo. Los reportes se publican antes del gate. SAST seleccionado
siempre bloquea si no se completa, incluso si faltan secretos.

## Reportes y evidencia

Descargar el artefacto **security-assessment** de Actions en una carpeta fuera
del alcance del siguiente escaneo, por ejemplo `reports/before/` en la raiz.
Contiene JSON/SARIF originales, hallazgos normalizados, riesgo, HTML/Markdown,
CSV, prompt Copilot, comparacion y manifiesto SHA-256.

Comparar los resultados con la matriz usando las reglas de
[VULNERABILITIES.md](security/VULNERABILITIES.md#como-distinguir-esperado-de-observado).
Los nombres nativos son `snyk-sast`, `trivy-sca` y `trivy-iac`.
No asumir que seis CWE equivalen a exactamente seis resultados.
Los campos `file` de la matriz son relativos a `lab/`; los resultados del motor
incluyen ese prefijo, por ejemplo `lab/backend/requirements.txt`. Al escanear todo
el repositorio tambien pueden aparecer hallazgos del propio motor.

Si **ya estan disponibles** Semgrep CE y Trivy en un entorno de analisis
autorizado, estos son comandos manuales opcionales; no instalan paquetes ni
forman otro pipeline. No se han ejecutado aqui:

```bash
cd lab
mkdir -p reports/manual
semgrep --version
semgrep scan --config security/semgrep-rules.yaml --metrics=off \
  --json-output reports/manual/semgrep-local.json \
  --sarif-output reports/manual/semgrep-local.sarif \
  backend/vulnerabilities frontend/src/vulnerabilities.js

trivy --version
trivy fs --scanners vuln --format json --output reports/manual/trivy-sca.json \
  --skip-dirs .git --skip-dirs reports --skip-dirs security/evidence .
trivy convert --format sarif --output reports/manual/trivy-sca.sarif \
  reports/manual/trivy-sca.json
trivy config --format json --output reports/manual/trivy-iac.json \
  --skip-dirs .git --skip-dirs reports --skip-dirs security/evidence .
trivy convert --format sarif --output reports/manual/trivy-iac.sarif \
  reports/manual/trivy-iac.json
```

La compatibilidad exacta de estas opciones depende de las versiones instaladas.
Conservar codigos de salida y logs; no ocultar errores con `|| true`.
El primer uso de Trivy puede descargar su DB/checks en ese entorno.
Las reglas comunitarias son una evaluacion independiente de las reglas locales:
si se usan, conservar tambien su revision/seleccion e IDs reales.

## Demostracion de remediacion

1. Primer push: conservar el artefacto, commit y cobertura como estado **before**.
2. Extraer `COPILOT-REMEDIATION.md` y pedir cambios pequenos sobre escenarios
   concretos. No ejecutar las funciones vulnerables para probar explotaciones.
3. Para SCA, actualizar manifiesto y lock de forma consistente, sin asumir que
   la primera version corregida para un CVE elimina todos los demas.
4. Copiar el `risk/risk-assessment.json` anterior a
   `lab/security/baselines/before.json` si se desea versionar el baseline.
5. Hacer nuevo push para reescanear. Para comparar con el baseline en ejecucion
   manual o en cada push, pasar `baseline: lab/security/baselines/before.json`
   en la llamada al workflow reutilizable desde el workflow activo.
6. Descargar el nuevo artefacto y revisar `comparison/COMPARISON-REPORT.md`,
   diferencias, cobertura y matriz. Un hallazgo no observado no se marca
   automaticamente como corregido.

No hay remediacion, commits ni pushes automaticos.

## Estado comprobado

Consultar [validation.json](security/evidence/validation.json) para los comandos,
resultados y limitaciones de la validacion inicial, **anterior al traslado**.
Sus rutas absolutas y hashes corresponden a aquel snapshot, no a la ubicacion
actual ni a la documentacion actualizada.
[relocation-validation.json](security/evidence/relocation-validation.json)
registra las comprobaciones despues del traslado.
La verificacion de avisos y de la sintaxis
**no prueba deteccion**. No se generaron JSON/SARIF ficticios cuando faltaban
escaneres. La deteccion con la DB actual de Trivy y el primer run GitHub quedan
pendientes.
