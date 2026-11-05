# Vulnerabilidades intencionales

Solo para analisis estatico educativo. No ejecutar las funciones vulnerables,
instalar sus dependencias, desplegar Terraform/Kubernetes ni usar esto en produccion.

La fuente estructurada es [expected-findings.json](expected-findings.json).
**Todas las detecciones iniciales estan NOT_RUN**: ninguna se declara detectada.
La evidencia de validacion se conserva en [evidence/validation.json](evidence/validation.json).
Los campos `file` de la matriz son relativos a `lab/` (`path_base`).
Los reportes del motor usan rutas desde la raiz del repositorio: por ejemplo,
`lab/backend/vulnerabilities/sql_injection.py`. Aplicar ese prefijo al comparar.

## SAST

Las funciones no se ejecutan al importar los archivos ni desde los entrypoints.
Las credenciales son ficticias y no autentican contra ningun sistema.

| Escenario / CWE | Archivo y funcion | Riesgo | Regla local Semgrep | Correccion pequena |
|---|---|---|---|---|
| SAST-01 / CWE-89 | [sql_injection.py](../backend/vulnerabilities/sql_injection.py), `vulnerable_sql_lookup` | SQL construido con entrada sin parametrizar | `lab.python.sql-injection` | Placeholders y parametros enlazados |
| SAST-02 / CWE-78 | [command_injection.py](../backend/vulnerabilities/command_injection.py), `vulnerable_shell_command` | Entrada de usuario llega al shell | `lab.python.command-injection` | Argumentos separados y sin shell |
| SAST-03 / CWE-22 | [path_traversal.py](../backend/vulnerabilities/path_traversal.py), `vulnerable_file_read` | Lectura fuera del directorio permitido | `lab.python.path-traversal` | Resolver y verificar confinamiento |
| SAST-04 / CWE-327 | [weak_cryptography.py](../backend/vulnerabilities/weak_cryptography.py), `vulnerable_md5_digest` | MD5 no sirve para almacenar passwords | `lab.python.weak-cryptography` | Argon2id/scrypt con salt individual |
| SAST-05 / CWE-798 | [weak_cryptography.py](../backend/vulnerabilities/weak_cryptography.py), `vulnerable_fictional_password` | Password ficticio embebido | `lab.python.fictional-hardcoded-password` | Inyeccion desde gestor de secretos |
| SAST-06 / CWE-79 | [vulnerabilities.js](../frontend/src/vulnerabilities.js), `vulnerable_inner_html` | Entrada no confiable asignada a `innerHTML` | `lab.javascript.xss` | `textContent` o sanitizador revisado |

### Community Edition frente a reglas locales

Las seis reglas de [semgrep-rules.yaml](semgrep-rules.yaml) son **locales**,
pequenas y especificas para estos ejemplos. No se presentan como reglas oficiales
ni como un analisis de taint completo. Por ejemplo, encontrar `innerHTML` no
demuestra por si solo que exista una fuente explotable.

No se ejecutaron Semgrep ni sus reglas comunitarias: no se conoce aun que
escenarios detecta `p/owasp-top-ten` u otra seleccion comunitaria. Tampoco se ha
validado la aceptacion de las reglas locales por el ejecutable Semgrep.
No se afirma que una regla comunitaria haya fallado.

El pipeline central usa **Snyk Code**, no Semgrep CE. No interpreta este archivo
de reglas locales. Snyk y Semgrep pueden discrepar en CWE, alcance, taint,
credenciales evidentemente ficticias y funciones sin entrypoints HTTP.
El uso de Snyk puede enviar el codigo de este lab al servicio externo.

## SCA: seis CVE verificados

Fuente de severidad y CVSS: GitHub Security Advisories, consultado el 2026-11-05.
No son severidades observadas en una ejecucion de Trivy.

| Escenario | CVE / paquete | Version sembrada | Primera corregida para ese CVE | Severidad / CVSS | Fuente oficial |
|---|---|---|---|---|---|
| SCA-PY-01 | CVE-2024-35195 / requests | 2.31.0 | 2.32.0 | MEDIUM / 5.6 | [GHSA-9wx4-h78v-vm56](https://github.com/advisories/GHSA-9wx4-h78v-vm56) |
| SCA-PY-02 | CVE-2021-33503 / urllib3 | 1.26.4 | 1.26.5 | HIGH / 7.5 | [GHSA-q2q7-5pp4-w6pg](https://github.com/advisories/GHSA-q2q7-5pp4-w6pg) |
| SCA-PY-03 | CVE-2020-14343 / PyYAML | 5.3.1 | 5.4 | CRITICAL / 9.8 | [GHSA-8q59-q68h-6hv4](https://github.com/advisories/GHSA-8q59-q68h-6hv4) |
| SCA-JS-01 | CVE-2021-23337 / lodash | 4.17.20 | 4.17.21 | HIGH / 7.2 | [GHSA-35jh-r3h4-6jhm](https://github.com/advisories/GHSA-35jh-r3h4-6jhm) |
| SCA-JS-02 | CVE-2021-44906 / minimist | 1.2.5 | 1.2.6 | CRITICAL / 9.8 | [GHSA-xvch-5gv4-984h](https://github.com/advisories/GHSA-xvch-5gv4-984h) |
| SCA-JS-03 | CVE-2020-11022 / jquery | 3.4.1 | 3.5.0 | MEDIUM / 6.9 | [GHSA-gxr4-xjj5-5px2](https://github.com/advisories/GHSA-gxr4-xjj5-5px2) |

Los pins Python estan en [requirements.txt](../backend/requirements.txt).
Las tres dependencias npm estan en [package.json](../frontend/package.json) y
[package-lock.json](../frontend/package-lock.json). No tienen dependencias
transitivas segun los metadatos de esas versiones en el registro oficial.
El lock v3 incluye URLs e integridades SHA-512 obtenidas del registro npm;
no se descargaron sus tarballs ni se instalo ningun paquete vulnerable.

Estos CVE y rangos son reales, pero su presencia/deteccion con **la base actual
de Trivy sigue sin comprobarse** porque Trivy no esta disponible.
Los minimos corregidos no son recomendaciones de seguridad global: algunas
versiones antiguas estan retiradas o tienen otros CVE. Para remediar, elegir una
version mantenida compatible y repetir el escaneo completo.

## IaC: escenarios esperados

| Escenario | Archivo | Configuracion intencional | Correccion |
|---|---|---|---|
| IAC-TF-01 | [security_groups.tf](../infrastructure/terraform/security_groups.tf) | Default SG abierto a todo Internet, SSH y egress ilimitado | SG dedicado, puertos y CIDR minimos |
| IAC-TF-02 | [storage.tf](../infrastructure/terraform/storage.tf) | Bloqueo de ACL publicas desactivado | Habilitar bloqueos y quitar ACL publica |
| IAC-TF-03 | [storage.tf](../infrastructure/terraform/storage.tf) | Bloqueo de politicas publicas desactivado | Habilitar los cuatro controles de acceso publico |
| IAC-TF-04 | [storage.tf](../infrastructure/terraform/storage.tf) | ACL publica y `s3:GetObject` anonimo | Bucket privado y principals especificos |
| IAC-TF-05 | [storage.tf](../infrastructure/terraform/storage.tf) | EBS con `encrypted=false` | Cifrado con clave apropiada |
| IAC-K8S-01 | [deployment.yaml](../infrastructure/kubernetes/deployment.yaml) | Contenedor privilegiado | `privileged: false` |
| IAC-K8S-02 | [deployment.yaml](../infrastructure/kubernetes/deployment.yaml) | UID 0 | UID no cero y `runAsNonRoot: true` |
| IAC-K8S-03 | [rbac.yaml](../infrastructure/kubernetes/rbac.yaml) | ClusterRole con comodines | Role namespaced y privilegios minimos |
| IAC-K8S-04 | [deployment.yaml](../infrastructure/kubernetes/deployment.yaml) | Escalada de privilegios habilitada | `allowPrivilegeEscalation: false` |
| IAC-K8S-05 | [deployment.yaml](../infrastructure/kubernetes/deployment.yaml) | Root filesystem escribible | `readOnlyRootFilesystem: true` |
| IAC-K8S-06 | [deployment.yaml](../infrastructure/kubernetes/deployment.yaml) | Capabilities `ALL`, sin drop | Drop `ALL`, adiciones justificadas |
| IAC-K8S-07 | [deployment.yaml](../infrastructure/kubernetes/deployment.yaml) | Sin requests/limits | Presupuestos CPU/memoria adecuados |
| IAC-K8S-08 | [deployment.yaml](../infrastructure/kubernetes/deployment.yaml) | Token de cuenta de servicio innecesario | Desactivar automount |
| IAC-DOCKER-01/03 | [backend](../backend/Dockerfile) / [frontend](../frontend/Dockerfile) | Sin `USER` no-root | Usuario no privilegiado |
| IAC-DOCKER-02/04 | [backend](../backend/Dockerfile) / [frontend](../frontend/Dockerfile) | Sin `HEALTHCHECK` | Control significativo en servicios persistentes |

Los IDs AWS-0107, AWS-0086, AWS-0087, AWS-0026, KSV-0017, KSV-0012,
KSV-0105, KSV-0003, KSV-0022, DS-0002 y DS-0026 se verificaron en metadatos
oficiales de [trivy-checks](https://github.com/aquasecurity/trivy-checks/tree/main/checks).
Sus formas con prefijo `AVD-` son candidatos de correlacion, no resultados.
Los identificadores `LAB-*` son propios del laboratorio y **no** IDs oficiales.
La existencia de un check no demuestra que la version/configuracion del runner
lo ejecute ni que detecte este archivo.

La falta de `HEALTHCHECK` es un control de hardening, no necesariamente una
vulnerabilidad explotable; estos contenedores imprimen un banner y terminan.
No se crean Service, Ingress, Namespace ni puertos publicados.
El RBAC se limita a una cuenta ficticia del namespace del lab, no a usuarios anonimos.

S3 no declara un recurso SSE propio. Esto **no significa que AWS almacenaria los
objetos sin cifrar**: AWS aplica SSE-S3 por defecto desde 2023. El escenario
inequivoco de cifrado deshabilitado es el volumen EBS; la ausencia de una politica
explicita S3/KMS puede generar hallazgos adicionales segun el perfil.

## Como distinguir esperado de observado

- `NOT_RUN`: no se ejecuto el escaner o esa cobertura; no significa no detectado.
- `DETECTED`: existe un resultado real vinculado a escenario, archivo y regla/CVE.
- `NOT_DETECTED`: ejecucion completada con alcance compatible, sin coincidencia.
- `SCAN_FAILED`: fallo tecnico; no interpretar como resultado limpio.

Conservar fecha, version del escaner, version/fecha de DB, configuracion de reglas,
SHA del commit, comando, codigo de salida y JSON/SARIF originales. Para reglas
comunitarias, guardar el ID realmente emitido; no sustituirlo por el ID local.
Un resultado debe corresponder al archivo y al CVE/CWE/check, no solo al conteo.
Para SCA, comparar tambien paquete y version. Registrar hallazgos extra aparte.

La desaparicion de un hallazgo tras un cambio es **NOT_DETECTED**, no prueba
automatica de remediacion: comprobar que la cobertura y herramientas no cambiaron.
El baseline del motor central permite comparar sin reimplementar su Risk Engine.
