# Analisis de implementaciones existentes

Se inspeccionaron las tres referencias de Seagull en modo de solo lectura:
`gcr-deploy/scripts`, `gcr-deploy/action_for_releases/action.yaml` y
`gcr-deploy/action_for_releases/scripts`, bajo su carpeta de composite workflows.
No se modificaron ni se copiaron credenciales, URLs internas o datos privados.

## Componentes observados

| Componente | Funcion y patrones relevantes |
|---|---|
| `scripts/trivy_scan.py` | Escanea CycloneDX con `trivy sbom --format json`; deriva SARIF con `trivy convert`. Distingue resultados completos y fallidos. Corrige metadatos de SO para evitar escaneos ciegos de paquetes del sistema. |
| `action_for_releases/action.yaml` | Composite de releases con modos imagen/codigo, credenciales via inputs/env y artefactos separados. Snyk usa `snyk code test`, `--org` y `--sarif-file-output`. |
| `scripts/parse_sarif_thresholds.py` | Lectura SARIF, reglas, niveles, `security-severity`, conteo y excepciones. |
| `scripts/check_thresholds.sh` | Aplica umbrales y configuracion, pero admite paso vacuo si no hay SARIF. No se reutiliza ese comportamiento. |
| `action_for_releases/scripts/write_release_summary.py` | Agrega estados de artefactos y hallazgos, diferencia imagen/codigo y resultados no disponibles. |
| Otros scripts enumerados | Consolidacion, SBOM, comentarios y publicacion externa; no necesarios para este alcance y sin trasladar sus integraciones privadas. |

## Reutilizado como patron

- Un escaneo Trivy JSON y conversion SARIF, sin dos consultas de base por formato.
- Separacion de resultados por herramienta y disciplina de estados.
- Identidad de ejecucion, hashes y conservacion de artefactos.
- Autenticacion Snyk por entorno; organizacion opcional y sin tokens en argumentos.
- Resumen Markdown de ejecucion con tablas de estado y hallazgos, publicado en
  `GITHUB_STEP_SUMMARY` como en `write_release_summary.py`.

## Adaptado

El origen analiza imagenes/SBOM de releases. Este pipeline analiza el filesystem
del repositorio del evento: `trivy fs --scanners vuln` para SCA y `trivy config`
para IaC. No necesita registro de contenedores, infraestructura cloud, DefectDojo,
S3, claves de aplicaciones o mapas de productos.

Se conserva el patron de la referencia: `docker pull` y `docker run --rm` para
Snyk Code, credenciales via entorno, `--org` opcional y exportaciones independientes.
La referencia usa una imagen Docker mutable y tolera el codigo de salida con
`|| true`. Aqui se fija el digest de la imagen, se distinguen los codigos 0/1/2/3
y se validan los documentos; Trivy se prepara en el runner con checksum.
La fuente se monta en solo lectura y la salida en otro volumen. Se sobrescribe
el entrypoint de la imagen para invocar directamente `/usr/local/bin/snyk`:
el entrypoint general del proveedor puede instalar dependencias del objetivo y
reconstruir argumentos mediante shell, algo que no necesita un analisis SAST.
Un JSON/SARIF ausente, invalido o fallido no se cuenta como cero hallazgos.
No se traslada la suposicion de que un gate sin reportes debe aprobar.
El resumen muestra los motivos de fallo y distingue resultados pendientes,
no disponibles y completados. La coleccion paralela se consolida una sola vez;
no se trasladan las integraciones de releases o publicacion externa.

## Nuevo

Inventario multitecnologia, staging filtrado sin modificar fuente, configuracion
validada, seleccion explicita de SAST/IaC/dependencias, esquema comun, fingerprints,
EPSS/KEV, riesgo separado de CVSS, informes, prompt dinamico Copilot,
baseline explicito y workflow reutilizable con checkout separado del motor.

Las decisiones son adaptaciones tecnicas, no una copia de codigo privado.
El escaneo de SO/SBOM de imagenes queda fuera del alcance de este primer pipeline
de repositorio; no se afirma cobertura de paquetes del sistema de una imagen.
