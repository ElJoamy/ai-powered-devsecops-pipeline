# Changelog

## Unreleased

- Workflow por etapas: preparacion, escaneres seleccionados en paralelo,
  consolidacion de resultados y gate final independiente.
- Evidencia aislada por escaner con manifiesto e identidad de ejecucion,
  configuracion y motor; deteccion explicita de resultados ausentes o invalidos.
- Resumenes visibles en GitHub Actions con estados, severidades, prioridades,
  motivos del gate y enlaces a los artefactos, incluso ante fallos parciales.
- Reejecucion de jobs fallidos sin colisiones de artefactos ni cancelacion de
  escaneres independientes; normalizacion e inteligencia centralizadas.

## 0.1.0 - 2026-11-05

- Pipeline GitHub Actions en cada push, pull request y ejecucion manual.
- Motor dentro de `.github/security/`, sin paquete de aplicacion en `src/`.
- Snyk Code SAST con autorizacion explicita; Trivy SCA e IaC.
- Inventario, validacion, normalizacion, riesgo EPSS/KEV, reportes y prompt Copilot.
- Workflow reutilizable, comparacion explicita con baseline y manifiesto SHA-256.
- Instalacion y ejecucion de escaneres limitadas al runner de Actions.
- Instalacion definida directamente en el workflow, sin script instalador separado.
- Snyk Code en Docker como en la accion de releases, con digest fijado, fuente de
  solo lectura y reportes separados; Trivy permanece en el runner.
- Selector unico `scan-types` para las siete combinaciones SAST/IaC/dependencias;
  todo por defecto y SAST siempre exigido cuando se selecciona.
- Sin pruebas unitarias.
- Laboratorio vulnerable integrado en `lab/`, escaneado como parte del repositorio
  actual en cada push, con matriz de 29 escenarios y evidencia de validacion.
- Contexto Snyk personal sin organizacion explicita ni valores vacios propagados;
  errores nativos depurados visibles en el gate, con orientacion sobre Snyk Code.
- `SNYK_ORG` opcional aceptado como Secret o Variable y transmitido al motor;
  el identificador de contexto se depura tambien en logs y diagnosticos.
