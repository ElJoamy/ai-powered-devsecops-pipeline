# Contrato de reportes

## Evidencia entre jobs

Los artefactos `security-scan-sast`, `security-scan-dependencies` y
`security-scan-iac` son colecciones intermedias, no informes finales. Cada uno
contiene `metadata/collection.json`, `metadata/execution.json`, inventario,
estados de escaneres, resultados originales/diagnosticos disponibles y
`manifest.json`. No incluyen riesgo, comparacion ni gate.

La coleccion identifica tipo de escaneo, repositorio, commit, run, intento,
commit del motor y huella de configuracion efectiva. La huella omite solamente
el selector de tipos, que difiere entre workers; no contiene credenciales.
La consolidacion valida identidad, inventario SHA-256 y rutas antes de copiar
resultados. Un artefacto faltante o invalido produce un registro FAILED y un
error de procesamiento, no `findings: []` presentado como exito.

El resumen de Actions se escribe fuera del artefacto para no alterar su
manifiesto. Antes de consolidar, los conteos figuran pendientes; despues se
derivan de hallazgos procesados y se mantienen no disponibles para escaneos
fallidos. El resumen no sustituye los JSON ni acredita cobertura universal.

## Informe consolidado

Los documentos normalizado y de riesgo tienen envelope:

```json
{"schema_version": "1.0", "metadata": {}, "scanners": [], "findings": []}
```

`findings: []` solo representa ausencia de hallazgos reportados. Debe interpretarse
junto con `metadata/scanners.json`, `summary.json` y la integridad de ejecucion.
Un fallo no representa un analisis limpio. Los esquemas en `../schemas/`
validan hallazgos normalizados, riesgo, politica y comparacion.

Cada hallazgo conserva ID SHA-256, herramientas y procedencia, tipo, identificadores,
titulo/descripccion, severidad original, CVSS/vector cuando existen, ubicacion,
paquete/ecosistema/versiones, regla/recurso, referencias, evidencia y recomendacion.
Valores ausentes son `null` o UNKNOWN; no se inventan versiones corregidas,
dependencias transitivas o relaciones con una dependencia directa.

El fingerprint incluye tipo, CVE o regla, ecosistema, paquete, version instalada,
archivo, regla y recurso; SAST/IaC agregan lineas y columnas. Se unen solo
identidades coincidentes y se preservan todas las herramientas, referencias y
evidencias. Es conservador: reglas distintas no se fusionan por compartir CVE.
Cambiar version/ubicacion puede producir nuevos IDs, no una correccion inferida.

Trivy JSON es autoritativo para SCA/IaC, porque SARIF pierde datos de paquetes.
Snyk se procesa como SARIF JSON o estructura de issues soportada. Snyk puede omitir
su archivo JSON cuando no encuentra issues; en ese caso se conserva el SARIF
nativo validado como JSON, se registra `json_export` y nunca se sintetiza un
documento vacio. Una salida que no pueda validarse se marca FAILED.

Riesgo agrega `epss_probability`, `kev_listed`, procedencia de inteligencia,
`contextual_risk`, `priority`, `risk_factors`, `confidence` y `limitations`.
Los datos originales permanecen sin sobrescribir.

El baseline debe ser un documento normalizado o de riesgo con el mismo esquema.
Sin baseline, NO_BASELINE. Con baseline: `new`, `unchanged`, `changed` y
`not_detected`; los cambios de prioridad figuran en `changed_fields`.
Los hallazgos no detectados incluyen incertidumbre de cobertura/versiones;
nunca se etiquetan automaticamente como corregidos.

El prompt Copilot incluye todos los IDs en una tabla y detalles de los primeros
30, con referencias a JSON para los demas. Los datos del escaner se tratan como
contenido no confiable, no como instrucciones para el agente.
