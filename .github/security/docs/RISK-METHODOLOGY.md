# Priorizacion contextual

Se conserva `original_severity`, `cvss_score` y `cvss_vector`. No se modifica un
CVSS Base Score ni se presenta prioridad como una nueva severidad publicada.
El algoritmo no usa una suma de pesos arbitrarios: aplica la primera regla que
corresponda, en este orden.

| Condicion | Prioridad inicial | Motivo |
|---|---|---|
| CVE listado en CISA KEV | P0 | Evidencia publica de explotacion conocida, no prueba de explotabilidad de esta aplicacion. |
| CVSS >= 9, o severidad Critical sin CVSS | P1 | Gravedad tecnica critica requiere atencion alta. |
| CVSS >= 7, o severidad High sin CVSS | P1 | Gravedad tecnica alta. |
| EPSS >= 0.1 | P1 | Umbral operativo explicito de probabilidad poblacional de explotacion. |
| Medium + exposicion a Internet declarada + criticidad alta o datos confidenciales/restringidos | P1 | Impacto contextual explicitamente declarado. |
| Medium | P2 | Triaje medio. |
| Low | P3 | Triaje bajo. |
| Severidad desconocida sin CVSS | REVIEW | Falta evidencia para clasificar. |

La politica YAML configura umbrales tecnicos/EPSS y prioridades de cada regla.
El umbral EPSS 0.1 es una eleccion conservadora de triaje, no una probabilidad
calibrada para el proyecto. El contexto desconocido no se interpreta como bajo.
Los niveles SARIF error/warning/note se interpretan como High/Medium/Low solo
para el triaje, preservando el nivel original.

No se rebaja riesgo por controles compensatorios no verificados ni por ausencia
de evidencia de alcanzabilidad. `reachability` queda UNKNOWN salvo evidencia
explicita de herramienta, e incluso UNREACHABLE no es motivo automatico para
afirmar que el componente es seguro.

EPSS se consulta por CVE en lotes acotados, KEV como catalogo publico. No se
envia codigo a estas fuentes. Fechas y fuente quedan en la evidencia; las
consultas tienen presupuesto temporal y cache. Un error, limite, dato ausente o
modo offline produce UNAVAILABLE/DISABLED y `null`, no EPSS=0 o KEV=false.
KEV=false solo se asigna tras validar un catalogo completo disponible.

`confidence` expresa confianza en la decision de triaje, no en una afirmacion de
explotabilidad. Las limitaciones se conservan por hallazgo.
