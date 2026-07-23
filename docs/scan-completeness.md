# Completitud del scan

## Objetivo

Hacer visible qué evidencia pudo recoger OCM en cada snapshot. La
completitud no mide si el equipo es seguro, no modifica el score de riesgo y
no sustituye la revisión de los findings.

El bloque `coverage` forma parte del contrato `scan_now` desde
`schema_version: "v2"`. Los scans históricos v1 carecen de esa evidencia y
se muestran como **No disponible**; nunca se reconstruye ni se infiere de
forma retrospectiva.

## Estados

### `complete`

Las dos familias TCP y UDP se enumeraron, la ejecución fue elevada, no hubo
warnings ni timeouts DNS y los findings no protegidos disponen de identidad y
contexto de proceso completos.

Las limitaciones inherentes siguen aplicando: es una fotografía puntual, la
API UDP usada no expone peer remoto, el DNS tiene un presupuesto total de
200 ms y el intel externo no forma parte del motor local.

### `partial`

El núcleo TCP está disponible, pero alguna evidencia auxiliar o contextual es
incompleta. Ejemplos:

- ejecución no elevada o elevación no resoluble;
- fallo de una familia UDP;
- usuario, línea de comandos o proceso padre no resoluble;
- warning del collector o del inventario de procesos;
- al menos una resolución DNS agotó el presupuesto.

### `degraded`

Falta evidencia material para interpretar el snapshot con normalidad:

- falló TCP IPv4 o TCP IPv6; o
- un finding no protegido carece de ruta, SHA-256 o estado de trust
  resoluble.

Un fallo simultáneo de TCP IPv4 y TCP IPv6 aborta `scan_now`; por tanto no
existe un snapshot que pueda etiquetarse.

## Métricas expuestas

`coverage.collector` registra éxito por familia, observaciones TCP y
endpoints UDP con PID. `udp_findings` permanece en cero porque
`GetExtendedUdpTable` no proporciona el peer remoto y OCM no inventa un
destino.

`coverage.process` cuenta findings, procesos protegidos y resoluciones de
ruta, usuario, línea de comandos y linaje. `complete_context` requiere ruta,
usuario, línea de comandos, PPID y nombre del padre.

`coverage.identity` distingue hash fresco, hash de caché, hash no disponible,
trust resuelto y trust desconocido. `complete_identity` exige SHA-256,
identidad física del archivo y trust resoluble.

`coverage.dns` muestra IP públicas candidatas, hits de caché, PTR resueltos,
ausencia de PTR y timeouts.

## Limitaciones estables

- `POINT_IN_TIME_SNAPSHOT`
- `UDP_REMOTE_PEER_NOT_AVAILABLE`
- `EXTERNAL_INTEL_NOT_ENABLED`
- `DNS_RESOLUTION_BUDGET_200_MS`

Los warnings técnicos se conservan como texto para diagnóstico y se escapan
antes de mostrarse en la UI o el HTML exportado.

## Relación con el riesgo

La cobertura describe la calidad de la evidencia del scan completo. El riesgo
describe un finding concreto mediante score, banda, `reason_codes` y acción
recomendada. Son dimensiones distintas: un scan `complete` puede contener
findings críticos y un scan `degraded` no demuestra por sí mismo actividad
maliciosa.
