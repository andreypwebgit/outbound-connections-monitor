# Roadmap

## v0.1

Objetivo: producto pequeño, útil, explicable y manual.

Incluye:
- app de escritorio Windows
- `Scan Now`
- collector de conexiones salientes activas
- enricher local con hash, trust y contexto
- baseline por estados
- afinidad de red
- scoring explicable
- exportación JSON/HTML
- SQLite local
- UI básica funcional
- tests críticos del dominio

No incluye:
- monitorización continua
- servicio residente
- packet capture
- bloqueo automático
- remediación
- sidecars como base
- Sysmon/ETW obligatorios

## v0.2

Posibles mejoras:
- histórico más rico
- timeline básica
- comparativas entre scans
- Sysmon opcional
- revalidación más guiada

## v0.3

Posibles mejoras:
- patrones repetitivos o beaconing simple
- mejores reglas de afinidad
- gestión de baseline más ergonómica
- más contexto de cambios entre versiones

## v0.5.0 — completada

- collector TCP IPv4/IPv6 y procesos mediante APIs nativas de Windows;
- DNS inverso paralelo con presupuesto acotado;
- comparativa entre scans persistidos (`NUEVO` / `CAMBIO`);
- vista de gestión del baseline con transiciones manuales válidas;
- CI con formato y Clippy sin warnings.

Se mantiene deliberadamente fuera: monitorización continua, bloqueo,
remediación e intel externo obligatorio.

## v0.5.1 — completada

- precisión contextual de `SUSPICIOUS_COMMAND_LINE`;
- eliminación del falso positivo de `--bypasscsp-schemes` en aplicaciones
  Chromium/Electron;
- conservación de la detección fuerte de argumentos PowerShell reales, sin
  allowlists por producto.

## v1.0.0 — completada

- arquitectura y contrato público estabilizados en `scan_now` v2;
- panel de completitud con cobertura por etapa, limitaciones y warnings;
- compatibilidad fiel con históricos v1 sin inferencia retrospectiva;
- ejecutable, MSI y NSIS firmados y verificados antes de publicación;
- release con versiones sincronizadas, checksums SHA-256, SBOM SPDX y
  attestation de procedencia;
- CI y release sobre Windows 2022 con acciones fijadas por commit, auditoría
  npm, formato, Clippy y 101 tests;
- documentación pública, técnica y política de seguridad alineadas.

Se mantienen fuera por diseño: monitorización continua, bloqueo,
remediación, packet capture e intel externo obligatorio.

## Regla de roadmap

El proyecto debe crecer por capas y necesidad explícita, no por anticipación.
