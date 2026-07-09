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

## v1.0

Objetivo:
- arquitectura estable
- rendimiento validado
- UX madura
- documentación y testing endurecidos

## Regla de roadmap

Nada de v0.2+ debe contaminar v0.1 sin necesidad explícita.
El proyecto debe crecer por capas, no por anticipación.