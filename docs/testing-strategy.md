# Testing Strategy

## Objetivo

Validar que la v0.1 es útil, estable, explicable y que no degrada su arquitectura con cambios no controlados.

## Principios

- probar primero el dominio crítico;
- evitar tests ornamentales;
- cubrir contrato, baseline, afinidad, scoring y caché;
- degradar con elegancia cuando faltan datos;
- mantener fixtures simples y legibles.

## Capas de testing

### 1. Contrato JSON
Validar que `scan_now` cumple el shape definido en `docs/scan-now-contract.json`.

### 2. Risk Engine
Validar:
- bandas de riesgo;
- `reason_codes`;
- recomendaciones;
- prioridad de señales fuertes.

### 3. Baseline transitions
Validar:
- `Unknown -> Candidate`
- `Candidate -> Observed_Local`
- `Candidate -> Baseline_Provisional`
- `Baseline_Provisional -> Baseline_Consolidated`
- `Baseline_Consolidated -> Revalidation_Required`
- procesos críticos -> `Potentially_Dangerous`

### 4. Affinity
Validar:
- afinidad alta con coincidencia razonable;
- degradación con dominio nuevo;
- diferencia entre IP exacta y afinidad contextual;
- cambios de puerto plausibles vs raros.

### 5. Identity Cache
Validar:
- hit de caché cuando no cambia la clave de invalidación;
- miss de caché cuando cambian `file_id`, `volume_serial`, `file_size` o `last_write_time`;
- distinción entre hash `cache` y `fresh`.

### 6. Path classification
Validar:
- `Windows`
- `ProgramFiles`
- `ProgramFilesX86`
- `AppData`
- `Temp`
- `Downloads`
- `Desktop`
- `UserProfile`
- `Other`
- `Missing`

### 7. SQLite integration
Validar:
- creación de esquema;
- persistencia de scans y findings;
- persistencia de baseline y decisiones;
- índices y consultas básicas esperadas.

## Escenarios mínimos obligatorios

1. proceso firmado, hash conocido y destino habitual;
2. proceso firmado con hash nuevo -> revalidación;
3. binario unsigned validado manualmente -> `Observed_Local`;
4. proceso huérfano -> crítico;
5. destino por IP pura con baja afinidad;
6. root domain nuevo para binario conocido;
7. cambio de puerto plausible con afinidad media;
8. fallo de proveedor externo sin romper el scan;
9. degradación cuando no se puede resolver path o trust.

## Fixtures recomendados

- findings simulados en JSON;
- baseline inicial controlado;
- respuestas mock de VirusTotal/AbuseIPDB;
- ejemplos de binarios firmados, unsigned y revalidados.

## Ubicación de los tests

- Unitarios por módulo: `#[cfg(test)]` al final de cada archivo de
  `src-tauri/src/core/` (enricher, identity_cache, baseline_manager,
  affinity, risk_engine, exporter).
- Integración: `src-tauri/tests/contract_test.rs` (valida respuestas contra
  `docs/scan-now-contract.json` con un mini-validador de JSON Schema, sin
  dependencias) y `src-tauri/tests/storage_test.rs` (SQLite end-to-end).
- Ejecución: `cargo test` dentro de `src-tauri/`.

Los mocks de VirusTotal/AbuseIPDB quedan pendientes de que exista el bloque
de Intel externo (opcional, no implementado en el motor local).

## Regla de aceptación

Una tarea no se considera terminada si toca contrato, scoring, baseline, afinidad, caché o persistencia y no deja tests o actualizaciones de tests relacionados.