# Testing Strategy

## Objetivo

Validar que OCM es útil, estable, explicable y que no degrada su arquitectura con cambios no controlados.

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

### 8. Collector, diff y gestión de baseline
Validar parsing binario de tablas TCP, filtros de estado, deduplicación del
diff, selección cronológica del scan anterior y proyecciones/acciones de la
vista de baseline.

### 9. Completitud y compatibilidad

Validar:
- clasificación `complete`, `partial` y `degraded`;
- fallos independientes de familias TCP/UDP;
- métricas de proceso, identidad, trust y DNS;
- exportación UI/HTML con valores escapados;
- contrato v2 con `coverage` obligatorio;
- lectura, persistencia y exportación de históricos v1 sin cobertura
  inventada.

### 10. Política de release

`scripts/test-release-pipeline.ps1` valida sin dependencias adicionales:

- aceptación del tag que coincide con los cuatro manifiestos y rechazo de uno
  divergente;
- presencia de build Tauri, checksums SHA-256, SBOM, attestation y publicación;
- ausencia de credenciales Azure, `signCommand`, environment de firma y
  scripts retirados;
- aviso unsigned coherente en workflow, README, SECURITY y documentación de
  distribución.

### 11. Hardening del repositorio

`scripts/test-github-hardening.ps1` valida que:

- CodeQL cubra Rust y JavaScript/TypeScript en push, pull request y ejecución
  programada, usando `pull_request` para mantener segura la ejecución de PR;
- todos los usos de GitHub Actions permanezcan fijados a SHA completa;
- el check estable `Build & test (Windows)` y el propio test de política sigan
  presentes en CI;
- Dependabot mantenga cobertura de GitHub Actions, Cargo y npm.

GitHub ejecuta CodeQL en modo `none`, soportado para Rust y lenguajes
interpretados: es análisis estático complementario. No sustituye el build,
Clippy, la suite Rust ni las pruebas funcionales que se ejecutan en Windows.

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

Suite v1.0.0: **101 tests** (80 unitarios + 11 de contrato + 10 de
integración SQLite), más el test de política del pipeline de release. CI
ejecuta además validación de versiones, auditoría npm, build de Tailwind,
`cargo fmt --check` y
`cargo clippy --locked --all-targets -- -D warnings`.

CI ejecuta además el test local de hardening del repositorio. CodeQL mantiene
dos checks independientes, `Analyze (rust)` y
`Analyze (javascript-typescript)`, para que la protección de `main` pueda
exigir cobertura explícita de ambos lenguajes.

Suite v1.0.1: **102 tests** (80 unitarios + 11 de
contrato + 11 de integración SQLite). El caso adicional valida la conversión
segura de `duration_ms` al rango entero de SQLite con `rusqlite` 0.40.

Los mocks de VirusTotal/AbuseIPDB quedan pendientes de que exista el bloque
de Intel externo (opcional, no implementado en el motor local).

## Regla de aceptación

Una tarea no se considera terminada si toca contrato, scoring, baseline, afinidad, caché o persistencia y no deja tests o actualizaciones de tests relacionados.
