# Architecture

## Stack cerrado

- Windows only
- Tauri 2
- Rust puro en backend
- HTML5 semántico + Tailwind CSS v4 + JavaScript ESM en frontend
- SQLite como persistencia local

## Filosofía

La arquitectura debe ser pequeña, explicable y modular. No se permiten sidecars como base, monitorización continua ni capas innecesarias.

## Bloques principales

### 1. Collector
Responsable de obtener el snapshot de conexiones salientes activas visibles y asociarlas a procesos.

Responsabilidades:
- enumerar conexiones TCP IPv4/IPv6 activas mediante
  `GetExtendedTcpTable` (sin parsing localizado);
- enumerar endpoints UDP con PID mediante `GetExtendedUdpTable`; como esta
  API no expone peer remoto, no inventar findings UDP;
- asociar conexión a PID/proceso;
- producir observaciones crudas consistentes.

El inventario de procesos usa Toolhelp + APIs de proceso/token/servicios para
ruta, PPID, usuario, inicio, command line y servicios. Un fallo parcial deja
el campo afectado sin resolver. Authenticode permanece en PowerShell y queda
amortizado por el identity cache.

### 2. Enricher
Responsable de enriquecer cada observación con identidad del binario, trust y contexto de red.

Responsabilidades:
- resolver ruta del ejecutable;
- detectar archivo ausente o irresoluble;
- obtener identidad fuerte del archivo;
- calcular o recuperar SHA-256 desde caché;
- verificar firma y confianza;
- clasificar la ruta;
- enriquecer hostname, root domain, ASN y país cuando sea viable.

### 3. Risk Engine
Responsable de calcular baseline state, afinidad, score y recomendación.

Responsabilidades:
- consultar baseline existente;
- comparar identidad actual vs histórica;
- calcular afinidad;
- asignar banda de riesgo;
- emitir `reason_codes`;
- decidir si hace falta Intel externo.

El cálculo de afinidad vive en `core/affinity.rs` como submódulo de esta
responsabilidad (perfiles históricos por binario, señales matched/mismatched
y pesos documentados en `docs/implementation-notes.md`).

### 4. Baseline Manager
Responsable de gestionar el ciclo de vida de los estados del baseline.

Estados válidos:
- `Unknown`
- `Candidate`
- `Observed_Local`
- `Baseline_Provisional`
- `Baseline_Consolidated`
- `Revalidation_Required`
- `Potentially_Dangerous`

### 5. Identity Cache
Responsable de evitar recalcular hash y trust si el archivo no ha cambiado.

Clave de invalidación:
- `volume_serial`
- `file_id`
- `file_size`
- `last_write_time`

Valor cacheado:
- `sha256`
- firma/trust
- timestamp de verificación

Implementación en dos niveles: persistente sobre SQLite
(`binary_identity` + `trust_records`) y memoización por path dentro de un
mismo scan. Un miss con identidad física conocida pero hash distinto expone
`hash_changed`, que dispara la revalidación del baseline.

### 6. Storage
Responsable de persistir scans, observations, identities, baseline, decisiones y auditoría en SQLite.

### 7. Intel Adapters
Responsable de consultar proveedores externos de manera opcional y selectiva.

Proveedores previstos:
- VirusTotal
- AbuseIPDB
- OpenRouter solo para casos ambiguos

### 8. Exporter
Responsable de exportar resultados a JSON y HTML.

### 9. Tauri Commands
Responsable de exponer el backend al frontend.

Comando principal:
- `scan_now`

Comandos de soporte:
- `get_scan_history` — metadatos de los últimos escaneos persistidos
- `get_scan` — recupera un scan completo persistido (shape del contrato)
- `get_scan_comparison` — compara un scan persistido con su predecesor
- `get_baseline_entries` — proyección de lectura para gestionar el baseline
- `export_scan` — exporta un scan persistido a JSON o HTML
- `record_manual_decision` — decisiones manuales de baseline
  (`validate_local`, `revoke_local_validation`, `revalidate_accept`)

### 10. Scan Diff

Consulta pura sobre dos payloads `scans.raw_json`. Identifica conexiones
nuevas/cambiadas, binarios nuevos y cambios de baseline sin modificar el
contrato `scan_now` ni el estado de aprendizaje.

### 11. Coverage Engine

Responsable de resumir la cobertura real del collector y del enriquecimiento
sin alterar el riesgo ni el baseline.

Entradas:
- éxito/fallo por familia TCP y UDP;
- ejecución elevada;
- warnings del collector y del inventario de procesos;
- contadores DNS;
- campos de proceso, identidad y trust de los findings.

Salida: bloque `coverage` del contrato v2 con estado `complete`, `partial` o
`degraded`, métricas, limitaciones y warnings. Las reglas normativas viven en
`docs/scan-completeness.md`.

## Flujo principal

1. Usuario pulsa `Scan Now`.
2. Collector obtiene observaciones crudas.
3. Enricher resuelve binario, hash, firma y contexto.
4. Risk Engine calcula baseline, afinidad, score y riesgo.
5. Coverage Engine resume la calidad y los límites de la evidencia.
6. Intel externo se consulta solo si aporta valor.
7. Storage persiste scan y findings.
8. Frontend recibe JSON estable y lo renderiza.

## Reglas de arquitectura

- no meter lógica crítica en `main.rs`;
- no mezclar rendering UI con scoring;
- no depender de Internet para el escaneo básico;
- no usar IP como identidad principal del baseline;
- no usar “visto antes” como criterio suficiente de confianza;
- no convertir el proyecto en un EDR.
