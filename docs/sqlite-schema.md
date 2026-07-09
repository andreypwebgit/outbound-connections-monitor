# SQLite Schema

## Objetivo

Persistir scans, findings, identidad de binarios, baseline, decisiones y auditoría de forma simple y trazable.

## Motor

- SQLite único local
- sin base de datos servidor
- sin cachés distribuidas

## Entidades principales

### 1. scans
Metadatos del escaneo.

Campos mínimos sugeridos:
- `scan_id` TEXT PK
- `started_at` TEXT
- `finished_at` TEXT
- `duration_ms` INTEGER
- `app_version` TEXT
- `hostname` TEXT

### 2. network_observations
Observaciones por conexión/finding dentro de un scan.

Campos mínimos sugeridos:
- `finding_id` TEXT PK
- `scan_id` TEXT FK
- `protocol` TEXT
- `state` TEXT
- `local_ip` TEXT
- `local_port` INTEGER
- `remote_ip` TEXT
- `remote_port` INTEGER
- `hostname` TEXT NULL
- `root_domain` TEXT NULL
- `asn_org` TEXT NULL
- `country` TEXT NULL
- `pid` INTEGER
- `process_name` TEXT

### 3. binary_identity
Identidad física/lógica del binario.

Campos mínimos sugeridos:
- `binary_id` TEXT PK
- `normalized_path` TEXT NULL
- `volume_serial` TEXT NULL
- `file_id` TEXT NULL
- `file_size` INTEGER
- `last_write_time` TEXT NULL
- `sha256` TEXT NULL

### 4. trust_records
Resultado de trust/firma del binario.

Campos mínimos sugeridos:
- `trust_id` TEXT PK
- `binary_id` TEXT FK
- `signature_status` TEXT
- `signature_source` TEXT
- `signer_subject` TEXT NULL
- `signer_thumbprint` TEXT NULL
- `chain_status` TEXT
- `verified_at` TEXT

### 5. baseline_entries
Estado del baseline por binario/patrón.

Campos mínimos sugeridos:
- `baseline_id` TEXT PK
- `binary_id` TEXT FK
- `state` TEXT
- `seen_count` INTEGER
- `distinct_days` INTEGER
- `first_seen` TEXT NULL
- `last_seen` TEXT NULL
- `manual_validation` INTEGER

### 6. affinity_profiles
Patrones de comportamiento de red conocidos.

Campos mínimos sugeridos:
- `affinity_id` TEXT PK
- `binary_id` TEXT FK
- `root_domain` TEXT NULL
- `asn_org` TEXT NULL
- `remote_port` INTEGER NULL
- `times_seen` INTEGER
- `last_seen` TEXT NULL

### 7. risk_decisions
Resultado del motor de riesgo por finding.

Campos mínimos sugeridos:
- `decision_id` TEXT PK
- `finding_id` TEXT FK
- `risk_score` INTEGER
- `risk_band` TEXT
- `recommended_action` TEXT
- `affinity_score` INTEGER
- `affinity_level` TEXT

### 8. manual_decisions
Intervenciones manuales del usuario.

Campos mínimos sugeridos:
- `manual_decision_id` TEXT PK
- `binary_id` TEXT FK
- `decision_type` TEXT
- `notes` TEXT NULL
- `created_at` TEXT

### 9. intel_results
Resultados de Intel externo.

Campos mínimos sugeridos:
- `intel_result_id` TEXT PK
- `finding_id` TEXT FK
- `provider` TEXT
- `consulted_at` TEXT
- `raw_summary` TEXT NULL
- `score_hint` INTEGER NULL

### 10. audit_events
Trazabilidad técnica interna.

Campos mínimos sugeridos:
- `event_id` TEXT PK
- `scan_id` TEXT NULL
- `event_type` TEXT
- `message` TEXT
- `created_at` TEXT

## Índices mínimos recomendados

- `network_observations(scan_id)`
- `network_observations(remote_ip)`
- `network_observations(root_domain)`
- `binary_identity(sha256)`
- `binary_identity(file_id, volume_serial)`
- `baseline_entries(state)`
- `risk_decisions(risk_band)`
- `affinity_profiles(binary_id)`

## Reglas de diseño

- no ocultar el esquema tras magia ORM;
- no introducir tablas intermedias sin función clara;
- no duplicar datos sin razón explícita;
- documentar cualquier cambio de esquema;
- mantener alineación con el contrato `scan_now` y el scoring.