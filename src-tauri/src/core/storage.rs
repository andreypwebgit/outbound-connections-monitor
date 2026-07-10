use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};

use crate::core::errors::AppError;
use crate::core::models::{BaselineInfo, ScanHistoryEntry, ScanNowResponse, TrustInfo};

/// Contador para generar IDs únicos sin dependencia de uuid.
static ID_COUNTER: AtomicU64 = AtomicU64::new(0);

fn generate_id(prefix: &str) -> String {
    let seq = ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}-{}-{}", prefix, Utc::now().timestamp_micros(), seq)
}

/// Identidad de binario tal como está persistida (fila de `binary_identity`).
/// Es la estructura que consulta el identity cache.
#[derive(Debug, Clone)]
pub struct StoredIdentity {
    pub sha256: String,
    pub normalized_path: Option<String>,
    pub volume_serial: Option<String>,
    pub file_id: Option<String>,
    pub file_size: u64,
    pub last_write_time: Option<String>,
}

/// Perfil de comportamiento de red persistido (fila de `affinity_profiles`).
#[derive(Debug, Clone)]
pub struct AffinityProfile {
    pub hostname: Option<String>,
    pub root_domain: Option<String>,
    pub asn_org: Option<String>,
    pub remote_port: Option<u16>,
    pub times_seen: u32,
    pub last_seen: Option<String>,
}

pub struct Storage {
    pub conn: Mutex<Connection>,
}

impl Storage {
    pub fn new(db_path: PathBuf) -> Result<Self, AppError> {
        let conn = Connection::open(&db_path)?;
        let storage = Self { conn: Mutex::new(conn) };
        storage.init_schema()?;
        Ok(storage)
    }

    /// Base de datos en memoria para tests de integración.
    pub fn new_in_memory() -> Result<Self, AppError> {
        let conn = Connection::open_in_memory()?;
        let storage = Self { conn: Mutex::new(conn) };
        storage.init_schema()?;
        Ok(storage)
    }

    fn init_schema(&self) -> Result<(), AppError> {
        let schema = "
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                started_at TEXT,
                finished_at TEXT,
                duration_ms INTEGER,
                app_version TEXT,
                hostname TEXT
            );

            CREATE TABLE IF NOT EXISTS network_observations (
                finding_id TEXT PRIMARY KEY,
                scan_id TEXT,
                protocol TEXT,
                state TEXT,
                local_ip TEXT,
                local_port INTEGER,
                remote_ip TEXT,
                remote_port INTEGER,
                hostname TEXT,
                root_domain TEXT,
                asn_org TEXT,
                country TEXT,
                pid INTEGER,
                process_name TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            );

            CREATE TABLE IF NOT EXISTS binary_identity (
                binary_id TEXT PRIMARY KEY,
                normalized_path TEXT,
                volume_serial TEXT,
                file_id TEXT,
                file_size INTEGER,
                last_write_time TEXT,
                sha256 TEXT
            );

            CREATE TABLE IF NOT EXISTS trust_records (
                trust_id TEXT PRIMARY KEY,
                binary_id TEXT,
                signature_status TEXT,
                signature_source TEXT,
                signer_subject TEXT,
                signer_thumbprint TEXT,
                chain_status TEXT,
                verified_at TEXT,
                FOREIGN KEY (binary_id) REFERENCES binary_identity(binary_id)
            );

            CREATE TABLE IF NOT EXISTS baseline_entries (
                baseline_id TEXT PRIMARY KEY,
                binary_id TEXT,
                state TEXT,
                seen_count INTEGER,
                distinct_days INTEGER,
                first_seen TEXT,
                last_seen TEXT,
                manual_validation INTEGER,
                FOREIGN KEY (binary_id) REFERENCES binary_identity(binary_id)
            );

            CREATE TABLE IF NOT EXISTS affinity_profiles (
                affinity_id TEXT PRIMARY KEY,
                binary_id TEXT,
                root_domain TEXT,
                asn_org TEXT,
                remote_port INTEGER,
                times_seen INTEGER,
                last_seen TEXT,
                FOREIGN KEY (binary_id) REFERENCES binary_identity(binary_id)
            );

            CREATE TABLE IF NOT EXISTS risk_decisions (
                decision_id TEXT PRIMARY KEY,
                finding_id TEXT,
                risk_score INTEGER,
                risk_band TEXT,
                recommended_action TEXT,
                affinity_score INTEGER,
                affinity_level TEXT,
                FOREIGN KEY (finding_id) REFERENCES network_observations(finding_id)
            );

            CREATE TABLE IF NOT EXISTS manual_decisions (
                manual_decision_id TEXT PRIMARY KEY,
                binary_id TEXT,
                decision_type TEXT,
                notes TEXT,
                created_at TEXT,
                FOREIGN KEY (binary_id) REFERENCES binary_identity(binary_id)
            );

            CREATE TABLE IF NOT EXISTS intel_results (
                intel_result_id TEXT PRIMARY KEY,
                finding_id TEXT,
                provider TEXT,
                consulted_at TEXT,
                raw_summary TEXT,
                score_hint INTEGER,
                FOREIGN KEY (finding_id) REFERENCES network_observations(finding_id)
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                event_id TEXT PRIMARY KEY,
                scan_id TEXT,
                event_type TEXT,
                message TEXT,
                created_at TEXT
            );

            -- Indices recomendados
            CREATE INDEX IF NOT EXISTS idx_network_observations_scan_id ON network_observations(scan_id);
            CREATE INDEX IF NOT EXISTS idx_network_observations_remote_ip ON network_observations(remote_ip);
            CREATE INDEX IF NOT EXISTS idx_network_observations_root_domain ON network_observations(root_domain);
            CREATE INDEX IF NOT EXISTS idx_binary_identity_sha256 ON binary_identity(sha256);
            CREATE INDEX IF NOT EXISTS idx_binary_identity_file_id ON binary_identity(file_id, volume_serial);
            CREATE INDEX IF NOT EXISTS idx_binary_identity_path ON binary_identity(normalized_path);
            CREATE INDEX IF NOT EXISTS idx_baseline_entries_state ON baseline_entries(state);
            CREATE INDEX IF NOT EXISTS idx_baseline_entries_binary_id ON baseline_entries(binary_id);
            CREATE INDEX IF NOT EXISTS idx_risk_decisions_risk_band ON risk_decisions(risk_band);
            CREATE INDEX IF NOT EXISTS idx_affinity_profiles_binary_id ON affinity_profiles(binary_id);
            CREATE INDEX IF NOT EXISTS idx_audit_events_scan_id ON audit_events(scan_id);
        ";

        let conn = self.conn.lock().unwrap();
        conn.execute_batch(schema)?;

        // Migraciones v0.3 (ignoramos errores si las columnas ya existen)
        let _ = conn.execute("ALTER TABLE network_observations ADD COLUMN ppid INTEGER", params![]);
        let _ = conn.execute("ALTER TABLE network_observations ADD COLUMN parent_name TEXT", params![]);
        let _ = conn.execute("ALTER TABLE network_observations ADD COLUMN command_line TEXT", params![]);
        let _ = conn.execute("ALTER TABLE network_observations ADD COLUMN user_context TEXT", params![]);

        // Migraciones v0.4:
        // - scans.raw_json: respuesta completa del scan para reproducibilidad
        //   de exportaciones e historial (ver docs/sqlite-schema.md).
        // - affinity_profiles.hostname: el modelo de afinidad usa hostname/FQDN
        //   como señal fuerte además del root_domain.
        let _ = conn.execute("ALTER TABLE scans ADD COLUMN raw_json TEXT", params![]);
        let _ = conn.execute("ALTER TABLE affinity_profiles ADD COLUMN hostname TEXT", params![]);

        // Corrección de datos v0.4 (idempotente): la lógica anterior usaba
        // Observed_Local como "visto varias veces", pero según el lifecycle
        // ese estado SOLO puede alcanzarse por validación manual. Las entradas
        // sin manual_validation vuelven a Candidate para re-aprender con las
        // reglas actuales.
        let _ = conn.execute(
            "UPDATE baseline_entries SET state = 'Candidate' WHERE state = 'Observed_Local' AND manual_validation = 0",
            params![],
        );

        Ok(())
    }

    // ------------------------------------------------------------------
    // Identity cache (binary_identity + trust_records)
    // ------------------------------------------------------------------

    /// Busca la identidad almacenada más reciente para una clave física
    /// (file_id + volume_serial). Puede haber varias filas para el mismo
    /// archivo físico si su contenido cambió con el tiempo: se devuelve la
    /// última escrita.
    pub fn find_identity_by_physical_key(
        &self,
        volume_serial: &str,
        file_id: &str,
    ) -> Result<Option<StoredIdentity>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT sha256, normalized_path, volume_serial, file_id, file_size, last_write_time
             FROM binary_identity
             WHERE volume_serial = ?1 AND file_id = ?2 AND sha256 IS NOT NULL
             ORDER BY last_write_time DESC LIMIT 1",
        )?;
        let row = stmt
            .query_row(params![volume_serial, file_id], Self::map_stored_identity)
            .optional()?;
        Ok(row)
    }

    /// Fallback de búsqueda por ruta normalizada cuando no hay file_id
    /// disponible (p. ej. archivo sin permisos de apertura).
    pub fn find_identity_by_path(&self, normalized_path: &str) -> Result<Option<StoredIdentity>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT sha256, normalized_path, volume_serial, file_id, file_size, last_write_time
             FROM binary_identity
             WHERE normalized_path = ?1 AND sha256 IS NOT NULL
             ORDER BY last_write_time DESC LIMIT 1",
        )?;
        let row = stmt
            .query_row(params![normalized_path], Self::map_stored_identity)
            .optional()?;
        Ok(row)
    }

    /// Garantiza la fila padre en `binary_identity` para satisfacer las FK
    /// de las tablas hijas (el build bundled de SQLite activa FK por defecto).
    /// Solo crea la fila mínima; los datos físicos los completa
    /// `upsert_identity` cuando el enricher los conoce.
    fn ensure_binary_row(conn: &Connection, binary_id: &str) -> Result<(), AppError> {
        conn.execute(
            "INSERT OR IGNORE INTO binary_identity (binary_id, sha256) VALUES (?1, ?1)",
            params![binary_id],
        )?;
        Ok(())
    }

    fn map_stored_identity(row: &rusqlite::Row) -> rusqlite::Result<StoredIdentity> {
        Ok(StoredIdentity {
            sha256: row.get(0)?,
            normalized_path: row.get(1)?,
            volume_serial: row.get(2)?,
            file_id: row.get(3)?,
            file_size: row.get::<_, Option<i64>>(4)?.unwrap_or(0) as u64,
            last_write_time: row.get(5)?,
        })
    }

    /// Inserta o actualiza la identidad de un binario. `binary_id` es el
    /// SHA-256: dos versiones del mismo archivo físico son dos filas.
    pub fn upsert_identity(&self, identity: &StoredIdentity) -> Result<(), AppError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO binary_identity (binary_id, normalized_path, volume_serial, file_id, file_size, last_write_time, sha256)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?1)
             ON CONFLICT(binary_id) DO UPDATE SET
                normalized_path = excluded.normalized_path,
                volume_serial = excluded.volume_serial,
                file_id = excluded.file_id,
                file_size = excluded.file_size,
                last_write_time = excluded.last_write_time",
            params![
                identity.sha256,
                identity.normalized_path,
                identity.volume_serial,
                identity.file_id,
                identity.file_size as i64,
                identity.last_write_time,
            ],
        )?;
        Ok(())
    }

    /// Recupera el trust cacheado más reciente para un binario.
    pub fn get_trust_for_binary(&self, sha256: &str) -> Result<Option<TrustInfo>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT signature_status, signature_source, signer_subject, signer_thumbprint, chain_status
             FROM trust_records WHERE binary_id = ?1
             ORDER BY verified_at DESC LIMIT 1",
        )?;
        let row = stmt
            .query_row(params![sha256], |row| {
                Ok(TrustInfo {
                    signature_status: row.get(0)?,
                    signature_source: row.get(1)?,
                    signer_subject: row.get(2)?,
                    signer_thumbprint: row.get(3)?,
                    chain_status: row.get(4)?,
                })
            })
            .optional()?;
        Ok(row)
    }

    pub fn save_trust_record(&self, sha256: &str, trust: &TrustInfo) -> Result<(), AppError> {
        let conn = self.conn.lock().unwrap();
        Self::ensure_binary_row(&conn, sha256)?;
        // Un registro de trust por binario es suficiente para el caché:
        // trust_id determinista para no acumular filas por scan.
        conn.execute(
            "INSERT INTO trust_records (trust_id, binary_id, signature_status, signature_source, signer_subject, signer_thumbprint, chain_status, verified_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(trust_id) DO UPDATE SET
                signature_status = excluded.signature_status,
                signature_source = excluded.signature_source,
                signer_subject = excluded.signer_subject,
                signer_thumbprint = excluded.signer_thumbprint,
                chain_status = excluded.chain_status,
                verified_at = excluded.verified_at",
            params![
                format!("TRST-{}", sha256),
                sha256,
                trust.signature_status,
                trust.signature_source,
                trust.signer_subject,
                trust.signer_thumbprint,
                trust.chain_status,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Baseline
    // ------------------------------------------------------------------

    pub fn get_baseline_entry(&self, binary_id: &str) -> Result<Option<BaselineInfo>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT state, seen_count, distinct_days, first_seen, last_seen, manual_validation
             FROM baseline_entries WHERE binary_id = ?1",
        )?;

        let row = stmt
            .query_row(params![binary_id], |row| {
                let manual_val_int: i32 = row.get(5)?;
                Ok(BaselineInfo {
                    state: row.get(0)?,
                    seen_count: row.get(1)?,
                    distinct_days: row.get(2)?,
                    first_seen: row.get(3)?,
                    last_seen: row.get(4)?,
                    manual_validation: manual_val_int > 0,
                })
            })
            .optional()?;

        Ok(row)
    }

    /// Escribe el estado de baseline calculado por el BaselineManager.
    /// La lógica de transiciones NO vive aquí: storage solo persiste.
    pub fn write_baseline_entry(&self, binary_id: &str, info: &BaselineInfo) -> Result<(), AppError> {
        let conn = self.conn.lock().unwrap();
        Self::ensure_binary_row(&conn, binary_id)?;
        conn.execute(
            "INSERT INTO baseline_entries (baseline_id, binary_id, state, seen_count, distinct_days, first_seen, last_seen, manual_validation)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(baseline_id) DO UPDATE SET
                state = excluded.state,
                seen_count = excluded.seen_count,
                distinct_days = excluded.distinct_days,
                first_seen = excluded.first_seen,
                last_seen = excluded.last_seen,
                manual_validation = excluded.manual_validation",
            params![
                format!("BSL-{}", binary_id),
                binary_id,
                info.state,
                info.seen_count,
                info.distinct_days,
                info.first_seen,
                info.last_seen,
                if info.manual_validation { 1 } else { 0 },
            ],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Affinity profiles
    // ------------------------------------------------------------------

    pub fn get_affinity_profiles(&self, binary_id: &str) -> Result<Vec<AffinityProfile>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT hostname, root_domain, asn_org, remote_port, times_seen, last_seen
             FROM affinity_profiles WHERE binary_id = ?1",
        )?;
        let rows = stmt.query_map(params![binary_id], |row| {
            Ok(AffinityProfile {
                hostname: row.get(0)?,
                root_domain: row.get(1)?,
                asn_org: row.get(2)?,
                remote_port: row.get::<_, Option<i64>>(3)?.map(|p| p as u16),
                times_seen: row.get::<_, Option<u32>>(4)?.unwrap_or(0),
                last_seen: row.get(5)?,
            })
        })?;

        let mut profiles = Vec::new();
        for row in rows {
            profiles.push(row?);
        }
        Ok(profiles)
    }

    /// Registra (o refuerza) el patrón de destino observado para un binario.
    /// El perfil es por combinación (hostname, root_domain, asn, puerto):
    /// clave determinista para acumular `times_seen` sin duplicados.
    pub fn record_affinity_observation(
        &self,
        binary_id: &str,
        hostname: Option<&str>,
        root_domain: Option<&str>,
        asn_org: Option<&str>,
        remote_port: u16,
    ) -> Result<(), AppError> {
        let now = Utc::now().to_rfc3339();
        let profile_key = format!(
            "AFF-{}-{}-{}-{}-{}",
            binary_id,
            hostname.unwrap_or("-"),
            root_domain.unwrap_or("-"),
            asn_org.unwrap_or("-"),
            remote_port
        );

        let conn = self.conn.lock().unwrap();
        Self::ensure_binary_row(&conn, binary_id)?;
        conn.execute(
            "INSERT INTO affinity_profiles (affinity_id, binary_id, hostname, root_domain, asn_org, remote_port, times_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7)
             ON CONFLICT(affinity_id) DO UPDATE SET
                times_seen = times_seen + 1,
                last_seen = excluded.last_seen",
            params![profile_key, binary_id, hostname, root_domain, asn_org, remote_port, now],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Manual decisions
    // ------------------------------------------------------------------

    pub fn record_manual_decision(
        &self,
        binary_id: &str,
        decision_type: &str,
        notes: Option<&str>,
    ) -> Result<(), AppError> {
        let conn = self.conn.lock().unwrap();
        Self::ensure_binary_row(&conn, binary_id)?;
        conn.execute(
            "INSERT INTO manual_decisions (manual_decision_id, binary_id, decision_type, notes, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                generate_id("MDC"),
                binary_id,
                decision_type,
                notes,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Audit events
    // ------------------------------------------------------------------

    /// Registra un evento de auditoría técnica. Los fallos aquí no deben
    /// romper el pipeline: el llamador decide ignorar el Result si procede.
    pub fn record_audit_event(
        &self,
        scan_id: Option<&str>,
        event_type: &str,
        message: &str,
    ) -> Result<(), AppError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO audit_events (event_id, scan_id, event_type, message, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                generate_id("EVT"),
                scan_id,
                event_type,
                message,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Scans / findings / history
    // ------------------------------------------------------------------

    pub fn save_scan_results(&self, response: &ScanNowResponse) -> Result<(), AppError> {
        let raw_json = serde_json::to_string(response)
            .map_err(|e| AppError::SystemError(format!("Failed to serialize scan for persistence: {}", e)))?;

        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        tx.execute(
            "INSERT INTO scans (scan_id, started_at, finished_at, duration_ms, app_version, hostname, raw_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                response.scan_id,
                response.started_at,
                response.finished_at,
                response.duration_ms,
                response.host.app_version,
                response.host.hostname,
                raw_json,
            ],
        )?;

        for finding in &response.findings {
            tx.execute(
                "INSERT INTO network_observations (finding_id, scan_id, protocol, state, local_ip, local_port, remote_ip, remote_port, hostname, root_domain, asn_org, country, pid, process_name, ppid, parent_name, command_line, user_context)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
                params![
                    finding.finding_id,
                    response.scan_id,
                    finding.protocol,
                    finding.state,
                    finding.local.ip,
                    finding.local.port,
                    finding.remote.ip,
                    finding.remote.port,
                    finding.remote.hostname,
                    finding.remote.root_domain,
                    finding.remote.asn_org,
                    finding.remote.country,
                    finding.process.pid,
                    finding.process.name,
                    finding.process.ppid,
                    finding.process.parent_name,
                    finding.process.command_line,
                    finding.process.user
                ],
            )?;

            tx.execute(
                "INSERT INTO risk_decisions (decision_id, finding_id, risk_score, risk_band, recommended_action, affinity_score, affinity_level)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    format!("RSK-{}", finding.finding_id),
                    finding.finding_id,
                    finding.risk.score,
                    finding.risk.band,
                    finding.risk.recommended_action,
                    finding.affinity.score,
                    finding.affinity.level,
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Historial ligero de escaneos: metadatos + contadores del summary
    /// persistido, sin deserializar los findings completos.
    pub fn get_scan_history(&self, limit: u32) -> Result<Vec<ScanHistoryEntry>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT scan_id, started_at, finished_at, duration_ms,
                    json_extract(raw_json, '$.summary.total_observations'),
                    json_extract(raw_json, '$.summary.accepted_count'),
                    json_extract(raw_json, '$.summary.review_count'),
                    json_extract(raw_json, '$.summary.danger_count')
             FROM scans
             ORDER BY started_at DESC
             LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![limit], |row| {
            Ok(ScanHistoryEntry {
                scan_id: row.get(0)?,
                started_at: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                finished_at: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                duration_ms: row.get::<_, Option<i64>>(3)?.unwrap_or(0) as u64,
                total_observations: row.get::<_, Option<u32>>(4)?.unwrap_or(0),
                accepted_count: row.get::<_, Option<u32>>(5)?.unwrap_or(0),
                review_count: row.get::<_, Option<u32>>(6)?.unwrap_or(0),
                danger_count: row.get::<_, Option<u32>>(7)?.unwrap_or(0),
            })
        })?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    /// Recupera un scan completo desde su representación persistida.
    /// Base de la exportación reproducible exigida por docs/export-format.md.
    pub fn get_scan_response(&self, scan_id: &str) -> Result<Option<ScanNowResponse>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT raw_json FROM scans WHERE scan_id = ?1")?;
        let raw: Option<Option<String>> = stmt
            .query_row(params![scan_id], |row| row.get::<_, Option<String>>(0))
            .optional()?;

        match raw.flatten() {
            Some(json) => {
                let response = serde_json::from_str(&json).map_err(|e| {
                    AppError::SystemError(format!("Persisted scan {} is not deserializable: {}", scan_id, e))
                })?;
                Ok(Some(response))
            }
            None => Ok(None),
        }
    }
}
