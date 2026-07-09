use rusqlite::{params, Connection, OptionalExtension};
use std::path::PathBuf;
use std::sync::Mutex;
use chrono::Utc;
use crate::core::errors::AppError;
use crate::core::models::{BaselineInfo, ScanNowResponse, Finding};

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
            CREATE INDEX IF NOT EXISTS idx_baseline_entries_state ON baseline_entries(state);
            CREATE INDEX IF NOT EXISTS idx_risk_decisions_risk_band ON risk_decisions(risk_band);
            CREATE INDEX IF NOT EXISTS idx_affinity_profiles_binary_id ON affinity_profiles(binary_id);
        ";

        let conn = self.conn.lock().unwrap();
        conn.execute_batch(schema)?;
        Ok(())
    }

    pub fn get_baseline_for_sha256(&self, sha256: &str) -> Result<Option<BaselineInfo>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT state, seen_count, distinct_days, first_seen, last_seen, manual_validation FROM baseline_entries WHERE binary_id = ?1")?;
        
        let row = stmt.query_row(params![sha256], |row| {
            let state: String = row.get(0)?;
            let seen_count: u32 = row.get(1)?;
            let distinct_days: u32 = row.get(2)?;
            let first_seen: Option<String> = row.get(3)?;
            let last_seen: Option<String> = row.get(4)?;
            let manual_val_int: i32 = row.get(5)?;
            
            Ok(BaselineInfo {
                state,
                seen_count,
                distinct_days,
                first_seen,
                last_seen,
                manual_validation: manual_val_int > 0,
            })
        }).optional()?;
        
        Ok(row)
    }
    
    pub fn upsert_baseline_for_sha256(&self, sha256: &str) -> Result<BaselineInfo, AppError> {
        // En un caso real, calcularíamos distinct_days basado en la fecha actual.
        // Aquí incrementamos seen_count y actualizamos last_seen.
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        
        let existing = {
            let mut stmt = conn.prepare("SELECT seen_count FROM baseline_entries WHERE binary_id = ?1")?;
            stmt.query_row(params![sha256], |row| row.get::<_, u32>(0)).optional()?
        };
        
        if let Some(mut count) = existing {
            count += 1;
            // Simplificación para la prueba de concepto: si se ve más de 5 veces, pasa a Known / Baseline_Provisional.
            let new_state = if count > 5 { "Baseline_Provisional" } else { "Observed_Local" };
            
            conn.execute(
                "UPDATE baseline_entries SET seen_count = ?1, last_seen = ?2, state = ?3 WHERE binary_id = ?4",
                params![count, now, new_state, sha256]
            )?;
        } else {
            conn.execute(
                "INSERT INTO binary_identity (binary_id, sha256) VALUES (?1, ?1) ON CONFLICT DO NOTHING",
                params![sha256]
            )?;
            conn.execute(
                "INSERT INTO baseline_entries (baseline_id, binary_id, state, seen_count, distinct_days, first_seen, last_seen, manual_validation) 
                 VALUES (?1, ?2, 'Unknown', 1, 1, ?3, ?3, 0)",
                params![format!("BSL-{}", sha256), sha256, now]
            )?;
        }
        
        drop(conn); // liberamos el lock
        self.get_baseline_for_sha256(sha256).map(|opt| opt.unwrap_or_else(|| BaselineInfo {
            state: "Unknown".to_string(),
            seen_count: 1,
            distinct_days: 1,
            first_seen: Some(now.clone()),
            last_seen: Some(now.clone()),
            manual_validation: false,
        }))
    }

    pub fn save_scan_results(&self, response: &ScanNowResponse) -> Result<(), AppError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        
        tx.execute(
            "INSERT INTO scans (scan_id, started_at, finished_at, duration_ms, app_version, hostname) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                response.scan_id,
                response.started_at,
                response.finished_at,
                response.duration_ms,
                response.host.app_version,
                response.host.hostname
            ]
        )?;
        
        for finding in &response.findings {
            tx.execute(
                "INSERT INTO network_observations (finding_id, scan_id, protocol, state, local_ip, local_port, remote_ip, remote_port, pid, process_name) 
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    finding.finding_id,
                    response.scan_id,
                    finding.protocol,
                    finding.state,
                    finding.local.ip,
                    finding.local.port,
                    finding.remote.ip,
                    finding.remote.port,
                    finding.process.pid,
                    finding.process.name
                ]
            )?;
            
            // Insertar trust records y risk decisions simplificados para v0.2
            tx.execute(
                "INSERT INTO risk_decisions (decision_id, finding_id, risk_score, risk_band, recommended_action) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    format!("RSK-{}", finding.finding_id),
                    finding.finding_id,
                    finding.risk.score,
                    finding.risk.band,
                    finding.risk.recommended_action
                ]
            )?;
        }
        
        tx.commit()?;
        Ok(())
    }
}
