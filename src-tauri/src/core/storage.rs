use rusqlite::Connection;
use std::path::PathBuf;
use crate::core::errors::AppError;

pub struct Storage {
    conn: Connection,
}

impl Storage {
    pub fn new(db_path: PathBuf) -> Result<Self, AppError> {
        let conn = Connection::open(&db_path)?;
        let storage = Self { conn };
        storage.init_schema()?;
        Ok(storage)
    }

    fn init_schema(&self) -> Result<(), AppError> {
        // Ejecutamos las sentencias de inicialización de la base de datos
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

        self.conn.execute_batch(schema)?;
        Ok(())
    }

    // Aquí irían los métodos de inserción/consulta que el Risk Engine y el core requieran.
    // Por el momento, la inicialización está cubierta.
}
