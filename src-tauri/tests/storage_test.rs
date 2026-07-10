//! Tests de integración de SQLite (testing-strategy.md, capa 7):
//! creación de esquema, persistencia de scans/findings, historial y
//! reproducibilidad del scan persistido.

use app_lib::core::models::*;
use app_lib::core::storage::Storage;

fn minimal_response(scan_id: &str, started_at: &str) -> ScanNowResponse {
    ScanNowResponse {
        scan_id: scan_id.to_string(),
        schema_version: "v1".to_string(),
        started_at: started_at.to_string(),
        finished_at: started_at.to_string(),
        duration_ms: 1500,
        host: HostInfo {
            platform: "windows".to_string(),
            hostname: "TEST-PC".to_string(),
            app_version: "0.5.0".to_string(),
        },
        summary: ScanSummary {
            total_observations: 1,
            accepted_count: 1,
            review_count: 0,
            danger_count: 0,
            unknown_count: 1,
            candidate_count: 0,
            revalidation_count: 0,
            orphaned_count: 0,
        },
        findings: vec![Finding {
            finding_id: format!("FND-{}-0", scan_id),
            protocol: "TCP".to_string(),
            state: "ESTABLISHED".to_string(),
            local: LocalEndpoint {
                ip: "192.168.1.2".to_string(),
                port: 50000,
            },
            remote: RemoteEndpoint {
                ip: "1.1.1.1".to_string(),
                port: 443,
                hostname: Some("one.one.one.one".to_string()),
                root_domain: Some("one.one".to_string()),
                asn_org: None,
                country: None,
            },
            process: ProcessInfo {
                pid: 77,
                name: "curl.exe".to_string(),
                started_at: None,
                path: Some("C:\\Windows\\System32\\curl.exe".to_string()),
                path_class: "Windows".to_string(),
                file_missing: false,
                orphaned: false,
                services: vec![],
                ppid: Some(1),
                parent_name: Some("cmd.exe".to_string()),
                command_line: Some("curl https://one.one.one.one".to_string()),
                user: Some("TEST-PC\\dev".to_string()),
            },
            binary_identity: BinaryIdentity {
                volume_serial: Some("11223344".to_string()),
                file_id: Some("0000000000000042".to_string()),
                file_size: 55555,
                last_write_time: Some("2026-01-01T00:00:00+00:00".to_string()),
                sha256: Some("f".repeat(64)),
                hash_source: Some("fresh".to_string()),
            },
            trust: TrustInfo {
                signature_status: "Valid".to_string(),
                signature_source: "catalog".to_string(),
                signer_subject: Some("CN=Microsoft Windows".to_string()),
                signer_thumbprint: Some("00FF".to_string()),
                chain_status: "Trusted".to_string(),
            },
            baseline: BaselineInfo {
                state: "Unknown".to_string(),
                seen_count: 1,
                distinct_days: 1,
                first_seen: Some(started_at.to_string()),
                last_seen: Some(started_at.to_string()),
                manual_validation: false,
            },
            affinity: AffinityInfo {
                score: 10,
                level: "none".to_string(),
                matched_signals: vec!["COMMON_PORT".to_string()],
                mismatched_signals: vec!["NO_HISTORICAL_PROFILE".to_string()],
            },
            intel: IntelInfo {
                consulted: false,
                virustotal: VtIntel::default(),
                abuseipdb: AbuseIpdbIntel::default(),
                llm: LlmIntel::default(),
            },
            risk: RiskInfo {
                score: 20,
                band: "known_low".to_string(),
                reason_codes: vec!["UNKNOWN_BASELINE".to_string()],
                recommended_action: "observe".to_string(),
            },
        }],
    }
}

#[test]
fn schema_creation_is_idempotent_on_same_file() {
    let db_path = std::env::temp_dir().join("ocm_storage_test_idempotent.db");
    let _ = std::fs::remove_file(&db_path);

    {
        let storage = Storage::new(db_path.clone()).expect("first open");
        storage
            .save_scan_results(&minimal_response("SCAN-A", "2026-07-09T09:00:00+00:00"))
            .expect("save should work");
    }
    {
        // Reabrir sobre el mismo archivo re-ejecuta migraciones sin fallar.
        let storage = Storage::new(db_path.clone()).expect("second open");
        let history = storage.get_scan_history(10).expect("history should work");
        assert_eq!(history.len(), 1);
    }

    let _ = std::fs::remove_file(&db_path);
}

#[test]
fn scan_roundtrip_preserves_full_contract_payload() {
    let storage = Storage::new_in_memory().unwrap();
    let response = minimal_response("SCAN-B", "2026-07-09T10:00:00+00:00");
    storage.save_scan_results(&response).unwrap();

    let restored = storage
        .get_scan_response("SCAN-B")
        .expect("query ok")
        .expect("scan must exist");

    // El scan restaurado es fiel al original (base del export reproducible).
    assert_eq!(restored.scan_id, response.scan_id);
    assert_eq!(restored.findings.len(), 1);
    let f = &restored.findings[0];
    assert_eq!(
        f.binary_identity.sha256,
        response.findings[0].binary_identity.sha256
    );
    assert_eq!(f.trust.signature_source, "catalog");
    assert_eq!(f.affinity.matched_signals, vec!["COMMON_PORT".to_string()]);
    assert_eq!(f.baseline.state, "Unknown");
}

#[test]
fn history_is_ordered_most_recent_first_with_summary_counts() {
    let storage = Storage::new_in_memory().unwrap();
    storage
        .save_scan_results(&minimal_response("SCAN-OLD", "2026-07-08T09:00:00+00:00"))
        .unwrap();
    storage
        .save_scan_results(&minimal_response("SCAN-NEW", "2026-07-09T09:00:00+00:00"))
        .unwrap();

    let history = storage.get_scan_history(10).unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].scan_id, "SCAN-NEW");
    assert_eq!(history[1].scan_id, "SCAN-OLD");
    assert_eq!(history[0].total_observations, 1);
    assert_eq!(history[0].accepted_count, 1);
    assert_eq!(history[0].danger_count, 0);
}

#[test]
fn missing_scan_returns_none_not_error() {
    let storage = Storage::new_in_memory().unwrap();
    let result = storage.get_scan_response("SCAN-GHOST").unwrap();
    assert!(result.is_none());
}

#[test]
fn normalized_findings_are_queryable_by_scan() {
    let storage = Storage::new_in_memory().unwrap();
    storage
        .save_scan_results(&minimal_response("SCAN-C", "2026-07-09T11:00:00+00:00"))
        .unwrap();

    let conn = storage.conn.lock().unwrap();
    let count: u32 = conn
        .query_row(
            "SELECT COUNT(*) FROM network_observations WHERE scan_id = 'SCAN-C'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);

    // La decisión de riesgo persiste afinidad (antes quedaba a NULL).
    let (affinity_score, affinity_level): (u32, String) = conn
        .query_row(
            "SELECT affinity_score, affinity_level FROM risk_decisions WHERE finding_id = 'FND-SCAN-C-0'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(affinity_score, 10);
    assert_eq!(affinity_level, "none");

    // hostname/root_domain también se persisten en la observación.
    let (hostname, root_domain): (Option<String>, Option<String>) = conn
        .query_row(
            "SELECT hostname, root_domain FROM network_observations WHERE finding_id = 'FND-SCAN-C-0'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(hostname.as_deref(), Some("one.one.one.one"));
    assert_eq!(root_domain.as_deref(), Some("one.one"));
}

#[test]
fn audit_events_are_recorded() {
    let storage = Storage::new_in_memory().unwrap();
    storage
        .record_audit_event(Some("SCAN-D"), "scan_started", "test message")
        .unwrap();
    storage
        .record_audit_event(None, "baseline_transition", "abc: Unknown -> Candidate")
        .unwrap();

    let conn = storage.conn.lock().unwrap();
    let count: u32 = conn
        .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 2);

    let (event_type, message): (String, String) = conn
        .query_row(
            "SELECT event_type, message FROM audit_events WHERE scan_id = 'SCAN-D'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(event_type, "scan_started");
    assert_eq!(message, "test message");
}

#[test]
fn manual_decisions_are_recorded_with_notes() {
    let storage = Storage::new_in_memory().unwrap();
    let sha = "9".repeat(64);
    storage
        .record_manual_decision(&sha, "validate_local", Some("herramienta interna de build"))
        .unwrap();

    let conn = storage.conn.lock().unwrap();
    let (decision_type, notes): (String, Option<String>) = conn
        .query_row(
            "SELECT decision_type, notes FROM manual_decisions WHERE binary_id = ?1",
            [&sha],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(decision_type, "validate_local");
    assert_eq!(notes.as_deref(), Some("herramienta interna de build"));
}

#[test]
fn previous_scan_query_uses_persisted_chronology() {
    let storage = Storage::new_in_memory().unwrap();
    storage
        .save_scan_results(&minimal_response("SCAN-1", "2026-07-08T09:00:00+00:00"))
        .unwrap();
    storage
        .save_scan_results(&minimal_response("SCAN-2", "2026-07-09T09:00:00+00:00"))
        .unwrap();
    storage
        .save_scan_results(&minimal_response("SCAN-3", "2026-07-10T09:00:00+00:00"))
        .unwrap();

    let previous = storage
        .get_previous_scan_response("SCAN-3")
        .unwrap()
        .expect("previous scan");
    assert_eq!(previous.scan_id, "SCAN-2");
    assert!(storage
        .get_previous_scan_response("SCAN-1")
        .unwrap()
        .is_none());
}

#[test]
fn baseline_management_projection_exposes_counters_and_validation() {
    let storage = Storage::new_in_memory().unwrap();
    let sha = "a".repeat(64);
    storage
        .write_baseline_entry(
            &sha,
            &BaselineInfo {
                state: "Observed_Local".to_string(),
                seen_count: 7,
                distinct_days: 3,
                first_seen: Some("2026-07-01T09:00:00+00:00".to_string()),
                last_seen: Some("2026-07-10T09:00:00+00:00".to_string()),
                manual_validation: true,
            },
        )
        .unwrap();
    storage
        .save_trust_record(
            &sha,
            &TrustInfo {
                signature_status: "Valid".to_string(),
                signature_source: "embedded".to_string(),
                signer_subject: Some("CN=Test".to_string()),
                signer_thumbprint: None,
                chain_status: "Trusted".to_string(),
            },
        )
        .unwrap();
    storage
        .record_manual_decision(&sha, "validate_local", None)
        .unwrap();

    let entries = storage.get_baseline_entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].sha256, sha);
    assert_eq!(entries[0].state, "Observed_Local");
    assert_eq!(entries[0].seen_count, 7);
    assert_eq!(entries[0].distinct_days, 3);
    assert!(entries[0].manual_validation);
    assert_eq!(entries[0].signature_status.as_deref(), Some("Valid"));
    assert_eq!(
        entries[0].last_manual_decision.as_deref(),
        Some("validate_local")
    );
}
