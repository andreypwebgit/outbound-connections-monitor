//! Tests de contrato: valida que las respuestas de `scan_now` cumplen el
//! shape de docs/scan-now-contract.json (testing-strategy.md, capa 1).
//!
//! Se usa un validador mínimo del subset de JSON Schema que emplea el
//! contrato (type, required, properties, additionalProperties, enum, const,
//! items, minimum/maximum) para no añadir dependencias externas.

use app_lib::core::models::*;
use serde_json::Value;

// ----------------------------------------------------------------------
// Mini-validador del subset de JSON Schema usado por el contrato
// ----------------------------------------------------------------------

fn validate(value: &Value, schema: &Value, path: &str, errors: &mut Vec<String>) {
    // const
    if let Some(expected) = schema.get("const") {
        if value != expected {
            errors.push(format!(
                "{}: expected const {}, got {}",
                path, expected, value
            ));
        }
    }

    // enum
    if let Some(allowed) = schema.get("enum").and_then(|e| e.as_array()) {
        if !allowed.contains(value) {
            errors.push(format!(
                "{}: value {} not in enum {:?}",
                path, value, allowed
            ));
        }
    }

    // type (string o array de strings)
    if let Some(type_spec) = schema.get("type") {
        let types: Vec<String> = match type_spec {
            Value::String(s) => vec![s.clone()],
            Value::Array(arr) => arr
                .iter()
                .filter_map(|t| t.as_str().map(String::from))
                .collect(),
            _ => vec![],
        };
        if !types.is_empty() && !types.iter().any(|t| matches_type(value, t)) {
            errors.push(format!(
                "{}: type mismatch, expected {:?}, got {}",
                path, types, value
            ));
            return;
        }
    }

    // minimum / maximum
    if let (Some(min), Some(n)) = (
        schema.get("minimum").and_then(|m| m.as_f64()),
        value.as_f64(),
    ) {
        if n < min {
            errors.push(format!("{}: {} below minimum {}", path, n, min));
        }
    }
    if let (Some(max), Some(n)) = (
        schema.get("maximum").and_then(|m| m.as_f64()),
        value.as_f64(),
    ) {
        if n > max {
            errors.push(format!("{}: {} above maximum {}", path, n, max));
        }
    }

    // object: required / properties / additionalProperties
    if let Value::Object(map) = value {
        if let Some(required) = schema.get("required").and_then(|r| r.as_array()) {
            for key in required.iter().filter_map(|k| k.as_str()) {
                if !map.contains_key(key) {
                    errors.push(format!("{}: missing required property '{}'", path, key));
                }
            }
        }
        let properties = schema.get("properties").and_then(|p| p.as_object());
        if let Some(props) = properties {
            for (key, val) in map {
                match props.get(key) {
                    Some(subschema) => {
                        validate(val, subschema, &format!("{}.{}", path, key), errors)
                    }
                    None => {
                        if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
                            errors.push(format!(
                                "{}: unexpected additional property '{}'",
                                path, key
                            ));
                        }
                    }
                }
            }
        }
    }

    // array: items
    if let (Value::Array(arr), Some(items)) = (value, schema.get("items")) {
        for (i, item) in arr.iter().enumerate() {
            validate(item, items, &format!("{}[{}]", path, i), errors);
        }
    }
}

fn matches_type(value: &Value, type_name: &str) -> bool {
    match type_name {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "integer" => value.is_i64() || value.is_u64(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => false,
    }
}

fn load_contract() -> Value {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../docs/scan-now-contract.json"
    ))
    .expect("contract file must exist");
    serde_json::from_str(&raw).expect("contract must be valid JSON")
}

fn assert_valid(response: &ScanNowResponse) {
    let contract = load_contract();
    let value = serde_json::to_value(response).expect("response must serialize");
    let mut errors = Vec::new();
    validate(&value, &contract, "$", &mut errors);
    assert!(
        errors.is_empty(),
        "contract violations:\n{}",
        errors.join("\n")
    );
}

// ----------------------------------------------------------------------
// Fixtures
// ----------------------------------------------------------------------

fn full_finding() -> Finding {
    Finding {
        finding_id: "FND-1-0".to_string(),
        protocol: "TCP".to_string(),
        state: "ESTABLISHED".to_string(),
        local: LocalEndpoint {
            ip: "192.168.1.10".to_string(),
            port: 52000,
        },
        remote: RemoteEndpoint {
            ip: "140.82.121.4".to_string(),
            port: 443,
            hostname: Some("lb-140-82-121-4-fra.github.com".to_string()),
            root_domain: Some("github.com".to_string()),
            asn_org: None,
            country: None,
        },
        process: ProcessInfo {
            pid: 4242,
            name: "app.exe".to_string(),
            started_at: Some("2026-07-09T08:00:00+00:00".to_string()),
            path: Some("C:\\Program Files\\App\\app.exe".to_string()),
            path_class: "ProgramFiles".to_string(),
            file_missing: false,
            orphaned: false,
            services: vec!["AppSvc".to_string()],
            ppid: Some(1000),
            parent_name: Some("services.exe".to_string()),
            command_line: Some("\"C:\\Program Files\\App\\app.exe\" --run".to_string()),
            user: Some("NT AUTHORITY\\SYSTEM".to_string()),
        },
        binary_identity: BinaryIdentity {
            volume_serial: Some("1A2B3C4D".to_string()),
            file_id: Some("0000000000A1B2C3".to_string()),
            file_size: 123456,
            last_write_time: Some("2026-06-01T10:00:00+00:00".to_string()),
            sha256: Some(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            ),
            hash_source: Some("cache".to_string()),
        },
        trust: TrustInfo {
            signature_status: "Valid".to_string(),
            signature_source: "embedded".to_string(),
            signer_subject: Some("CN=App Vendor".to_string()),
            signer_thumbprint: Some("AABBCCDD".to_string()),
            chain_status: "Trusted".to_string(),
        },
        baseline: BaselineInfo {
            state: "Baseline_Consolidated".to_string(),
            seen_count: 42,
            distinct_days: 12,
            first_seen: Some("2026-05-01T00:00:00+00:00".to_string()),
            last_seen: Some("2026-07-09T08:00:00+00:00".to_string()),
            manual_validation: false,
        },
        affinity: AffinityInfo {
            score: 95,
            level: "high".to_string(),
            matched_signals: vec!["SAME_HOSTNAME".to_string(), "SAME_PORT".to_string()],
            mismatched_signals: vec![],
        },
        intel: IntelInfo {
            consulted: false,
            virustotal: VtIntel {
                consulted: false,
                malicious_votes: None,
            },
            abuseipdb: AbuseIpdbIntel {
                consulted: false,
                abuse_confidence_score: None,
                usage_type: None,
            },
            llm: LlmIntel {
                consulted: false,
                confidence: None,
                summary: None,
            },
        },
        risk: RiskInfo {
            score: 0,
            band: "known_safe".to_string(),
            reason_codes: vec!["KNOWN_HASH".to_string(), "VALID_SIGNATURE".to_string()],
            recommended_action: "ignore".to_string(),
        },
    }
}

/// Finding degradado: proceso huérfano, sin path, sin hash, sin hostname.
/// Todo lo no resuelto debe ser null y seguir cumpliendo el contrato.
fn degraded_finding() -> Finding {
    Finding {
        finding_id: "FND-1-1".to_string(),
        protocol: "TCP".to_string(),
        state: "ESTABLISHED".to_string(),
        local: LocalEndpoint {
            ip: "192.168.1.10".to_string(),
            port: 52001,
        },
        remote: RemoteEndpoint {
            ip: "203.0.113.66".to_string(),
            port: 4444,
            hostname: None,
            root_domain: None,
            asn_org: None,
            country: None,
        },
        process: ProcessInfo {
            pid: 6666,
            name: "Unknown".to_string(),
            started_at: None,
            path: None,
            path_class: "Missing".to_string(),
            file_missing: true,
            orphaned: true,
            services: vec![],
            ppid: None,
            parent_name: None,
            command_line: None,
            user: None,
        },
        binary_identity: BinaryIdentity {
            volume_serial: None,
            file_id: None,
            file_size: 0,
            last_write_time: None,
            sha256: None,
            hash_source: None,
        },
        trust: TrustInfo {
            signature_status: "Unknown".to_string(),
            signature_source: "unknown".to_string(),
            signer_subject: None,
            signer_thumbprint: None,
            chain_status: "Unknown".to_string(),
        },
        baseline: BaselineInfo {
            state: "Potentially_Dangerous".to_string(),
            seen_count: 0,
            distinct_days: 0,
            first_seen: None,
            last_seen: None,
            manual_validation: false,
        },
        affinity: AffinityInfo {
            score: 0,
            level: "none".to_string(),
            matched_signals: vec![],
            mismatched_signals: vec![
                "NO_HISTORICAL_PROFILE".to_string(),
                "IP_ONLY_DESTINATION".to_string(),
            ],
        },
        intel: IntelInfo {
            consulted: false,
            virustotal: VtIntel::default(),
            abuseipdb: AbuseIpdbIntel::default(),
            llm: LlmIntel::default(),
        },
        risk: RiskInfo {
            score: 100,
            band: "potentially_dangerous".to_string(),
            reason_codes: vec!["ORPHANED_IMAGE".to_string()],
            recommended_action: "investigate".to_string(),
        },
    }
}

fn response_with(findings: Vec<Finding>) -> ScanNowResponse {
    let danger = findings
        .iter()
        .filter(|f| f.risk.band == "potentially_dangerous")
        .count() as u32;
    let accepted = findings
        .iter()
        .filter(|f| f.risk.band == "known_safe" || f.risk.band == "known_low")
        .count() as u32;
    ScanNowResponse {
        scan_id: "SCAN-1751980800".to_string(),
        schema_version: "v1".to_string(),
        started_at: "2026-07-09T09:00:00+00:00".to_string(),
        finished_at: "2026-07-09T09:00:07+00:00".to_string(),
        duration_ms: 7000,
        host: HostInfo {
            platform: "windows".to_string(),
            hostname: "TEST-PC".to_string(),
            app_version: "0.5.0".to_string(),
        },
        summary: ScanSummary {
            total_observations: findings.len() as u32,
            accepted_count: accepted,
            review_count: 0,
            danger_count: danger,
            unknown_count: 0,
            candidate_count: 0,
            revalidation_count: 0,
            orphaned_count: findings.iter().filter(|f| f.process.orphaned).count() as u32,
        },
        findings,
    }
}

// ----------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------

#[test]
fn fully_populated_response_satisfies_contract() {
    assert_valid(&response_with(vec![full_finding()]));
}

#[test]
fn degraded_response_satisfies_contract_with_honest_nulls() {
    // Escenario 9 de testing-strategy: degradación sin path ni trust.
    assert_valid(&response_with(vec![degraded_finding()]));
}

#[test]
fn mixed_response_satisfies_contract() {
    assert_valid(&response_with(vec![full_finding(), degraded_finding()]));
}

#[test]
fn empty_findings_response_satisfies_contract() {
    assert_valid(&response_with(vec![]));
}

#[test]
fn validator_rejects_invalid_baseline_state() {
    let mut finding = full_finding();
    finding.baseline.state = "Totally_Fine".to_string(); // estado inventado

    let contract = load_contract();
    let value = serde_json::to_value(response_with(vec![finding])).unwrap();
    let mut errors = Vec::new();
    validate(&value, &contract, "$", &mut errors);
    assert!(
        errors.iter().any(|e| e.contains("baseline.state")),
        "invented baseline states must be caught: {:?}",
        errors
    );
}

#[test]
fn validator_rejects_invalid_band_and_action() {
    let mut finding = full_finding();
    finding.risk.band = "mega_safe".to_string();
    finding.risk.recommended_action = "panic".to_string();

    let contract = load_contract();
    let value = serde_json::to_value(response_with(vec![finding])).unwrap();
    let mut errors = Vec::new();
    validate(&value, &contract, "$", &mut errors);
    assert!(errors.iter().any(|e| e.contains("risk.band")));
    assert!(errors.iter().any(|e| e.contains("recommended_action")));
}

#[test]
fn validator_rejects_hash_source_outside_enum() {
    let mut finding = full_finding();
    finding.binary_identity.hash_source = Some("guessed".to_string());

    let contract = load_contract();
    let value = serde_json::to_value(response_with(vec![finding])).unwrap();
    let mut errors = Vec::new();
    validate(&value, &contract, "$", &mut errors);
    assert!(errors.iter().any(|e| e.contains("hash_source")));
}

#[test]
fn validator_rejects_missing_required_top_level_field() {
    let contract = load_contract();
    let mut value = serde_json::to_value(response_with(vec![])).unwrap();
    value.as_object_mut().unwrap().remove("summary");
    let mut errors = Vec::new();
    validate(&value, &contract, "$", &mut errors);
    assert!(errors
        .iter()
        .any(|e| e.contains("missing required property 'summary'")));
}
