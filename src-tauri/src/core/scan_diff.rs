use std::collections::{HashMap, HashSet};

use crate::core::models::{Finding, FindingComparison, ScanComparison, ScanNowResponse};

pub struct ScanDiff;

impl ScanDiff {
    pub fn compare(
        current: &ScanNowResponse,
        previous: Option<&ScanNowResponse>,
    ) -> ScanComparison {
        let Some(previous) = previous else {
            return ScanComparison {
                scan_id: current.scan_id.clone(),
                previous_scan_id: None,
                new_connections_count: 0,
                changed_connections_count: 0,
                new_binaries_count: 0,
                baseline_changes_count: 0,
                findings: current
                    .findings
                    .iter()
                    .map(|finding| FindingComparison {
                        finding_id: finding.finding_id.clone(),
                        is_new_connection: false,
                        connection_changed: false,
                        is_new_binary: false,
                        previous_baseline_state: None,
                    })
                    .collect(),
            };
        };

        let previous_binaries: HashSet<String> = previous.findings.iter().map(binary_key).collect();
        let previous_baselines: HashMap<String, String> = previous
            .findings
            .iter()
            .map(|finding| (binary_key(finding), finding.baseline.state.clone()))
            .collect();
        let previous_connections: HashSet<String> =
            previous.findings.iter().map(connection_key).collect();
        let previous_connection_states: HashSet<(String, String)> = previous
            .findings
            .iter()
            .map(|finding| (connection_key(finding), finding.state.clone()))
            .collect();

        let mut new_connection_keys = HashSet::new();
        let mut changed_connection_keys = HashSet::new();
        let mut new_binary_keys = HashSet::new();
        let mut baseline_change_keys = HashSet::new();
        let mut findings = Vec::with_capacity(current.findings.len());

        for finding in &current.findings {
            let binary = binary_key(finding);
            let connection = connection_key(finding);
            let is_new_binary = !previous_binaries.contains(&binary);
            let is_new_connection = !previous_connections.contains(&connection);
            let connection_changed = !is_new_connection
                && !previous_connection_states
                    .contains(&(connection.clone(), finding.state.clone()));
            let previous_baseline_state = previous_baselines
                .get(&binary)
                .and_then(|state| (state != &finding.baseline.state).then(|| state.clone()));

            if is_new_connection {
                new_connection_keys.insert(connection.clone());
            }
            if connection_changed {
                changed_connection_keys.insert(connection);
            }
            if is_new_binary {
                new_binary_keys.insert(binary.clone());
            }
            if previous_baseline_state.is_some() {
                baseline_change_keys.insert(binary);
            }

            findings.push(FindingComparison {
                finding_id: finding.finding_id.clone(),
                is_new_connection,
                connection_changed,
                is_new_binary,
                previous_baseline_state,
            });
        }

        ScanComparison {
            scan_id: current.scan_id.clone(),
            previous_scan_id: Some(previous.scan_id.clone()),
            new_connections_count: new_connection_keys.len() as u32,
            changed_connections_count: changed_connection_keys.len() as u32,
            new_binaries_count: new_binary_keys.len() as u32,
            baseline_changes_count: baseline_change_keys.len() as u32,
            findings,
        }
    }
}

fn binary_key(finding: &Finding) -> String {
    if let Some(sha256) = finding.binary_identity.sha256.as_deref() {
        return format!("sha256:{}", sha256.to_ascii_lowercase());
    }
    if let Some(path) = finding.process.path.as_deref() {
        return format!("path:{}", path.to_lowercase());
    }
    format!("process:{}", finding.process.name.to_lowercase())
}

fn connection_key(finding: &Finding) -> String {
    format!(
        "{}|{}|{}|{}",
        binary_key(finding),
        finding.protocol.to_ascii_uppercase(),
        finding.remote.ip.to_ascii_lowercase(),
        finding.remote.port
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::models::{
        AbuseIpdbIntel, AffinityInfo, BaselineInfo, BinaryIdentity, HostInfo, IntelInfo, LlmIntel,
        LocalEndpoint, ProcessInfo, RemoteEndpoint, RiskInfo, ScanSummary, TrustInfo, VtIntel,
    };

    fn scan(id: &str, findings: Vec<Finding>) -> ScanNowResponse {
        ScanNowResponse {
            scan_id: id.to_string(),
            schema_version: "v1".to_string(),
            started_at: "2026-07-10T10:00:00Z".to_string(),
            finished_at: "2026-07-10T10:00:00Z".to_string(),
            duration_ms: 10,
            host: HostInfo {
                platform: "windows".to_string(),
                hostname: "test".to_string(),
                app_version: "0.5.0".to_string(),
            },
            summary: ScanSummary::default(),
            findings,
        }
    }

    fn finding(
        id: &str,
        sha: &str,
        remote: &str,
        port: u16,
        state: &str,
        baseline: &str,
    ) -> Finding {
        Finding {
            finding_id: id.to_string(),
            protocol: "TCP".to_string(),
            state: state.to_string(),
            local: LocalEndpoint {
                ip: "192.168.1.2".to_string(),
                port: 50_000,
            },
            remote: RemoteEndpoint {
                ip: remote.to_string(),
                port,
                hostname: None,
                root_domain: None,
                asn_org: None,
                country: None,
            },
            process: ProcessInfo {
                pid: 1,
                name: "test.exe".to_string(),
                started_at: None,
                path: Some("C:\\test.exe".to_string()),
                path_class: "Other".to_string(),
                file_missing: false,
                orphaned: false,
                services: vec![],
                ppid: None,
                parent_name: None,
                command_line: None,
                user: None,
            },
            binary_identity: BinaryIdentity {
                volume_serial: None,
                file_id: None,
                file_size: 1,
                last_write_time: None,
                sha256: Some(sha.to_string()),
                hash_source: Some("cache".to_string()),
            },
            trust: TrustInfo {
                signature_status: "Unknown".to_string(),
                signature_source: "unknown".to_string(),
                signer_subject: None,
                signer_thumbprint: None,
                chain_status: "Unknown".to_string(),
            },
            baseline: BaselineInfo {
                state: baseline.to_string(),
                seen_count: 1,
                distinct_days: 1,
                first_seen: None,
                last_seen: None,
                manual_validation: false,
            },
            affinity: AffinityInfo {
                score: 0,
                level: "none".to_string(),
                matched_signals: vec![],
                mismatched_signals: vec![],
            },
            intel: IntelInfo {
                consulted: false,
                virustotal: VtIntel::default(),
                abuseipdb: AbuseIpdbIntel::default(),
                llm: LlmIntel::default(),
            },
            risk: RiskInfo {
                score: 0,
                band: "unknown".to_string(),
                reason_codes: vec![],
                recommended_action: "observe".to_string(),
            },
        }
    }

    #[test]
    fn first_scan_has_no_false_new_markers_without_reference() {
        let current = scan(
            "SCAN-1",
            vec![finding(
                "F-1",
                "a",
                "1.1.1.1",
                443,
                "ESTABLISHED",
                "Unknown",
            )],
        );
        let comparison = ScanDiff::compare(&current, None);
        assert_eq!(comparison.previous_scan_id, None);
        assert_eq!(comparison.new_connections_count, 0);
        assert!(!comparison.findings[0].is_new_connection);
    }

    #[test]
    fn detects_new_connection_binary_and_baseline_change() {
        let previous = scan(
            "SCAN-1",
            vec![finding("F-1", "a", "1.1.1.1", 443, "SYN_SENT", "Unknown")],
        );
        let current = scan(
            "SCAN-2",
            vec![
                finding("F-2", "a", "1.1.1.1", 443, "ESTABLISHED", "Candidate"),
                finding("F-3", "b", "8.8.8.8", 53, "ESTABLISHED", "Unknown"),
            ],
        );

        let comparison = ScanDiff::compare(&current, Some(&previous));
        assert_eq!(comparison.previous_scan_id.as_deref(), Some("SCAN-1"));
        assert_eq!(comparison.new_connections_count, 1);
        assert_eq!(comparison.changed_connections_count, 1);
        assert_eq!(comparison.new_binaries_count, 1);
        assert_eq!(comparison.baseline_changes_count, 1);
        assert_eq!(
            comparison.findings[0].previous_baseline_state.as_deref(),
            Some("Unknown")
        );
        assert!(comparison.findings[0].connection_changed);
        assert!(comparison.findings[1].is_new_connection);
        assert!(comparison.findings[1].is_new_binary);
    }

    #[test]
    fn duplicate_sockets_count_as_one_connection_difference() {
        let previous = scan("SCAN-1", vec![]);
        let current = scan(
            "SCAN-2",
            vec![
                finding("F-1", "a", "1.1.1.1", 443, "ESTABLISHED", "Unknown"),
                finding("F-2", "a", "1.1.1.1", 443, "ESTABLISHED", "Unknown"),
            ],
        );
        let comparison = ScanDiff::compare(&current, Some(&previous));
        assert_eq!(comparison.new_connections_count, 1);
        assert_eq!(comparison.new_binaries_count, 1);
    }
}
