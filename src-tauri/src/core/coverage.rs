use crate::core::enricher::Enricher;
use crate::core::models::{
    CollectorCoverage, DnsCoverage, Finding, IdentityCoverage, ProcessCoverage, ScanCoverage,
};

pub const LIMIT_POINT_IN_TIME: &str = "POINT_IN_TIME_SNAPSHOT";
pub const LIMIT_UDP_NO_REMOTE_PEER: &str = "UDP_REMOTE_PEER_NOT_AVAILABLE";
pub const LIMIT_EXTERNAL_INTEL_DISABLED: &str = "EXTERNAL_INTEL_NOT_ENABLED";
pub const LIMIT_DNS_BUDGET: &str = "DNS_RESOLUTION_BUDGET_200_MS";

pub struct CoverageSignals<'a> {
    pub elevated: Option<bool>,
    pub tcp_ipv4_collected: bool,
    pub tcp_ipv6_collected: bool,
    pub udp_ipv4_collected: bool,
    pub udp_ipv6_collected: bool,
    pub udp_owner_endpoints: u32,
    pub collector_warnings: &'a [String],
    pub enricher_warnings: &'a [String],
    pub dns: DnsCoverage,
}

pub struct CoverageEngine;

impl CoverageEngine {
    pub fn evaluate(signals: CoverageSignals<'_>, findings: &[Finding]) -> ScanCoverage {
        let process = process_coverage(findings);
        let identity = identity_coverage(findings);
        let warnings = signals
            .collector_warnings
            .iter()
            .chain(signals.enricher_warnings.iter())
            .cloned()
            .collect::<Vec<_>>();

        let collector = CollectorCoverage {
            tcp_ipv4_collected: signals.tcp_ipv4_collected,
            tcp_ipv6_collected: signals.tcp_ipv6_collected,
            tcp_observations: findings.len() as u32,
            udp_ipv4_collected: signals.udp_ipv4_collected,
            udp_ipv6_collected: signals.udp_ipv6_collected,
            udp_owner_endpoints: signals.udp_owner_endpoints,
            // GetExtendedUdpTable no expone el peer remoto. Mantenerlo
            // explícitamente en cero evita presentar endpoints como findings.
            udp_findings: 0,
        };

        let material_identity_gap = findings.iter().any(|finding| {
            !Enricher::is_protected_system_process(&finding.process.name)
                && (finding.process.path.is_none()
                    || finding.binary_identity.sha256.is_none()
                    || finding.trust.signature_status == "Unknown")
        });
        let contextual_gap = findings.iter().any(|finding| {
            !Enricher::is_protected_system_process(&finding.process.name)
                && (finding.process.user.is_none()
                    || finding.process.command_line.is_none()
                    || finding.process.ppid.is_none()
                    || finding.process.parent_name.is_none())
        });

        let status = if !collector.tcp_ipv4_collected
            || !collector.tcp_ipv6_collected
            || material_identity_gap
        {
            "degraded"
        } else if signals.elevated != Some(true)
            || !collector.udp_ipv4_collected
            || !collector.udp_ipv6_collected
            || contextual_gap
            || !warnings.is_empty()
            || signals.dns.timed_out > 0
        {
            "partial"
        } else {
            "complete"
        };

        ScanCoverage {
            status: status.to_string(),
            elevated: signals.elevated,
            collector,
            process,
            identity,
            dns: signals.dns,
            limitations: vec![
                LIMIT_POINT_IN_TIME.to_string(),
                LIMIT_UDP_NO_REMOTE_PEER.to_string(),
                LIMIT_EXTERNAL_INTEL_DISABLED.to_string(),
                LIMIT_DNS_BUDGET.to_string(),
            ],
            warnings,
        }
    }
}

fn process_coverage(findings: &[Finding]) -> ProcessCoverage {
    let mut coverage = ProcessCoverage {
        findings: findings.len() as u32,
        ..ProcessCoverage::default()
    };

    for finding in findings {
        let process = &finding.process;
        let protected = Enricher::is_protected_system_process(&process.name);
        if protected {
            coverage.protected_system_findings += 1;
        }
        if process.path.is_some() {
            coverage.path_resolved += 1;
        }
        if process.user.is_some() {
            coverage.user_resolved += 1;
        }
        if process.command_line.is_some() {
            coverage.command_line_resolved += 1;
        }
        if process.ppid.is_some() && process.parent_name.is_some() {
            coverage.parent_resolved += 1;
        }
        if process.path.is_some()
            && process.user.is_some()
            && process.command_line.is_some()
            && process.ppid.is_some()
            && process.parent_name.is_some()
        {
            coverage.complete_context += 1;
        }
    }

    coverage
}

fn identity_coverage(findings: &[Finding]) -> IdentityCoverage {
    let mut coverage = IdentityCoverage::default();

    for finding in findings {
        match finding.binary_identity.hash_source.as_deref() {
            Some("fresh") => coverage.hash_fresh += 1,
            Some("cache") => coverage.hash_cache += 1,
            _ => coverage.hash_unavailable += 1,
        }

        if finding.trust.signature_status == "Unknown" {
            coverage.trust_unknown += 1;
        } else {
            coverage.trust_resolved += 1;
        }

        if finding.binary_identity.sha256.is_some()
            && finding.binary_identity.volume_serial.is_some()
            && finding.binary_identity.file_id.is_some()
            && finding.binary_identity.last_write_time.is_some()
            && finding.trust.signature_status != "Unknown"
        {
            coverage.complete_identity += 1;
        }
    }

    coverage
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::models::*;

    fn finding(complete: bool, protected: bool) -> Finding {
        Finding {
            finding_id: "FND-1".to_string(),
            protocol: "TCP".to_string(),
            state: "ESTABLISHED".to_string(),
            local: LocalEndpoint {
                ip: "192.168.1.2".to_string(),
                port: 50_000,
            },
            remote: RemoteEndpoint {
                ip: "1.1.1.1".to_string(),
                port: 443,
                hostname: None,
                root_domain: None,
                asn_org: None,
                country: None,
            },
            process: ProcessInfo {
                pid: 42,
                name: if protected { "System" } else { "app.exe" }.to_string(),
                started_at: Some("2026-07-23T10:00:00Z".to_string()),
                path: complete.then(|| "C:\\Program Files\\App\\app.exe".to_string()),
                path_class: if complete { "ProgramFiles" } else { "Missing" }.to_string(),
                file_missing: !complete,
                orphaned: false,
                services: vec![],
                ppid: complete.then_some(4),
                parent_name: complete.then(|| "services.exe".to_string()),
                command_line: complete.then(|| "app.exe --run".to_string()),
                user: complete.then(|| "TEST\\user".to_string()),
            },
            binary_identity: BinaryIdentity {
                volume_serial: complete.then(|| "ABCD".to_string()),
                file_id: complete.then(|| "1234".to_string()),
                file_size: if complete { 10 } else { 0 },
                last_write_time: complete.then(|| "2026-07-23T10:00:00Z".to_string()),
                sha256: complete.then(|| "a".repeat(64)),
                hash_source: complete.then(|| "fresh".to_string()),
            },
            trust: TrustInfo {
                signature_status: if complete { "Valid" } else { "Unknown" }.to_string(),
                signature_source: if complete { "embedded" } else { "unknown" }.to_string(),
                signer_subject: None,
                signer_thumbprint: None,
                chain_status: if complete { "Trusted" } else { "Unknown" }.to_string(),
            },
            baseline: BaselineInfo {
                state: "Unknown".to_string(),
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
                score: 20,
                band: "known_low".to_string(),
                reason_codes: vec![],
                recommended_action: "observe".to_string(),
            },
        }
    }

    fn signals_with_warnings<'a>(
        elevated: Option<bool>,
        collector_warnings: &'a [String],
        enricher_warnings: &'a [String],
    ) -> CoverageSignals<'a> {
        CoverageSignals {
            elevated,
            tcp_ipv4_collected: true,
            tcp_ipv6_collected: true,
            udp_ipv4_collected: true,
            udp_ipv6_collected: true,
            udp_owner_endpoints: 3,
            collector_warnings,
            enricher_warnings,
            dns: DnsCoverage {
                public_ip_candidates: 1,
                cache_hits: 0,
                resolved: 1,
                no_ptr_record: 0,
                timed_out: 0,
            },
        }
    }

    fn signals(elevated: Option<bool>) -> CoverageSignals<'static> {
        signals_with_warnings(elevated, &[], &[])
    }

    #[test]
    fn complete_status_requires_full_core_evidence_and_elevation() {
        let coverage = CoverageEngine::evaluate(signals(Some(true)), &[finding(true, false)]);
        assert_eq!(coverage.status, "complete");
        assert_eq!(coverage.process.complete_context, 1);
        assert_eq!(coverage.identity.complete_identity, 1);
        assert_eq!(coverage.collector.udp_findings, 0);
    }

    #[test]
    fn standard_user_or_dns_timeout_is_partial_not_secure_or_insecure() {
        let mut input = signals(Some(false));
        input.dns.timed_out = 1;
        let coverage = CoverageEngine::evaluate(input, &[finding(true, false)]);
        assert_eq!(coverage.status, "partial");
        assert_eq!(coverage.elevated, Some(false));
        assert_eq!(coverage.dns.timed_out, 1);
    }

    #[test]
    fn missing_tcp_family_or_non_protected_identity_is_degraded() {
        let mut input = signals(Some(true));
        input.tcp_ipv6_collected = false;
        let coverage = CoverageEngine::evaluate(input, &[finding(false, false)]);
        assert_eq!(coverage.status, "degraded");
        assert_eq!(coverage.identity.hash_unavailable, 1);
        assert!(!coverage.collector.tcp_ipv6_collected);
    }

    #[test]
    fn protected_process_gaps_are_counted_without_forcing_degraded_status() {
        let coverage = CoverageEngine::evaluate(signals(Some(true)), &[finding(false, true)]);
        assert_eq!(coverage.status, "complete");
        assert_eq!(coverage.process.protected_system_findings, 1);
        assert_eq!(coverage.identity.hash_unavailable, 1);
    }

    #[test]
    fn warnings_and_udp_family_failure_make_evidence_partial() {
        let warnings = vec!["service enumeration unavailable".to_string()];
        let mut input = signals_with_warnings(Some(true), &[], &warnings);
        input.udp_ipv6_collected = false;
        let coverage = CoverageEngine::evaluate(input, &[finding(true, false)]);
        assert_eq!(coverage.status, "partial");
        assert_eq!(coverage.warnings, warnings);
    }
}
