use std::fs;
use std::path::Path;

use crate::core::errors::AppError;
use crate::core::models::{Finding, ScanNowResponse};

pub struct Exporter;

impl Exporter {
    /// Exporta el scan a JSON con el mismo shape del contrato `scan_now`
    /// (docs/export-format.md: el JSON exportado respeta el contrato).
    pub fn export_to_json(
        response: &ScanNowResponse,
        path: impl AsRef<Path>,
    ) -> Result<(), AppError> {
        let json = serde_json::to_string_pretty(response)
            .map_err(|e| AppError::SystemError(format!("JSON serialization failed: {}", e)))?;

        fs::write(path, json).map_err(AppError::IoError)?;

        Ok(())
    }

    /// Exporta una vista HTML legible y autónoma (sin recursos externos).
    /// Contenido mínimo según docs/export-format.md: fecha, resumen global,
    /// findings con banda, baseline, proceso/ruta/destino, reason codes y
    /// recomendación. No reinterpreta datos: lo no resuelto se muestra como
    /// "unknown".
    pub fn export_to_html(
        response: &ScanNowResponse,
        path: impl AsRef<Path>,
    ) -> Result<(), AppError> {
        let html = Self::render_html(response);
        fs::write(path, html).map_err(AppError::IoError)?;
        Ok(())
    }

    pub fn render_html(response: &ScanNowResponse) -> String {
        let s = &response.summary;
        let coverage_html = Self::render_coverage(response);
        let mut findings_html = String::new();
        for finding in &response.findings {
            findings_html.push_str(&Self::render_finding(finding));
        }

        format!(
            r#"<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Scan {scan_id}</title>
<style>
  body {{ font-family: system-ui, -apple-system, "Segoe UI", sans-serif; margin: 2rem auto; max-width: 72rem; color: #1f2937; padding: 0 1rem; }}
  h1 {{ font-size: 1.4rem; }}
  h2 {{ font-size: 1.1rem; margin-top: 2rem; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 0.85rem; }}
  th, td {{ border: 1px solid #d1d5db; padding: 0.4rem 0.6rem; text-align: left; vertical-align: top; }}
  th {{ background: #f3f4f6; }}
  .meta {{ color: #6b7280; font-size: 0.85rem; }}
  .band {{ font-weight: 600; white-space: nowrap; }}
  .band-known_safe {{ color: #15803d; }}
  .band-known_low {{ color: #4d7c0f; }}
  .band-known_moderate {{ color: #a16207; }}
  .band-known_high {{ color: #c2410c; }}
  .band-potentially_dangerous {{ color: #b91c1c; }}
  .mono {{ font-family: ui-monospace, Consolas, monospace; font-size: 0.78rem; word-break: break-all; }}
  .summary-grid {{ display: flex; flex-wrap: wrap; gap: 0.75rem; margin: 1rem 0; }}
  .summary-item {{ border: 1px solid #d1d5db; border-radius: 0.4rem; padding: 0.5rem 0.9rem; }}
  .summary-item span {{ display: block; }}
  .summary-item .label {{ font-size: 0.7rem; text-transform: uppercase; color: #6b7280; }}
  .summary-item .value {{ font-size: 1.15rem; font-weight: 600; }}
  .coverage {{ border: 1px solid #d1d5db; border-radius: 0.4rem; padding: 0.9rem; }}
  .coverage-complete {{ border-left: 0.35rem solid #15803d; }}
  .coverage-partial {{ border-left: 0.35rem solid #a16207; }}
  .coverage-degraded {{ border-left: 0.35rem solid #b91c1c; }}
  .coverage-legacy {{ border-left: 0.35rem solid #6b7280; }}
  .coverage ul {{ margin: 0.4rem 0 0; }}
  .reasons {{ margin: 0; padding-left: 1.1rem; }}
</style>
</head>
<body>
<h1>Outbound Connections Monitor — Informe de escaneo</h1>
<p class="meta">
  Scan: {scan_id} · Host: {hostname} · Versión: {app_version}<br>
  Inicio: {started_at} · Fin: {finished_at} · Duración: {duration_ms} ms · Esquema: {schema_version}
</p>

<h2>Resumen</h2>
<div class="summary-grid">
  <div class="summary-item"><span class="label">Observaciones</span><span class="value">{total}</span></div>
  <div class="summary-item"><span class="label">Aceptadas</span><span class="value">{accepted}</span></div>
  <div class="summary-item"><span class="label">Revisión</span><span class="value">{review}</span></div>
  <div class="summary-item"><span class="label">Peligro</span><span class="value">{danger}</span></div>
  <div class="summary-item"><span class="label">Unknown</span><span class="value">{unknown}</span></div>
  <div class="summary-item"><span class="label">Candidate</span><span class="value">{candidate}</span></div>
  <div class="summary-item"><span class="label">Revalidación</span><span class="value">{revalidation}</span></div>
  <div class="summary-item"><span class="label">Huérfanos</span><span class="value">{orphaned}</span></div>
</div>

{coverage}

<h2>Hallazgos ({findings_count})</h2>
<table>
  <thead>
    <tr>
      <th>Proceso</th>
      <th>Destino</th>
      <th>Riesgo</th>
      <th>Baseline</th>
      <th>Afinidad</th>
      <th>Motivos</th>
      <th>Recomendación</th>
    </tr>
  </thead>
  <tbody>
{findings}
  </tbody>
</table>
</body>
</html>
"#,
            scan_id = escape_html(&response.scan_id),
            hostname = escape_html(&response.host.hostname),
            app_version = escape_html(&response.host.app_version),
            started_at = escape_html(&response.started_at),
            finished_at = escape_html(&response.finished_at),
            duration_ms = response.duration_ms,
            schema_version = escape_html(&response.schema_version),
            total = s.total_observations,
            accepted = s.accepted_count,
            review = s.review_count,
            danger = s.danger_count,
            unknown = s.unknown_count,
            candidate = s.candidate_count,
            revalidation = s.revalidation_count,
            orphaned = s.orphaned_count,
            coverage = coverage_html,
            findings_count = response.findings.len(),
            findings = findings_html,
        )
    }

    fn render_coverage(response: &ScanNowResponse) -> String {
        let Some(coverage) = &response.coverage else {
            return r#"<h2>Completitud del scan</h2>
<div class="coverage coverage-legacy">
  <strong>No disponible</strong>
  <p class="meta">Este scan histórico usa un esquema anterior que no registraba cobertura. No se infiere información retrospectiva.</p>
</div>"#
                .to_string();
        };

        let elevated = match coverage.elevated {
            Some(true) => "sí",
            Some(false) => "no",
            None => "no resuelto",
        };
        let limitations = coverage
            .limitations
            .iter()
            .map(|item| format!("<li>{}</li>", escape_html(item)))
            .collect::<Vec<_>>()
            .join("");
        let warnings = if coverage.warnings.is_empty() {
            "<li>Ninguna advertencia técnica.</li>".to_string()
        } else {
            coverage
                .warnings
                .iter()
                .map(|item| format!("<li>{}</li>", escape_html(item)))
                .collect::<Vec<_>>()
                .join("")
        };

        format!(
            r#"<h2>Completitud del scan</h2>
<div class="coverage coverage-{status}">
  <strong>Estado de evidencia: {status}</strong>
  <p class="meta">Ejecución elevada: {elevated}. Este estado describe cobertura, no el nivel de seguridad del equipo.</p>
  <table>
    <tbody>
      <tr><th>Collector</th><td>TCP IPv4: {tcp4} · TCP IPv6: {tcp6} · observaciones TCP: {tcp_total}<br>UDP IPv4: {udp4} · UDP IPv6: {udp6} · endpoints owner: {udp_endpoints} · findings UDP: {udp_findings}</td></tr>
      <tr><th>Procesos</th><td>Contexto completo: {process_complete}/{process_total} · rutas: {paths} · usuarios: {users} · command lines: {cmdlines} · padres: {parents} · protegidos: {protected}</td></tr>
      <tr><th>Identidad</th><td>Completa: {identity_complete}/{process_total} · hash fresh: {hash_fresh} · cache: {hash_cache} · no disponible: {hash_missing} · trust resuelto: {trust_resolved} · unknown: {trust_unknown}</td></tr>
      <tr><th>DNS</th><td>IPs públicas: {dns_candidates} · cache hits: {dns_cache} · resueltas: {dns_resolved} · sin PTR: {dns_no_ptr} · timeout: {dns_timeout}</td></tr>
    </tbody>
  </table>
  <p><strong>Limitaciones conocidas</strong></p>
  <ul>{limitations}</ul>
  <p><strong>Advertencias</strong></p>
  <ul>{warnings}</ul>
</div>"#,
            status = escape_html(&coverage.status),
            elevated = elevated,
            tcp4 = yes_no(coverage.collector.tcp_ipv4_collected),
            tcp6 = yes_no(coverage.collector.tcp_ipv6_collected),
            tcp_total = coverage.collector.tcp_observations,
            udp4 = yes_no(coverage.collector.udp_ipv4_collected),
            udp6 = yes_no(coverage.collector.udp_ipv6_collected),
            udp_endpoints = coverage.collector.udp_owner_endpoints,
            udp_findings = coverage.collector.udp_findings,
            process_complete = coverage.process.complete_context,
            process_total = coverage.process.findings,
            paths = coverage.process.path_resolved,
            users = coverage.process.user_resolved,
            cmdlines = coverage.process.command_line_resolved,
            parents = coverage.process.parent_resolved,
            protected = coverage.process.protected_system_findings,
            identity_complete = coverage.identity.complete_identity,
            hash_fresh = coverage.identity.hash_fresh,
            hash_cache = coverage.identity.hash_cache,
            hash_missing = coverage.identity.hash_unavailable,
            trust_resolved = coverage.identity.trust_resolved,
            trust_unknown = coverage.identity.trust_unknown,
            dns_candidates = coverage.dns.public_ip_candidates,
            dns_cache = coverage.dns.cache_hits,
            dns_resolved = coverage.dns.resolved,
            dns_no_ptr = coverage.dns.no_ptr_record,
            dns_timeout = coverage.dns.timed_out,
            limitations = limitations,
            warnings = warnings,
        )
    }

    fn render_finding(finding: &Finding) -> String {
        let hostname = finding.remote.hostname.as_deref().unwrap_or("unknown");
        let path = finding.process.path.as_deref().unwrap_or("unknown");
        let sha = finding
            .binary_identity
            .sha256
            .as_deref()
            .unwrap_or("unknown");
        let reasons = finding
            .risk
            .reason_codes
            .iter()
            .map(|r| format!("<li>{}</li>", escape_html(r)))
            .collect::<Vec<_>>()
            .join("");

        format!(
            r#"    <tr>
      <td><strong>{name}</strong> (PID {pid})<br><span class="mono">{path}</span><br><span class="mono">SHA-256: {sha}</span><br>Firma: {signature}</td>
      <td>{protocol} {remote_ip}:{remote_port}<br>{hostname}</td>
      <td class="band band-{band}">{band}<br>score {score}</td>
      <td>{baseline}</td>
      <td>{affinity_level} ({affinity_score})</td>
      <td><ul class="reasons">{reasons}</ul></td>
      <td>{action}</td>
    </tr>
"#,
            name = escape_html(&finding.process.name),
            pid = finding.process.pid,
            path = escape_html(path),
            sha = escape_html(sha),
            signature = escape_html(&finding.trust.signature_status),
            protocol = escape_html(&finding.protocol),
            remote_ip = escape_html(&finding.remote.ip),
            remote_port = finding.remote.port,
            hostname = escape_html(hostname),
            band = escape_html(&finding.risk.band),
            score = finding.risk.score,
            baseline = escape_html(&finding.baseline.state),
            affinity_level = escape_html(&finding.affinity.level),
            affinity_score = finding.affinity.score,
            reasons = reasons,
            action = escape_html(&finding.risk.recommended_action),
        )
    }
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "sí"
    } else {
        "no"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::models::*;

    fn sample_response() -> ScanNowResponse {
        ScanNowResponse {
            scan_id: "SCAN-1".to_string(),
            schema_version: "v2".to_string(),
            started_at: "2026-07-09T10:00:00Z".to_string(),
            finished_at: "2026-07-09T10:00:05Z".to_string(),
            duration_ms: 5000,
            host: HostInfo {
                platform: "windows".to_string(),
                hostname: "TEST-PC".to_string(),
                app_version: "1.0.0".to_string(),
            },
            summary: ScanSummary {
                total_observations: 1,
                accepted_count: 0,
                review_count: 1,
                danger_count: 0,
                unknown_count: 1,
                candidate_count: 0,
                revalidation_count: 0,
                orphaned_count: 0,
            },
            coverage: Some(ScanCoverage {
                status: "partial".to_string(),
                elevated: Some(false),
                collector: CollectorCoverage {
                    tcp_ipv4_collected: true,
                    tcp_ipv6_collected: true,
                    tcp_observations: 1,
                    udp_ipv4_collected: true,
                    udp_ipv6_collected: true,
                    udp_owner_endpoints: 4,
                    udp_findings: 0,
                },
                process: ProcessCoverage {
                    findings: 1,
                    protected_system_findings: 0,
                    complete_context: 0,
                    path_resolved: 1,
                    user_resolved: 0,
                    command_line_resolved: 0,
                    parent_resolved: 0,
                },
                identity: IdentityCoverage {
                    complete_identity: 1,
                    hash_fresh: 1,
                    hash_cache: 0,
                    hash_unavailable: 0,
                    trust_resolved: 1,
                    trust_unknown: 0,
                },
                dns: DnsCoverage {
                    public_ip_candidates: 1,
                    cache_hits: 0,
                    resolved: 0,
                    no_ptr_record: 1,
                    timed_out: 0,
                },
                limitations: vec!["POINT_IN_TIME_SNAPSHOT".to_string()],
                warnings: vec![],
            }),
            findings: vec![Finding {
                finding_id: "FND-1".to_string(),
                protocol: "TCP".to_string(),
                state: "ESTABLISHED".to_string(),
                local: LocalEndpoint {
                    ip: "192.168.1.2".to_string(),
                    port: 51000,
                },
                remote: RemoteEndpoint {
                    ip: "8.8.8.8".to_string(),
                    port: 443,
                    hostname: None,
                    root_domain: None,
                    asn_org: None,
                    country: None,
                },
                process: ProcessInfo {
                    pid: 42,
                    name: "app<script>.exe".to_string(),
                    started_at: None,
                    path: Some("C:\\Program Files\\App\\app.exe".to_string()),
                    path_class: "ProgramFiles".to_string(),
                    file_missing: false,
                    orphaned: false,
                    services: vec![],
                    ppid: None,
                    parent_name: None,
                    command_line: None,
                    user: None,
                },
                binary_identity: BinaryIdentity {
                    volume_serial: Some("AB12CD34".to_string()),
                    file_id: Some("00000000000A1B2C".to_string()),
                    file_size: 12345,
                    last_write_time: Some("2026-01-01T00:00:00Z".to_string()),
                    sha256: Some("deadbeef".to_string()),
                    hash_source: Some("fresh".to_string()),
                },
                trust: TrustInfo {
                    signature_status: "Valid".to_string(),
                    signature_source: "embedded".to_string(),
                    signer_subject: Some("CN=App".to_string()),
                    signer_thumbprint: Some("FF00".to_string()),
                    chain_status: "Trusted".to_string(),
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
                    score: 10,
                    level: "none".to_string(),
                    matched_signals: vec![],
                    mismatched_signals: vec!["NO_HISTORICAL_PROFILE".to_string()],
                },
                intel: IntelInfo {
                    consulted: false,
                    virustotal: VtIntel::default(),
                    abuseipdb: AbuseIpdbIntel::default(),
                    llm: LlmIntel::default(),
                },
                risk: RiskInfo {
                    score: 35,
                    band: "known_low".to_string(),
                    reason_codes: vec!["UNKNOWN_BASELINE".to_string()],
                    recommended_action: "observe".to_string(),
                },
            }],
        }
    }

    #[test]
    fn html_export_contains_required_sections() {
        let html = Exporter::render_html(&sample_response());
        // Contenido mínimo de docs/export-format.md
        assert!(html.contains("SCAN-1"));
        assert!(html.contains("2026-07-09T10:00:00Z"));
        assert!(html.contains("Resumen"));
        assert!(html.contains("known_low"));
        assert!(html.contains("Unknown"));
        assert!(html.contains("8.8.8.8"));
        assert!(html.contains("UNKNOWN_BASELINE"));
        assert!(html.contains("observe"));
        assert!(html.contains("C:\\Program Files\\App\\app.exe"));
        assert!(html.contains("Completitud del scan"));
        assert!(html.contains("Estado de evidencia: partial"));
        assert!(html.contains("POINT_IN_TIME_SNAPSHOT"));
    }

    #[test]
    fn html_export_escapes_untrusted_strings() {
        let html = Exporter::render_html(&sample_response());
        assert!(
            !html.contains("app<script>.exe"),
            "process names must be escaped"
        );
        assert!(html.contains("app&lt;script&gt;.exe"));
    }

    #[test]
    fn html_export_marks_unresolved_values_clearly() {
        let html = Exporter::render_html(&sample_response());
        // hostname era None: se representa como unknown, no se inventa.
        assert!(html.contains("unknown"));
    }

    #[test]
    fn json_export_roundtrips_contract_shape() {
        let response = sample_response();
        let dir = std::env::temp_dir().join("ocm_export_test.json");
        let path = dir.to_string_lossy().to_string();
        Exporter::export_to_json(&response, &path).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        let parsed: ScanNowResponse = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.scan_id, response.scan_id);
        assert_eq!(parsed.findings.len(), 1);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn legacy_v1_export_does_not_invent_coverage() {
        let mut response = sample_response();
        response.schema_version = "v1".to_string();
        response.coverage = None;

        let json = serde_json::to_value(&response).unwrap();
        assert!(json.get("coverage").is_none());
        let html = Exporter::render_html(&response);
        assert!(html.contains("No disponible"));
        assert!(html.contains("no registraba cobertura"));
    }
}
