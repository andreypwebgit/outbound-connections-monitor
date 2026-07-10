use std::collections::HashMap;
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use dns_lookup::lookup_addr;
use tauri::{command, Emitter};

use crate::core::affinity::{extract_root_domain, is_private_ip, AffinityContext, AffinityEngine};
use crate::core::baseline_manager::{BaselineManager, BaselineObservation};
use crate::core::collector::Collector;
use crate::core::enricher::{Enricher, SystemProcessMap};
use crate::core::exporter::Exporter;
use crate::core::identity_cache::IdentityCache;
use crate::core::models::{
    AbuseIpdbIntel, AffinityLevel, BaselineInfo, Finding, HostInfo, IntelInfo, LlmIntel, LocalEndpoint,
    RemoteEndpoint, RiskInfo, ScanNowResponse, ScanSummary, VtIntel,
};
use crate::core::risk_engine::{RiskContext, RiskEngine};
use crate::core::storage::Storage;

#[command]
pub async fn scan_now(
    app: tauri::AppHandle,
    state: tauri::State<'_, Storage>,
    paths: tauri::State<'_, crate::core::paths::AppPaths>,
) -> Result<ScanNowResponse, String> {
    let start_time = SystemTime::now();
    let started_at: DateTime<Utc> = start_time.into();
    let scan_id = format!("SCAN-{}", started_at.timestamp());

    let _ = state.record_audit_event(Some(&scan_id), "scan_started", "Scan Now triggered");

    app.emit("scan-progress", "Construyendo mapa de procesos del sistema...").unwrap_or(());
    let process_map = SystemProcessMap::build().map_err(|e| {
        let _ = state.record_audit_event(Some(&scan_id), "collector_error", &e.to_string());
        e.to_string()
    })?;

    app.emit("scan-progress", "Recolectando conexiones activas (netstat)...").unwrap_or(());
    let raw_observations = Collector::collect_active_connections().map_err(|e| {
        let _ = state.record_audit_event(Some(&scan_id), "collector_error", &e.to_string());
        e.to_string()
    })?;

    let _ = state.record_audit_event(
        Some(&scan_id),
        "observations_collected",
        &format!("{} raw observations", raw_observations.len()),
    );

    let mut identity_cache = IdentityCache::new();
    // Memoizaciones por scan: DNS inverso por IP y baseline por binario.
    let mut dns_memo: HashMap<String, Option<String>> = HashMap::new();
    let mut baseline_memo: HashMap<String, (BaselineInfo, bool, Option<String>)> = HashMap::new();
    // Los perfiles de afinidad del scan se registran al FINAL para que un
    // destino no coincida consigo mismo dentro del mismo scan.
    let mut pending_affinity: Vec<(String, Option<String>, Option<String>, u16)> = Vec::new();

    let mut findings = Vec::new();
    let mut summary = ScanSummary::default();
    summary.total_observations = raw_observations.len() as u32;

    for (index, obs) in raw_observations.into_iter().enumerate() {
        if index % 3 == 0 {
            app.emit(
                "scan-progress",
                format!("Analizando conexión {}/{}...", index + 1, summary.total_observations),
            )
            .unwrap_or(());
        }
        let finding_id = format!("FND-{}-{}", started_at.timestamp(), index);

        let local = LocalEndpoint {
            ip: obs.local_ip,
            port: obs.local_port,
        };

        // --- DNS inverso (memoizado por IP; solo IPs públicas) ----------
        let hostname = dns_memo
            .entry(obs.remote_ip.clone())
            .or_insert_with(|| {
                if is_private_ip(&obs.remote_ip) {
                    None
                } else {
                    obs.remote_ip
                        .parse::<std::net::IpAddr>()
                        .ok()
                        .and_then(|ip| lookup_addr(&ip).ok())
                }
            })
            .clone();

        let root_domain = hostname.as_deref().and_then(extract_root_domain);

        let remote = RemoteEndpoint {
            ip: obs.remote_ip.clone(),
            port: obs.remote_port,
            hostname: hostname.clone(),
            root_domain: root_domain.clone(),
            // ASN y país requieren fuentes externas (intel opcional, fuera
            // del escaneo básico): se reportan como no resueltos.
            asn_org: None,
            country: None,
        };

        // --- Proceso + identidad (con caché) -----------------------------
        let process_info = Enricher::get_process_info(obs.pid, &process_map);
        let resolved = identity_cache.resolve(process_info.path.as_ref(), &state);

        if resolved.identity.sha256.is_none() && !process_info.file_missing && !process_info.orphaned {
            let _ = state.record_audit_event(
                Some(&scan_id),
                "hash_error",
                &format!("Could not hash binary for PID {} ({})", process_info.pid, process_info.name),
            );
        }

        // Hallazgo crítico: huérfano o binario irresoluble no protegido.
        let critical = process_info.orphaned
            || (process_info.file_missing && !Enricher::is_protected_system_process(&process_info.name));

        // --- Continuidad de firmante tras cambio de hash ------------------
        let signer_continuity = if resolved.hash_changed {
            match (&resolved.previous_sha256, &resolved.trust.signer_thumbprint) {
                (Some(prev), Some(current_thumb)) => state
                    .get_trust_for_binary(prev)
                    .ok()
                    .flatten()
                    .and_then(|t| t.signer_thumbprint)
                    .map(|prev_thumb| prev_thumb == *current_thumb)
                    .unwrap_or(false),
                _ => false,
            }
        } else {
            false
        };

        // --- Afinidad (antes de registrar el destino actual) -------------
        let affinity_ctx = AffinityContext {
            binary_id: resolved.identity.sha256.as_deref(),
            fallback_binary_id: resolved.previous_sha256.as_deref(),
            signer_continuity,
            hostname: hostname.as_deref(),
            root_domain: root_domain.as_deref(),
            asn_org: None,
            remote_ip: &obs.remote_ip,
            remote_port: obs.remote_port,
        };
        let affinity = AffinityEngine::compute(&affinity_ctx, &state);

        if let Some(sha) = resolved.identity.sha256.as_ref() {
            pending_affinity.push((sha.clone(), hostname.clone(), root_domain.clone(), obs.remote_port));
        }

        // --- Baseline (una evaluación por binario y por scan) -------------
        let affinity_level = AffinityLevel::from_score(affinity.score);
        let baseline = match resolved.identity.sha256.as_ref() {
            Some(sha) => {
                let cached = baseline_memo.get(sha).and_then(|(info, was_critical, _)| {
                    // Si este finding es crítico y el memoizado no lo era,
                    // reevaluamos: el estado debe reflejar el hallazgo crítico.
                    if critical && !was_critical {
                        None
                    } else {
                        Some(info.clone())
                    }
                });
                match cached {
                    Some(info) => info,
                    None => {
                        let observation = BaselineObservation {
                            sha256: Some(sha),
                            hash_changed: resolved.hash_changed,
                            previous_sha256: resolved.previous_sha256.as_ref(),
                            critical,
                            trust_valid: resolved.trust.signature_status == "Valid",
                            path_suspicious: matches!(process_info.path_class.as_str(), "Temp" | "Downloads"),
                            affinity_level,
                        };
                        let info = BaselineManager::evaluate(&observation, &state, Some(&scan_id));
                        baseline_memo.insert(sha.clone(), (info.clone(), critical, resolved.previous_sha256.clone()));
                        info
                    }
                }
            }
            None => {
                let observation = BaselineObservation {
                    sha256: None,
                    hash_changed: false,
                    previous_sha256: None,
                    critical,
                    trust_valid: false,
                    path_suspicious: false,
                    affinity_level,
                };
                BaselineManager::evaluate(&observation, &state, Some(&scan_id))
            }
        };

        // --- Riesgo -------------------------------------------------------
        let ip_only_destination = hostname.is_none() && !is_private_ip(&obs.remote_ip);
        let risk: RiskInfo = RiskEngine::evaluate(&RiskContext {
            process: &process_info,
            identity: &resolved.identity,
            trust: &resolved.trust,
            baseline: &baseline,
            affinity: &affinity,
            hash_changed: resolved.hash_changed,
            ip_only_destination,
        });

        // --- Summary ------------------------------------------------------
        // Semántica: accepted/review/danger derivan de la banda de riesgo;
        // unknown/candidate/revalidation derivan del estado de baseline;
        // orphaned del proceso (docs/implementation-notes.md).
        match risk.band.as_str() {
            "known_safe" | "known_low" => summary.accepted_count += 1,
            "known_moderate" | "known_high" => summary.review_count += 1,
            "potentially_dangerous" => summary.danger_count += 1,
            _ => {}
        }
        match baseline.state.as_str() {
            "Unknown" => summary.unknown_count += 1,
            "Candidate" => summary.candidate_count += 1,
            "Revalidation_Required" => summary.revalidation_count += 1,
            _ => {}
        }
        if process_info.orphaned {
            summary.orphaned_count += 1;
        }

        let intel = IntelInfo {
            consulted: false,
            virustotal: VtIntel::default(),
            abuseipdb: AbuseIpdbIntel::default(),
            llm: LlmIntel::default(),
        };

        findings.push(Finding {
            finding_id,
            protocol: obs.protocol,
            state: obs.state,
            local,
            remote,
            process: process_info,
            binary_identity: resolved.identity,
            trust: resolved.trust,
            baseline,
            affinity,
            intel,
            risk,
        });
    }

    // Registrar los destinos observados como perfiles de afinidad para
    // futuros scans (una vez computada toda la afinidad del scan actual).
    for (binary_id, hostname, root_domain, port) in pending_affinity {
        let ctx = AffinityContext {
            binary_id: Some(&binary_id),
            fallback_binary_id: None,
            signer_continuity: false,
            hostname: hostname.as_deref(),
            root_domain: root_domain.as_deref(),
            asn_org: None,
            remote_ip: "",
            remote_port: port,
        };
        AffinityEngine::record_observation(&ctx, &state);
    }

    let finished_at: DateTime<Utc> = Utc::now();
    let duration_ms = start_time.elapsed().unwrap_or_default().as_millis() as u64;

    let response = ScanNowResponse {
        scan_id: scan_id.clone(),
        schema_version: "v1".to_string(),
        started_at: started_at.to_rfc3339(),
        finished_at: finished_at.to_rfc3339(),
        duration_ms,
        host: HostInfo {
            platform: "windows".to_string(),
            hostname: std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown-host".to_string()),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
        },
        summary,
        findings,
    };

    app.emit("scan-progress", "Guardando resultados...").unwrap_or(());
    // Export automático a JSON en el directorio de datos de la app
    // (raíz del repo en dev, %LOCALAPPDATA% en release).
    if let Err(e) = Exporter::export_to_json(&response, paths.last_scan_file()) {
        log::warn!("Failed to write last_scan.json: {}", e);
    }

    if let Err(e) = state.save_scan_results(&response) {
        let _ = state.record_audit_event(Some(&scan_id), "persistence_error", &e.to_string());
        log::error!("Failed to save scan results to DB: {}", e);
    }

    let _ = state.record_audit_event(
        Some(&scan_id),
        "scan_finished",
        &format!("{} findings in {} ms", response.findings.len(), duration_ms),
    );

    Ok(response)
}
