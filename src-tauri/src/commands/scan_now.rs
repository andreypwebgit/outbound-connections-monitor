use std::time::SystemTime;
use chrono::{DateTime, Utc};
use tauri::command;

use crate::core::collector::Collector;
use crate::core::enricher::{Enricher, SystemProcessMap, TrustCache};
use crate::core::risk_engine::RiskEngine;
use crate::core::baseline_manager::BaselineManager;
use crate::core::exporter::Exporter;
use crate::core::models::{
    ScanNowResponse, HostInfo, ScanSummary, Finding, LocalEndpoint, RemoteEndpoint,
    AffinityInfo, IntelInfo, VtIntel, AbuseIpdbIntel, LlmIntel
};

#[command]
pub async fn scan_now() -> Result<ScanNowResponse, String> {
    let start_time = SystemTime::now();
    let started_at: DateTime<Utc> = start_time.into();
    
    // 1. Gather OS processes mapping
    let process_map = SystemProcessMap::build()
        .map_err(|e| e.to_string())?;

    // 2. Collect raw observations (active outbound connections)
    let raw_observations = Collector::collect_active_connections()
        .map_err(|e| e.to_string())?;
        
    let mut trust_cache = TrustCache::new();
        
    let mut findings = Vec::new();
    let mut summary = ScanSummary::default();
    
    summary.total_observations = raw_observations.len() as u32;

    for (index, obs) in raw_observations.into_iter().enumerate() {
        let finding_id = format!("FND-{}-{}", started_at.timestamp(), index);
        
        let local = LocalEndpoint {
            ip: obs.local_ip,
            port: obs.local_port,
        };
        
        let remote = RemoteEndpoint {
            ip: obs.remote_ip,
            port: obs.remote_port,
            hostname: None, // Omitimos resolución inversa DNS por defecto en v0.1 para evitar latencia excesiva
            root_domain: None,
            asn_org: None,
            country: None,
        };
        
        let process_info = Enricher::get_process_info(obs.pid, &process_map);
        let binary_identity = Enricher::get_binary_identity(process_info.path.as_ref());
        let trust_info = Enricher::get_trust_info(process_info.path.as_ref(), &mut trust_cache);
        
        let baseline = BaselineManager::get_baseline_for_identity(binary_identity.sha256.as_ref());
        
        // Mock affinity for v0.1 since we don't have historical data to compute it yet.
        let affinity = AffinityInfo {
            score: 0,
            level: "none".to_string(),
            matched_signals: vec![],
            mismatched_signals: vec!["NEW_DESTINATION".to_string()],
        };
        
        let risk = RiskEngine::evaluate(
            &process_info,
            &binary_identity,
            &trust_info,
            &baseline,
            &affinity,
        );
        
        match risk.recommended_action.as_str() {
            "ignore" => summary.accepted_count += 1,
            "observe" => summary.candidate_count += 1,
            "review" => summary.review_count += 1,
            "revalidate" => summary.revalidation_count += 1,
            "investigate" => summary.danger_count += 1,
            _ => summary.unknown_count += 1,
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
        
        let finding = Finding {
            finding_id,
            protocol: obs.protocol,
            state: obs.state,
            local,
            remote,
            process: process_info,
            binary_identity,
            trust: trust_info,
            baseline,
            affinity,
            intel,
            risk,
        };
        
        findings.push(finding);
    }
    
    let finished_at: DateTime<Utc> = Utc::now();
    let duration_ms = start_time.elapsed().unwrap_or_default().as_millis() as u64;
    
    let response = ScanNowResponse {
        scan_id: format!("SCAN-{}", started_at.timestamp()),
        schema_version: "v1".to_string(),
        started_at: started_at.to_rfc3339(),
        finished_at: finished_at.to_rfc3339(),
        duration_ms,
        host: HostInfo {
            platform: "windows".to_string(),
            hostname: "local-host".to_string(), // Omitimos gethostname por simplicidad
            app_version: "0.1.0".to_string(),
        },
        summary,
        findings,
    };
    
    // Export to JSON outside src-tauri to prevent hot-reload loop
    let _ = Exporter::export_to_json(&response, "../last_scan.json");
    
    Ok(response)
}
