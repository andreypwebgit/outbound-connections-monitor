use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanNowResponse {
    pub scan_id: String,
    pub schema_version: String,
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: u64,
    pub host: HostInfo,
    pub summary: ScanSummary,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HostInfo {
    pub platform: String,
    pub hostname: String,
    pub app_version: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ScanSummary {
    pub total_observations: u32,
    pub accepted_count: u32,
    pub review_count: u32,
    pub danger_count: u32,
    pub unknown_count: u32,
    pub candidate_count: u32,
    pub revalidation_count: u32,
    pub orphaned_count: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Finding {
    pub finding_id: String,
    pub protocol: String,
    pub state: String,
    pub local: LocalEndpoint,
    pub remote: RemoteEndpoint,
    pub process: ProcessInfo,
    pub binary_identity: BinaryIdentity,
    pub trust: TrustInfo,
    pub baseline: BaselineInfo,
    pub affinity: AffinityInfo,
    pub intel: IntelInfo,
    pub risk: RiskInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LocalEndpoint {
    pub ip: String,
    pub port: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemoteEndpoint {
    pub ip: String,
    pub port: u16,
    pub hostname: Option<String>,
    pub root_domain: Option<String>,
    pub asn_org: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub started_at: Option<String>,
    pub path: Option<String>,
    pub path_class: String,
    pub file_missing: bool,
    pub orphaned: bool,
    pub services: Vec<String>,
    pub ppid: Option<u32>,
    pub parent_name: Option<String>,
    pub command_line: Option<String>,
    pub user: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BinaryIdentity {
    pub volume_serial: Option<String>,
    pub file_id: Option<String>,
    pub file_size: u64,
    pub last_write_time: Option<String>,
    pub sha256: Option<String>,
    pub hash_source: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TrustInfo {
    pub signature_status: String,
    pub signature_source: String,
    pub signer_subject: Option<String>,
    pub signer_thumbprint: Option<String>,
    pub chain_status: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BaselineInfo {
    pub state: String,
    pub seen_count: u32,
    pub distinct_days: u32,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub manual_validation: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AffinityInfo {
    pub score: u8,
    pub level: String,
    pub matched_signals: Vec<String>,
    pub mismatched_signals: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IntelInfo {
    pub consulted: bool,
    pub virustotal: VtIntel,
    pub abuseipdb: AbuseIpdbIntel,
    pub llm: LlmIntel,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct VtIntel {
    pub consulted: bool,
    pub malicious_votes: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AbuseIpdbIntel {
    pub consulted: bool,
    pub abuse_confidence_score: Option<u8>,
    pub usage_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct LlmIntel {
    pub consulted: bool,
    pub confidence: Option<f32>,
    pub summary: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RiskInfo {
    pub score: u8,
    pub band: String,
    pub reason_codes: Vec<String>,
    pub recommended_action: String,
}

// Internal Enums for Domain Logic
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaselineState {
    Unknown,
    Candidate,
    ObservedLocal,
    BaselineProvisional,
    BaselineConsolidated,
    RevalidationRequired,
    PotentiallyDangerous,
}

impl BaselineState {
    pub fn as_str(&self) -> &'static str {
        match self {
            BaselineState::Unknown => "Unknown",
            BaselineState::Candidate => "Candidate",
            BaselineState::ObservedLocal => "Observed_Local",
            BaselineState::BaselineProvisional => "Baseline_Provisional",
            BaselineState::BaselineConsolidated => "Baseline_Consolidated",
            BaselineState::RevalidationRequired => "Revalidation_Required",
            BaselineState::PotentiallyDangerous => "Potentially_Dangerous",
        }
    }
}
