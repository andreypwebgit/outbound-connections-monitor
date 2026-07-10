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

/// Entrada ligera del historial de escaneos para la UI.
/// Se construye desde `scans` + el summary persistido, sin cargar findings.
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanHistoryEntry {
    pub scan_id: String,
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: u64,
    pub total_observations: u32,
    pub accepted_count: u32,
    pub review_count: u32,
    pub danger_count: u32,
}

/// Comparativa de consulta entre un scan persistido y su predecesor. No
/// forma parte del contrato `scan_now`.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanComparison {
    pub scan_id: String,
    pub previous_scan_id: Option<String>,
    pub new_connections_count: u32,
    pub changed_connections_count: u32,
    pub new_binaries_count: u32,
    pub baseline_changes_count: u32,
    pub findings: Vec<FindingComparison>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingComparison {
    pub finding_id: String,
    pub is_new_connection: bool,
    pub connection_changed: bool,
    pub is_new_binary: bool,
    pub previous_baseline_state: Option<String>,
}

/// Fila de la vista de gestión del baseline. Es una proyección de consulta,
/// no un nuevo estado de dominio ni una extensión de `scan_now`.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BaselineListEntry {
    pub sha256: String,
    pub normalized_path: Option<String>,
    pub state: String,
    pub seen_count: u32,
    pub distinct_days: u32,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub manual_validation: bool,
    pub signature_status: Option<String>,
    pub signer_subject: Option<String>,
    pub last_manual_decision: Option<String>,
    pub last_manual_decision_at: Option<String>,
}

// Internal Enums for Domain Logic
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "Unknown" => Some(BaselineState::Unknown),
            "Candidate" => Some(BaselineState::Candidate),
            "Observed_Local" => Some(BaselineState::ObservedLocal),
            "Baseline_Provisional" => Some(BaselineState::BaselineProvisional),
            "Baseline_Consolidated" => Some(BaselineState::BaselineConsolidated),
            "Revalidation_Required" => Some(BaselineState::RevalidationRequired),
            "Potentially_Dangerous" => Some(BaselineState::PotentiallyDangerous),
            _ => None,
        }
    }

    /// Transiciones automáticas permitidas por `docs/baseline-lifecycle.md`.
    ///
    /// Nota de interpretación (documentada en docs/implementation-notes.md):
    /// la Regla 4 del lifecycle obliga a empujar a `Revalidation_Required`
    /// cualquier "elemento conocido" cuyo hash cambie, por lo que además de
    /// `Baseline_Consolidated -> Revalidation_Required` se aceptan
    /// `Observed_Local -> Revalidation_Required` y
    /// `Baseline_Provisional -> Revalidation_Required`.
    pub fn is_valid_automatic_transition(&self, next: BaselineState) -> bool {
        if next == BaselineState::PotentiallyDangerous {
            // "Any -> Potentially_Dangerous"
            return true;
        }
        matches!(
            (self, next),
            (BaselineState::Unknown, BaselineState::Candidate)
                | (BaselineState::Candidate, BaselineState::BaselineProvisional)
                | (
                    BaselineState::BaselineProvisional,
                    BaselineState::BaselineConsolidated
                )
                | (
                    BaselineState::ObservedLocal,
                    BaselineState::RevalidationRequired
                )
                | (
                    BaselineState::BaselineProvisional,
                    BaselineState::RevalidationRequired
                )
                | (
                    BaselineState::BaselineConsolidated,
                    BaselineState::RevalidationRequired
                )
        )
    }

    /// Transiciones que requieren decisión manual explícita del usuario.
    ///
    /// - `Candidate -> Observed_Local` está en el lifecycle como transición
    ///   de validación manual.
    /// - Las salidas de `Revalidation_Required` y `Potentially_Dangerous`
    ///   hacia `Candidate` no están enumeradas en el lifecycle; se aceptan
    ///   solo como decisión manual para que un falso positivo pueda
    ///   re-aprenderse (ver docs/implementation-notes.md).
    pub fn is_valid_manual_transition(&self, next: BaselineState) -> bool {
        matches!(
            (self, next),
            (BaselineState::Candidate, BaselineState::ObservedLocal)
                | (BaselineState::ObservedLocal, BaselineState::Candidate)
                | (
                    BaselineState::RevalidationRequired,
                    BaselineState::Candidate
                )
                | (
                    BaselineState::PotentiallyDangerous,
                    BaselineState::Candidate
                )
        )
    }
}

/// Niveles de afinidad válidos según `docs/affinity-model.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AffinityLevel {
    High,
    Medium,
    Low,
    None,
}

impl AffinityLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            AffinityLevel::High => "high",
            AffinityLevel::Medium => "medium",
            AffinityLevel::Low => "low",
            AffinityLevel::None => "none",
        }
    }

    /// Mapeo score -> nivel siguiendo las bandas orientativas del modelo:
    /// 90-100 fuerte, 70-89 razonable, 40-69 débil, 0-39 desajuste.
    pub fn from_score(score: u8) -> Self {
        match score {
            90..=100 => AffinityLevel::High,
            70..=89 => AffinityLevel::Medium,
            40..=69 => AffinityLevel::Low,
            _ => AffinityLevel::None,
        }
    }
}
