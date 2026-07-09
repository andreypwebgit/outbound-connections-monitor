use crate::core::models::{BaselineInfo, BaselineState};

pub struct BaselineManager;

impl BaselineManager {
    // En v0.1, esta lógica se simula o asume estados iniciales si no hay persistencia conectada aún.
    // El Storage gestiona SQLite. Aquí determinamos las transiciones.
    
    pub fn get_baseline_for_identity(sha256: Option<&String>) -> BaselineInfo {
        if sha256.is_none() {
            return BaselineInfo {
                state: BaselineState::Unknown.as_str().to_string(),
                seen_count: 1,
                distinct_days: 1,
                first_seen: None,
                last_seen: None,
                manual_validation: false,
            };
        }
        
        // TODO: En v0.1 real conectaremos a `Storage::get_baseline(sha256)`.
        // Simularemos Candidate para mostrar el funcionamiento básico de Risk Engine.
        BaselineInfo {
            state: BaselineState::Candidate.as_str().to_string(),
            seen_count: 1,
            distinct_days: 1,
            first_seen: None,
            last_seen: None,
            manual_validation: false,
        }
    }
}
