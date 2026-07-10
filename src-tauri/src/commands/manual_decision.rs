use tauri::command;

use crate::core::baseline_manager::BaselineManager;
use crate::core::models::BaselineInfo;
use crate::core::storage::Storage;

/// Registra una decisión manual del usuario sobre un binario identificado
/// por su SHA-256 y devuelve el estado de baseline resultante.
///
/// Tipos válidos (docs/baseline-lifecycle.md + docs/implementation-notes.md):
/// - `validate_local`:   Candidate -> Observed_Local
/// - `revalidate_accept`: Revalidation_Required | Potentially_Dangerous -> Candidate
#[command]
pub async fn record_manual_decision(
    sha256: String,
    decision_type: String,
    notes: Option<String>,
    state: tauri::State<'_, Storage>,
) -> Result<BaselineInfo, String> {
    BaselineManager::apply_manual_decision_with_notes(&sha256, &decision_type, notes.as_deref(), &state)
}
