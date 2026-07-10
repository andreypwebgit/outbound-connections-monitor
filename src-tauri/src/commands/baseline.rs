use tauri::command;

use crate::core::models::BaselineListEntry;
use crate::core::storage::Storage;

/// Lista las identidades que han entrado en el lifecycle. Es una consulta de
/// solo lectura; las transiciones siguen en `record_manual_decision`.
#[command]
pub async fn get_baseline_entries(
    state: tauri::State<'_, Storage>,
) -> Result<Vec<BaselineListEntry>, String> {
    state
        .get_baseline_entries()
        .map_err(|error| error.to_string())
}
