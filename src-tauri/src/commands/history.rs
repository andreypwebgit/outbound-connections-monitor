use tauri::command;

use crate::core::models::{ScanHistoryEntry, ScanNowResponse};
use crate::core::storage::Storage;

/// Devuelve los metadatos de los últimos escaneos persistidos (más reciente
/// primero). No carga findings: la UI pide el scan completo con `get_scan`.
#[command]
pub async fn get_scan_history(state: tauri::State<'_, Storage>) -> Result<Vec<ScanHistoryEntry>, String> {
    state.get_scan_history(50).map_err(|e| e.to_string())
}

/// Recupera un scan completo desde la persistencia (raw_json) para volver a
/// visualizarlo en la UI con el mismo shape del contrato.
#[command]
pub async fn get_scan(scan_id: String, state: tauri::State<'_, Storage>) -> Result<ScanNowResponse, String> {
    state
        .get_scan_response(&scan_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("Scan {} not found or has no persisted payload", scan_id))
}
