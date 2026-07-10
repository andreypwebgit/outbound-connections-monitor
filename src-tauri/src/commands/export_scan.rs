use std::fs;

use tauri::command;

use crate::core::exporter::Exporter;
use crate::core::paths::AppPaths;
use crate::core::storage::Storage;

/// Exporta un scan persistido a JSON o HTML y devuelve la ruta del archivo.
///
/// La exportación se reconstruye desde el resultado persistido del scan
/// (docs/export-format.md: "reproducible a partir del resultado persistido")
/// y no cambia el estado del sistema.
#[command]
pub async fn export_scan(
    scan_id: String,
    format: String,
    state: tauri::State<'_, Storage>,
    paths: tauri::State<'_, AppPaths>,
) -> Result<String, String> {
    // El scan_id forma parte del nombre de archivo: solo se aceptan IDs con
    // el alfabeto que genera la propia app (evita separadores de ruta).
    if scan_id.is_empty()
        || !scan_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!("Invalid scan id '{}'", scan_id));
    }

    let response = state
        .get_scan_response(&scan_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("Scan {} not found or has no persisted payload", scan_id))?;

    // Carpeta de exports del directorio de datos de la app
    // (raíz del repo en dev, %LOCALAPPDATA% en release).
    let export_dir = paths.exports_dir();
    fs::create_dir_all(&export_dir).map_err(|e| format!("Cannot create exports dir: {}", e))?;

    let (file_name, result) = match format.as_str() {
        "json" => {
            let path = export_dir.join(format!("{}.json", scan_id));
            let result = Exporter::export_to_json(&response, &path);
            (path, result)
        }
        "html" => {
            let path = export_dir.join(format!("{}.html", scan_id));
            let result = Exporter::export_to_html(&response, &path);
            (path, result)
        }
        other => {
            return Err(format!(
                "Unsupported export format '{}': use json or html",
                other
            ))
        }
    };

    result.map_err(|e| e.to_string())?;

    let _ = state.record_audit_event(
        Some(&scan_id),
        "scan_exported",
        &format!("format={} file={}", format, file_name.display()),
    );

    let absolute = fs::canonicalize(&file_name).unwrap_or(file_name);
    // canonicalize en Windows produce prefijo \\?\ que ensucia la UI.
    Ok(absolute
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .to_string())
}
