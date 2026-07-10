pub mod core;
pub mod commands;

use tauri::Manager;

use crate::core::paths::AppPaths;
use crate::core::storage::Storage;

/// Resuelve el directorio de datos según el perfil:
/// - dev: `../` relativo al cwd de `tauri dev` (raíz del repo, fuera de
///   src-tauri para no disparar el hot-reload) — comportamiento histórico;
/// - release: `%LOCALAPPDATA%\{identifier}` — la app puede vivir en
///   Program Files (no escribible) y el cwd de un acceso directo no es fiable.
fn resolve_data_dir(app: &tauri::App) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    if cfg!(debug_assertions) {
        Ok(std::path::PathBuf::from(".."))
    } else {
        let dir = app.path().app_local_data_dir()?;
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }

            let data_dir = resolve_data_dir(app)?;
            let paths = AppPaths::new(data_dir);
            let storage = Storage::new(paths.database_file())?;

            app.manage(storage);
            app.manage(paths);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::scan_now::scan_now,
            commands::history::get_scan_history,
            commands::history::get_scan,
            commands::export_scan::export_scan,
            commands::manual_decision::record_manual_decision
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
