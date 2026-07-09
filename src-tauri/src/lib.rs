pub mod core;
pub mod commands;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Inicializar SQLite aquí (fuera de src-tauri para evitar hot-reload loop en dev)
    let _storage = core::storage::Storage::new(std::path::PathBuf::from("../ocm_baseline.db"))
        .expect("Failed to initialize local database");

    tauri::Builder::default()
        .manage(_storage)
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::scan_now::scan_now
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
