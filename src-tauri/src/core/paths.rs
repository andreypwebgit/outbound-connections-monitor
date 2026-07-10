use std::path::{Path, PathBuf};

/// Rutas de datos de la aplicación (base de datos, export automático y
/// carpeta de exports). Se resuelven UNA vez en el arranque y se inyectan
/// como estado de Tauri: ningún comando debe volver a depender del cwd.
///
/// - En desarrollo (`debug_assertions`), la base es `../` relativa al cwd de
///   `tauri dev` (la raíz del repo), fuera de `src-tauri` para no disparar el
///   hot-reload. Es el comportamiento histórico del proyecto.
/// - En release, la base es el directorio de datos local del usuario
///   (`%LOCALAPPDATA%\{identifier}`): la app puede instalarse en
///   `Program Files` (no escribible sin privilegios) y el cwd de un acceso
///   directo no es predecible.
#[derive(Debug, Clone)]
pub struct AppPaths {
    data_dir: PathBuf,
}

impl AppPaths {
    pub fn new(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Base de datos SQLite (baseline, identidades, scans, auditoría).
    pub fn database_file(&self) -> PathBuf {
        self.data_dir.join("ocm_baseline.db")
    }

    /// Export JSON automático del último scan.
    pub fn last_scan_file(&self) -> PathBuf {
        self.data_dir.join("last_scan.json")
    }

    /// Carpeta de exportaciones bajo demanda (JSON/HTML).
    pub fn exports_dir(&self) -> PathBuf {
        self.data_dir.join("exports")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_all_paths_from_data_dir() {
        let paths = AppPaths::new(PathBuf::from(r"C:\Users\dev\AppData\Local\ocm"));
        assert_eq!(
            paths.database_file(),
            PathBuf::from(r"C:\Users\dev\AppData\Local\ocm\ocm_baseline.db")
        );
        assert_eq!(
            paths.last_scan_file(),
            PathBuf::from(r"C:\Users\dev\AppData\Local\ocm\last_scan.json")
        );
        assert_eq!(
            paths.exports_dir(),
            PathBuf::from(r"C:\Users\dev\AppData\Local\ocm\exports")
        );
        assert_eq!(
            paths.data_dir(),
            Path::new(r"C:\Users\dev\AppData\Local\ocm")
        );
    }
}
