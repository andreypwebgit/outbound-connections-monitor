use std::fmt;

#[derive(Debug)]
pub enum AppError {
    DatabaseError(rusqlite::Error),
    IoError(std::io::Error),
    CollectorError(String),
    EnricherError(String),
    SystemError(String),
}

impl std::error::Error for AppError {}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::DatabaseError(err) => write!(f, "Database error: {}", err),
            AppError::IoError(err) => write!(f, "IO error: {}", err),
            AppError::CollectorError(err) => write!(f, "Collector error: {}", err),
            AppError::EnricherError(err) => write!(f, "Enricher error: {}", err),
            AppError::SystemError(err) => write!(f, "System error: {}", err),
        }
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(err: rusqlite::Error) -> Self {
        AppError::DatabaseError(err)
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::IoError(err)
    }
}

// Para poder enviar errores como Strings a Tauri (Result<T, String>)
impl From<AppError> for String {
    fn from(err: AppError) -> String {
        err.to_string()
    }
}
