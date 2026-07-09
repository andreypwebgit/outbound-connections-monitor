use crate::core::models::ScanNowResponse;
use std::fs;
use crate::core::errors::AppError;

pub struct Exporter;

impl Exporter {
    pub fn export_to_json(response: &ScanNowResponse, path: &str) -> Result<(), AppError> {
        let json = serde_json::to_string_pretty(response)
            .map_err(|e| AppError::SystemError(format!("JSON serialization failed: {}", e)))?;
            
        fs::write(path, json)
            .map_err(|e| AppError::IoError(e))?;
            
        Ok(())
    }
}
