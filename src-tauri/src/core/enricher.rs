use std::process::Command;
use std::collections::HashMap;
use std::path::Path;
use std::fs;
use sha2::{Sha256, Digest};
use crate::core::errors::AppError;
use crate::core::models::{ProcessInfo, BinaryIdentity, TrustInfo};

pub struct SystemProcessMap {
    pub map: HashMap<u32, (String, String)>, // PID -> (Name, ExecutablePath)
}

impl SystemProcessMap {
    pub fn build() -> Result<Self, AppError> {
        let mut map = HashMap::new();
        
        let output = Command::new("wmic")
            .args(&["process", "get", "processid,name,executablepath", "/format:csv"])
            .output()
            .map_err(|e| AppError::EnricherError(format!("Failed to execute wmic: {}", e)))?;
            
        let stdout = String::from_utf8_lossy(&output.stdout);
        
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("Node,") {
                continue;
            }
            
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 4 {
                // Node,ExecutablePath,Name,ProcessId
                let exe_path = parts[1].trim().to_string();
                let name = parts[2].trim().to_string();
                let pid_str = parts[3].trim();
                
                if let Ok(pid) = pid_str.parse::<u32>() {
                    map.insert(pid, (name, exe_path));
                }
            }
        }
        
        Ok(Self { map })
    }
}

pub struct Enricher;

impl Enricher {
    pub fn get_process_info(pid: u32, sys_map: &SystemProcessMap) -> ProcessInfo {
        if let Some((name, path)) = sys_map.map.get(&pid) {
            let path_opt = if path.is_empty() { None } else { Some(path.clone()) };
            let file_missing = path_opt.as_ref().map_or(true, |p| !Path::new(p).exists());
            
            ProcessInfo {
                pid,
                name: name.clone(),
                started_at: None,
                path: path_opt.clone(),
                path_class: Self::classify_path(path_opt.as_deref()),
                file_missing,
                orphaned: false, // We'd need more logic to check if orphaned, but if pid exists in wmic, it's running.
            }
        } else {
            // Proceso huérfano (la conexión existe pero el proceso ya murió)
            ProcessInfo {
                pid,
                name: "Unknown".to_string(),
                started_at: None,
                path: None,
                path_class: "Missing".to_string(),
                file_missing: true,
                orphaned: true,
            }
        }
    }

    pub fn get_binary_identity(path: Option<&String>) -> BinaryIdentity {
        if let Some(p) = path {
            let path_obj = Path::new(p);
            if path_obj.exists() {
                let metadata = fs::metadata(path_obj).ok();
                let file_size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
                
                // TODO: Usar IdentityCache real en lugar de hashear siempre.
                // Para v0.1 básica, calculamos SHA256 directamente (es la regla STRICT obligatoria).
                let sha256 = Self::compute_sha256(path_obj);

                return BinaryIdentity {
                    volume_serial: None,
                    file_id: None,
                    file_size,
                    last_write_time: None, // Omitido por simplicidad en este prototipo, se puede leer del metadata
                    sha256,
                    hash_source: Some("fresh".to_string()),
                };
            }
        }
        
        BinaryIdentity {
            volume_serial: None,
            file_id: None,
            file_size: 0,
            last_write_time: None,
            sha256: None,
            hash_source: None,
        }
    }

    pub fn get_trust_info(_path: Option<&String>) -> TrustInfo {
        // En Windows requeriríamos llamar a WinVerifyTrust de forma nativa.
        // Como estamos en v0.1 y evitamos C/C++ bindings si no es indispensable, 
        // simularemos o llamaremos a PowerShell Get-AuthenticodeSignature.
        // Dado el impacto en rendimiento, asumiremos Unknown temporalmente si no es crítico,
        // o implementaremos la llamada PS.
        // Por la regla "mínima complejidad", usamos Unknown hasta necesitar la API nativa.
        
        TrustInfo {
            signature_status: "Unknown".to_string(),
            signature_source: "unknown".to_string(),
            signer_subject: None,
            signer_thumbprint: None,
            chain_status: "Unknown".to_string(),
        }
    }

    fn classify_path(path: Option<&str>) -> String {
        match path {
            Some(p) => {
                let p_lower = p.to_lowercase();
                if p_lower.contains("windows") {
                    "Windows".to_string()
                } else if p_lower.contains("program files (x86)") {
                    "ProgramFilesX86".to_string()
                } else if p_lower.contains("program files") {
                    "ProgramFiles".to_string()
                } else if p_lower.contains("appdata") {
                    "AppData".to_string()
                } else if p_lower.contains("temp") {
                    "Temp".to_string()
                } else if p_lower.contains("downloads") {
                    "Downloads".to_string()
                } else if p_lower.contains("desktop") {
                    "Desktop".to_string()
                } else if p_lower.contains("users") {
                    "UserProfile".to_string()
                } else {
                    "Other".to_string()
                }
            }
            None => "Missing".to_string()
        }
    }

    fn compute_sha256(path: &Path) -> Option<String> {
        if let Ok(bytes) = fs::read(path) {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let result = hasher.finalize();
            return Some(hex::encode(result));
        }
        None
    }
}
