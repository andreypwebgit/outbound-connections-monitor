use std::process::Command;
use std::collections::HashMap;
use std::path::Path;
use std::fs;
use sha2::{Sha256, Digest};
use crate::core::errors::AppError;
use crate::core::models::{ProcessInfo, BinaryIdentity, TrustInfo};

pub struct SystemProcessMap {
    pub map: HashMap<u32, (String, String, Vec<String>)>, // PID -> (Name, ExecutablePath, Services)
}

impl SystemProcessMap {
    pub fn build() -> Result<Self, AppError> {
        let mut map = HashMap::new();
        
        // 1. Obtener procesos
        let output = Command::new("wmic")
            .args(&["process", "get", "processid,name,executablepath", "/format:csv"])
            .output()
            .map_err(|e| AppError::EnricherError(format!("Failed to execute wmic process: {}", e)))?;
            
        let stdout = String::from_utf8_lossy(&output.stdout);
        
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("Node,") {
                continue;
            }
            
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 4 {
                let exe_path = parts[1].trim().to_string();
                let name = parts[2].trim().to_string();
                let pid_str = parts[3].trim();
                
                if let Ok(pid) = pid_str.parse::<u32>() {
                    map.insert(pid, (name, exe_path, Vec::new()));
                }
            }
        }
        
        // 2. Obtener servicios (mapeo PID a Servicios)
        if let Ok(svc_output) = Command::new("wmic").args(&["service", "get", "name,processid", "/format:csv"]).output() {
            let svc_stdout = String::from_utf8_lossy(&svc_output.stdout);
            for line in svc_stdout.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with("Node,") {
                    continue;
                }
                
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() >= 3 {
                    // Node,Name,ProcessId
                    let svc_name = parts[1].trim().to_string();
                    let pid_str = parts[2].trim();
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        if pid > 0 { // Ignorar PID 0
                            if let Some(entry) = map.get_mut(&pid) {
                                entry.2.push(svc_name);
                            }
                        }
                    }
                }
            }
        }
        
        Ok(Self { map })
    }
}

pub struct TrustCache {
    pub map: HashMap<String, TrustInfo>,
}

impl TrustCache {
    pub fn new() -> Self {
        Self { map: HashMap::new() }
    }
}

pub struct Enricher;

impl Enricher {
    pub fn get_process_info(pid: u32, sys_map: &SystemProcessMap) -> ProcessInfo {
        if let Some((name, path, services)) = sys_map.map.get(&pid) {
            let path_opt = if path.is_empty() { None } else { Some(path.clone()) };
            let file_missing = path_opt.as_ref().map_or(true, |p| !Path::new(p).exists());
            
            ProcessInfo {
                pid,
                name: name.clone(),
                started_at: None,
                path: path_opt.clone(),
                path_class: Self::classify_path(path_opt.as_deref()),
                file_missing,
                orphaned: false,
                services: services.clone(),
            }
        } else {
            ProcessInfo {
                pid,
                name: "Unknown".to_string(),
                started_at: None,
                path: None,
                path_class: "Missing".to_string(),
                file_missing: true,
                orphaned: true,
                services: Vec::new(),
            }
        }
    }

    pub fn get_binary_identity(path: Option<&String>) -> BinaryIdentity {
        if let Some(p) = path {
            let path_obj = Path::new(p);
            if path_obj.exists() {
                let metadata = fs::metadata(path_obj).ok();
                let file_size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
                
                let sha256 = Self::compute_sha256(path_obj);

                return BinaryIdentity {
                    volume_serial: None,
                    file_id: None,
                    file_size,
                    last_write_time: None,
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

    pub fn get_trust_info(path: Option<&String>, cache: &mut TrustCache) -> TrustInfo {
        if let Some(p) = path {
            if p.is_empty() {
                return Self::unknown_trust();
            }
            
            // Comprobar caché
            if let Some(cached) = cache.map.get(p) {
                return cached.clone();
            }
            
            // Ejecutar PowerShell para obtener la firma (Authenticode)
            let ps_command = format!(
                "$s=Get-AuthenticodeSignature -FilePath '{}'; if($s){{ Write-Output ($s.Status.ToString()+'|'+$s.SignerCertificate.Subject+'|'+$s.SignerCertificate.Thumbprint) }} else {{ Write-Output 'Unknown||' }}",
                p.replace("'", "''")
            );
            
            if let Ok(output) = Command::new("powershell")
                .args(&["-NoProfile", "-Command", &ps_command])
                .output() {
                    
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let parts: Vec<&str> = stdout.split('|').collect();
                
                let status = if parts.len() > 0 && !parts[0].is_empty() { parts[0].to_string() } else { "Unknown".to_string() };
                let subject = if parts.len() > 1 && !parts[1].is_empty() { Some(parts[1].to_string()) } else { None };
                let thumbprint = if parts.len() > 2 && !parts[2].is_empty() { Some(parts[2].to_string()) } else { None };
                
                let trust_info = TrustInfo {
                    signature_status: status.clone(),
                    signature_source: "powershell".to_string(),
                    signer_subject: subject,
                    signer_thumbprint: thumbprint,
                    chain_status: status, // Simplificado para v0.2
                };
                
                cache.map.insert(p.clone(), trust_info.clone());
                return trust_info;
            }
        }
        
        Self::unknown_trust()
    }
    
    fn unknown_trust() -> TrustInfo {
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
