use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::process::Command;

use chrono::{DateTime, NaiveDateTime, Utc};
use sha2::{Digest, Sha256};

use crate::core::errors::AppError;
use crate::core::models::{ProcessInfo, TrustInfo};

/// Contexto de un proceso vivo resuelto desde el sistema operativo.
pub struct ProcessContext {
    pub name: String,
    pub path: String,
    pub services: Vec<String>,
    pub ppid: Option<u32>,
    pub command_line: Option<String>,
    pub user: Option<String>,
    pub started_at: Option<String>,
}

pub struct SystemProcessMap {
    pub map: HashMap<u32, ProcessContext>,
}

impl SystemProcessMap {
    pub fn build() -> Result<Self, AppError> {
        // WMIC es la vía rápida; en builds de Windows 11 donde ya no existe,
        // degradamos a PowerShell CIM (más lento pero equivalente).
        let mut map = match Self::build_from_wmic() {
            Ok(map) if !map.is_empty() => map,
            _ => Self::build_from_cim()?,
        };

        Self::attach_users(&mut map);
        Self::attach_services(&mut map);

        Ok(Self { map })
    }

    fn build_from_wmic() -> Result<HashMap<u32, ProcessContext>, AppError> {
        let mut map = HashMap::new();

        let output = Command::new("wmic")
            .args(&[
                "process",
                "get",
                "ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate",
                "/format:csv",
            ])
            .output()
            .map_err(|e| AppError::EnricherError(format!("Failed to execute wmic process: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Columnas CSV de WMIC en orden alfabético tras Node:
        // Node,CommandLine,CreationDate,ExecutablePath,Name,ParentProcessId,ProcessId
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("Node,") {
                continue;
            }

            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 7 {
                if let Ok(pid) = parts.last().unwrap().trim().parse::<u32>() {
                    let ppid = parts[parts.len() - 2].trim().parse::<u32>().ok();
                    let name = parts[parts.len() - 3].trim().to_string();
                    let path = parts[parts.len() - 4].trim().to_string();
                    let started_at = parse_cim_datetime(parts[parts.len() - 5].trim());
                    // CommandLine puede contener comas: es todo lo que queda en medio.
                    let cmd = parts[1..parts.len() - 5].join(",").trim().to_string();

                    map.insert(
                        pid,
                        ProcessContext {
                            name,
                            path,
                            services: Vec::new(),
                            ppid,
                            command_line: if cmd.is_empty() { None } else { Some(cmd) },
                            user: None,
                            started_at,
                        },
                    );
                }
            }
        }

        Ok(map)
    }

    fn build_from_cim() -> Result<HashMap<u32, ProcessContext>, AppError> {
        let mut map = HashMap::new();

        let ps_command = "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,@{N='CreationDateIso';E={if($_.CreationDate){$_.CreationDate.ToUniversalTime().ToString('o')}}} | ConvertTo-Json -Compress";

        let output = Command::new("powershell")
            .args(&["-NoProfile", "-NonInteractive", "-Command", ps_command])
            .output()
            .map_err(|e| AppError::EnricherError(format!("Failed to execute CIM fallback: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
            .map_err(|e| AppError::EnricherError(format!("CIM fallback returned invalid JSON: {}", e)))?;

        let items: Vec<serde_json::Value> = match parsed {
            serde_json::Value::Array(arr) => arr,
            obj @ serde_json::Value::Object(_) => vec![obj],
            _ => Vec::new(),
        };

        for item in items {
            let pid = item.get("ProcessId").and_then(|v| v.as_u64()).map(|v| v as u32);
            if let Some(pid) = pid {
                let ppid = item.get("ParentProcessId").and_then(|v| v.as_u64()).map(|v| v as u32);
                let name = item.get("Name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let path = item.get("ExecutablePath").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let cmd = item.get("CommandLine").and_then(|v| v.as_str()).map(|s| s.to_string());
                let started_at = item
                    .get("CreationDateIso")
                    .and_then(|v| v.as_str())
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.with_timezone(&Utc).to_rfc3339());

                map.insert(
                    pid,
                    ProcessContext {
                        name,
                        path,
                        services: Vec::new(),
                        ppid,
                        command_line: cmd.filter(|c| !c.is_empty()),
                        user: None,
                        started_at,
                    },
                );
            }
        }

        Ok(map)
    }

    fn attach_users(map: &mut HashMap<u32, ProcessContext>) {
        if let Ok(tasklist_output) = Command::new("tasklist").args(&["/v", "/fo", "csv"]).output() {
            let tasklist_stdout = String::from_utf8_lossy(&tasklist_output.stdout);
            for line in tasklist_stdout.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with("\"Image Name\"") || line.starts_with("\"Nombre de imagen\"") {
                    continue;
                }

                let parts: Vec<&str> = line.split("\",\"").collect();
                if parts.len() >= 8 {
                    let pid_str = parts[1].replace("\"", "").trim().to_string();
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        let user = parts[6].replace("\"", "").trim().to_string();
                        if let Some(ctx) = map.get_mut(&pid) {
                            if user != "N/D" && user != "N/A" && !user.is_empty() {
                                ctx.user = Some(user);
                            }
                        }
                    }
                }
            }
        }
    }

    fn attach_services(map: &mut HashMap<u32, ProcessContext>) {
        let wmic_ok = if let Ok(svc_output) = Command::new("wmic")
            .args(&["service", "get", "name,processid", "/format:csv"])
            .output()
        {
            let svc_stdout = String::from_utf8_lossy(&svc_output.stdout);
            let mut any = false;
            for line in svc_stdout.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with("Node,") {
                    continue;
                }

                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() >= 3 {
                    let svc_name = parts[1].trim().to_string();
                    if let Ok(pid) = parts[2].trim().parse::<u32>() {
                        any = true;
                        if pid > 0 {
                            if let Some(entry) = map.get_mut(&pid) {
                                entry.services.push(svc_name);
                            }
                        }
                    }
                }
            }
            any
        } else {
            false
        };

        if !wmic_ok {
            // Fallback CIM para servicios cuando WMIC no está disponible.
            let ps_command = "Get-CimInstance Win32_Service | Where-Object { $_.ProcessId -gt 0 } | Select-Object Name,ProcessId | ConvertTo-Json -Compress";
            if let Ok(output) = Command::new("powershell")
                .args(&["-NoProfile", "-NonInteractive", "-Command", ps_command])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(stdout.trim()) {
                    let items: Vec<serde_json::Value> = match parsed {
                        serde_json::Value::Array(arr) => arr,
                        obj @ serde_json::Value::Object(_) => vec![obj],
                        _ => Vec::new(),
                    };
                    for item in items {
                        if let (Some(name), Some(pid)) = (
                            item.get("Name").and_then(|v| v.as_str()),
                            item.get("ProcessId").and_then(|v| v.as_u64()),
                        ) {
                            if let Some(entry) = map.get_mut(&(pid as u32)) {
                                entry.services.push(name.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Convierte un CIM datetime de WMIC ("20260709103000.123456+060") a RFC3339 UTC.
fn parse_cim_datetime(raw: &str) -> Option<String> {
    if raw.len() < 21 {
        return None;
    }
    let naive = NaiveDateTime::parse_from_str(&raw[..14], "%Y%m%d%H%M%S").ok()?;
    // El sufijo son minutos de offset respecto a UTC: +060 / -300.
    let offset_part = &raw[raw.len() - 4..];
    let sign = match offset_part.chars().next()? {
        '+' => 1i64,
        '-' => -1i64,
        _ => return None,
    };
    let minutes: i64 = offset_part[1..].parse().ok()?;
    let utc = naive - chrono::Duration::minutes(sign * minutes);
    Some(DateTime::<Utc>::from_naive_utc_and_offset(utc, Utc).to_rfc3339())
}

/// Identidad física de un archivo en disco: la clave de invalidación
/// del identity cache definida en docs/architecture.md.
#[derive(Debug, Clone)]
pub struct FileStat {
    pub file_size: u64,
    pub last_write_time: Option<String>,
    pub volume_serial: Option<String>,
    pub file_id: Option<String>,
}

pub struct Enricher;

impl Enricher {
    pub fn get_process_info(pid: u32, sys_map: &SystemProcessMap) -> ProcessInfo {
        if let Some(ctx) = sys_map.map.get(&pid) {
            let path_opt = if ctx.path.is_empty() { None } else { Some(ctx.path.clone()) };
            let file_missing = path_opt.as_ref().map_or(true, |p| !Path::new(p).exists());

            // Resolver Parent Name
            let mut parent_name = None;
            if let Some(p_id) = ctx.ppid {
                if let Some(parent_ctx) = sys_map.map.get(&p_id) {
                    parent_name = Some(parent_ctx.name.clone());
                }
            }

            ProcessInfo {
                pid,
                name: ctx.name.clone(),
                started_at: ctx.started_at.clone(),
                path: path_opt.clone(),
                path_class: Self::classify_path(path_opt.as_deref()),
                file_missing,
                orphaned: false,
                services: ctx.services.clone(),
                ppid: ctx.ppid,
                parent_name,
                command_line: ctx.command_line.clone(),
                user: ctx.user.clone(),
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
                ppid: None,
                parent_name: None,
                command_line: None,
                user: None,
            }
        }
    }

    /// Procesos del kernel/PPL a los que no se puede acceder desde user-mode:
    /// que no expongan ruta o hash no es señal de riesgo sino comportamiento
    /// esperado de Windows (heurística introducida en v0.3.1).
    pub fn is_protected_system_process(name: &str) -> bool {
        let n = name.to_lowercase();
        matches!(
            n.as_str(),
            "system" | "registry" | "memory compression" | "msmpeng.exe" | "csrss.exe" | "smss.exe" | "services.exe"
        )
    }

    /// Obtiene la identidad física del archivo (clave de invalidación del caché).
    pub fn stat_file(path: &Path) -> Option<FileStat> {
        let metadata = fs::metadata(path).ok()?;
        let file_size = metadata.len();
        let last_write_time = metadata
            .modified()
            .ok()
            .map(|t| DateTime::<Utc>::from(t).to_rfc3339());

        let (volume_serial, file_id) = match File::open(path) {
            Ok(file) => win_file_identity::volume_and_file_id(&file)
                .map(|(v, f)| (Some(v), Some(f)))
                .unwrap_or((None, None)),
            Err(_) => (None, None),
        };

        Some(FileStat {
            file_size,
            last_write_time,
            volume_serial,
            file_id,
        })
    }

    /// SHA-256 en streaming para no cargar binarios grandes en memoria.
    pub fn compute_sha256(path: &Path) -> Option<String> {
        let mut file = File::open(path).ok()?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 1024 * 1024];
        loop {
            match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => hasher.update(&buffer[..n]),
                Err(_) => return None,
            }
        }
        Some(hex::encode(hasher.finalize()))
    }

    /// Verifica Authenticode vía PowerShell y mapea el resultado a los enums
    /// del contrato `scan_now`:
    /// - signature_status: Valid | Invalid | Unsigned | Unknown
    /// - signature_source: embedded | catalog | none | unknown
    /// - chain_status: Trusted | Untrusted | Unknown
    pub fn verify_authenticode(path: &str) -> TrustInfo {
        if path.is_empty() {
            return Self::unknown_trust();
        }

        let ps_command = format!(
            "$s=Get-AuthenticodeSignature -LiteralPath '{}'; if($s){{ $t=if($s.SignatureType){{$s.SignatureType.ToString()}}else{{'None'}}; $th=if($s.SignerCertificate){{$s.SignerCertificate.Thumbprint}}else{{''}}; $su=if($s.SignerCertificate){{$s.SignerCertificate.Subject}}else{{''}}; Write-Output ($s.Status.ToString()+'|'+$t+'|'+$th+'|'+$su) }} else {{ Write-Output 'UnknownError|None||' }}",
            path.replace("'", "''")
        );

        if let Ok(output) = Command::new("powershell")
            .args(&["-NoProfile", "-NonInteractive", "-Command", &ps_command])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            // El subject puede contener '|' en teoría: va al final y usamos splitn.
            let parts: Vec<&str> = stdout.splitn(4, '|').collect();
            if parts.len() == 4 {
                return Self::map_authenticode(parts[0], parts[1], parts[2], parts[3]);
            }
        }

        Self::unknown_trust()
    }

    fn map_authenticode(raw_status: &str, raw_type: &str, thumbprint: &str, subject: &str) -> TrustInfo {
        let (signature_status, chain_status) = match raw_status {
            "Valid" => ("Valid", "Trusted"),
            "NotSigned" => ("Unsigned", "Unknown"),
            "HashMismatch" | "NotTrusted" | "Invalid" | "NotSupportedFileFormat" => ("Invalid", "Untrusted"),
            _ => ("Unknown", "Unknown"),
        };

        let signature_source = match raw_type {
            "Authenticode" => "embedded",
            "Catalog" => "catalog",
            "None" => {
                if signature_status == "Unsigned" {
                    "none"
                } else {
                    "unknown"
                }
            }
            _ => "unknown",
        };

        TrustInfo {
            signature_status: signature_status.to_string(),
            signature_source: signature_source.to_string(),
            signer_subject: if subject.is_empty() { None } else { Some(subject.to_string()) },
            signer_thumbprint: if thumbprint.is_empty() { None } else { Some(thumbprint.to_string()) },
            chain_status: chain_status.to_string(),
        }
    }

    pub fn unknown_trust() -> TrustInfo {
        TrustInfo {
            signature_status: "Unknown".to_string(),
            signature_source: "unknown".to_string(),
            signer_subject: None,
            signer_thumbprint: None,
            chain_status: "Unknown".to_string(),
        }
    }

    /// Clasifica una ruta comparando componentes del path (no substrings del
    /// string completo, que producía falsos positivos tipo "ContemplateApp"
    /// clasificado como Temp). El orden evalúa primero las ubicaciones más
    /// específicas/sospechosas: C:\Windows\Temp debe ser Temp, no Windows.
    pub fn classify_path(path: Option<&str>) -> String {
        let p = match path {
            Some(p) if !p.is_empty() => p,
            _ => return "Missing".to_string(),
        };

        let components: Vec<String> = Path::new(p)
            .components()
            .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
            .collect();

        let has = |name: &str| components.iter().any(|c| c == name);

        if has("temp") || has("tmp") {
            "Temp".to_string()
        } else if has("downloads") {
            "Downloads".to_string()
        } else if has("desktop") {
            "Desktop".to_string()
        } else if has("appdata") {
            "AppData".to_string()
        } else if has("program files (x86)") {
            "ProgramFilesX86".to_string()
        } else if has("program files") {
            "ProgramFiles".to_string()
        } else if has("windows") {
            "Windows".to_string()
        } else if has("users") {
            "UserProfile".to_string()
        } else {
            "Other".to_string()
        }
    }
}

/// FFI mínimo a kernel32 para obtener volume_serial y file_id.
/// `std::os::windows::fs::MetadataExt` solo expone estos campos en nightly,
/// por lo que declaramos la única función necesaria sin añadir dependencias.
#[cfg(windows)]
mod win_file_identity {
    use std::fs::File;
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    #[allow(non_snake_case)]
    struct FILETIME {
        dwLowDateTime: u32,
        dwHighDateTime: u32,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct BY_HANDLE_FILE_INFORMATION {
        dwFileAttributes: u32,
        ftCreationTime: FILETIME,
        ftLastAccessTime: FILETIME,
        ftLastWriteTime: FILETIME,
        dwVolumeSerialNumber: u32,
        nFileSizeHigh: u32,
        nFileSizeLow: u32,
        nNumberOfLinks: u32,
        nFileIndexHigh: u32,
        nFileIndexLow: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileInformationByHandle(
            h_file: *mut core::ffi::c_void,
            lp_file_information: *mut BY_HANDLE_FILE_INFORMATION,
        ) -> i32;
    }

    pub fn volume_and_file_id(file: &File) -> Option<(String, String)> {
        unsafe {
            let mut info = std::mem::zeroed::<BY_HANDLE_FILE_INFORMATION>();
            if GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) != 0 {
                let file_index = ((info.nFileIndexHigh as u64) << 32) | (info.nFileIndexLow as u64);
                Some((
                    format!("{:08X}", info.dwVolumeSerialNumber),
                    format!("{:016X}", file_index),
                ))
            } else {
                None
            }
        }
    }
}

#[cfg(not(windows))]
mod win_file_identity {
    use std::fs::File;

    pub fn volume_and_file_id(_file: &File) -> Option<(String, String)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_path_covers_all_contract_classes() {
        assert_eq!(Enricher::classify_path(None), "Missing");
        assert_eq!(Enricher::classify_path(Some("")), "Missing");
        assert_eq!(
            Enricher::classify_path(Some(r"C:\Windows\System32\svchost.exe")),
            "Windows"
        );
        assert_eq!(
            Enricher::classify_path(Some(r"C:\Program Files\App\app.exe")),
            "ProgramFiles"
        );
        assert_eq!(
            Enricher::classify_path(Some(r"C:\Program Files (x86)\App\app.exe")),
            "ProgramFilesX86"
        );
        assert_eq!(
            Enricher::classify_path(Some(r"C:\Users\dev\AppData\Roaming\App\app.exe")),
            "AppData"
        );
        assert_eq!(
            Enricher::classify_path(Some(r"C:\Users\dev\Downloads\setup.exe")),
            "Downloads"
        );
        assert_eq!(
            Enricher::classify_path(Some(r"C:\Users\dev\Desktop\tool.exe")),
            "Desktop"
        );
        assert_eq!(
            Enricher::classify_path(Some(r"C:\Users\dev\bin\tool.exe")),
            "UserProfile"
        );
        assert_eq!(Enricher::classify_path(Some(r"D:\opt\tool.exe")), "Other");
    }

    #[test]
    fn classify_path_prefers_most_suspicious_component() {
        // Temp dentro de Windows es Temp, no Windows.
        assert_eq!(
            Enricher::classify_path(Some(r"C:\Windows\Temp\payload.exe")),
            "Temp"
        );
        // AppData\Local\Temp es Temp, no AppData.
        assert_eq!(
            Enricher::classify_path(Some(r"C:\Users\dev\AppData\Local\Temp\x.exe")),
            "Temp"
        );
    }

    #[test]
    fn classify_path_does_not_match_substrings() {
        // "ContemplateApp" contiene "temp" como substring pero no es Temp.
        assert_eq!(
            Enricher::classify_path(Some(r"C:\Program Files\ContemplateApp\app.exe")),
            "ProgramFiles"
        );
        // "MyDownloadsManager" no es Downloads.
        assert_eq!(
            Enricher::classify_path(Some(r"D:\MyDownloadsManager\run.exe")),
            "Other"
        );
    }

    #[test]
    fn parse_cim_datetime_handles_offsets() {
        let parsed = parse_cim_datetime("20260709103000.123456+060").expect("should parse");
        assert!(parsed.starts_with("2026-07-09T09:30:00"));

        let parsed_neg = parse_cim_datetime("20260709103000.123456-300").expect("should parse");
        assert!(parsed_neg.starts_with("2026-07-09T15:30:00"));

        assert!(parse_cim_datetime("").is_none());
        assert!(parse_cim_datetime("garbage").is_none());
    }

    #[test]
    fn protected_system_processes_recognized() {
        assert!(Enricher::is_protected_system_process("System"));
        assert!(Enricher::is_protected_system_process("MsMpEng.exe"));
        assert!(!Enricher::is_protected_system_process("chrome.exe"));
    }

    #[test]
    fn map_authenticode_respects_contract_enums() {
        let valid = Enricher::map_authenticode("Valid", "Authenticode", "ABC123", "CN=Test");
        assert_eq!(valid.signature_status, "Valid");
        assert_eq!(valid.signature_source, "embedded");
        assert_eq!(valid.chain_status, "Trusted");
        assert_eq!(valid.signer_subject.as_deref(), Some("CN=Test"));

        let catalog = Enricher::map_authenticode("Valid", "Catalog", "ABC", "CN=MS");
        assert_eq!(catalog.signature_source, "catalog");

        let unsigned = Enricher::map_authenticode("NotSigned", "None", "", "");
        assert_eq!(unsigned.signature_status, "Unsigned");
        assert_eq!(unsigned.signature_source, "none");
        assert_eq!(unsigned.chain_status, "Unknown");
        assert!(unsigned.signer_subject.is_none());

        let invalid = Enricher::map_authenticode("HashMismatch", "Authenticode", "X", "CN=Evil");
        assert_eq!(invalid.signature_status, "Invalid");
        assert_eq!(invalid.chain_status, "Untrusted");

        let unknown = Enricher::map_authenticode("UnknownError", "None", "", "");
        assert_eq!(unknown.signature_status, "Unknown");
        assert_eq!(unknown.signature_source, "unknown");
    }

    #[test]
    fn stat_and_hash_real_file() {
        let dir = std::env::temp_dir();
        let file_path = dir.join("ocm_enricher_test_file.bin");
        fs::write(&file_path, b"hello world").unwrap();

        let stat = Enricher::stat_file(&file_path).expect("stat should work");
        assert_eq!(stat.file_size, 11);
        assert!(stat.last_write_time.is_some());
        #[cfg(windows)]
        {
            assert!(stat.volume_serial.is_some());
            assert!(stat.file_id.is_some());
        }

        let hash = Enricher::compute_sha256(&file_path).expect("hash should work");
        // SHA-256 conocido de "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );

        let _ = fs::remove_file(&file_path);
    }
}
