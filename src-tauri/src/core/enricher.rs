use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::process::Command;

use chrono::{DateTime, Utc};
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
    pub warnings: Vec<String>,
}

impl SystemProcessMap {
    pub fn build() -> Result<Self, AppError> {
        let (map, warnings) = win_process::snapshot()?;
        Ok(Self { map, warnings })
    }
}

/// Inventario de procesos mediante APIs de Windows. Evita WMIC, CIM y
/// tasklist, y conserva `None` en los campos que un proceso protegido no
/// permita consultar.
#[cfg(windows)]
mod win_process {
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::ptr;

    use chrono::{DateTime, Utc};

    use super::ProcessContext;
    use crate::core::errors::AppError;

    type Handle = *mut c_void;
    type ScHandle = *mut c_void;

    const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_USER_CLASS: u32 = 1;
    const TOKEN_ELEVATION_CLASS: u32 = 20;
    const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;
    const SC_MANAGER_ENUMERATE_SERVICE: u32 = 0x0004;
    const SC_ENUM_PROCESS_INFO: u32 = 0;
    const SERVICE_WIN32: u32 = 0x0030;
    const SERVICE_STATE_ALL: u32 = 0x0003;
    const ERROR_MORE_DATA: u32 = 234;
    const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;

    pub fn snapshot() -> Result<(HashMap<u32, ProcessContext>, Vec<String>), AppError> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot as isize == -1 {
            return Err(AppError::EnricherError(format!(
                "CreateToolhelp32Snapshot failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let snapshot = OwnedHandle(snapshot);

        let mut entry: ProcessEntry32W = unsafe { zeroed() };
        entry.size = size_of::<ProcessEntry32W>() as u32;
        if unsafe { Process32FirstW(snapshot.0, &mut entry) } == 0 {
            return Err(AppError::EnricherError(format!(
                "Process32FirstW failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let mut map = HashMap::new();
        loop {
            let pid = entry.process_id;
            let name = utf16_array_to_string(&entry.exe_file);
            let process = open_process(pid);
            let context = match process {
                Some(handle) => ProcessContext {
                    name,
                    path: query_process_path(handle.0).unwrap_or_default(),
                    services: Vec::new(),
                    ppid: (entry.parent_process_id != 0).then_some(entry.parent_process_id),
                    command_line: query_command_line(handle.0),
                    user: query_process_user(handle.0),
                    started_at: query_started_at(handle.0),
                },
                None => ProcessContext {
                    name,
                    path: String::new(),
                    services: Vec::new(),
                    ppid: (entry.parent_process_id != 0).then_some(entry.parent_process_id),
                    command_line: None,
                    user: None,
                    started_at: None,
                },
            };
            map.insert(pid, context);

            if unsafe { Process32NextW(snapshot.0, &mut entry) } == 0 {
                break;
            }
        }

        let mut warnings = Vec::new();
        if let Err(error) = attach_services(&mut map) {
            warnings.push(error);
        }
        Ok((map, warnings))
    }

    pub fn current_process_elevated() -> Option<bool> {
        let mut token: Handle = ptr::null_mut();
        let process = unsafe { GetCurrentProcess() };
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return None;
        }
        let token = OwnedHandle(token);
        let mut elevation = TokenElevation {
            token_is_elevated: 0,
        };
        let mut returned = 0u32;
        let ok = unsafe {
            GetTokenInformation(
                token.0,
                TOKEN_ELEVATION_CLASS,
                (&mut elevation as *mut TokenElevation).cast(),
                size_of::<TokenElevation>() as u32,
                &mut returned,
            )
        };
        (ok != 0 && returned >= size_of::<TokenElevation>() as u32)
            .then_some(elevation.token_is_elevated != 0)
    }

    fn open_process(pid: u32) -> Option<OwnedHandle> {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        (!handle.is_null()).then_some(OwnedHandle(handle))
    }

    fn query_process_path(process: Handle) -> Option<String> {
        let mut buffer = vec![0u16; 32_768];
        let mut length = buffer.len() as u32;
        let ok =
            unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut length) };
        (ok != 0 && length > 0).then(|| String::from_utf16_lossy(&buffer[..length as usize]))
    }

    fn query_started_at(process: Handle) -> Option<String> {
        let mut creation: FileTime = unsafe { zeroed() };
        let mut exit: FileTime = unsafe { zeroed() };
        let mut kernel: FileTime = unsafe { zeroed() };
        let mut user: FileTime = unsafe { zeroed() };
        let ok =
            unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) };
        (ok != 0).then(|| filetime_to_rfc3339(creation)).flatten()
    }

    fn filetime_to_rfc3339(value: FileTime) -> Option<String> {
        let ticks = ((value.high as u64) << 32) | value.low as u64;
        let unix_ticks = ticks.checked_sub(WINDOWS_TO_UNIX_EPOCH_100NS)?;
        let seconds = (unix_ticks / 10_000_000) as i64;
        let nanos = ((unix_ticks % 10_000_000) * 100) as u32;
        DateTime::<Utc>::from_timestamp(seconds, nanos).map(|date| date.to_rfc3339())
    }

    fn query_process_user(process: Handle) -> Option<String> {
        let mut token: Handle = ptr::null_mut();
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return None;
        }
        let token = OwnedHandle(token);

        let mut required = 0u32;
        unsafe {
            GetTokenInformation(token.0, TOKEN_USER_CLASS, ptr::null_mut(), 0, &mut required);
        }
        if required < size_of::<TokenUser>() as u32 {
            return None;
        }

        let mut buffer = vec![0u8; required as usize];
        if unsafe {
            GetTokenInformation(
                token.0,
                TOKEN_USER_CLASS,
                buffer.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        } == 0
        {
            return None;
        }

        let token_user = unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<TokenUser>()) };
        lookup_account_sid(token_user.user.sid)
    }

    fn lookup_account_sid(sid: *mut c_void) -> Option<String> {
        if sid.is_null() {
            return None;
        }
        let mut name_len = 0u32;
        let mut domain_len = 0u32;
        let mut sid_type = 0u32;
        unsafe {
            LookupAccountSidW(
                ptr::null(),
                sid,
                ptr::null_mut(),
                &mut name_len,
                ptr::null_mut(),
                &mut domain_len,
                &mut sid_type,
            );
        }
        if name_len == 0 {
            return None;
        }

        let mut name = vec![0u16; name_len as usize];
        let mut domain = vec![0u16; domain_len.max(1) as usize];
        let ok = unsafe {
            LookupAccountSidW(
                ptr::null(),
                sid,
                name.as_mut_ptr(),
                &mut name_len,
                domain.as_mut_ptr(),
                &mut domain_len,
                &mut sid_type,
            )
        };
        if ok == 0 {
            return None;
        }

        let name = String::from_utf16_lossy(&name[..name_len as usize]);
        let domain = String::from_utf16_lossy(&domain[..domain_len as usize]);
        Some(if domain.is_empty() {
            name
        } else {
            format!("{domain}\\{name}")
        })
    }

    /// ProcessCommandLineInformation (60) devuelve una UNICODE_STRING dentro
    /// del buffer del llamador. Si un proceso protegido lo deniega, el campo
    /// queda honestamente a `None`.
    fn query_command_line(process: Handle) -> Option<String> {
        let mut required = 0u32;
        unsafe {
            NtQueryInformationProcess(
                process,
                PROCESS_COMMAND_LINE_INFORMATION,
                ptr::null_mut(),
                0,
                &mut required,
            );
        }
        if required < size_of::<UnicodeString>() as u32 {
            return None;
        }

        let mut buffer = vec![0u8; required as usize];
        let status = unsafe {
            NtQueryInformationProcess(
                process,
                PROCESS_COMMAND_LINE_INFORMATION,
                buffer.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        };
        if status < 0 {
            return None;
        }

        let command = unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<UnicodeString>()) };
        if command.buffer.is_null() || command.length == 0 || command.length % 2 != 0 {
            return None;
        }
        let bytes = command.length as usize;
        let start = command.buffer as usize;
        let end = start.checked_add(bytes)?;
        let buffer_start = buffer.as_ptr() as usize;
        let buffer_end = buffer_start.checked_add(buffer.len())?;
        if start < buffer_start || end > buffer_end {
            return None;
        }

        let utf16 = unsafe { std::slice::from_raw_parts(command.buffer, bytes / 2) };
        Some(String::from_utf16_lossy(utf16))
    }

    fn attach_services(map: &mut HashMap<u32, ProcessContext>) -> Result<(), String> {
        let manager =
            unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_ENUMERATE_SERVICE) };
        if manager.is_null() {
            return Err(format!(
                "OpenSCManagerW failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let manager = OwnedServiceHandle(manager);

        let mut required = 0u32;
        let mut returned = 0u32;
        let mut resume = 0u32;
        let first = unsafe {
            EnumServicesStatusExW(
                manager.0,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                ptr::null_mut(),
                0,
                &mut required,
                &mut returned,
                &mut resume,
                ptr::null(),
            )
        };
        if first == 0
            && std::io::Error::last_os_error().raw_os_error() != Some(ERROR_MORE_DATA as i32)
        {
            return Err(format!(
                "EnumServicesStatusExW size query failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if required == 0 {
            return Ok(());
        }

        let mut buffer = vec![0u8; required as usize];
        resume = 0;
        let ok = unsafe {
            EnumServicesStatusExW(
                manager.0,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                buffer.as_mut_ptr(),
                required,
                &mut required,
                &mut returned,
                &mut resume,
                ptr::null(),
            )
        };
        if ok == 0 {
            return Err(format!(
                "EnumServicesStatusExW failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        for index in 0..returned as usize {
            let offset = index * size_of::<EnumServiceStatusProcessW>();
            if offset + size_of::<EnumServiceStatusProcessW>() > buffer.len() {
                return Err("EnumServicesStatusExW returned a truncated buffer".to_string());
            }
            let service = unsafe {
                ptr::read_unaligned(
                    buffer
                        .as_ptr()
                        .add(offset)
                        .cast::<EnumServiceStatusProcessW>(),
                )
            };
            if service.status.process_id == 0 {
                continue;
            }
            if let Some(context) = map.get_mut(&service.status.process_id) {
                if let Some(name) = wide_ptr_to_string(service.service_name, 1024) {
                    context.services.push(name);
                }
            }
        }
        Ok(())
    }

    fn utf16_array_to_string(value: &[u16]) -> String {
        let length = value
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(value.len());
        String::from_utf16_lossy(&value[..length])
    }

    fn wide_ptr_to_string(value: *const u16, max_units: usize) -> Option<String> {
        if value.is_null() {
            return None;
        }
        let mut length = 0usize;
        while length < max_units && unsafe { *value.add(length) } != 0 {
            length += 1;
        }
        (length < max_units).then(|| {
            let slice = unsafe { std::slice::from_raw_parts(value, length) };
            String::from_utf16_lossy(slice)
        })
    }

    struct OwnedHandle(Handle);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    struct OwnedServiceHandle(ScHandle);

    impl Drop for OwnedServiceHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CloseServiceHandle(self.0) };
            }
        }
    }

    #[repr(C)]
    struct ProcessEntry32W {
        size: u32,
        usage: u32,
        process_id: u32,
        default_heap_id: usize,
        module_id: u32,
        threads: u32,
        parent_process_id: u32,
        priority_class_base: i32,
        flags: u32,
        exe_file: [u16; 260],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SidAndAttributes {
        sid: *mut c_void,
        attributes: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct TokenUser {
        user: SidAndAttributes,
    }

    #[repr(C)]
    struct TokenElevation {
        token_is_elevated: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ServiceStatusProcess {
        service_type: u32,
        current_state: u32,
        controls_accepted: u32,
        win32_exit_code: u32,
        service_specific_exit_code: u32,
        check_point: u32,
        wait_hint: u32,
        process_id: u32,
        service_flags: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct EnumServiceStatusProcessW {
        service_name: *mut u16,
        display_name: *mut u16,
        status: ServiceStatusProcess,
    }

    #[link(name = "kernel32")]
    #[allow(non_snake_case)]
    extern "system" {
        fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> Handle;
        fn GetCurrentProcess() -> Handle;
        fn Process32FirstW(snapshot: Handle, entry: *mut ProcessEntry32W) -> i32;
        fn Process32NextW(snapshot: Handle, entry: *mut ProcessEntry32W) -> i32;
        fn OpenProcess(access: u32, inherit: i32, process_id: u32) -> Handle;
        fn QueryFullProcessImageNameW(
            process: Handle,
            flags: u32,
            path: *mut u16,
            size: *mut u32,
        ) -> i32;
        fn GetProcessTimes(
            process: Handle,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
    }

    #[link(name = "advapi32")]
    #[allow(non_snake_case)]
    extern "system" {
        fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
        fn GetTokenInformation(
            token: Handle,
            information_class: u32,
            information: *mut c_void,
            information_length: u32,
            return_length: *mut u32,
        ) -> i32;
        fn LookupAccountSidW(
            system_name: *const u16,
            sid: *mut c_void,
            name: *mut u16,
            name_length: *mut u32,
            domain: *mut u16,
            domain_length: *mut u32,
            sid_name_use: *mut u32,
        ) -> i32;
        fn OpenSCManagerW(
            machine_name: *const u16,
            database_name: *const u16,
            access: u32,
        ) -> ScHandle;
        fn EnumServicesStatusExW(
            manager: ScHandle,
            info_level: u32,
            service_type: u32,
            service_state: u32,
            services: *mut u8,
            buffer_size: u32,
            bytes_needed: *mut u32,
            services_returned: *mut u32,
            resume_handle: *mut u32,
            group_name: *const u16,
        ) -> i32;
        fn CloseServiceHandle(handle: ScHandle) -> i32;
    }

    #[link(name = "ntdll")]
    #[allow(non_snake_case)]
    extern "system" {
        fn NtQueryInformationProcess(
            process: Handle,
            information_class: u32,
            information: *mut c_void,
            information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn windows_filetime_epoch_converts_to_unix_epoch() {
            let ticks = WINDOWS_TO_UNIX_EPOCH_100NS;
            let time = FileTime {
                low: ticks as u32,
                high: (ticks >> 32) as u32,
            };
            assert_eq!(
                filetime_to_rfc3339(time).as_deref(),
                Some("1970-01-01T00:00:00+00:00")
            );
        }

        #[test]
        fn utf16_array_stops_at_nul() {
            let value = [b'o' as u16, b'c' as u16, b'm' as u16, 0, b'x' as u16];
            assert_eq!(utf16_array_to_string(&value), "ocm");
        }
    }
}

#[cfg(not(windows))]
mod win_process {
    use std::collections::HashMap;

    use super::ProcessContext;
    use crate::core::errors::AppError;

    pub fn snapshot() -> Result<(HashMap<u32, ProcessContext>, Vec<String>), AppError> {
        Err(AppError::EnricherError(
            "OCM only supports the Windows process APIs".to_string(),
        ))
    }

    pub fn current_process_elevated() -> Option<bool> {
        None
    }
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
    pub fn current_process_elevated() -> Option<bool> {
        win_process::current_process_elevated()
    }

    pub fn get_process_info(pid: u32, sys_map: &SystemProcessMap) -> ProcessInfo {
        if let Some(ctx) = sys_map.map.get(&pid) {
            let path_opt = if ctx.path.is_empty() {
                None
            } else {
                Some(ctx.path.clone())
            };
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
            "system"
                | "registry"
                | "memory compression"
                | "msmpeng.exe"
                | "csrss.exe"
                | "smss.exe"
                | "services.exe"
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
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps_command])
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

    fn map_authenticode(
        raw_status: &str,
        raw_type: &str,
        thumbprint: &str,
        subject: &str,
    ) -> TrustInfo {
        let (signature_status, chain_status) = match raw_status {
            "Valid" => ("Valid", "Trusted"),
            "NotSigned" => ("Unsigned", "Unknown"),
            "HashMismatch" | "NotTrusted" | "Invalid" | "NotSupportedFileFormat" => {
                ("Invalid", "Untrusted")
            }
            _ => ("Unknown", "Unknown"),
        };

        let signature_source = match raw_type {
            "Authenticode" => "embedded",
            "Catalog" => "catalog",
            "None" if signature_status == "Unsigned" => "none",
            "None" => "unknown",
            _ => "unknown",
        };

        TrustInfo {
            signature_status: signature_status.to_string(),
            signature_source: signature_source.to_string(),
            signer_subject: if subject.is_empty() {
                None
            } else {
                Some(subject.to_string())
            },
            signer_thumbprint: if thumbprint.is_empty() {
                None
            } else {
                Some(thumbprint.to_string())
            },
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
    struct FileTime {
        dwLowDateTime: u32,
        dwHighDateTime: u32,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct ByHandleFileInformation {
        dwFileAttributes: u32,
        ftCreationTime: FileTime,
        ftLastAccessTime: FileTime,
        ftLastWriteTime: FileTime,
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
            lp_file_information: *mut ByHandleFileInformation,
        ) -> i32;
    }

    pub fn volume_and_file_id(file: &File) -> Option<(String, String)> {
        unsafe {
            let mut info = std::mem::zeroed::<ByHandleFileInformation>();
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
