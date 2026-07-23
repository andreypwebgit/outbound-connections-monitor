use std::ffi::c_void;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

use crate::core::errors::AppError;

const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const NO_ERROR: u32 = 0;
const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
const UDP_TABLE_OWNER_PID: u32 = 1;

const MIB_TCP_STATE_SYN_SENT: u32 = 3;
const MIB_TCP_STATE_ESTAB: u32 = 5;
const MIB_TCP_STATE_CLOSE_WAIT: u32 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawObservation {
    pub protocol: String,
    pub state: String,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub pid: u32,
}

/// Resultado del snapshot nativo. Los avisos permiten degradar por familia
/// (por ejemplo, conservar IPv4 si la tabla IPv6 falla) sin ocultar el error.
#[derive(Debug)]
pub struct CollectionResult {
    pub observations: Vec<RawObservation>,
    pub warnings: Vec<String>,
    pub tcp_ipv4_collected: bool,
    pub tcp_ipv6_collected: bool,
    pub udp_ipv4_collected: bool,
    pub udp_ipv6_collected: bool,
    /// Endpoints UDP con PID observados. No se convierten en findings porque
    /// GetExtendedUdpTable no expone el peer remoto y no se inventan datos.
    pub udp_endpoint_count: u32,
}

pub struct Collector;

impl Collector {
    pub fn collect_active_connections() -> Result<CollectionResult, AppError> {
        assemble_collection(
            collect_tcp_family(AF_INET),
            collect_tcp_family(AF_INET6),
            count_udp_endpoints(AF_INET),
            count_udp_endpoints(AF_INET6),
        )
    }
}

fn assemble_collection(
    tcp_ipv4: Result<Vec<RawObservation>, String>,
    tcp_ipv6: Result<Vec<RawObservation>, String>,
    udp_ipv4: Result<u32, String>,
    udp_ipv6: Result<u32, String>,
) -> Result<CollectionResult, AppError> {
    let tcp_ipv4_collected = tcp_ipv4.is_ok();
    let tcp_ipv6_collected = tcp_ipv6.is_ok();
    let udp_ipv4_collected = udp_ipv4.is_ok();
    let udp_ipv6_collected = udp_ipv6.is_ok();
    let mut warnings = Vec::new();
    let mut observations = Vec::new();

    match tcp_ipv4 {
        Ok(mut rows) => observations.append(&mut rows),
        Err(error) => warnings.push(error),
    }
    match tcp_ipv6 {
        Ok(mut rows) => observations.append(&mut rows),
        Err(error) => warnings.push(error),
    }

    if !tcp_ipv4_collected && !tcp_ipv6_collected {
        return Err(AppError::CollectorError(format!(
            "GetExtendedTcpTable failed for IPv4 and IPv6: {}",
            warnings.join("; ")
        )));
    }

    let mut udp_endpoint_count = 0u32;
    match udp_ipv4 {
        Ok(count) => udp_endpoint_count = udp_endpoint_count.saturating_add(count),
        Err(error) => warnings.push(error),
    }
    match udp_ipv6 {
        Ok(count) => udp_endpoint_count = udp_endpoint_count.saturating_add(count),
        Err(error) => warnings.push(error),
    }

    Ok(CollectionResult {
        observations,
        warnings,
        tcp_ipv4_collected,
        tcp_ipv6_collected,
        udp_ipv4_collected,
        udp_ipv6_collected,
        udp_endpoint_count,
    })
}

fn collect_tcp_family(family: u32) -> Result<Vec<RawObservation>, String> {
    let buffer = query_tcp_table(family)?;
    match family {
        AF_INET => parse_tcp_v4_table(&buffer),
        AF_INET6 => parse_tcp_v6_table(&buffer),
        _ => Err(format!("unsupported address family {family}")),
    }
}

fn query_tcp_table(family: u32) -> Result<Vec<u8>, String> {
    let mut size = 0u32;
    // SAFETY: the first call intentionally passes a null output buffer so
    // Windows returns the required byte count in `size`.
    let first = unsafe {
        GetExtendedTcpTable(
            ptr::null_mut(),
            &mut size,
            1,
            family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if first != ERROR_INSUFFICIENT_BUFFER && first != NO_ERROR {
        return Err(win_api_error(
            "GetExtendedTcpTable size query",
            family,
            first,
        ));
    }

    query_sized_table(size, family, "GetExtendedTcpTable", |buffer, size| unsafe {
        GetExtendedTcpTable(buffer, size, 1, family, TCP_TABLE_OWNER_PID_ALL, 0)
    })
}

fn count_udp_endpoints(family: u32) -> Result<u32, String> {
    let mut size = 0u32;
    // SAFETY: size-probe call; see `query_tcp_table`.
    let first = unsafe {
        GetExtendedUdpTable(
            ptr::null_mut(),
            &mut size,
            1,
            family,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if first != ERROR_INSUFFICIENT_BUFFER && first != NO_ERROR {
        return Err(win_api_error(
            "GetExtendedUdpTable size query",
            family,
            first,
        ));
    }

    let buffer = query_sized_table(size, family, "GetExtendedUdpTable", |buffer, size| unsafe {
        GetExtendedUdpTable(buffer, size, 1, family, UDP_TABLE_OWNER_PID, 0)
    })?;
    table_row_count(&buffer, "UDP")
}

fn query_sized_table(
    initial_size: u32,
    family: u32,
    api_name: &str,
    mut call: impl FnMut(*mut c_void, &mut u32) -> u32,
) -> Result<Vec<u8>, String> {
    let mut size = initial_size.max(size_of::<u32>() as u32);
    for _ in 0..3 {
        let mut buffer = vec![0u8; size as usize];
        let status = call(buffer.as_mut_ptr().cast(), &mut size);
        match status {
            NO_ERROR => {
                buffer.truncate(size as usize);
                return Ok(buffer);
            }
            ERROR_INSUFFICIENT_BUFFER => continue,
            code => return Err(win_api_error(api_name, family, code)),
        }
    }
    Err(format!(
        "{api_name} kept resizing for {}",
        family_label(family)
    ))
}

fn parse_tcp_v4_table(buffer: &[u8]) -> Result<Vec<RawObservation>, String> {
    parse_rows::<MibTcpRowOwnerPid>(buffer, "TCP/IPv4", |row| {
        let local = IpAddr::V4(Ipv4Addr::from(row.local_addr.to_ne_bytes()));
        let remote = IpAddr::V4(Ipv4Addr::from(row.remote_addr.to_ne_bytes()));
        observation_from_row(
            row.state,
            local,
            port_from_dword(row.local_port),
            remote,
            port_from_dword(row.remote_port),
            row.owning_pid,
        )
    })
}

fn parse_tcp_v6_table(buffer: &[u8]) -> Result<Vec<RawObservation>, String> {
    parse_rows::<MibTcp6RowOwnerPid>(buffer, "TCP/IPv6", |row| {
        let local = IpAddr::V6(Ipv6Addr::from(row.local_addr));
        let remote = IpAddr::V6(Ipv6Addr::from(row.remote_addr));
        observation_from_row(
            row.state,
            local,
            port_from_dword(row.local_port),
            remote,
            port_from_dword(row.remote_port),
            row.owning_pid,
        )
    })
}

fn parse_rows<T: Copy>(
    buffer: &[u8],
    label: &str,
    mut convert: impl FnMut(T) -> Option<RawObservation>,
) -> Result<Vec<RawObservation>, String> {
    let count = table_row_count(buffer, label)? as usize;
    let rows_size = count
        .checked_mul(size_of::<T>())
        .and_then(|bytes| bytes.checked_add(size_of::<u32>()))
        .ok_or_else(|| format!("{label} table size overflow"))?;
    if buffer.len() < rows_size {
        return Err(format!(
            "{label} table truncated: expected {rows_size} bytes, got {}",
            buffer.len()
        ));
    }

    let mut observations = Vec::new();
    for index in 0..count {
        let offset = size_of::<u32>() + index * size_of::<T>();
        // SAFETY: bounds were checked above. read_unaligned avoids assuming
        // alignment for the byte buffer returned by the Windows API.
        let row = unsafe { ptr::read_unaligned(buffer.as_ptr().add(offset).cast::<T>()) };
        if let Some(observation) = convert(row) {
            observations.push(observation);
        }
    }
    Ok(observations)
}

fn table_row_count(buffer: &[u8], label: &str) -> Result<u32, String> {
    let bytes: [u8; 4] = buffer
        .get(..size_of::<u32>())
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| format!("{label} table omitted its row count"))?;
    Ok(u32::from_ne_bytes(bytes))
}

fn observation_from_row(
    state: u32,
    local: IpAddr,
    local_port: u16,
    remote: IpAddr,
    remote_port: u16,
    pid: u32,
) -> Option<RawObservation> {
    let state = tcp_state_label(state)?;
    if local.is_loopback() || remote.is_loopback() || remote.is_unspecified() {
        return None;
    }

    Some(RawObservation {
        protocol: "TCP".to_string(),
        state: state.to_string(),
        local_ip: local.to_string(),
        local_port,
        remote_ip: remote.to_string(),
        remote_port,
        pid,
    })
}

fn tcp_state_label(state: u32) -> Option<&'static str> {
    match state {
        MIB_TCP_STATE_SYN_SENT => Some("SYN_SENT"),
        MIB_TCP_STATE_ESTAB => Some("ESTABLISHED"),
        MIB_TCP_STATE_CLOSE_WAIT => Some("CLOSE_WAIT"),
        _ => None,
    }
}

fn port_from_dword(port: u32) -> u16 {
    u16::from_be(port as u16)
}

fn family_label(family: u32) -> &'static str {
    match family {
        AF_INET => "IPv4",
        AF_INET6 => "IPv6",
        _ => "unknown family",
    }
}

fn win_api_error(api: &str, family: u32, code: u32) -> String {
    format!(
        "{api} failed for {}: Windows error {code} ({})",
        family_label(family),
        std::io::Error::from_raw_os_error(code as i32)
    )
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MibTcpRowOwnerPid {
    state: u32,
    local_addr: u32,
    local_port: u32,
    remote_addr: u32,
    remote_port: u32,
    owning_pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MibTcp6RowOwnerPid {
    local_addr: [u8; 16],
    local_scope_id: u32,
    local_port: u32,
    remote_addr: [u8; 16],
    remote_scope_id: u32,
    remote_port: u32,
    state: u32,
    owning_pid: u32,
}

#[link(name = "iphlpapi")]
extern "system" {
    fn GetExtendedTcpTable(
        tcp_table: *mut c_void,
        size: *mut u32,
        order: i32,
        family: u32,
        table_class: u32,
        reserved: u32,
    ) -> u32;

    fn GetExtendedUdpTable(
        udp_table: *mut c_void,
        size: *mut u32,
        order: i32,
        family: u32,
        table_class: u32,
        reserved: u32,
    ) -> u32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_conversion_matches_network_byte_order() {
        assert_eq!(port_from_dword(443u16.to_be() as u32), 443);
        assert_eq!(port_from_dword(53u16.to_be() as u32), 53);
    }

    #[test]
    fn only_actionable_tcp_states_are_retained() {
        assert_eq!(tcp_state_label(MIB_TCP_STATE_SYN_SENT), Some("SYN_SENT"));
        assert_eq!(tcp_state_label(MIB_TCP_STATE_ESTAB), Some("ESTABLISHED"));
        assert_eq!(
            tcp_state_label(MIB_TCP_STATE_CLOSE_WAIT),
            Some("CLOSE_WAIT")
        );
        assert_eq!(tcp_state_label(2), None); // LISTEN
        assert_eq!(tcp_state_label(11), None); // TIME_WAIT
    }

    #[test]
    fn loopback_and_unspecified_remote_are_excluded() {
        assert!(observation_from_row(
            MIB_TCP_STATE_ESTAB,
            "127.0.0.1".parse().unwrap(),
            50000,
            "8.8.8.8".parse().unwrap(),
            443,
            10,
        )
        .is_none());
        assert!(observation_from_row(
            MIB_TCP_STATE_ESTAB,
            "192.168.1.2".parse().unwrap(),
            50000,
            "0.0.0.0".parse().unwrap(),
            0,
            10,
        )
        .is_none());
    }

    #[test]
    fn parses_v4_rows_without_text_localization() {
        let row = MibTcpRowOwnerPid {
            state: MIB_TCP_STATE_ESTAB,
            local_addr: u32::from_ne_bytes([192, 168, 1, 20]),
            local_port: 50123u16.to_be() as u32,
            remote_addr: u32::from_ne_bytes([1, 1, 1, 1]),
            remote_port: 443u16.to_be() as u32,
            owning_pid: 4242,
        };
        let mut buffer = Vec::from(1u32.to_ne_bytes());
        // SAFETY: tests serialize a plain repr(C), Copy row to exercise the
        // exact variable-length table parser used for the FFI result.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&row as *const MibTcpRowOwnerPid).cast::<u8>(),
                size_of::<MibTcpRowOwnerPid>(),
            )
        };
        buffer.extend_from_slice(bytes);

        let observations = parse_tcp_v4_table(&buffer).unwrap();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].remote_ip, "1.1.1.1");
        assert_eq!(observations[0].remote_port, 443);
        assert_eq!(observations[0].pid, 4242);
    }

    #[test]
    fn rejects_truncated_native_table() {
        let buffer = Vec::from(2u32.to_ne_bytes());
        let error = parse_tcp_v4_table(&buffer).unwrap_err();
        assert!(error.contains("truncated"));
    }

    #[test]
    fn collection_reports_each_family_without_hiding_partial_failure() {
        let result = assemble_collection(
            Ok(vec![RawObservation {
                protocol: "TCP".to_string(),
                state: "ESTABLISHED".to_string(),
                local_ip: "192.168.1.2".to_string(),
                local_port: 50_000,
                remote_ip: "1.1.1.1".to_string(),
                remote_port: 443,
                pid: 42,
            }]),
            Err("IPv6 unavailable".to_string()),
            Ok(3),
            Err("UDP IPv6 unavailable".to_string()),
        )
        .unwrap();

        assert!(result.tcp_ipv4_collected);
        assert!(!result.tcp_ipv6_collected);
        assert!(result.udp_ipv4_collected);
        assert!(!result.udp_ipv6_collected);
        assert_eq!(result.udp_endpoint_count, 3);
        assert_eq!(result.warnings.len(), 2);
    }

    #[test]
    fn collection_fails_only_when_both_tcp_families_fail() {
        let error = assemble_collection(
            Err("IPv4 unavailable".to_string()),
            Err("IPv6 unavailable".to_string()),
            Ok(0),
            Ok(0),
        )
        .unwrap_err();
        assert!(error.to_string().contains("IPv4 and IPv6"));
    }
}
