use std::process::Command;
use crate::core::errors::AppError;

#[derive(Debug, Clone)]
pub struct RawObservation {
    pub protocol: String,
    pub state: String,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub pid: u32,
}

pub struct Collector;

impl Collector {
    pub fn collect_active_connections() -> Result<Vec<RawObservation>, AppError> {
        let output = Command::new("netstat")
            .arg("-ano")
            .output()
            .map_err(|e| AppError::CollectorError(format!("Failed to execute netstat: {}", e)))?;

        if !output.status.success() {
            return Err(AppError::CollectorError("netstat returned non-zero status".to_string()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut observations = Vec::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Expected for TCP: [Proto, Local Address, Foreign Address, State, PID]
            // Expected for UDP: [Proto, Local Address, Foreign Address, PID]
            
            if parts.len() >= 4 {
                let proto = parts[0].to_uppercase();
                
                if proto == "TCP" && parts.len() >= 5 {
                    let state = parts[3];
                    // Sólo nos interesan conexiones activas o establecidas para análisis saliente.
                    // Para simplificar la prueba y v0.1, tomaremos ESTABLISHED y SYN_SENT.
                    if state != "ESTABLISHED" && state != "SYN_SENT" && state != "CLOSE_WAIT" {
                        continue;
                    }
                    
                    let local = parts[1];
                    let remote = parts[2];
                    let pid_str = parts[4];
                    
                    if let (Some((lip, lport)), Some((rip, rport))) = (Self::parse_address(local), Self::parse_address(remote)) {
                        // Ignorar loopback para "Outbound Monitor"
                        if lip == "127.0.0.1" || lip == "::1" || rip == "127.0.0.1" || rip == "::1" || rip == "0.0.0.0" || rip == "[::]" {
                            continue;
                        }
                        
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            observations.push(RawObservation {
                                protocol: proto,
                                state: state.to_string(),
                                local_ip: lip,
                                local_port: lport,
                                remote_ip: rip,
                                remote_port: rport,
                                pid,
                            });
                        }
                    }
                } else if proto == "UDP" {
                    // UDP no tiene estado en netstat, parts.len() == 4
                    let local = parts[1];
                    let remote = parts[2];
                    let pid_str = parts[3];
                    
                    if let (Some((lip, lport)), Some((rip, rport))) = (Self::parse_address(local), Self::parse_address(remote)) {
                        if lip == "127.0.0.1" || lip == "::1" || rip == "127.0.0.1" || rip == "::1" || rip == "0.0.0.0" || rip == "[::]" || rip == "*"{
                            continue;
                        }
                        
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            observations.push(RawObservation {
                                protocol: proto,
                                state: "STATELESS".to_string(),
                                local_ip: lip,
                                local_port: lport,
                                remote_ip: rip,
                                remote_port: rport,
                                pid,
                            });
                        }
                    }
                }
            }
        }
        
        Ok(observations)
    }

    fn parse_address(addr: &str) -> Option<(String, u16)> {
        // Puede ser IPv4 "192.168.1.1:80" o IPv6 "[fe80::1]:80"
        let last_colon = addr.rfind(':')?;
        let ip_part = &addr[..last_colon];
        let port_part = &addr[last_colon + 1..];
        
        let port = port_part.parse::<u16>().ok()?;
        
        // Limpiar corchetes de IPv6 si los hay
        let ip = if ip_part.starts_with('[') && ip_part.ends_with(']') {
            ip_part[1..ip_part.len()-1].to_string()
        } else {
            ip_part.to_string()
        };
        
        Some((ip, port))
    }
}
