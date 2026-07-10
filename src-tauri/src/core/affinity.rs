//! Cálculo de afinidad de red (docs/affinity-model.md).
//!
//! Este módulo forma parte de la responsabilidad del Risk Engine
//! ("calcular afinidad", docs/architecture.md §3) pero vive en archivo
//! propio para mantener módulos pequeños con una sola responsabilidad.
//!
//! La afinidad compara el destino observado con los perfiles históricos del
//! MISMO binario (tabla `affinity_profiles`), nunca con la IP exacta como
//! ancla: las señales son hostname/FQDN, root domain, ASN, puerto y patrón
//! histórico.

use std::net::IpAddr;

use crate::core::models::{AffinityInfo, AffinityLevel};
use crate::core::storage::{AffinityProfile, Storage};

/// Pesos de las señales de afinidad. Los valores concretos no están fijados
/// en la documentación (solo las bandas 90-100/70-89/40-69/0-39); son
/// decisión de implementación registrada en docs/implementation-notes.md.
///
/// Propiedades que garantizan:
/// - El puerto por sí solo nunca supera `low` (regla 2 del modelo).
/// - `high` exige hostname exacto + puerto conocido + patrón repetido.
/// - Solo root domain (subdominio nuevo) alcanza como mucho `medium`.
const W_SAME_HOSTNAME: u8 = 60;
const W_SAME_ROOT_DOMAIN: u8 = 40;
const W_SAME_ASN: u8 = 20;
const W_SAME_PORT: u8 = 30;
const W_COMMON_PORT: u8 = 10;
const W_ESTABLISHED_PATTERN: u8 = 10;
const W_SIGNER_CONTINUITY: u8 = 10;

/// Puertos salientes habituales que no constituyen señal negativa por sí
/// mismos aunque el binario no los haya usado antes.
const COMMON_OUTBOUND_PORTS: &[u16] = &[80, 443, 53, 22, 25, 123, 465, 587, 993, 995, 8080, 8443];

/// Contexto de la observación actual para el cálculo de afinidad.
pub struct AffinityContext<'a> {
    /// SHA-256 del binario observado (identidad del perfil).
    pub binary_id: Option<&'a str>,
    /// Identidad previa cuando el identity cache detectó cambio de hash:
    /// sus perfiles se heredan ("cambio razonablemente revalidable").
    pub fallback_binary_id: Option<&'a str>,
    /// El signer del binario nuevo coincide con el del previo.
    pub signer_continuity: bool,
    pub hostname: Option<&'a str>,
    pub root_domain: Option<&'a str>,
    pub asn_org: Option<&'a str>,
    pub remote_ip: &'a str,
    pub remote_port: u16,
}

pub struct AffinityEngine;

impl AffinityEngine {
    /// Calcula la afinidad del destino actual contra los perfiles históricos.
    /// Debe llamarse ANTES de `record_observation` para no coincidir con la
    /// propia observación que se está evaluando.
    pub fn compute(ctx: &AffinityContext, storage: &Storage) -> AffinityInfo {
        let mut matched: Vec<String> = Vec::new();
        let mut mismatched: Vec<String> = Vec::new();
        let mut score: u16 = 0;

        // Señal de destino independiente del histórico: IP pura.
        let ip_only = ctx.hostname.is_none();
        let private_dest = is_private_ip(ctx.remote_ip);
        if ip_only {
            if private_dest {
                // Destinos de red local sin PTR son normales: señal neutra.
                matched.push("PRIVATE_NETWORK_DESTINATION".to_string());
            } else {
                mismatched.push("IP_ONLY_DESTINATION".to_string());
            }
        }

        let profiles = Self::load_profiles(ctx, storage, &mut matched);

        if profiles.is_empty() {
            mismatched.push("NO_HISTORICAL_PROFILE".to_string());
            if COMMON_OUTBOUND_PORTS.contains(&ctx.remote_port) {
                score += W_COMMON_PORT as u16;
                matched.push("COMMON_PORT".to_string());
            }
            let score = score.min(100) as u8;
            return AffinityInfo {
                score,
                level: AffinityLevel::from_score(score).as_str().to_string(),
                matched_signals: matched,
                mismatched_signals: mismatched,
            };
        }

        // --- Señales de dominio/hostname -------------------------------
        let same_hostname = ctx
            .hostname
            .is_some_and(|h| profiles.iter().any(|p| p.hostname.as_deref() == Some(h)));
        let same_root_domain = ctx.root_domain.is_some_and(|rd| {
            profiles
                .iter()
                .any(|p| p.root_domain.as_deref() == Some(rd))
        });
        let history_has_domains = profiles.iter().any(|p| p.root_domain.is_some());

        if same_hostname {
            score += W_SAME_HOSTNAME as u16;
            matched.push("SAME_HOSTNAME".to_string());
        } else if same_root_domain {
            // Subdominio nuevo dentro del mismo ecosistema: señal media.
            score += W_SAME_ROOT_DOMAIN as u16;
            matched.push("SAME_ROOT_DOMAIN".to_string());
        } else if history_has_domains && ctx.root_domain.is_some() {
            mismatched.push("NEW_ROOT_DOMAIN".to_string());
        }

        // --- Señal de ASN (solo cuando hay dato; en v0.1 suele ser null) --
        if let Some(asn) = ctx.asn_org {
            let same_asn = profiles.iter().any(|p| p.asn_org.as_deref() == Some(asn));
            if same_asn {
                score += W_SAME_ASN as u16;
                matched.push("SAME_ASN".to_string());
            } else if profiles.iter().any(|p| p.asn_org.is_some()) {
                mismatched.push("NEW_ASN".to_string());
            }
        }

        // --- Señal de puerto --------------------------------------------
        let same_port = profiles
            .iter()
            .any(|p| p.remote_port == Some(ctx.remote_port));
        if same_port {
            score += W_SAME_PORT as u16;
            matched.push("SAME_PORT".to_string());
        } else if COMMON_OUTBOUND_PORTS.contains(&ctx.remote_port) {
            // Puerto nuevo pero plausible para software legítimo.
            score += W_COMMON_PORT as u16;
            matched.push("COMMON_PORT".to_string());
        } else {
            mismatched.push("NEW_PORT".to_string());
        }

        // --- Patrón histórico repetido ----------------------------------
        let established = profiles.iter().any(|p| {
            p.times_seen >= 3
                && (p.hostname.as_deref() == ctx.hostname
                    || p.root_domain.as_deref() == ctx.root_domain)
                && p.remote_port == Some(ctx.remote_port)
        });
        if established {
            score += W_ESTABLISHED_PATTERN as u16;
            matched.push("ESTABLISHED_PATTERN".to_string());
        }

        // --- Continuidad de identidad tras cambio de hash ----------------
        if ctx.signer_continuity {
            score += W_SIGNER_CONTINUITY as u16;
            matched.push("SAME_SIGNER".to_string());
        }

        // Cambio múltiple simultáneo de señales críticas: se explicita
        // aunque el score bajo ya lo refleje.
        let domain_drifted = mismatched
            .iter()
            .any(|s| s == "NEW_ROOT_DOMAIN" || s == "IP_ONLY_DESTINATION");
        let port_drifted = mismatched.iter().any(|s| s == "NEW_PORT");
        if domain_drifted && port_drifted {
            mismatched.push("MULTI_SIGNAL_DRIFT".to_string());
        }

        let score = score.min(100) as u8;
        AffinityInfo {
            score,
            level: AffinityLevel::from_score(score).as_str().to_string(),
            matched_signals: matched,
            mismatched_signals: mismatched,
        }
    }

    /// Registra la observación actual como perfil (o refuerzo de perfil)
    /// para futuros cálculos. Se llama tras `compute`.
    pub fn record_observation(ctx: &AffinityContext, storage: &Storage) {
        if let Some(binary_id) = ctx.binary_id {
            if let Err(e) = storage.record_affinity_observation(
                binary_id,
                ctx.hostname,
                ctx.root_domain,
                ctx.asn_org,
                ctx.remote_port,
            ) {
                log::warn!("affinity: failed to record observation: {}", e);
            }
        }
    }

    fn load_profiles(
        ctx: &AffinityContext,
        storage: &Storage,
        matched: &mut Vec<String>,
    ) -> Vec<AffinityProfile> {
        let mut profiles = match ctx.binary_id {
            Some(id) => storage.get_affinity_profiles(id).unwrap_or_else(|e| {
                log::warn!("affinity: failed to load profiles: {}", e);
                Vec::new()
            }),
            None => Vec::new(),
        };

        // Herencia de perfiles en revalidación: si el binario acaba de
        // cambiar de hash, su histórico razonable es el de la identidad
        // previa (docs/affinity-model.md: "cambio razonablemente revalidable").
        if profiles.is_empty() {
            if let Some(prev) = ctx.fallback_binary_id {
                if let Ok(inherited) = storage.get_affinity_profiles(prev) {
                    if !inherited.is_empty() {
                        matched.push("INHERITED_HISTORY".to_string());
                        profiles = inherited;
                    }
                }
            }
        }

        profiles
    }
}

/// Deriva el root domain (eTLD+1 aproximado) de un hostname resuelto.
///
/// Implementación local sin lista completa de sufijos públicos: se cubren
/// los sufijos de dos niveles habituales (`co.uk`, `com.mx`, ...) mediante
/// heurística. Limitación aceptada y documentada: no es una PSL completa,
/// pero evita depender de datos externos para el escaneo básico.
pub fn extract_root_domain(hostname: &str) -> Option<String> {
    let host = hostname.trim_end_matches('.').to_lowercase();
    if host.is_empty() || host.parse::<IpAddr>().is_ok() {
        return None;
    }

    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|l| l.is_empty()) {
        return None;
    }

    let tld = labels[labels.len() - 1];
    let sld = labels[labels.len() - 2];
    const SECOND_LEVEL: &[&str] = &["co", "com", "net", "org", "gov", "edu", "ac", "mil"];

    if labels.len() >= 3 && tld.len() == 2 && SECOND_LEVEL.contains(&sld) {
        Some(labels[labels.len() - 3..].join("."))
    } else {
        Some(labels[labels.len() - 2..].join("."))
    }
}

/// Rangos privados/link-local: un destino de LAN sin hostname no debe
/// tratarse como "IP pura" sospechosa.
pub fn is_private_ip(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_private() || v4.is_link_local() || v4.is_loopback(),
        Ok(IpAddr::V6(v6)) => {
            v6.is_loopback()
                // fe80::/10 link-local, fc00::/7 unique-local
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_profile(
        storage: &Storage,
        binary_id: &str,
        hostname: Option<&str>,
        root: Option<&str>,
        port: u16,
        times: u32,
    ) {
        for _ in 0..times {
            storage
                .record_affinity_observation(binary_id, hostname, root, None, port)
                .unwrap();
        }
    }

    fn ctx<'a>(
        binary_id: Option<&'a str>,
        hostname: Option<&'a str>,
        root_domain: Option<&'a str>,
        remote_ip: &'a str,
        remote_port: u16,
    ) -> AffinityContext<'a> {
        AffinityContext {
            binary_id,
            fallback_binary_id: None,
            signer_continuity: false,
            hostname,
            root_domain,
            asn_org: None,
            remote_ip,
            remote_port,
        }
    }

    #[test]
    fn root_domain_extraction() {
        assert_eq!(
            extract_root_domain("ax-0001.ax-msedge.net"),
            Some("ax-msedge.net".to_string())
        );
        assert_eq!(
            extract_root_domain("edge.example.co.uk"),
            Some("example.co.uk".to_string())
        );
        assert_eq!(
            extract_root_domain("example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(extract_root_domain("localhost"), None);
        assert_eq!(extract_root_domain("52.222.10.1"), None);
        assert_eq!(extract_root_domain(""), None);
    }

    #[test]
    fn private_ip_detection() {
        assert!(is_private_ip("192.168.1.10"));
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("172.16.5.5"));
        assert!(!is_private_ip("172.32.0.1"));
        assert!(!is_private_ip("8.8.8.8"));
        assert!(is_private_ip("fe80::1"));
        assert!(!is_private_ip("2606:4700::1"));
    }

    #[test]
    fn high_affinity_for_strong_repeat_match() {
        let storage = Storage::new_in_memory().unwrap();
        let bin = "a".repeat(64);
        seed_profile(
            &storage,
            &bin,
            Some("api.example.com"),
            Some("example.com"),
            443,
            5,
        );

        let info = AffinityEngine::compute(
            &ctx(
                Some(&bin),
                Some("api.example.com"),
                Some("example.com"),
                "8.8.8.8",
                443,
            ),
            &storage,
        );

        assert_eq!(
            info.level, "high",
            "score={} signals={:?}",
            info.score, info.matched_signals
        );
        assert!(info.matched_signals.contains(&"SAME_HOSTNAME".to_string()));
        assert!(info.matched_signals.contains(&"SAME_PORT".to_string()));
        assert!(info
            .matched_signals
            .contains(&"ESTABLISHED_PATTERN".to_string()));
    }

    #[test]
    fn medium_affinity_for_new_subdomain_same_ecosystem() {
        let storage = Storage::new_in_memory().unwrap();
        let bin = "b".repeat(64);
        seed_profile(
            &storage,
            &bin,
            Some("api.example.com"),
            Some("example.com"),
            443,
            5,
        );

        // Subdominio nuevo dentro del mismo root domain, mismo puerto.
        let info = AffinityEngine::compute(
            &ctx(
                Some(&bin),
                Some("cdn.example.com"),
                Some("example.com"),
                "8.8.8.8",
                443,
            ),
            &storage,
        );

        assert_eq!(
            info.level, "medium",
            "score={} signals={:?}",
            info.score, info.matched_signals
        );
        assert!(info
            .matched_signals
            .contains(&"SAME_ROOT_DOMAIN".to_string()));
        assert!(!info.matched_signals.contains(&"SAME_HOSTNAME".to_string()));
    }

    #[test]
    fn new_domain_degrades_affinity() {
        let storage = Storage::new_in_memory().unwrap();
        let bin = "c".repeat(64);
        seed_profile(
            &storage,
            &bin,
            Some("api.example.com"),
            Some("example.com"),
            443,
            5,
        );

        let info = AffinityEngine::compute(
            &ctx(
                Some(&bin),
                Some("evil.attacker.net"),
                Some("attacker.net"),
                "8.8.8.8",
                443,
            ),
            &storage,
        );

        assert!(info.score < 70, "unrelated domain must not reach medium");
        assert!(info
            .mismatched_signals
            .contains(&"NEW_ROOT_DOMAIN".to_string()));
    }

    #[test]
    fn port_alone_never_exceeds_low() {
        // Regla 2 del modelo: el puerto no decide por sí solo.
        let storage = Storage::new_in_memory().unwrap();
        let bin = "d".repeat(64);
        seed_profile(
            &storage,
            &bin,
            Some("api.example.com"),
            Some("example.com"),
            443,
            5,
        );

        // IP pura desconocida, mismo puerto 443.
        let info =
            AffinityEngine::compute(&ctx(Some(&bin), None, None, "203.0.113.9", 443), &storage);

        assert!(
            info.score < 70,
            "ip-only destination with matching port must stay low, got {}",
            info.score
        );
        assert!(info
            .mismatched_signals
            .contains(&"IP_ONLY_DESTINATION".to_string()));
    }

    #[test]
    fn plausible_port_change_keeps_medium_with_same_domain() {
        let storage = Storage::new_in_memory().unwrap();
        let bin = "e".repeat(64);
        seed_profile(
            &storage,
            &bin,
            Some("api.example.com"),
            Some("example.com"),
            443,
            5,
        );

        // Mismo hostname, puerto nuevo pero común (8443).
        let info = AffinityEngine::compute(
            &ctx(
                Some(&bin),
                Some("api.example.com"),
                Some("example.com"),
                "8.8.8.8",
                8443,
            ),
            &storage,
        );

        assert_eq!(info.level, "medium", "score={}", info.score);
        assert!(info.matched_signals.contains(&"COMMON_PORT".to_string()));
    }

    #[test]
    fn rare_port_change_is_flagged() {
        let storage = Storage::new_in_memory().unwrap();
        let bin = "f".repeat(64);
        seed_profile(
            &storage,
            &bin,
            Some("api.example.com"),
            Some("example.com"),
            443,
            5,
        );

        let info = AffinityEngine::compute(
            &ctx(
                Some(&bin),
                Some("api.example.com"),
                Some("example.com"),
                "8.8.8.8",
                4444,
            ),
            &storage,
        );

        assert!(info.mismatched_signals.contains(&"NEW_PORT".to_string()));
        assert!(info.score < 90, "rare port must block high affinity");
    }

    #[test]
    fn no_history_yields_conservative_none() {
        let storage = Storage::new_in_memory().unwrap();
        let bin = "0".repeat(64);

        let info = AffinityEngine::compute(
            &ctx(
                Some(&bin),
                Some("api.example.com"),
                Some("example.com"),
                "8.8.8.8",
                443,
            ),
            &storage,
        );

        assert_eq!(info.level, "none");
        assert!(info
            .mismatched_signals
            .contains(&"NO_HISTORICAL_PROFILE".to_string()));
    }

    #[test]
    fn private_lan_destination_is_not_penalized_as_ip_only() {
        let storage = Storage::new_in_memory().unwrap();
        let info = AffinityEngine::compute(&ctx(None, None, None, "192.168.1.50", 8009), &storage);
        assert!(!info
            .mismatched_signals
            .contains(&"IP_ONLY_DESTINATION".to_string()));
        assert!(info
            .matched_signals
            .contains(&"PRIVATE_NETWORK_DESTINATION".to_string()));
    }

    #[test]
    fn revalidated_binary_inherits_previous_profiles() {
        let storage = Storage::new_in_memory().unwrap();
        let old_bin = "1".repeat(64);
        seed_profile(
            &storage,
            &old_bin,
            Some("api.example.com"),
            Some("example.com"),
            443,
            5,
        );

        let new_bin = "2".repeat(64);
        let mut context = ctx(
            Some(&new_bin),
            Some("api.example.com"),
            Some("example.com"),
            "8.8.8.8",
            443,
        );
        context.fallback_binary_id = Some(&old_bin);
        context.signer_continuity = true;

        let info = AffinityEngine::compute(&context, &storage);

        assert!(info
            .matched_signals
            .contains(&"INHERITED_HISTORY".to_string()));
        assert!(info.matched_signals.contains(&"SAME_SIGNER".to_string()));
        assert!(
            info.score >= 90,
            "revalidable change with same signer should stay high, got {}",
            info.score
        );
    }

    #[test]
    fn multi_signal_drift_is_explicit() {
        let storage = Storage::new_in_memory().unwrap();
        let bin = "3".repeat(64);
        seed_profile(
            &storage,
            &bin,
            Some("api.example.com"),
            Some("example.com"),
            443,
            5,
        );

        let info = AffinityEngine::compute(
            &ctx(
                Some(&bin),
                Some("x.unrelated.io"),
                Some("unrelated.io"),
                "8.8.8.8",
                4444,
            ),
            &storage,
        );

        assert!(info
            .mismatched_signals
            .contains(&"MULTI_SIGNAL_DRIFT".to_string()));
        assert_eq!(info.level, "none");
    }

    #[test]
    fn recording_observations_builds_profiles() {
        let storage = Storage::new_in_memory().unwrap();
        let bin = "4".repeat(64);
        let context = ctx(
            Some(&bin),
            Some("api.example.com"),
            Some("example.com"),
            "8.8.8.8",
            443,
        );

        AffinityEngine::record_observation(&context, &storage);
        AffinityEngine::record_observation(&context, &storage);

        let profiles = storage.get_affinity_profiles(&bin).unwrap();
        assert_eq!(profiles.len(), 1, "same pattern must upsert, not duplicate");
        assert_eq!(profiles[0].times_seen, 2);
        assert_eq!(profiles[0].hostname.as_deref(), Some("api.example.com"));
    }
}
