use crate::core::enricher::Enricher;
use crate::core::models::{AffinityInfo, BaselineInfo, BinaryIdentity, ProcessInfo, RiskInfo, TrustInfo};

/// Contexto completo de evaluación de riesgo para un finding.
pub struct RiskContext<'a> {
    pub process: &'a ProcessInfo,
    pub identity: &'a BinaryIdentity,
    pub trust: &'a TrustInfo,
    pub baseline: &'a BaselineInfo,
    pub affinity: &'a AffinityInfo,
    /// El identity cache detectó que el archivo físico cambió de contenido.
    pub hash_changed: bool,
    /// Destino por IP pública sin hostname resoluble.
    pub ip_only_destination: bool,
}

pub struct RiskEngine;

impl RiskEngine {
    pub fn evaluate(ctx: &RiskContext) -> RiskInfo {
        let mut score: i32 = 0;
        let mut reason_codes: Vec<String> = Vec::new();
        let mut critical = false;

        let push = |codes: &mut Vec<String>, code: &str| {
            if !codes.iter().any(|c| c == code) {
                codes.push(code.to_string());
            }
        };

        // ------------------------------------------------------------
        // 1. Integridad del proceso/binario (señales críticas primero)
        // ------------------------------------------------------------
        if ctx.process.orphaned {
            score += 80;
            critical = true;
            push(&mut reason_codes, "ORPHANED_IMAGE");
        }

        if ctx.process.file_missing && !ctx.process.orphaned {
            if Enricher::is_protected_system_process(&ctx.process.name) {
                // Procesos kernel/PPL: la falta de ruta es esperable, no señal.
                push(&mut reason_codes, "PROTECTED_SYSTEM_PROCESS");
            } else {
                score += 50;
                critical = true;
                push(&mut reason_codes, "FILE_MISSING");
            }
        }

        // ------------------------------------------------------------
        // 2. Ruta de ejecución
        // ------------------------------------------------------------
        match ctx.process.path_class.as_str() {
            "Temp" | "Downloads" => {
                score += 30;
                push(&mut reason_codes, "SUSPICIOUS_PATH");
            }
            "Windows" => {
                if ctx.trust.signature_status != "Valid" {
                    score += 60;
                    push(&mut reason_codes, "UNSIGNED_SYSTEM_PROCESS");
                } else if let Some(subject) = &ctx.trust.signer_subject {
                    if !subject.to_lowercase().contains("microsoft") {
                        score += 40;
                        push(&mut reason_codes, "SYSTEM_PATH_BUT_NOT_MICROSOFT");
                    } else {
                        push(&mut reason_codes, "VALID_MICROSOFT_SIGNATURE");
                    }
                }
            }
            "ProgramFiles" | "ProgramFilesX86" => {
                push(&mut reason_codes, "EXPECTED_PATH");
            }
            _ => {}
        }

        // ------------------------------------------------------------
        // 3. Heurísticas de contexto de ejecución (v0.3)
        // ------------------------------------------------------------
        if let Some(cmd) = &ctx.process.command_line {
            let cmd_lower = cmd.to_lowercase();
            if cmd_lower.contains("-enc")
                || cmd_lower.contains("-encodedcommand")
                || cmd_lower.contains("bypass")
                || cmd_lower.contains("hidden")
                || cmd_lower.contains("nop")
                || cmd_lower.contains("noninteractive")
                || cmd_lower.contains("iex")
                || cmd_lower.contains("invoke-expression")
            {
                score += 60;
                push(&mut reason_codes, "SUSPICIOUS_COMMAND_LINE");
            }
        }

        if let Some(parent) = &ctx.process.parent_name {
            let p_lower = parent.to_lowercase();
            if p_lower.contains("winword.exe")
                || p_lower.contains("excel.exe")
                || p_lower.contains("powerpnt.exe")
                || p_lower.contains("outlook.exe")
            {
                score += 80;
                push(&mut reason_codes, "OFFICE_SPAWNED_NETWORK_PROCESS");
            } else if p_lower.contains("wscript.exe") || p_lower.contains("cscript.exe") {
                score += 70;
                push(&mut reason_codes, "SCRIPT_SPAWNED_NETWORK_PROCESS");
            }
        }

        if let Some(user) = &ctx.process.user {
            let u_lower = user.to_lowercase();
            let proc_lower = ctx.process.name.to_lowercase();
            if u_lower.contains("system")
                && (proc_lower.contains("chrome.exe")
                    || proc_lower.contains("edge.exe")
                    || proc_lower.contains("firefox.exe")
                    || proc_lower.contains("explorer.exe"))
            {
                score += 75;
                push(&mut reason_codes, "USER_PROCESS_AS_SYSTEM");
            }
        }

        // ------------------------------------------------------------
        // 4. Trust / firma
        // ------------------------------------------------------------
        match ctx.trust.signature_status.as_str() {
            "Invalid" => {
                score += 80;
                push(&mut reason_codes, "INVALID_SIGNATURE");
            }
            "Unsigned" => {
                score += 25;
                push(&mut reason_codes, "UNSIGNED_BINARY");
            }
            _ => {}
        }

        // ------------------------------------------------------------
        // 5. Identidad / hash
        // ------------------------------------------------------------
        if ctx.hash_changed {
            score += 30;
            push(&mut reason_codes, "NEW_HASH");
        }

        // ------------------------------------------------------------
        // 6. Baseline
        // ------------------------------------------------------------
        match ctx.baseline.state.as_str() {
            "Unknown" => {
                score += 20;
                push(&mut reason_codes, "UNKNOWN_BASELINE");
            }
            "Revalidation_Required" => {
                score += 40;
                push(&mut reason_codes, "REVALIDATION_REQUIRED");
            }
            "Potentially_Dangerous" => {
                score += 60;
                critical = true;
            }
            _ => {}
        }

        // ------------------------------------------------------------
        // 7. Afinidad y destino
        // ------------------------------------------------------------
        if ctx.affinity.level == "none" || ctx.affinity.level == "low" {
            score += 15;
            push(&mut reason_codes, "LOW_AFFINITY");
        }

        if ctx.ip_only_destination {
            score += 15;
            push(&mut reason_codes, "IP_ONLY_DESTINATION");
        }

        // Códigos descriptivos de destino (sin puntuación adicional: los
        // puntos ya los aporta la señal de afinidad; estos explican).
        let known_destination = ctx.affinity.matched_signals.iter().any(|s| {
            s == "SAME_HOSTNAME" || s == "SAME_ROOT_DOMAIN" || s == "ESTABLISHED_PATTERN"
        });
        let new_destination = ctx
            .affinity
            .mismatched_signals
            .iter()
            .any(|s| s == "NO_HISTORICAL_PROFILE" || s == "NEW_ROOT_DOMAIN");
        if known_destination {
            push(&mut reason_codes, "KNOWN_DESTINATION");
        } else if new_destination {
            push(&mut reason_codes, "NEW_DESTINATION");
        }

        // ------------------------------------------------------------
        // 8. Señales que REDUCEN riesgo (scoring-model.md)
        // ------------------------------------------------------------
        if ctx.trust.signature_status == "Valid" && ctx.trust.chain_status == "Trusted" {
            score -= 15;
            push(&mut reason_codes, "VALID_SIGNATURE");
        }

        match ctx.baseline.state.as_str() {
            "Baseline_Consolidated" => {
                score -= 25;
                push(&mut reason_codes, "ESTABLISHED_BASELINE");
                push(&mut reason_codes, "KNOWN_HASH");
            }
            "Baseline_Provisional" => {
                score -= 10;
                push(&mut reason_codes, "KNOWN_HASH");
            }
            "Observed_Local" => {
                if ctx.baseline.manual_validation {
                    score -= 20;
                    push(&mut reason_codes, "LOCAL_OBSERVED");
                    push(&mut reason_codes, "MANUAL_TRUST");
                }
            }
            _ => {}
        }

        if ctx.affinity.level == "high" {
            score -= 15;
            push(&mut reason_codes, "HIGH_AFFINITY");
        }

        // ------------------------------------------------------------
        // 9. Consolidación: floor crítico, clamp y banda
        // ------------------------------------------------------------
        // Los hallazgos críticos (huérfano / binario irresoluble) no pueden
        // quedar absueltos por señales positivas: floor en banda crítica.
        if critical && score < 80 {
            score = 80;
        }

        let score = score.clamp(0, 100) as u8;
        let band = Self::score_to_band(score);

        // La acción recomendada sale de la banda, con un override explicable:
        // un baseline en Revalidation_Required siempre recomienda `revalidate`
        // aunque el resto de señales dejen la banda por debajo de known_high.
        let recommended_action = if ctx.baseline.state == "Revalidation_Required" && band != "potentially_dangerous" {
            "revalidate".to_string()
        } else {
            Self::band_to_action(&band)
        };

        RiskInfo {
            score,
            band,
            reason_codes,
            recommended_action,
        }
    }

    fn score_to_band(score: u8) -> String {
        match score {
            0..=19 => "known_safe".to_string(),
            20..=39 => "known_low".to_string(),
            40..=59 => "known_moderate".to_string(),
            60..=79 => "known_high".to_string(),
            _ => "potentially_dangerous".to_string(),
        }
    }

    fn band_to_action(band: &str) -> String {
        match band {
            "known_safe" => "ignore".to_string(),
            "known_low" => "observe".to_string(),
            "known_moderate" => "review".to_string(),
            "known_high" => "revalidate".to_string(),
            _ => "investigate".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(path_class: &str) -> ProcessInfo {
        ProcessInfo {
            pid: 1234,
            name: "app.exe".to_string(),
            started_at: None,
            path: Some(format!("C:\\{}\\app.exe", path_class)),
            path_class: path_class.to_string(),
            file_missing: false,
            orphaned: false,
            services: vec![],
            ppid: None,
            parent_name: None,
            command_line: None,
            user: None,
        }
    }

    fn identity(sha: Option<&str>) -> BinaryIdentity {
        BinaryIdentity {
            volume_serial: Some("ABCD1234".to_string()),
            file_id: Some("0000000000001234".to_string()),
            file_size: 1000,
            last_write_time: Some("2026-01-01T00:00:00Z".to_string()),
            sha256: sha.map(|s| s.to_string()),
            hash_source: sha.map(|_| "fresh".to_string()),
        }
    }

    fn valid_trust() -> TrustInfo {
        TrustInfo {
            signature_status: "Valid".to_string(),
            signature_source: "embedded".to_string(),
            signer_subject: Some("CN=Vendor Inc".to_string()),
            signer_thumbprint: Some("AA11".to_string()),
            chain_status: "Trusted".to_string(),
        }
    }

    fn unsigned_trust() -> TrustInfo {
        TrustInfo {
            signature_status: "Unsigned".to_string(),
            signature_source: "none".to_string(),
            signer_subject: None,
            signer_thumbprint: None,
            chain_status: "Unknown".to_string(),
        }
    }

    fn baseline(state: &str) -> BaselineInfo {
        BaselineInfo {
            state: state.to_string(),
            seen_count: 10,
            distinct_days: 5,
            first_seen: Some("2026-01-01T00:00:00Z".to_string()),
            last_seen: Some("2026-07-01T00:00:00Z".to_string()),
            manual_validation: false,
        }
    }

    fn affinity(level: &str, score: u8) -> AffinityInfo {
        AffinityInfo {
            score,
            level: level.to_string(),
            matched_signals: if level == "high" {
                vec!["SAME_HOSTNAME".to_string(), "SAME_PORT".to_string()]
            } else {
                vec![]
            },
            mismatched_signals: if level == "none" {
                vec!["NO_HISTORICAL_PROFILE".to_string()]
            } else {
                vec![]
            },
        }
    }

    #[test]
    fn consolidated_signed_high_affinity_is_known_safe() {
        // Escenario 1 de testing-strategy: firmado, hash conocido, destino habitual.
        let p = process("ProgramFiles");
        let ctx = RiskContext {
            process: &p,
            identity: &identity(Some("aa")),
            trust: &valid_trust(),
            baseline: &baseline("Baseline_Consolidated"),
            affinity: &affinity("high", 95),
            hash_changed: false,
            ip_only_destination: false,
        };
        let risk = RiskEngine::evaluate(&ctx);
        assert_eq!(risk.band, "known_safe", "score={} reasons={:?}", risk.score, risk.reason_codes);
        assert_eq!(risk.recommended_action, "ignore");
        assert!(risk.reason_codes.contains(&"KNOWN_HASH".to_string()));
        assert!(risk.reason_codes.contains(&"VALID_SIGNATURE".to_string()));
        assert!(risk.reason_codes.contains(&"HIGH_AFFINITY".to_string()));
        assert!(risk.reason_codes.contains(&"ESTABLISHED_BASELINE".to_string()));
    }

    #[test]
    fn orphaned_process_is_critical_regardless_of_other_signals() {
        // Escenario 4: proceso huérfano -> crítico. AGENTS.md §3.
        let mut p = process("ProgramFiles");
        p.orphaned = true;
        p.file_missing = true;
        let ctx = RiskContext {
            process: &p,
            identity: &identity(None),
            trust: &valid_trust(),
            baseline: &baseline("Baseline_Consolidated"),
            affinity: &affinity("high", 95),
            hash_changed: false,
            ip_only_destination: false,
        };
        let risk = RiskEngine::evaluate(&ctx);
        assert_eq!(risk.band, "potentially_dangerous");
        assert_eq!(risk.recommended_action, "investigate");
        assert!(risk.reason_codes.contains(&"ORPHANED_IMAGE".to_string()));
        assert!(risk.score >= 80);
    }

    #[test]
    fn missing_file_is_critical_unless_protected() {
        let mut p = process("Other");
        p.file_missing = true;
        let ctx = RiskContext {
            process: &p,
            identity: &identity(None),
            trust: &unsigned_trust(),
            baseline: &baseline("Unknown"),
            affinity: &affinity("none", 0),
            hash_changed: false,
            ip_only_destination: false,
        };
        let risk = RiskEngine::evaluate(&ctx);
        assert_eq!(risk.band, "potentially_dangerous");
        assert!(risk.reason_codes.contains(&"FILE_MISSING".to_string()));

        // Proceso protegido: mismo caso pero exento.
        let mut protected = process("Other");
        protected.name = "MsMpEng.exe".to_string();
        protected.file_missing = true;
        let ctx2 = RiskContext {
            process: &protected,
            identity: &identity(None),
            trust: &unsigned_trust(),
            baseline: &baseline("Unknown"),
            affinity: &affinity("none", 0),
            hash_changed: false,
            ip_only_destination: false,
        };
        let risk2 = RiskEngine::evaluate(&ctx2);
        assert!(risk2.reason_codes.contains(&"PROTECTED_SYSTEM_PROCESS".to_string()));
        assert!(!risk2.reason_codes.contains(&"FILE_MISSING".to_string()));
        assert_ne!(risk2.band, "potentially_dangerous");
    }

    #[test]
    fn hash_change_forces_revalidation_recommendation() {
        // Escenario 2: firmado con hash nuevo -> revalidación.
        let p = process("ProgramFiles");
        let ctx = RiskContext {
            process: &p,
            identity: &identity(Some("bb")),
            trust: &valid_trust(),
            baseline: &baseline("Revalidation_Required"),
            affinity: &affinity("high", 95),
            hash_changed: true,
            ip_only_destination: false,
        };
        let risk = RiskEngine::evaluate(&ctx);
        assert_eq!(risk.recommended_action, "revalidate");
        assert!(risk.reason_codes.contains(&"NEW_HASH".to_string()));
        assert!(risk.reason_codes.contains(&"REVALIDATION_REQUIRED".to_string()));
        assert_ne!(risk.band, "known_safe");
    }

    #[test]
    fn manually_validated_local_binary_gets_relief() {
        // Escenario 3: unsigned validado manualmente -> Observed_Local.
        let p = process("UserProfile");
        let mut b = baseline("Observed_Local");
        b.manual_validation = true;
        let ctx = RiskContext {
            process: &p,
            identity: &identity(Some("cc")),
            trust: &unsigned_trust(),
            baseline: &b,
            affinity: &affinity("high", 95),
            hash_changed: false,
            ip_only_destination: false,
        };
        let risk = RiskEngine::evaluate(&ctx);
        assert!(risk.reason_codes.contains(&"LOCAL_OBSERVED".to_string()));
        assert!(risk.reason_codes.contains(&"MANUAL_TRUST".to_string()));
        assert!(
            risk.band == "known_safe" || risk.band == "known_low",
            "validated local binary should not stay high: {} ({:?})",
            risk.band,
            risk.reason_codes
        );
    }

    #[test]
    fn ip_only_destination_with_low_affinity_raises_risk() {
        // Escenario 5: destino por IP pura con baja afinidad.
        let p = process("ProgramFiles");
        let ctx = RiskContext {
            process: &p,
            identity: &identity(Some("dd")),
            trust: &valid_trust(),
            baseline: &baseline("Candidate"),
            affinity: &affinity("none", 10),
            hash_changed: false,
            ip_only_destination: true,
        };
        let risk = RiskEngine::evaluate(&ctx);
        assert!(risk.reason_codes.contains(&"IP_ONLY_DESTINATION".to_string()));
        assert!(risk.reason_codes.contains(&"LOW_AFFINITY".to_string()));
        assert!(risk.score >= 15);
    }

    #[test]
    fn unsigned_binary_from_temp_is_flagged() {
        let p = process("Temp");
        let ctx = RiskContext {
            process: &p,
            identity: &identity(Some("ee")),
            trust: &unsigned_trust(),
            baseline: &baseline("Unknown"),
            affinity: &affinity("none", 0),
            hash_changed: false,
            ip_only_destination: false,
        };
        let risk = RiskEngine::evaluate(&ctx);
        assert!(risk.reason_codes.contains(&"SUSPICIOUS_PATH".to_string()));
        assert!(risk.reason_codes.contains(&"UNSIGNED_BINARY".to_string()));
        assert!(risk.reason_codes.contains(&"UNKNOWN_BASELINE".to_string()));
        assert!(
            risk.band == "known_high" || risk.band == "potentially_dangerous",
            "got {} ({})",
            risk.band,
            risk.score
        );
    }

    #[test]
    fn office_spawned_process_keeps_v03_heuristics() {
        let mut p = process("AppData");
        p.parent_name = Some("WINWORD.EXE".to_string());
        let ctx = RiskContext {
            process: &p,
            identity: &identity(Some("ff")),
            trust: &unsigned_trust(),
            baseline: &baseline("Unknown"),
            affinity: &affinity("none", 0),
            hash_changed: false,
            ip_only_destination: false,
        };
        let risk = RiskEngine::evaluate(&ctx);
        assert!(risk.reason_codes.contains(&"OFFICE_SPAWNED_NETWORK_PROCESS".to_string()));
        assert_eq!(risk.band, "potentially_dangerous");
    }

    #[test]
    fn suspicious_command_line_detected() {
        let mut p = process("Windows");
        p.name = "powershell.exe".to_string();
        p.command_line = Some("powershell -NoP -NonI -W Hidden -Enc SQBFAFgA".to_string());
        let ctx = RiskContext {
            process: &p,
            identity: &identity(Some("11")),
            trust: &valid_trust(),
            baseline: &baseline("Unknown"),
            affinity: &affinity("none", 0),
            hash_changed: false,
            ip_only_destination: false,
        };
        let risk = RiskEngine::evaluate(&ctx);
        assert!(risk.reason_codes.contains(&"SUSPICIOUS_COMMAND_LINE".to_string()));
        assert_eq!(risk.band, "potentially_dangerous");
    }

    #[test]
    fn score_is_traceable_to_reason_codes() {
        // Regla: "el score debe ser trazable a señales concretas".
        // Un finding sin ninguna señal debe quedarse en 0 / known_safe.
        let p = process("Other");
        let ctx = RiskContext {
            process: &p,
            identity: &identity(Some("22")),
            trust: &valid_trust(),
            baseline: &baseline("Candidate"),
            affinity: &affinity("medium", 75),
            hash_changed: false,
            ip_only_destination: false,
        };
        let risk = RiskEngine::evaluate(&ctx);
        assert_eq!(risk.band, "known_safe");
        assert!(risk.reason_codes.contains(&"VALID_SIGNATURE".to_string()));
    }

    #[test]
    fn bands_map_to_actions() {
        assert_eq!(RiskEngine::score_to_band(0), "known_safe");
        assert_eq!(RiskEngine::score_to_band(19), "known_safe");
        assert_eq!(RiskEngine::score_to_band(20), "known_low");
        assert_eq!(RiskEngine::score_to_band(39), "known_low");
        assert_eq!(RiskEngine::score_to_band(40), "known_moderate");
        assert_eq!(RiskEngine::score_to_band(59), "known_moderate");
        assert_eq!(RiskEngine::score_to_band(60), "known_high");
        assert_eq!(RiskEngine::score_to_band(79), "known_high");
        assert_eq!(RiskEngine::score_to_band(80), "potentially_dangerous");
        assert_eq!(RiskEngine::score_to_band(100), "potentially_dangerous");

        assert_eq!(RiskEngine::band_to_action("known_safe"), "ignore");
        assert_eq!(RiskEngine::band_to_action("known_low"), "observe");
        assert_eq!(RiskEngine::band_to_action("known_moderate"), "review");
        assert_eq!(RiskEngine::band_to_action("known_high"), "revalidate");
        assert_eq!(RiskEngine::band_to_action("potentially_dangerous"), "investigate");
    }
}
