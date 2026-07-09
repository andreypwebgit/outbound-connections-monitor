use crate::core::models::{RiskInfo, BaselineInfo, ProcessInfo, BinaryIdentity, TrustInfo, AffinityInfo};

pub struct RiskEngine;

impl RiskEngine {
    pub fn evaluate(
        process: &ProcessInfo,
        _identity: &BinaryIdentity,
        trust: &TrustInfo,
        baseline: &BaselineInfo,
        affinity: &AffinityInfo,
    ) -> RiskInfo {
        let mut score: u8 = 0;
        let mut reason_codes = Vec::new();
        
        // 1. Process Checks
        if process.file_missing {
            score += 50;
            reason_codes.push("FILE_MISSING".to_string());
        }
        
        if process.orphaned {
            score += 50;
            reason_codes.push("ORPHANED_PROCESS".to_string());
        }
        
        match process.path_class.as_str() {
            "Temp" | "Downloads" => {
                score += 30;
                reason_codes.push("EXECUTING_FROM_TEMP_OR_DOWNLOADS".to_string());
            },
            "Windows" => {
                if trust.signature_status != "Valid" {
                    score += 60;
                    reason_codes.push("UNSIGNED_SYSTEM_PROCESS".to_string());
                } else if let Some(subject) = &trust.signer_subject {
                    if !subject.to_lowercase().contains("microsoft") {
                        score += 40;
                        reason_codes.push("SYSTEM_PATH_BUT_NOT_MICROSOFT".to_string());
                    } else {
                        reason_codes.push("VALID_MICROSOFT_SIGNATURE".to_string());
                    }
                }
            },
            _ => {}
        }
        
        // 1.5 Advanced Heuristics (v0.3)
        // Suspicious Command Line
        if let Some(cmd) = &process.command_line {
            let cmd_lower = cmd.to_lowercase();
            if cmd_lower.contains("-enc") || cmd_lower.contains("-encodedcommand") || 
               cmd_lower.contains("bypass") || cmd_lower.contains("hidden") ||
               cmd_lower.contains("nop") || cmd_lower.contains("noninteractive") ||
               cmd_lower.contains("iex") || cmd_lower.contains("invoke-expression") {
                score += 60;
                reason_codes.push("SUSPICIOUS_COMMAND_LINE".to_string());
            }
        }
        
        // Suspicious Parent Process
        if let Some(parent) = &process.parent_name {
            let p_lower = parent.to_lowercase();
            if p_lower.contains("winword.exe") || p_lower.contains("excel.exe") || 
               p_lower.contains("powerpnt.exe") || p_lower.contains("outlook.exe") {
                score += 80;
                reason_codes.push("OFFICE_SPAWNED_NETWORK_PROCESS".to_string());
            } else if p_lower.contains("wscript.exe") || p_lower.contains("cscript.exe") {
                score += 70;
                reason_codes.push("SCRIPT_SPAWNED_NETWORK_PROCESS".to_string());
            }
        }
        
        // Suspicious User Context
        if let Some(user) = &process.user {
            let u_lower = user.to_lowercase();
            let proc_lower = process.name.to_lowercase();
            // Si SYSTEM ejecuta procesos típicamente de usuario
            if u_lower.contains("system") {
                if proc_lower.contains("chrome.exe") || proc_lower.contains("edge.exe") || 
                   proc_lower.contains("firefox.exe") || proc_lower.contains("explorer.exe") {
                    score += 75;
                    reason_codes.push("USER_PROCESS_AS_SYSTEM".to_string());
                }
            }
        }
        
        // 2. Trust Checks
        if trust.signature_status == "Invalid" {
            score += 80;
            reason_codes.push("INVALID_SIGNATURE".to_string());
        }
        
        // 3. Baseline & Affinity
        if baseline.state == "Unknown" {
            score += 20;
            reason_codes.push("UNKNOWN_BASELINE".to_string());
        }
        
        if affinity.level == "none" || affinity.level == "low" {
            score += 15;
            reason_codes.push("LOW_AFFINITY".to_string());
        }
        
        // Capping score to 100
        if score > 100 {
            score = 100;
        }
        
        let band = Self::score_to_band(score);
        let recommended_action = Self::band_to_action(&band);
        
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
            80..=100 => "potentially_dangerous".to_string(),
            _ => "potentially_dangerous".to_string()
        }
    }
    
    fn band_to_action(band: &str) -> String {
        match band {
            "known_safe" => "ignore".to_string(),
            "known_low" => "observe".to_string(),
            "known_moderate" => "review".to_string(),
            "known_high" => "revalidate".to_string(),
            "potentially_dangerous" => "investigate".to_string(),
            _ => "investigate".to_string()
        }
    }
}
