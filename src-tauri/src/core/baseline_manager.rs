use chrono::{DateTime, Utc};

use crate::core::models::{AffinityLevel, BaselineInfo, BaselineState};
use crate::core::storage::Storage;

/// Umbrales de promoción prudente. baseline-lifecycle.md exige que la
/// promoción no sea por simple repetición: estos mínimos se combinan SIEMPRE
/// con señales cualitativas (trust válido, ruta normal, afinidad media/alta).
/// Los valores concretos no están fijados en la documentación; son decisión
/// de implementación registrada en docs/implementation-notes.md.
pub const CANDIDATE_MIN_SEEN: u32 = 2;
pub const PROVISIONAL_MIN_SEEN: u32 = 5;
pub const PROVISIONAL_MIN_DISTINCT_DAYS: u32 = 3;
pub const CONSOLIDATED_MIN_SEEN: u32 = 15;
pub const CONSOLIDATED_MIN_DISTINCT_DAYS: u32 = 7;

/// Señales de la observación actual que la máquina de estados necesita
/// para decidir transiciones. Se construye desde enricher + identity cache
/// + afinidad, nunca desde intel externo (el baseline es local).
pub struct BaselineObservation<'a> {
    pub sha256: Option<&'a String>,
    /// El archivo físico conocido cambió de contenido (identity cache).
    pub hash_changed: bool,
    pub previous_sha256: Option<&'a String>,
    /// Hallazgo crítico: proceso huérfano o binario irresoluble no protegido.
    /// No pasa por aprendizaje normal (AGENTS.md §3).
    pub critical: bool,
    /// `signature_status == "Valid"`.
    pub trust_valid: bool,
    /// Ruta clasificada como sospechosa (Temp/Downloads).
    pub path_suspicious: bool,
    pub affinity_level: AffinityLevel,
}

pub struct BaselineManager;

impl BaselineManager {
    /// Evalúa y persiste el estado de baseline para una observación.
    /// Devuelve el snapshot que viaja en el finding.
    pub fn evaluate(
        observation: &BaselineObservation,
        storage: &Storage,
        scan_id: Option<&str>,
    ) -> BaselineInfo {
        Self::evaluate_at(observation, storage, scan_id, Utc::now())
    }

    /// Variante con reloj inyectable para poder probar `distinct_days`
    /// y promociones multi-día de forma determinista.
    pub fn evaluate_at(
        observation: &BaselineObservation,
        storage: &Storage,
        scan_id: Option<&str>,
        now: DateTime<Utc>,
    ) -> BaselineInfo {
        // 1. Hallazgos críticos: no aprenden. "Any -> Potentially_Dangerous".
        if observation.critical {
            return Self::handle_critical(observation, storage, scan_id, now);
        }

        // 2. Sin SHA-256 no hay baseline: el hash es obligatorio para
        //    consolidar (baseline-lifecycle.md regla 2). Estado efímero.
        let sha256 = match observation.sha256 {
            Some(hash) => hash,
            None => return Self::ephemeral(BaselineState::Unknown),
        };

        // 3. Cambio de hash sobre un elemento conocido: empujar la identidad
        //    previa a Revalidation_Required (regla 4 del lifecycle).
        let previous_was_known = if observation.hash_changed {
            Self::push_revalidation_on_previous(observation, storage, scan_id, sha256)
        } else {
            false
        };

        // 4. Ciclo normal de la identidad actual.
        let existing = match storage.get_baseline_entry(sha256) {
            Ok(entry) => entry,
            Err(e) => {
                log::warn!("baseline: failed to read entry for {}: {}", sha256, e);
                return Self::ephemeral(BaselineState::Unknown);
            }
        };

        let info = match existing {
            None => Self::create_entry(sha256, previous_was_known, now),
            Some(entry) => Self::update_entry(
                sha256,
                entry,
                observation,
                previous_was_known,
                storage,
                scan_id,
                now,
            ),
        };

        if let Err(e) = storage.write_baseline_entry(sha256, &info) {
            log::warn!("baseline: failed to persist entry for {}: {}", sha256, e);
        }

        info
    }

    /// Aplica una decisión manual del usuario sobre un binario.
    ///
    /// Tipos soportados:
    /// - `validate_local`: `Candidate -> Observed_Local` (lifecycle).
    /// - `revoke_local_validation`: `Observed_Local -> Candidate`.
    /// - `revalidate_accept`: `Revalidation_Required|Potentially_Dangerous ->
    ///   Candidate` para que el elemento vuelva a aprenderse tras revisión
    ///   humana (decisión documentada en docs/implementation-notes.md).
    pub fn apply_manual_decision(
        sha256: &str,
        decision_type: &str,
        storage: &Storage,
    ) -> Result<BaselineInfo, String> {
        Self::apply_manual_decision_with_notes(sha256, decision_type, None, storage)
    }

    pub fn apply_manual_decision_with_notes(
        sha256: &str,
        decision_type: &str,
        notes: Option<&str>,
        storage: &Storage,
    ) -> Result<BaselineInfo, String> {
        let entry = storage
            .get_baseline_entry(sha256)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("No baseline entry for binary {}", sha256))?;

        let current = BaselineState::parse(&entry.state)
            .ok_or_else(|| format!("Stored baseline state '{}' is not valid", entry.state))?;

        let (target, manual_validation) = match decision_type {
            "validate_local" => (BaselineState::ObservedLocal, true),
            "revoke_local_validation" => (BaselineState::Candidate, false),
            "revalidate_accept" => (BaselineState::Candidate, false),
            other => return Err(format!("Unsupported manual decision type '{}'", other)),
        };

        if !current.is_valid_manual_transition(target) {
            return Err(format!(
                "Manual transition {} -> {} is not allowed by the baseline lifecycle",
                current.as_str(),
                target.as_str()
            ));
        }

        let updated = BaselineInfo {
            state: target.as_str().to_string(),
            manual_validation,
            ..entry
        };

        storage
            .write_baseline_entry(sha256, &updated)
            .map_err(|e| e.to_string())?;
        storage
            .record_manual_decision(sha256, decision_type, notes)
            .map_err(|e| e.to_string())?;
        let _ = storage.record_audit_event(
            None,
            "baseline_transition",
            &format!(
                "manual {}: {} -> {} for {}",
                decision_type,
                current.as_str(),
                target.as_str(),
                sha256
            ),
        );

        Ok(updated)
    }

    // ------------------------------------------------------------------
    // Internos
    // ------------------------------------------------------------------

    fn handle_critical(
        observation: &BaselineObservation,
        storage: &Storage,
        scan_id: Option<&str>,
        now: DateTime<Utc>,
    ) -> BaselineInfo {
        if let Some(sha256) = observation.sha256 {
            if let Ok(Some(entry)) = storage.get_baseline_entry(sha256) {
                // "Any -> Potentially_Dangerous" es siempre transición válida.
                let updated = BaselineInfo {
                    state: BaselineState::PotentiallyDangerous.as_str().to_string(),
                    last_seen: Some(now.to_rfc3339()),
                    ..entry
                };
                if let Err(e) = storage.write_baseline_entry(sha256, &updated) {
                    log::warn!("baseline: failed to mark critical entry: {}", e);
                }
                let _ = storage.record_audit_event(
                    scan_id,
                    "baseline_transition",
                    &format!("critical finding: {} -> Potentially_Dangerous", sha256),
                );
                return updated;
            }
        }
        // Sin identidad persistible: el hallazgo crítico se refleja en el
        // finding pero no contamina el aprendizaje (no se persiste entrada).
        Self::ephemeral(BaselineState::PotentiallyDangerous)
    }

    /// Devuelve `true` si la identidad previa estaba en un estado "conocido"
    /// (Observed_Local, Provisional o Consolidated) y fue empujada a
    /// Revalidation_Required.
    fn push_revalidation_on_previous(
        observation: &BaselineObservation,
        storage: &Storage,
        scan_id: Option<&str>,
        new_sha256: &str,
    ) -> bool {
        let previous = match observation.previous_sha256 {
            Some(prev) => prev,
            None => return false,
        };

        let entry = match storage.get_baseline_entry(previous) {
            Ok(Some(entry)) => entry,
            _ => return false,
        };

        let state = match BaselineState::parse(&entry.state) {
            Some(state) => state,
            None => return false,
        };

        if state.is_valid_automatic_transition(BaselineState::RevalidationRequired) {
            let updated = BaselineInfo {
                state: BaselineState::RevalidationRequired.as_str().to_string(),
                ..entry
            };
            if let Err(e) = storage.write_baseline_entry(previous, &updated) {
                log::warn!(
                    "baseline: failed to push revalidation on {}: {}",
                    previous,
                    e
                );
                return false;
            }
            let _ = storage.record_audit_event(
                scan_id,
                "baseline_transition",
                &format!(
                    "hash change detected: {} -> Revalidation_Required (replaced by {})",
                    previous, new_sha256
                ),
            );
            true
        } else {
            false
        }
    }

    fn create_entry(sha256: &str, previous_was_known: bool, now: DateTime<Utc>) -> BaselineInfo {
        let now_str = now.to_rfc3339();
        // Si el hash nuevo sustituye a un elemento conocido, la identidad
        // nueva nace directamente en Revalidation_Required: el cambio de hash
        // no debe ignorarse ni tratarse como primera aparición neutra.
        let state = if previous_was_known {
            BaselineState::RevalidationRequired
        } else {
            BaselineState::Unknown
        };
        let _ = sha256; // el llamador persiste; se mantiene la firma por claridad
        BaselineInfo {
            state: state.as_str().to_string(),
            seen_count: 1,
            distinct_days: 1,
            first_seen: Some(now_str.clone()),
            last_seen: Some(now_str),
            manual_validation: false,
        }
    }

    fn update_entry(
        sha256: &str,
        entry: BaselineInfo,
        observation: &BaselineObservation,
        previous_was_known: bool,
        storage: &Storage,
        scan_id: Option<&str>,
        now: DateTime<Utc>,
    ) -> BaselineInfo {
        let now_str = now.to_rfc3339();

        // Contadores de observación.
        let seen_count = entry.seen_count.saturating_add(1);
        let is_new_day = entry
            .last_seen
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|last| last.with_timezone(&Utc).date_naive() != now.date_naive())
            .unwrap_or(true);
        let distinct_days = if is_new_day {
            entry.distinct_days.saturating_add(1)
        } else {
            entry.distinct_days
        };

        let current = BaselineState::parse(&entry.state).unwrap_or(BaselineState::Unknown);

        // Un rollback a un hash previamente visto también es cambio relevante:
        // si esta identidad estaba consolidada, se revalida.
        let next = if previous_was_known
            && observation.hash_changed
            && current.is_valid_automatic_transition(BaselineState::RevalidationRequired)
        {
            BaselineState::RevalidationRequired
        } else {
            // Señales cualitativas para promoción prudente:
            // trust válido, ruta normal y afinidad media/alta.
            let quality_ok = observation.trust_valid
                && !observation.path_suspicious
                && matches!(
                    observation.affinity_level,
                    AffinityLevel::High | AffinityLevel::Medium
                );

            match current {
                BaselineState::Unknown if seen_count >= CANDIDATE_MIN_SEEN => {
                    BaselineState::Candidate
                }
                BaselineState::Candidate
                    if quality_ok
                        && seen_count >= PROVISIONAL_MIN_SEEN
                        && distinct_days >= PROVISIONAL_MIN_DISTINCT_DAYS =>
                {
                    BaselineState::BaselineProvisional
                }
                BaselineState::BaselineProvisional
                    if quality_ok
                        && seen_count >= CONSOLIDATED_MIN_SEEN
                        && distinct_days >= CONSOLIDATED_MIN_DISTINCT_DAYS =>
                {
                    BaselineState::BaselineConsolidated
                }
                other => other,
            }
        };

        if next != current {
            debug_assert!(current.is_valid_automatic_transition(next));
            let _ = storage.record_audit_event(
                scan_id,
                "baseline_transition",
                &format!("{}: {} -> {}", sha256, current.as_str(), next.as_str()),
            );
        }

        BaselineInfo {
            state: next.as_str().to_string(),
            seen_count,
            distinct_days,
            first_seen: entry.first_seen.or_else(|| Some(now_str.clone())),
            last_seen: Some(now_str),
            manual_validation: entry.manual_validation,
        }
    }

    fn ephemeral(state: BaselineState) -> BaselineInfo {
        BaselineInfo {
            state: state.as_str().to_string(),
            seen_count: 0,
            distinct_days: 0,
            first_seen: None,
            last_seen: None,
            manual_validation: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn obs<'a>(sha: &'a String) -> BaselineObservation<'a> {
        BaselineObservation {
            sha256: Some(sha),
            hash_changed: false,
            previous_sha256: None,
            critical: false,
            trust_valid: true,
            path_suspicious: false,
            affinity_level: AffinityLevel::Medium,
        }
    }

    #[test]
    fn first_sighting_is_unknown() {
        let storage = Storage::new_in_memory().unwrap();
        let sha = "a".repeat(64);
        let info = BaselineManager::evaluate(&obs(&sha), &storage, None);
        assert_eq!(info.state, "Unknown");
        assert_eq!(info.seen_count, 1);
        assert_eq!(info.distinct_days, 1);
        assert!(info.first_seen.is_some());
    }

    #[test]
    fn repeat_sighting_promotes_unknown_to_candidate() {
        let storage = Storage::new_in_memory().unwrap();
        let sha = "b".repeat(64);
        let now = Utc::now();
        BaselineManager::evaluate_at(&obs(&sha), &storage, None, now);
        let info = BaselineManager::evaluate_at(&obs(&sha), &storage, None, now);
        assert_eq!(info.state, "Candidate");
        assert_eq!(info.seen_count, 2);
    }

    #[test]
    fn repetition_alone_does_not_promote_beyond_candidate() {
        // Regla 1 del lifecycle: sin días distintos suficientes no hay
        // promoción aunque se repita muchas veces el mismo día.
        let storage = Storage::new_in_memory().unwrap();
        let sha = "c".repeat(64);
        let now = Utc::now();
        for _ in 0..30 {
            BaselineManager::evaluate_at(&obs(&sha), &storage, None, now);
        }
        let info = storage.get_baseline_entry(&sha).unwrap().unwrap();
        assert_eq!(info.state, "Candidate");
        assert_eq!(info.distinct_days, 1);
    }

    #[test]
    fn prudent_promotion_reaches_provisional_and_consolidated() {
        let storage = Storage::new_in_memory().unwrap();
        let sha = "d".repeat(64);
        let start = Utc::now();

        // Observaciones en días distintos con señales de calidad.
        let mut last = BaselineInfo {
            state: String::new(),
            seen_count: 0,
            distinct_days: 0,
            first_seen: None,
            last_seen: None,
            manual_validation: false,
        };
        for day in 0..20 {
            last = BaselineManager::evaluate_at(
                &obs(&sha),
                &storage,
                None,
                start + Duration::days(day),
            );
        }

        assert_eq!(last.state, "Baseline_Consolidated");
        assert!(last.seen_count >= CONSOLIDATED_MIN_SEEN);
        assert!(last.distinct_days >= CONSOLIDATED_MIN_DISTINCT_DAYS);
    }

    #[test]
    fn unsigned_binary_never_auto_promotes_past_candidate() {
        let storage = Storage::new_in_memory().unwrap();
        let sha = "e".repeat(64);
        let start = Utc::now();

        for day in 0..30 {
            let mut o = obs(&sha);
            o.trust_valid = false; // unsigned
            BaselineManager::evaluate_at(&o, &storage, None, start + Duration::days(day));
        }

        let info = storage.get_baseline_entry(&sha).unwrap().unwrap();
        assert_eq!(info.state, "Candidate");
    }

    #[test]
    fn suspicious_path_blocks_promotion() {
        let storage = Storage::new_in_memory().unwrap();
        let sha = "f".repeat(64);
        let start = Utc::now();

        for day in 0..30 {
            let mut o = obs(&sha);
            o.path_suspicious = true;
            BaselineManager::evaluate_at(&o, &storage, None, start + Duration::days(day));
        }

        let info = storage.get_baseline_entry(&sha).unwrap().unwrap();
        assert_eq!(info.state, "Candidate");
    }

    #[test]
    fn low_affinity_blocks_promotion() {
        let storage = Storage::new_in_memory().unwrap();
        let sha = "1".repeat(64);
        let start = Utc::now();

        for day in 0..30 {
            let mut o = obs(&sha);
            o.affinity_level = AffinityLevel::Low;
            BaselineManager::evaluate_at(&o, &storage, None, start + Duration::days(day));
        }

        let info = storage.get_baseline_entry(&sha).unwrap().unwrap();
        assert_eq!(info.state, "Candidate");
    }

    #[test]
    fn hash_change_pushes_known_entry_to_revalidation() {
        let storage = Storage::new_in_memory().unwrap();
        let old_sha = "2".repeat(64);
        let new_sha = "3".repeat(64);
        let start = Utc::now();

        // Consolidamos la identidad antigua.
        for day in 0..20 {
            BaselineManager::evaluate_at(
                &obs(&old_sha),
                &storage,
                None,
                start + Duration::days(day),
            );
        }
        assert_eq!(
            storage.get_baseline_entry(&old_sha).unwrap().unwrap().state,
            "Baseline_Consolidated"
        );

        // El archivo cambia de contenido: hash nuevo.
        let mut o = obs(&new_sha);
        o.hash_changed = true;
        o.previous_sha256 = Some(&old_sha);
        let info = BaselineManager::evaluate_at(&o, &storage, None, start + Duration::days(21));

        // La identidad nueva nace en Revalidation_Required...
        assert_eq!(info.state, "Revalidation_Required");
        // ...y la antigua se empuja también a Revalidation_Required.
        assert_eq!(
            storage.get_baseline_entry(&old_sha).unwrap().unwrap().state,
            "Revalidation_Required"
        );
    }

    #[test]
    fn hash_change_on_unconsolidated_previous_is_normal_first_sighting() {
        let storage = Storage::new_in_memory().unwrap();
        let old_sha = "4".repeat(64);
        let new_sha = "5".repeat(64);
        let now = Utc::now();

        // La identidad previa solo llegó a Unknown.
        BaselineManager::evaluate_at(&obs(&old_sha), &storage, None, now);

        let mut o = obs(&new_sha);
        o.hash_changed = true;
        o.previous_sha256 = Some(&old_sha);
        let info = BaselineManager::evaluate_at(&o, &storage, None, now);

        assert_eq!(info.state, "Unknown");
        assert_eq!(
            storage.get_baseline_entry(&old_sha).unwrap().unwrap().state,
            "Unknown"
        );
    }

    #[test]
    fn critical_finding_does_not_learn_and_is_potentially_dangerous() {
        let storage = Storage::new_in_memory().unwrap();
        let sha = "6".repeat(64);

        let mut o = obs(&sha);
        o.critical = true;
        let info = BaselineManager::evaluate(&o, &storage, None);

        assert_eq!(info.state, "Potentially_Dangerous");
        // No se creó entrada de aprendizaje nueva.
        assert!(storage.get_baseline_entry(&sha).unwrap().is_none());
    }

    #[test]
    fn critical_finding_on_known_entry_marks_it_dangerous() {
        let storage = Storage::new_in_memory().unwrap();
        let sha = "7".repeat(64);
        let now = Utc::now();

        BaselineManager::evaluate_at(&obs(&sha), &storage, None, now);
        BaselineManager::evaluate_at(&obs(&sha), &storage, None, now);

        let mut o = obs(&sha);
        o.critical = true;
        let info = BaselineManager::evaluate(&o, &storage, None);

        assert_eq!(info.state, "Potentially_Dangerous");
        assert_eq!(
            storage.get_baseline_entry(&sha).unwrap().unwrap().state,
            "Potentially_Dangerous"
        );
    }

    #[test]
    fn no_hash_means_ephemeral_unknown_without_persistence() {
        let storage = Storage::new_in_memory().unwrap();
        let o = BaselineObservation {
            sha256: None,
            hash_changed: false,
            previous_sha256: None,
            critical: false,
            trust_valid: false,
            path_suspicious: false,
            affinity_level: AffinityLevel::None,
        };
        let info = BaselineManager::evaluate(&o, &storage, None);
        assert_eq!(info.state, "Unknown");
        assert_eq!(info.seen_count, 0);
    }

    #[test]
    fn manual_validation_moves_candidate_to_observed_local() {
        let storage = Storage::new_in_memory().unwrap();
        let sha = "8".repeat(64);
        let now = Utc::now();

        BaselineManager::evaluate_at(&obs(&sha), &storage, None, now);
        BaselineManager::evaluate_at(&obs(&sha), &storage, None, now);
        assert_eq!(
            storage.get_baseline_entry(&sha).unwrap().unwrap().state,
            "Candidate"
        );

        let updated =
            BaselineManager::apply_manual_decision(&sha, "validate_local", &storage).unwrap();
        assert_eq!(updated.state, "Observed_Local");
        assert!(updated.manual_validation);
    }

    #[test]
    fn manual_validation_rejected_from_unknown() {
        let storage = Storage::new_in_memory().unwrap();
        let sha = "9".repeat(64);
        BaselineManager::evaluate(&obs(&sha), &storage, None);

        let result = BaselineManager::apply_manual_decision(&sha, "validate_local", &storage);
        assert!(
            result.is_err(),
            "Unknown -> Observed_Local is not a valid transition"
        );
    }

    #[test]
    fn manual_validation_can_be_revoked_back_to_candidate() {
        let storage = Storage::new_in_memory().unwrap();
        let sha = "ef".repeat(32);
        let now = Utc::now();

        BaselineManager::evaluate_at(&obs(&sha), &storage, None, now);
        BaselineManager::evaluate_at(&obs(&sha), &storage, None, now);
        BaselineManager::apply_manual_decision(&sha, "validate_local", &storage).unwrap();

        let updated =
            BaselineManager::apply_manual_decision(&sha, "revoke_local_validation", &storage)
                .unwrap();
        assert_eq!(updated.state, "Candidate");
        assert!(!updated.manual_validation);
    }

    #[test]
    fn observed_local_is_sticky_and_never_merges_into_consolidated() {
        let storage = Storage::new_in_memory().unwrap();
        let sha = "ab".repeat(32);
        let start = Utc::now();

        BaselineManager::evaluate_at(&obs(&sha), &storage, None, start);
        BaselineManager::evaluate_at(&obs(&sha), &storage, None, start);
        BaselineManager::apply_manual_decision(&sha, "validate_local", &storage).unwrap();

        for day in 1..40 {
            BaselineManager::evaluate_at(&obs(&sha), &storage, None, start + Duration::days(day));
        }

        let info = storage.get_baseline_entry(&sha).unwrap().unwrap();
        assert_eq!(info.state, "Observed_Local");
        assert!(info.manual_validation);
    }

    #[test]
    fn revalidation_exit_requires_manual_decision() {
        let storage = Storage::new_in_memory().unwrap();
        let sha = "cd".repeat(32);
        storage
            .write_baseline_entry(
                &sha,
                &BaselineInfo {
                    state: "Revalidation_Required".to_string(),
                    seen_count: 10,
                    distinct_days: 5,
                    first_seen: None,
                    last_seen: None,
                    manual_validation: false,
                },
            )
            .unwrap();

        // Escaneos posteriores no lo sacan de Revalidation_Required.
        let info = BaselineManager::evaluate(&obs(&sha), &storage, None);
        assert_eq!(info.state, "Revalidation_Required");

        // La decisión manual sí.
        let updated =
            BaselineManager::apply_manual_decision(&sha, "revalidate_accept", &storage).unwrap();
        assert_eq!(updated.state, "Candidate");
    }
}
