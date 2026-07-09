use crate::core::models::{BaselineInfo, BaselineState};
use crate::core::storage::Storage;

pub struct BaselineManager;

impl BaselineManager {
    pub fn get_baseline_for_identity(sha256: Option<&String>, storage: &Storage) -> BaselineInfo {
        if let Some(hash) = sha256 {
            match storage.upsert_baseline_for_sha256(hash) {
                Ok(info) => info,
                Err(e) => {
                    eprintln!("Error en Storage upsert: {:?}", e);
                    BaselineInfo {
                        state: BaselineState::Unknown.as_str().to_string(),
                        seen_count: 1,
                        distinct_days: 1,
                        first_seen: None,
                        last_seen: None,
                        manual_validation: false,
                    }
                }
            }
        } else {
            BaselineInfo {
                state: BaselineState::Unknown.as_str().to_string(),
                seen_count: 1,
                distinct_days: 1,
                first_seen: None,
                last_seen: None,
                manual_validation: false,
            }
        }
    }
}
