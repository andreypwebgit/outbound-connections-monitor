use std::collections::HashMap;
use std::path::Path;

use crate::core::enricher::Enricher;
use crate::core::models::{BinaryIdentity, TrustInfo};
use crate::core::storage::{Storage, StoredIdentity};

/// Resultado de resolver la identidad de un binario a través del caché.
#[derive(Debug, Clone)]
pub struct ResolvedIdentity {
    pub identity: BinaryIdentity,
    pub trust: TrustInfo,
    /// `true` cuando el archivo físico ya era conocido (mismo file_id/ruta)
    /// pero su contenido cambió: dispara revalidación en el BaselineManager.
    pub hash_changed: bool,
    /// SHA-256 previo del archivo físico cuando `hash_changed` es `true`.
    pub previous_sha256: Option<String>,
}

/// Caché de identidad de dos niveles:
///
/// 1. **Persistente (SQLite)**: la clave de invalidación definida en
///    docs/architecture.md — `volume_serial + file_id + file_size +
///    last_write_time`. Si la clave coincide con lo almacenado, se reutilizan
///    SHA-256 y trust sin recalcular (`hash_source = "cache"`).
/// 2. **Memoización por scan (memoria)**: dentro de un mismo scan, un path ya
///    resuelto no vuelve a tocar disco ni SQLite.
///
/// Un miss con identidad física conocida pero hash distinto expone
/// `hash_changed = true`: es la señal de revalidación exigida por AGENTS.md.
pub struct IdentityCache {
    memo: HashMap<String, ResolvedIdentity>,
}

impl IdentityCache {
    pub fn new() -> Self {
        Self { memo: HashMap::new() }
    }

    pub fn resolve(&mut self, path: Option<&String>, storage: &Storage) -> ResolvedIdentity {
        let path_str = match path {
            Some(p) if !p.is_empty() => p.clone(),
            _ => return Self::degraded(),
        };

        if let Some(cached) = self.memo.get(&path_str) {
            return cached.clone();
        }

        let resolved = self.resolve_uncached(&path_str, storage);
        self.memo.insert(path_str, resolved.clone());
        resolved
    }

    fn resolve_uncached(&self, path_str: &str, storage: &Storage) -> ResolvedIdentity {
        let path = Path::new(path_str);
        let stat = match Enricher::stat_file(path) {
            Some(stat) => stat,
            // Archivo ausente o inaccesible: identidad degradada honesta,
            // sin hash inventado (docs/error-handling.md §3).
            None => return Self::degraded(),
        };

        // Normalizamos a minúsculas: el filesystem de Windows es
        // case-insensitive y el mismo binario puede aparecer con distinto casing.
        let normalized_path = path_str.to_lowercase();

        // Búsqueda de identidad previa: clave física primero, ruta como fallback.
        let stored = self.find_stored(storage, &stat.volume_serial, &stat.file_id, &normalized_path);

        // HIT: clave de invalidación intacta -> reutilizar hash y trust.
        if let Some(ref prev) = stored {
            let key_matches = prev.file_size == stat.file_size
                && prev.last_write_time == stat.last_write_time
                && prev.last_write_time.is_some();

            if key_matches {
                let trust = self.trust_for(storage, &prev.sha256, path_str);
                return ResolvedIdentity {
                    identity: BinaryIdentity {
                        volume_serial: stat.volume_serial,
                        file_id: stat.file_id,
                        file_size: stat.file_size,
                        last_write_time: stat.last_write_time,
                        sha256: Some(prev.sha256.clone()),
                        hash_source: Some("cache".to_string()),
                    },
                    trust,
                    hash_changed: false,
                    previous_sha256: None,
                };
            }
        }

        // MISS: recalcular hash fresco.
        let sha256 = Enricher::compute_sha256(path);

        let (hash_changed, previous_sha256) = match (&sha256, &stored) {
            (Some(new_hash), Some(prev)) if *new_hash != prev.sha256 => {
                (true, Some(prev.sha256.clone()))
            }
            _ => (false, None),
        };

        let trust = match &sha256 {
            Some(hash) => {
                // Persistir la identidad nueva para futuros hits de caché.
                let record = StoredIdentity {
                    sha256: hash.clone(),
                    normalized_path: Some(normalized_path),
                    volume_serial: stat.volume_serial.clone(),
                    file_id: stat.file_id.clone(),
                    file_size: stat.file_size,
                    last_write_time: stat.last_write_time.clone(),
                };
                if let Err(e) = storage.upsert_identity(&record) {
                    log::warn!("identity_cache: failed to persist identity: {}", e);
                }
                self.trust_for(storage, hash, path_str)
            }
            // Hash ilegible: trust se calcula igualmente (Authenticode puede
            // funcionar aunque la lectura directa falle), pero sin caché.
            None => Enricher::verify_authenticode(path_str),
        };

        ResolvedIdentity {
            identity: BinaryIdentity {
                volume_serial: stat.volume_serial,
                file_id: stat.file_id,
                file_size: stat.file_size,
                last_write_time: stat.last_write_time,
                sha256: sha256.clone(),
                hash_source: sha256.as_ref().map(|_| "fresh".to_string()),
            },
            trust,
            hash_changed,
            previous_sha256,
        }
    }

    fn find_stored(
        &self,
        storage: &Storage,
        volume_serial: &Option<String>,
        file_id: &Option<String>,
        normalized_path: &str,
    ) -> Option<StoredIdentity> {
        if let (Some(vs), Some(fid)) = (volume_serial, file_id) {
            match storage.find_identity_by_physical_key(vs, fid) {
                Ok(Some(found)) => return Some(found),
                Ok(None) => {}
                Err(e) => log::warn!("identity_cache: physical key lookup failed: {}", e),
            }
        }
        match storage.find_identity_by_path(normalized_path) {
            Ok(found) => found,
            Err(e) => {
                log::warn!("identity_cache: path lookup failed: {}", e);
                None
            }
        }
    }

    /// Trust cacheado por SHA-256: la firma de un contenido idéntico no cambia
    /// entre scans salvo revocación, y `verified_at` queda registrado.
    fn trust_for(&self, storage: &Storage, sha256: &str, path_str: &str) -> TrustInfo {
        match storage.get_trust_for_binary(sha256) {
            Ok(Some(trust)) => trust,
            _ => {
                let trust = Enricher::verify_authenticode(path_str);
                if let Err(e) = storage.save_trust_record(sha256, &trust) {
                    log::warn!("identity_cache: failed to persist trust: {}", e);
                }
                trust
            }
        }
    }

    fn degraded() -> ResolvedIdentity {
        ResolvedIdentity {
            identity: BinaryIdentity {
                volume_serial: None,
                file_id: None,
                file_size: 0,
                last_write_time: None,
                sha256: None,
                hash_source: None,
            },
            trust: Enricher::unknown_trust(),
            hash_changed: false,
            previous_sha256: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::models::TrustInfo;
    use std::fs;

    fn test_file(name: &str, content: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(name);
        fs::write(&path, content).unwrap();
        path
    }

    fn seed_trust(storage: &Storage, sha256: &str) {
        // Sembramos trust para que el test no dependa de PowerShell.
        storage
            .save_trust_record(
                sha256,
                &TrustInfo {
                    signature_status: "Unsigned".to_string(),
                    signature_source: "none".to_string(),
                    signer_subject: None,
                    signer_thumbprint: None,
                    chain_status: "Unknown".to_string(),
                },
            )
            .unwrap();
    }

    #[test]
    fn cache_miss_then_hit_when_key_unchanged() {
        let storage = Storage::new_in_memory().unwrap();
        let path = test_file("ocm_cache_hit_test.bin", b"stable content");
        let path_string = path.to_string_lossy().to_string();

        // Primer scan: miss -> fresh
        let mut cache = IdentityCache::new();
        let first = cache.resolve(Some(&path_string), &storage);
        assert_eq!(first.identity.hash_source.as_deref(), Some("fresh"));
        assert!(first.identity.sha256.is_some());
        assert!(!first.hash_changed);

        seed_trust(&storage, first.identity.sha256.as_ref().unwrap());

        // Segundo scan (nuevo caché en memoria, mismo storage): hit -> cache
        let mut cache2 = IdentityCache::new();
        let second = cache2.resolve(Some(&path_string), &storage);
        assert_eq!(second.identity.hash_source.as_deref(), Some("cache"));
        assert_eq!(second.identity.sha256, first.identity.sha256);
        assert!(!second.hash_changed);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn cache_miss_and_hash_changed_when_content_changes() {
        let storage = Storage::new_in_memory().unwrap();
        let path = test_file("ocm_cache_change_test.bin", b"version one");
        let path_string = path.to_string_lossy().to_string();

        let mut cache = IdentityCache::new();
        let first = cache.resolve(Some(&path_string), &storage);
        let first_hash = first.identity.sha256.clone().unwrap();
        seed_trust(&storage, &first_hash);

        // Cambiamos el contenido (cambia file_size y last_write_time).
        fs::write(&path, b"version two - different bytes").unwrap();

        let mut cache2 = IdentityCache::new();
        let second = cache2.resolve(Some(&path_string), &storage);

        assert_eq!(second.identity.hash_source.as_deref(), Some("fresh"));
        assert!(second.hash_changed, "hash change must be detected");
        assert_eq!(second.previous_sha256.as_deref(), Some(first_hash.as_str()));
        assert_ne!(second.identity.sha256, Some(first_hash));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn missing_file_degrades_without_inventing_data() {
        let storage = Storage::new_in_memory().unwrap();
        let mut cache = IdentityCache::new();
        let ghost = "C:\\definitely\\not\\here\\ghost.exe".to_string();
        let resolved = cache.resolve(Some(&ghost), &storage);

        assert!(resolved.identity.sha256.is_none());
        assert!(resolved.identity.hash_source.is_none());
        assert_eq!(resolved.trust.signature_status, "Unknown");
        assert!(!resolved.hash_changed);
    }

    #[test]
    fn memoizes_within_a_scan() {
        let storage = Storage::new_in_memory().unwrap();
        let path = test_file("ocm_cache_memo_test.bin", b"memo content");
        let path_string = path.to_string_lossy().to_string();

        let mut cache = IdentityCache::new();
        let first = cache.resolve(Some(&path_string), &storage);
        seed_trust(&storage, first.identity.sha256.as_ref().unwrap());

        // Segunda resolución en el MISMO scan: debe venir de la memoización
        // (mismo hash_source "fresh", sin pasar a "cache").
        let second = cache.resolve(Some(&path_string), &storage);
        assert_eq!(second.identity.hash_source.as_deref(), Some("fresh"));
        assert_eq!(second.identity.sha256, first.identity.sha256);

        let _ = fs::remove_file(&path);
    }
}
