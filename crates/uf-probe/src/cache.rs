//! Per-network profile cache (master prompt §5.5): the best strategy order for
//! each [`Fingerprint`], kept on disk in a user-specific directory so a known
//! network connects instantly on the next launch.
//!
//! Stored as JSON, keyed by the fingerprint's hex. Only the hash is written —
//! never the raw gateway MAC or SSID.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::fingerprint::Fingerprint;
use crate::score::ScoreBoard;

/// What we remember about one network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// The ladder version these scores were gathered against (invalidate the
    /// profile if the binary's ladder changed).
    pub ladder_version: u32,
    /// Scores per ladder candidate.
    pub scores: ScoreBoard,
    /// Best + backup candidate indices, most recently computed.
    pub preferred: Vec<usize>,
}

impl Profile {
    /// An empty profile for a ladder of `n` candidates.
    pub fn empty(ladder_version: u32, n: usize) -> Self {
        Profile {
            ladder_version,
            scores: ScoreBoard::new(n),
            preferred: Vec::new(),
        }
    }
}

/// Fingerprint → profile, serialisable as a whole to one JSON file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileCache {
    /// Cache schema version.
    pub version: u32,
    /// Profiles keyed by fingerprint hex.
    pub profiles: HashMap<String, Profile>,
}

impl ProfileCache {
    /// A fresh, empty cache.
    pub fn new() -> Self {
        ProfileCache {
            version: 1,
            profiles: HashMap::new(),
        }
    }

    /// Look up a network's profile.
    pub fn get(&self, fp: Fingerprint) -> Option<&Profile> {
        self.profiles.get(&fp.to_hex())
    }

    /// Insert or replace a network's profile.
    pub fn put(&mut self, fp: Fingerprint, profile: Profile) {
        self.profiles.insert(fp.to_hex(), profile);
    }

    /// Serialise to a JSON string.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// Parse from a JSON string.
    pub fn from_json(s: &str) -> serde_json::Result<Self> {
        serde_json::from_str(s)
    }

    /// Load from disk, returning an empty cache if the file does not exist.
    /// A corrupt file is treated as empty (the prober simply re-scans) rather
    /// than an error that would block startup.
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(s) => Self::from_json(&s).unwrap_or_else(|_| ProfileCache::new()),
            Err(_) => ProfileCache::new(),
        }
    }

    /// Write to disk, creating parent directories as needed.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = self
            .to_json()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        // Write a sibling file and rename it over the old one, so a crash or
        // power loss mid-write never leaves a truncated cache (which `load`
        // would silently replace with an empty one, losing every profile).
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = std::path::PathBuf::from(tmp);
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_by_fingerprint() {
        let mut c = ProfileCache::new();
        let fp = Fingerprint(0xdead_beef);
        let mut p = Profile::empty(1, 6);
        p.preferred = vec![2, 1];
        c.put(fp, p.clone());
        assert_eq!(c.get(fp), Some(&p));
        assert!(c.get(Fingerprint(0x1)).is_none());
    }

    #[test]
    fn json_roundtrip() {
        let mut c = ProfileCache::new();
        c.put(Fingerprint(7), Profile::empty(1, 3));
        let json = c.to_json().unwrap();
        let back = ProfileCache::from_json(&json).unwrap();
        assert_eq!(back.get(Fingerprint(7)).unwrap().ladder_version, 1);
    }

    #[test]
    fn load_missing_file_is_empty() {
        let p = std::env::temp_dir().join("uf-probe-does-not-exist-xyz.json");
        let _ = std::fs::remove_file(&p);
        let c = ProfileCache::load(&p);
        assert!(c.profiles.is_empty());
    }

    #[test]
    fn save_then_load_roundtrips() {
        let dir = std::env::temp_dir().join(format!("uf-probe-test-{}", std::process::id()));
        let path = dir.join("profiles.json");
        let mut c = ProfileCache::new();
        c.put(Fingerprint(0x42), Profile::empty(1, 6));
        c.save(&path).unwrap();
        let loaded = ProfileCache::load(&path);
        assert!(loaded.get(Fingerprint(0x42)).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
