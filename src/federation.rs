//! Privacy-preserving cross-host intel federation stub.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

const BLOOM_SIZE: usize = 1024;

/// Hashed IOC signal for privacy-preserving export.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct HashedSignal {
    pub hash: String,
    pub kind: String,
}

/// Simple bloom-filter-backed federation hub (no raw telemetry).
pub struct FederationHub {
    bloom: Vec<bool>,
    signals: HashSet<HashedSignal>,
}

impl Default for FederationHub {
    fn default() -> Self {
        Self::new()
    }
}

impl FederationHub {
    pub fn new() -> Self {
        Self {
            bloom: vec![false; BLOOM_SIZE],
            signals: HashSet::new(),
        }
    }

    fn hash_index(value: &str) -> usize {
        let digest = Sha256::digest(value.as_bytes());
        let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) as usize;
        n % BLOOM_SIZE
    }

    fn hash_signal(value: &str, kind: &str) -> HashedSignal {
        let digest = Sha256::digest(format!("{}:{}", kind, value).as_bytes());
        let hash = digest
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        HashedSignal {
            hash,
            kind: kind.to_string(),
        }
    }

    /// Import a hashed IOC signal (local store + bloom).
    pub fn import_signal(&mut self, value: &str, kind: &str) {
        let sig = Self::hash_signal(value, kind);
        let idx = Self::hash_index(&sig.hash);
        self.bloom[idx] = true;
        self.signals.insert(sig);
    }

    /// Check if a value likely exists in federated intel (bloom may false-positive).
    pub fn might_match(&self, value: &str, kind: &str) -> bool {
        let sig = Self::hash_signal(value, kind);
        self.bloom[Self::hash_index(&sig.hash)]
    }

    /// Export hashed signals only — no raw telemetry.
    pub fn export_signals(&self) -> Vec<HashedSignal> {
        self.signals.iter().cloned().collect()
    }

    /// Import a batch of hashed signals from a peer.
    pub fn import_signals(&mut self, signals: &[HashedSignal]) {
        for sig in signals {
            let idx = Self::hash_index(&sig.hash);
            self.bloom[idx] = true;
            self.signals.insert(sig.clone());
        }
    }

    pub fn signal_count(&self) -> usize {
        self.signals.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_contains_no_raw_values() {
        let mut hub = FederationHub::new();
        hub.import_signal("evil.example.com", "domain");
        let exported = hub.export_signals();
        assert_eq!(exported.len(), 1);
        assert!(!exported[0].hash.is_empty());
        assert_eq!(exported[0].kind, "domain");
        let json = serde_json::to_string(&exported).unwrap();
        assert!(!json.contains("evil.example.com"));
    }

    #[test]
    fn round_trip_import_export() {
        let mut a = FederationHub::new();
        a.import_signal("abc123", "hash");
        let exported = a.export_signals();
        let mut b = FederationHub::new();
        b.import_signals(&exported);
        assert_eq!(b.signal_count(), 1);
        assert!(b.might_match("abc123", "hash"));
    }
}
