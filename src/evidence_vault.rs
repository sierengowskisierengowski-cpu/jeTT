//! Tamper-resistant append-only evidence vault with hash chain.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

const DEFAULT_VAULT_PATH: &str = "/var/jett/evidence/vault.jsonl";
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Record appended to the evidence vault.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerdictRecord {
    pub timestamp: u64,
    pub pid: u32,
    pub verdict: String,
    pub explanation: String,
    pub raw_event_ref: String,
    pub prev_hash: String,
    pub entry_hash: String,
}

/// Append-only JSONL evidence vault with SHA-256 hash chain.
pub struct EvidenceVault {
    path: String,
    last_hash: String,
}

impl EvidenceVault {
    pub fn new(path: Option<&str>) -> Self {
        let path = path.unwrap_or(DEFAULT_VAULT_PATH).to_string();
        let last_hash = Self::load_last_hash(&path).unwrap_or_else(|| GENESIS_HASH.to_string());
        Self { path, last_hash }
    }

    fn load_last_hash(path: &str) -> Option<String> {
        let file = fs::File::open(path).ok()?;
        let reader = BufReader::new(file);
        let mut last = None;
        for line in reader.lines().map_while(Result::ok) {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(rec) = serde_json::from_str::<VerdictRecord>(&line) {
                last = Some(rec.entry_hash);
            }
        }
        last
    }

    fn compute_hash(prev: &str, body: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(prev.as_bytes());
        hasher.update(body.as_bytes());
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    /// Append a verdict record; fills prev_hash and entry_hash automatically.
    pub fn append(
        &mut self,
        timestamp: u64,
        pid: u32,
        verdict: &str,
        explanation: &str,
        raw_event_ref: &str,
    ) -> std::io::Result<VerdictRecord> {
        if let Some(parent) = Path::new(&self.path).parent() {
            let _ = fs::create_dir_all(parent);
        }

        let body = format!(
            "{}|{}|{}|{}|{}",
            timestamp, pid, verdict, explanation, raw_event_ref
        );
        let entry_hash = Self::compute_hash(&self.last_hash, &body);
        let record = VerdictRecord {
            timestamp,
            pid,
            verdict: verdict.to_string(),
            explanation: explanation.to_string(),
            raw_event_ref: raw_event_ref.to_string(),
            prev_hash: self.last_hash.clone(),
            entry_hash: entry_hash.clone(),
        };

        let line = serde_json::to_string(&record)? + "\n";
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(line.as_bytes())?;

        self.last_hash = entry_hash;
        Ok(record)
    }

    /// Verify hash chain integrity for all entries.
    pub fn verify_chain(&self) -> Result<usize, (usize, String)> {
        let file = match fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err((0, e.to_string())),
        };

        let reader = BufReader::new(file);
        let mut expected_prev = GENESIS_HASH.to_string();
        let mut count = 0usize;

        for (idx, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| (idx, e.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }
            let rec: VerdictRecord =
                serde_json::from_str(&line).map_err(|e| (idx, e.to_string()))?;

            if rec.prev_hash != expected_prev {
                return Err((idx, "prev_hash mismatch".into()));
            }

            let body = format!(
                "{}|{}|{}|{}|{}",
                rec.timestamp, rec.pid, rec.verdict, rec.explanation, rec.raw_event_ref
            );
            let computed = Self::compute_hash(&rec.prev_hash, &body);
            if computed != rec.entry_hash {
                return Err((idx, "entry_hash mismatch".into()));
            }
            expected_prev = rec.entry_hash.clone();
            count += 1;
        }
        Ok(count)
    }

    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_path() -> String {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("/tmp/jett_vault_test_{}.jsonl", ts)
    }

    #[test]
    fn append_and_verify_chain() {
        let path = test_path();
        let mut vault = EvidenceVault::new(Some(&path));
        vault
            .append(1, 100, "ALLOW", "benign", "event_ref_1")
            .unwrap();
        vault
            .append(2, 101, "QUARANTINE", "hard rule", "event_ref_2")
            .unwrap();
        assert_eq!(vault.verify_chain().unwrap(), 2);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn genesis_starts_at_zero_hash() {
        let path = test_path();
        let vault = EvidenceVault::new(Some(&path));
        assert_eq!(vault.last_hash(), GENESIS_HASH);
        let _ = fs::remove_file(&path);
    }
}
