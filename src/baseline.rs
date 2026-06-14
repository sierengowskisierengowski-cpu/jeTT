//! Adaptive baseline histogram and drift scoring from ALLOW verdicts.

use crate::telemetry::ProcessEvent;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const DEFAULT_BASELINE_PATH: &str = "/var/jett/baseline.json";
const MAX_TOKENS: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct BaselineState {
    token_counts: HashMap<String, u32>,
    total_observations: u64,
}

/// Rolling histogram of benign exe/cmdline tokens from ALLOW verdicts.
pub struct Baseline {
    state: BaselineState,
    path: String,
}

impl Default for Baseline {
    fn default() -> Self {
        Self::new(None)
    }
}

impl Baseline {
    pub fn new(path: Option<&str>) -> Self {
        let path = path.unwrap_or(DEFAULT_BASELINE_PATH).to_string();
        let state = fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self { state, path }
    }

    fn tokenize(event: &ProcessEvent) -> Vec<String> {
        let mut tokens = Vec::new();
        if !event.exe_path.is_empty() {
            tokens.push(event.exe_path.clone());
            if let Some(base) = std::path::Path::new(&event.exe_path)
                .file_name()
                .and_then(|s| s.to_str())
            {
                tokens.push(base.to_string());
            }
        }
        for part in event.cmdline.split_whitespace().take(32) {
            if part.len() >= 2 {
                tokens.push(part.to_string());
            }
        }
        tokens
    }

    /// Record tokens from an ALLOW verdict event.
    pub fn observe_allow(&mut self, event: &ProcessEvent) {
        for token in Self::tokenize(event) {
            *self.state.token_counts.entry(token).or_insert(0) += 1;
            if self.state.token_counts.len() > MAX_TOKENS {
                self.prune_least_common();
            }
        }
        self.state.total_observations += 1;
    }

    fn prune_least_common(&mut self) {
        if self.state.token_counts.len() <= MAX_TOKENS {
            return;
        }
        let mut entries: Vec<_> = self
            .state
            .token_counts
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        entries.sort_by_key(|(_, c)| *c);
        let drop_n = entries.len().saturating_sub(MAX_TOKENS);
        for (k, _) in entries.into_iter().take(drop_n) {
            self.state.token_counts.remove(&k);
        }
    }

    /// Drift score in [0,1]: higher means more anomalous vs baseline.
    pub fn drift_score(&self, event: &ProcessEvent) -> f32 {
        if self.state.total_observations == 0 {
            return 0.0;
        }
        let tokens = Self::tokenize(event);
        if tokens.is_empty() {
            return 0.0;
        }
        let mut unknown = 0u32;
        for t in &tokens {
            if !self.state.token_counts.contains_key(t) {
                unknown += 1;
            }
        }
        unknown as f32 / tokens.len() as f32
    }

    /// Persist baseline to disk (best-effort).
    pub fn persist(&self) -> std::io::Result<()> {
        if let Some(parent) = Path::new(&self.path).parent() {
            let _ = fs::create_dir_all(parent);
        }
        let json = serde_json::to_string_pretty(&self.state)?;
        fs::write(&self.path, json)
    }

    pub fn observation_count(&self) -> u64 {
        self.state.total_observations
    }

    pub fn token_count(&self) -> usize {
        self.state.token_counts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::{EventSource, ProcessEvent};

    fn evt(exe: &str, cmd: &str) -> ProcessEvent {
        ProcessEvent {
            pid: 1,
            name: "git".into(),
            cmdline: cmd.into(),
            exe_path: exe.into(),
            uid: 1000,
            timestamp: 1,
            source: EventSource::Proc,
            inode: None,
        }
    }

    #[test]
    fn allow_builds_baseline() {
        let mut b = Baseline::new(Some("/tmp/jett_test_baseline.json"));
        b.observe_allow(&evt("/usr/bin/git", "git status"));
        assert!(b.token_count() > 0);
        assert_eq!(b.drift_score(&evt("/usr/bin/git", "git status")), 0.0);
    }

    #[test]
    fn unknown_exe_drifts_high() {
        let mut b = Baseline::new(Some("/tmp/jett_test_baseline2.json"));
        b.observe_allow(&evt("/usr/bin/git", "git status"));
        let score = b.drift_score(&evt("/tmp/evil", "curl | bash"));
        assert!(score > 0.5);
    }
}
