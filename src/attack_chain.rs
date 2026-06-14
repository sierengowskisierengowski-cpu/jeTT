//! ATT&CK-mapped attack chain detection from event sequences.

use crate::syscall_fingerprint::SyscallIntent;
use crate::telemetry::ProcessEvent;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

/// Subset of MITRE ATT&CK technique IDs relevant to jeTT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttackTechnique {
    T1059, // Command and Scripting Interpreter
    T1053, // Scheduled Task/Job
    T1071, // Application Layer Protocol (C2)
    T1027, // Obfuscated Files or Information
    T1548, // Abuse Elevation Control Mechanism
    T1105, // Ingress Tool Transfer
    T1059_004, // Unix Shell
}

impl AttackTechnique {
    pub fn id(&self) -> &'static str {
        match self {
            AttackTechnique::T1059 => "T1059",
            AttackTechnique::T1053 => "T1053",
            AttackTechnique::T1071 => "T1071",
            AttackTechnique::T1027 => "T1027",
            AttackTechnique::T1548 => "T1548",
            AttackTechnique::T1105 => "T1105",
            AttackTechnique::T1059_004 => "T1059.004",
        }
    }
}

/// Severity of a matched chain for confidence/response tiering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ChainSeverity {
    Low,
    Medium,
    High,
}

/// A matched attack chain hit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainHit {
    pub technique: String,
    pub confidence: f32,
    pub evidence_refs: Vec<String>,
    pub severity: ChainSeverity,
}

/// Per-PID rolling event window entry.
#[derive(Debug, Clone)]
struct WindowEvent {
    pid: u32,
    exe: String,
    verdict: String,
    behavior: String,
    intent: SyscallIntent,
}

/// Sequence matcher over per-PID event windows.
pub struct ChainMatcher {
    window_size: usize,
    windows: HashMap<u32, VecDeque<WindowEvent>>,
}

impl ChainMatcher {
    pub fn new(window_size: usize) -> Self {
        Self {
            window_size,
            windows: HashMap::new(),
        }
    }

    /// Observe an event and return a chain hit if a technique pattern matches.
    pub fn observe(
        &mut self,
        event: &ProcessEvent,
        verdict: &str,
        behavior: &str,
        intent: &SyscallIntent,
    ) -> Option<ChainHit> {
        let entry = WindowEvent {
            pid: event.pid,
            exe: event.exe_path.clone(),
            verdict: verdict.to_string(),
            behavior: behavior.to_string(),
            intent: intent.clone(),
        };

        let window = self.windows.entry(event.pid).or_default();
        window.push_back(entry);
        while window.len() > self.window_size {
            window.pop_front();
        }

        Self::match_window(window, event.pid)
    }

    fn match_window(window: &VecDeque<WindowEvent>, pid: u32) -> Option<ChainHit> {
        let latest = window.back()?;

        // T1071: outbound/C2 after suspicious exec
        if latest.intent.outbound || latest.intent.connect {
            let had_exec = window.iter().any(|e| e.intent.exec || e.intent.spawn_child);
            if had_exec || latest.verdict.contains("QUARANTINE") {
                return Some(ChainHit {
                    technique: AttackTechnique::T1071.id().to_string(),
                    confidence: 0.88,
                    evidence_refs: vec![format!("pid:{} outbound", pid)],
                    severity: ChainSeverity::High,
                });
            }
        }

        // T1059.004: shell + pipe/download pattern
        if latest.exe.contains("bash")
            || latest.exe.contains("sh")
            || latest.behavior.contains("curl")
            || latest.behavior.contains("wget")
        {
            if latest.behavior.contains('|') || latest.intent.exec {
                return Some(ChainHit {
                    technique: AttackTechnique::T1059_004.id().to_string(),
                    confidence: 0.85,
                    evidence_refs: vec![format!("pid:{} shell_pipeline", pid)],
                    severity: ChainSeverity::Medium,
                });
            }
        }

        // T1027: memfd / obfuscation
        if latest.intent.memfd || latest.behavior.contains("base64") {
            return Some(ChainHit {
                technique: AttackTechnique::T1027.id().to_string(),
                confidence: 0.82,
                evidence_refs: vec![format!("pid:{} obfuscation", pid)],
                severity: ChainSeverity::Medium,
            });
        }

        // T1548: pkexec/sudo elevation abuse
        if latest.exe.contains("pkexec") || latest.behavior.contains("sudo") {
            return Some(ChainHit {
                technique: AttackTechnique::T1548.id().to_string(),
                confidence: 0.8,
                evidence_refs: vec![format!("pid:{} elevation", pid)],
                severity: ChainSeverity::High,
            });
        }

        // T1105: ingress tool transfer
        if latest.behavior.contains("curl")
            || latest.behavior.contains("wget")
            || latest.intent.file_touch
        {
            if window.len() >= 2 {
                return Some(ChainHit {
                    technique: AttackTechnique::T1105.id().to_string(),
                    confidence: 0.78,
                    evidence_refs: vec![format!("pid:{} ingress", pid)],
                    severity: ChainSeverity::Low,
                });
            }
        }

        None
    }

    pub fn window_len(&self, pid: u32) -> usize {
        self.windows.get(&pid).map(|w| w.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::{EventSource, ProcessEvent};

    fn evt(pid: u32, exe: &str, behavior: &str) -> ProcessEvent {
        ProcessEvent {
            pid,
            name: "x".into(),
            cmdline: behavior.into(),
            exe_path: exe.into(),
            uid: 1000,
            timestamp: 1,
            source: EventSource::Proc,
            inode: None,
        }
    }

    #[test]
    fn detects_c2_chain() {
        let mut m = ChainMatcher::new(8);
        let intent = SyscallIntent {
            exec: true,
            outbound: true,
            connect: true,
            ..Default::default()
        };
        let hit = m
            .observe(
                &evt(1, "/bin/bash", "spawned_children outbound connect"),
                "🚨 QUARANTINE",
                "spawned_children outbound connect",
                &intent,
            )
            .unwrap();
        assert_eq!(hit.technique, "T1071");
    }

    #[test]
    fn detects_obfuscation() {
        let mut m = ChainMatcher::new(4);
        let intent = SyscallIntent {
            memfd: true,
            ..Default::default()
        };
        let hit = m
            .observe(&evt(2, "/tmp/.x", "memfd_create"), "🚨 QUARANTINE", "memfd", &intent)
            .unwrap();
        assert_eq!(hit.technique, "T1027");
    }

    #[test]
    fn window_bounded() {
        let mut m = ChainMatcher::new(2);
        let intent = SyscallIntent::default();
        for _ in 0..5 {
            m.observe(&evt(4, "/bin/true", ""), "✅ ALLOW", "", &intent);
        }
        assert_eq!(m.window_len(4), 2);
    }
}
