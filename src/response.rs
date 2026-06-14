//! Autonomous response tier selection (log / contain / kill+quarantine).

use crate::attack_chain::ChainSeverity;
use crate::enforce::should_quarantine_kill;

/// Response action tier for a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseTier {
    Log,
    Contain,
    KillQuarantine,
}

impl ResponseTier {
    pub fn label(&self) -> &'static str {
        match self {
            ResponseTier::Log => "log",
            ResponseTier::Contain => "contain",
            ResponseTier::KillQuarantine => "kill_quarantine",
        }
    }
}

/// Select response tier from calibrated confidence, chain severity, and enforce mode.
pub fn select_response_tier(
    confidence: f32,
    chain_severity: Option<ChainSeverity>,
    enforce_mode: bool,
) -> ResponseTier {
    if !enforce_mode {
        return ResponseTier::Log;
    }

    let severity_boost = match chain_severity {
        Some(ChainSeverity::High) => 0.15,
        Some(ChainSeverity::Medium) => 0.08,
        Some(ChainSeverity::Low) => 0.03,
        None => 0.0,
    };
    let effective = (confidence + severity_boost).min(1.0);

    if effective >= 0.92 && should_quarantine_kill(enforce_mode) {
        ResponseTier::KillQuarantine
    } else if effective >= 0.75 {
        ResponseTier::Contain
    } else {
        ResponseTier::Log
    }
}

/// Apply contain-tier placeholder (cgroup/netns intent logging).
pub fn apply_contain_placeholder(pid: u32, exe: &str) {
    eprintln!(
        "[*] CONTAIN tier selected for PID {} ({}) — cgroup/netns isolation placeholder (not yet enforced)",
        pid, exe
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn learn_mode_always_logs() {
        assert_eq!(
            select_response_tier(1.0, Some(ChainSeverity::High), false),
            ResponseTier::Log
        );
    }

    #[test]
    fn high_confidence_enforce_selects_kill() {
        let prev = std::env::var("JETT_ENFORCE_DRY_RUN").ok();
        std::env::remove_var("JETT_ENFORCE_DRY_RUN");
        assert_eq!(
            select_response_tier(0.95, Some(ChainSeverity::High), true),
            ResponseTier::KillQuarantine
        );
        restore("JETT_ENFORCE_DRY_RUN", prev.as_deref());
    }

    #[test]
    fn medium_confidence_selects_contain() {
        assert_eq!(
            select_response_tier(0.8, Some(ChainSeverity::Medium), true),
            ResponseTier::Contain
        );
    }

    #[test]
    fn low_confidence_logs_only() {
        assert_eq!(
            select_response_tier(0.5, None, true),
            ResponseTier::Log
        );
    }

    fn restore(key: &str, prev: Option<&str>) {
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }
}
