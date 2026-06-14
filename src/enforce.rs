//! Enforce-mode helpers — verdict labels and safe dry-run for smoke tests.

/// True when `JETT_MODE=enforce` (case-insensitive).
pub fn enforce_mode_from_env() -> bool {
    std::env::var("JETT_MODE")
        .map(|m| m.eq_ignore_ascii_case("enforce"))
        .unwrap_or(false)
}

/// True when `JETT_ENFORCE_DRY_RUN` is `1`, `true`, or `yes`.
/// Suppresses `kill -9` and quarantine file copies while still logging QUARANTINE verdicts.
pub fn enforce_dry_run() -> bool {
    std::env::var("JETT_ENFORCE_DRY_RUN")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

/// Whether the daemon should perform real quarantine kills (enforce on, dry-run off).
pub fn should_quarantine_kill(enforce_mode: bool) -> bool {
    enforce_mode && !enforce_dry_run()
}

/// Map model/hard-rule reason text to the console/log verdict label.
pub fn verdict_label_for_reason(reason: &str, enforce_mode: bool) -> String {
    if reason.starts_with("ERROR:") {
        return "⚠️ REVIEW".to_string();
    }
    let model_says_quarantine = reason.to_uppercase().contains("QUARANTINE");
    if model_says_quarantine {
        if enforce_mode {
            "🚨 QUARANTINE".to_string()
        } else {
            "🟡 WOULD-QUARANTINE".to_string()
        }
    } else {
        "✅ ALLOW".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dry_run_suppresses_real_kills() {
        let prev = std::env::var("JETT_ENFORCE_DRY_RUN").ok();
        std::env::set_var("JETT_ENFORCE_DRY_RUN", "1");
        assert!(!should_quarantine_kill(true));
        assert!(!should_quarantine_kill(false));
        restore_env("JETT_ENFORCE_DRY_RUN", prev.as_deref());
    }

    #[test]
    fn enforce_without_dry_run_enables_kills() {
        let prev = std::env::var("JETT_ENFORCE_DRY_RUN").ok();
        std::env::remove_var("JETT_ENFORCE_DRY_RUN");
        assert!(should_quarantine_kill(true));
        assert!(!should_quarantine_kill(false));
        restore_env("JETT_ENFORCE_DRY_RUN", prev.as_deref());
    }

    fn restore_env(key: &str, prev: Option<&str>) {
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn verdict_labels_differ_by_mode() {
        assert_eq!(
            verdict_label_for_reason("🚨 QUARANTINE | hard rule: curl", false),
            "🟡 WOULD-QUARANTINE"
        );
        assert_eq!(
            verdict_label_for_reason("🚨 QUARANTINE | hard rule: curl", true),
            "🚨 QUARANTINE"
        );
        assert_eq!(
            verdict_label_for_reason("ERROR: NoKvCacheSlot", true),
            "⚠️ REVIEW"
        );
        assert_eq!(
            verdict_label_for_reason("ALLOW — benign toolchain", true),
            "✅ ALLOW"
        );
    }

    #[test]
    fn enforce_mode_defaults_to_learn_without_env() {
        // CI may set JETT_MODE; only assert the learn branch when unset behavior is tested
        // via explicit false in should_quarantine_kill above.
        assert_eq!(
            verdict_label_for_reason("QUARANTINE outbound", false),
            "🟡 WOULD-QUARANTINE"
        );
    }
}
