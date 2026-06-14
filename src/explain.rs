//! Deterministic verdict explainability.

use crate::attack_chain::ChainHit;
use serde::{Deserialize, Serialize};

/// Structured explanation for a verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerdictExplanation {
    pub rule_id: Option<String>,
    pub model_reason: Option<String>,
    pub chain_ids: Vec<String>,
    pub confidence: f32,
    pub evidence_refs: Vec<String>,
}

impl VerdictExplanation {
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(rule) = &self.rule_id {
            parts.push(format!("rule:{}", rule));
        }
        if let Some(model) = &self.model_reason {
            parts.push(format!("model:{}", truncate(model, 60)));
        }
        if !self.chain_ids.is_empty() {
            parts.push(format!("chains:[{}]", self.chain_ids.join(",")));
        }
        parts.push(format!("conf:{:.2}", self.confidence));
        if !self.evidence_refs.is_empty() {
            parts.push(format!("evidence:[{}]", self.evidence_refs.join(",")));
        }
        parts.join(" | ")
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect::<String>() + "…"
    }
}

/// Build a deterministic explanation from hard rule, chain, and model outputs.
pub fn explain_verdict(
    reason: &str,
    chain_hit: Option<&ChainHit>,
    confidence: f32,
    evidence_refs: Vec<String>,
) -> VerdictExplanation {
    let upper = reason.to_uppercase();
    let rule_id = if reason.contains("hard rule:") {
        reason
            .split("hard rule:")
            .nth(1)
            .map(|s| s.trim().chars().take(40).collect())
    } else if upper.contains("QUARANTINE") && !upper.contains("ERROR") {
        None
    } else {
        None
    };

    let model_reason = if reason.starts_with("ERROR:") {
        Some(reason.to_string())
    } else if rule_id.is_none() && !reason.is_empty() {
        Some(reason.to_string())
    } else {
        None
    };

    let mut chain_ids = Vec::new();
    let mut refs = evidence_refs;
    if let Some(hit) = chain_hit {
        chain_ids.push(hit.technique.clone());
        refs.extend(hit.evidence_refs.clone());
    }

    VerdictExplanation {
        rule_id,
        model_reason,
        chain_ids,
        confidence,
        evidence_refs: refs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attack_chain::{ChainHit, ChainSeverity};

    #[test]
    fn hard_rule_explanation() {
        let exp = explain_verdict(
            "🚨 QUARANTINE | hard rule: curl_pipe_sh",
            None,
            1.0,
            vec![],
        );
        assert_eq!(exp.rule_id.as_deref(), Some("curl_pipe_sh"));
        assert!((exp.confidence - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn chain_ids_included() {
        let hit = ChainHit {
            technique: "T1071".into(),
            confidence: 0.9,
            evidence_refs: vec!["pid:1".into()],
            severity: ChainSeverity::High,
        };
        let exp = explain_verdict("QUARANTINE outbound", Some(&hit), 0.9, vec![]);
        assert!(exp.chain_ids.contains(&"T1071".to_string()));
        assert!(exp.summary().contains("T1071"));
    }
}
