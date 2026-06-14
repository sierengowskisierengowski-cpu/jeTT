//! Confidence calibration for autonomous response tier selection.

use crate::attack_chain::ChainSeverity;

/// Source of a verdict signal used for confidence weighting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfidenceSource {
    HardRule,
    Chain,
    Model,
    DriftBoost,
}

/// Calibrated confidence in [0.0, 1.0].
#[derive(Debug, Clone, PartialEq)]
pub struct CalibratedConfidence {
    pub value: f32,
    pub sources: Vec<ConfidenceSource>,
}

impl CalibratedConfidence {
    pub fn new(value: f32, sources: Vec<ConfidenceSource>) -> Self {
        Self {
            value: value.clamp(0.0, 1.0),
            sources,
        }
    }
}

const HARD_RULE_WEIGHT: f32 = 1.0;
const CHAIN_WEIGHT: f32 = 0.9;
const MODEL_WEIGHT: f32 = 0.7;
const DRIFT_BOOST: f32 = 0.15;

/// Combine rule, chain, model, and baseline drift into a single confidence score.
pub fn calibrate_confidence(
    from_hard_rule: bool,
    chain_severity: Option<ChainSeverity>,
    from_model: bool,
    drift_score: f32,
) -> CalibratedConfidence {
    let mut sources = Vec::new();
    let mut value = 0.0f32;

    if from_hard_rule {
        value = value.max(HARD_RULE_WEIGHT);
        sources.push(ConfidenceSource::HardRule);
    }
    if let Some(sev) = chain_severity {
        let chain_val = match sev {
            ChainSeverity::Low => 0.75,
            ChainSeverity::Medium => CHAIN_WEIGHT,
            ChainSeverity::High => 0.95,
        };
        value = value.max(chain_val);
        sources.push(ConfidenceSource::Chain);
    }
    if from_model {
        value = value.max(MODEL_WEIGHT);
        sources.push(ConfidenceSource::Model);
    }
    if drift_score > 0.5 {
        value = (value + DRIFT_BOOST).min(1.0);
        sources.push(ConfidenceSource::DriftBoost);
    }

    if sources.is_empty() {
        value = 0.5;
    }

    CalibratedConfidence::new(value, sources)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hard_rule_dominates() {
        let c = calibrate_confidence(true, None, true, 0.9);
        assert!((c.value - 1.0).abs() < f32::EPSILON);
        assert!(c.sources.contains(&ConfidenceSource::HardRule));
    }

    #[test]
    fn model_alone_is_moderate() {
        let c = calibrate_confidence(false, None, true, 0.0);
        assert!((c.value - MODEL_WEIGHT).abs() < f32::EPSILON);
    }

    #[test]
    fn drift_boosts_model_confidence() {
        let c = calibrate_confidence(false, None, true, 0.8);
        assert!(c.value > MODEL_WEIGHT);
        assert!(c.sources.contains(&ConfidenceSource::DriftBoost));
    }

    #[test]
    fn chain_severity_affects_score() {
        let low = calibrate_confidence(false, Some(ChainSeverity::Low), false, 0.0);
        let high = calibrate_confidence(false, Some(ChainSeverity::High), false, 0.0);
        assert!(high.value > low.value);
    }
}
