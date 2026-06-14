//! Tier 7 post-verdict pipeline — graph, chains, evidence, baseline, explain.

use crate::attack_chain::ChainMatcher;
use crate::baseline::Baseline;
use crate::confidence::{calibrate_confidence, CalibratedConfidence};
use crate::evidence_vault::EvidenceVault;
use crate::explain::{explain_verdict, VerdictExplanation};
use crate::probe_manager::ProbeManager;
use crate::response::{apply_contain_placeholder, select_response_tier, ResponseTier};
use crate::risk_graph::RiskGraph;
use crate::syscall_fingerprint::fingerprint_from_event;
use crate::telemetry::ProcessEvent;
use std::sync::{Mutex, OnceLock};

static RISK_GRAPH: OnceLock<Mutex<RiskGraph>> = OnceLock::new();
static CHAIN_MATCHER: OnceLock<Mutex<ChainMatcher>> = OnceLock::new();
static EVIDENCE_VAULT: OnceLock<Mutex<EvidenceVault>> = OnceLock::new();
static BASELINE: OnceLock<Mutex<Baseline>> = OnceLock::new();
static PROBE_MANAGER: OnceLock<Mutex<ProbeManager>> = OnceLock::new();

fn risk_graph() -> &'static Mutex<RiskGraph> {
    RISK_GRAPH.get_or_init(|| Mutex::new(RiskGraph::new()))
}

fn chain_matcher() -> &'static Mutex<ChainMatcher> {
    CHAIN_MATCHER.get_or_init(|| Mutex::new(ChainMatcher::new(16)))
}

fn evidence_vault() -> &'static Mutex<EvidenceVault> {
    EVIDENCE_VAULT.get_or_init(|| Mutex::new(EvidenceVault::new(None)))
}

fn baseline() -> &'static Mutex<Baseline> {
    BASELINE.get_or_init(|| Mutex::new(Baseline::default()))
}

fn probe_manager() -> &'static Mutex<ProbeManager> {
    PROBE_MANAGER.get_or_init(|| Mutex::new(ProbeManager::new()))
}

/// Context passed through the Tier 7 post-verdict pipeline.
#[derive(Debug, Clone)]
pub struct VerdictContext {
    pub event: ProcessEvent,
    pub verdict_label: String,
    pub reason: String,
    pub event_str: String,
    pub behavior: String,
    pub enforce_mode: bool,
    pub from_hard_rule: bool,
}

/// Result of the Tier 7 pipeline for logging and enforcement.
#[derive(Debug, Clone)]
pub struct Tier7Outcome {
    pub explanation: VerdictExplanation,
    pub confidence: CalibratedConfidence,
    pub response_tier: ResponseTier,
    pub chain_technique: Option<String>,
    pub graph_score: f32,
    pub probe_window_ms: u64,
}

/// Run graph, chain, evidence, baseline, confidence, and response tier selection.
pub fn process_verdict(ctx: &VerdictContext) -> Tier7Outcome {
    let intent = fingerprint_from_event(&ctx.event_str);

    let graph_score = {
        let mut g = risk_graph().lock().unwrap_or_else(|e| e.into_inner());
        g.record_event(&ctx.event, &ctx.verdict_label, &ctx.behavior, None);
        g.score_subtree(ctx.event.pid)
    };

    let chain_hit = {
        let mut m = chain_matcher().lock().unwrap_or_else(|e| e.into_inner());
        m.observe(&ctx.event, &ctx.verdict_label, &ctx.behavior, &intent)
    };

    if chain_hit.is_some() {
        let mut pm = probe_manager().lock().unwrap_or_else(|e| e.into_inner());
        pm.on_chain_alert();
    }

    let drift = {
        let b = baseline().lock().unwrap_or_else(|e| e.into_inner());
        b.drift_score(&ctx.event)
    };

    let confidence = calibrate_confidence(
        ctx.from_hard_rule,
        chain_hit.as_ref().map(|h| h.severity),
        !ctx.from_hard_rule && !ctx.verdict_label.contains("ALLOW"),
        drift,
    );

    let explanation = explain_verdict(
        &ctx.reason,
        chain_hit.as_ref(),
        confidence.value,
        vec![format!("pid:{}", ctx.event.pid)],
    );

    if let Ok(mut vault) = evidence_vault().lock() {
        let _ = vault.append(
            ctx.event.timestamp,
            ctx.event.pid,
            &ctx.verdict_label,
            &explanation.summary(),
            &ctx.event_str.chars().take(512).collect::<String>(),
        );
    }

    if ctx.verdict_label.contains("ALLOW") {
        if let Ok(mut b) = baseline().lock() {
            b.observe_allow(&ctx.event);
            let _ = b.persist();
        }
    }

    let probe_window_ms = probe_manager()
        .lock()
        .map(|pm| pm.behavior_window_ms(0.0))
        .unwrap_or(1500);

    let response_tier = select_response_tier(
        confidence.value,
        chain_hit.as_ref().map(|h| h.severity),
        ctx.enforce_mode,
    );

    if response_tier == ResponseTier::Contain {
        apply_contain_placeholder(ctx.event.pid, &ctx.event.exe_path);
    }

    Tier7Outcome {
        explanation,
        confidence,
        response_tier,
        chain_technique: chain_hit.as_ref().map(|h| h.technique.clone()),
        graph_score,
        probe_window_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::{EventSource, ProcessEvent};

    fn ctx(verdict: &str, reason: &str) -> VerdictContext {
        VerdictContext {
            event: ProcessEvent {
                pid: 9999,
                name: "bash".into(),
                cmdline: "curl | sh".into(),
                exe_path: "/usr/bin/bash".into(),
                uid: 1000,
                timestamp: 42,
                source: EventSource::Proc,
                inode: None,
            },
            verdict_label: verdict.into(),
            reason: reason.into(),
            event_str: "bash PID:9999 exe:/usr/bin/bash cmd:curl | sh behavior:outbound".into(),
            behavior: "outbound connect".into(),
            enforce_mode: false,
            from_hard_rule: reason.contains("hard rule"),
        }
    }

    #[test]
    fn pipeline_produces_explanation() {
        let outcome = process_verdict(&ctx(
            "🚨 QUARANTINE",
            "🚨 QUARANTINE | hard rule: curl_pipe_sh",
        ));
        assert!(!outcome.explanation.summary().is_empty());
        assert!(outcome.confidence.value >= 0.9);
    }
}
