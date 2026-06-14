pub mod adversarial;
pub mod config;
pub mod coordinator;
pub mod event;
pub mod hard_rules;
pub mod never_fast_trust;
pub mod stats;

pub use adversarial::{
    deception_mode, detect_evasion, honeypot_enabled, jittered_elapsed_ms, log_deception_audit,
    max_event_len, plausible_allow_reason, print_decoy_allow, sanitize_event_for_model,
    should_decoy_allow, silent_quarantine_reason, aggressive_mode, DeceptionMode, EvasionSignals,
};
pub use config::{
    ai_queue_size, dedup_window_ms, parse_telemetry_mode, stat_log_interval_sec,
    telemetry_mode_label, TelemetryMode,
};
pub use coordinator::EventCoordinator;
pub use event::{
    normalize_proc_name, parse_guard_event_fields, proc_name_from_exe, stat_inode, EventSource,
    ProcessEvent, JETT_EVT_EXEC,
};
pub use hard_rules::{hard_quarantine_reason, parse_guard_cmdline};
pub use never_fast_trust::{guard_event_skips_fast_trust, matches_never_fast_trust, NEVER_FAST_TRUST};
pub use stats::TelemetryStats;
