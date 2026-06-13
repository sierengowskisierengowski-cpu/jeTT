#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryMode {
    Proc,
    Ebpf,
    Both,
}

pub fn parse_telemetry_mode() -> TelemetryMode {
    match std::env::var("JETT_TELEMETRY")
        .unwrap_or_else(|_| "proc".into())
        .to_lowercase()
        .as_str()
    {
        "ebpf" => TelemetryMode::Ebpf,
        "both" => TelemetryMode::Both,
        _ => TelemetryMode::Proc,
    }
}

pub fn telemetry_mode_label(mode: TelemetryMode) -> &'static str {
    match mode {
        TelemetryMode::Proc => "proc",
        TelemetryMode::Ebpf => "ebpf",
        TelemetryMode::Both => "both",
    }
}

pub fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

pub fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

pub fn dedup_window_ms() -> u64 {
    env_u64("JETT_DEDUP_MS", 2000)
}

pub fn ai_queue_size() -> usize {
    env_usize("JETT_AI_QUEUE_SIZE", 64)
}

pub fn stat_log_interval_sec() -> u64 {
    env_u64("JETT_STAT_LOG_INTERVAL_SEC", 60)
}
