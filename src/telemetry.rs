//! Telemetry mode (Phase 2 scaffold). Full eBPF ringbuf wiring lands behind `ebpf` feature.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventSource {
    Proc,
    Ebpf,
}

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
