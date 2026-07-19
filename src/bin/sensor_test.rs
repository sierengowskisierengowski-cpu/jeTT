//! Phase 1 BPF smoke test (docs/jeTT-eBPF-Integration-Plan-v2.md §11).
//! Loads the observe-only `sched_process_exec` sensor and prints every event.
//! No AI, no enforcement — pure kernel -> Rust telemetry verification.

use std::sync::Arc;
use std::time::Duration;

use jeTT::ebpf::spawn_ebpf_sensor;
use jeTT::telemetry::event::ProcessEvent;
use jeTT::telemetry::stats::TelemetryStats;

fn main() {
    println!("[jett-sensor-test] Phase 1 BPF smoke test — observe only, no enforcement");

    let (tx, rx) = crossbeam_channel::unbounded::<ProcessEvent>();
    let stats = TelemetryStats::new();

    let run_secs: u64 = std::env::var("JETT_SENSOR_TEST_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    match spawn_ebpf_sensor(tx, Arc::clone(&stats)) {
        Ok(_handle) => {
            println!(
                "[jett-sensor-test] sensor attached — watching for {}s (Ctrl+C to stop early)",
                run_secs
            );
        }
        Err(e) => {
            eprintln!("[jett-sensor-test] FAILED to attach sensor: {}", e);
            std::process::exit(1);
        }
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(run_secs);
    let mut count = 0u64;
    while std::time::Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(ev) => {
                count += 1;
                println!(
                    "[EVENT #{count}] source={} pid={} uid={} comm/name={} exe_path={} inode={:?} ts={}",
                    ev.source_label(),
                    ev.pid,
                    ev.uid,
                    ev.name,
                    ev.exe_path,
                    ev.inode,
                    ev.timestamp,
                );
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }

    println!("[jett-sensor-test] done. {}", stats.log_line());
    println!("[jett-sensor-test] total events observed: {count}");
}
