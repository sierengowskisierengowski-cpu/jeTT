//! eBPF ringbuf sensor — polls sched_process_exec and emits ProcessEvent on a channel.
//! Never calls AI from the ringbuf callback.

use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crossbeam_channel::Sender;
use libbpf_rs::MapCore;
use libbpf_rs::{ObjectBuilder, RingBufferBuilder};

use crate::telemetry::event::{proc_name_from_exe, stat_inode, EventSource, ProcessEvent};
use crate::telemetry::stats::TelemetryStats;

#[repr(C)]
struct JettEvent {
    version: u32,
    pid: u32,
    uid: u32,
    event_type: u32,
    ts_ns: u64,
    comm: [c_char; 16],
    path: [c_char; 256],
}

fn bpf_object_path() -> PathBuf {
    if let Ok(p) = std::env::var("JETT_BPF_OBJECT") {
        return PathBuf::from(p);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bpf/jett_sensor.bpf.o")
}

fn cstr_field(raw: &[c_char]) -> String {
    unsafe { CStr::from_ptr(raw.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

fn kernel_ts_secs(ts_ns: u64) -> u64 {
    if ts_ns > 0 {
        ts_ns / 1_000_000_000
    } else {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

fn jett_event_to_process(ev: &JettEvent) -> ProcessEvent {
    let comm = cstr_field(&ev.comm);
    let path = cstr_field(&ev.path);
    let inode = stat_inode(&path);
    ProcessEvent {
        pid: ev.pid,
        name: proc_name_from_exe(&path, &comm),
        cmdline: String::new(),
        exe_path: path,
        uid: ev.uid,
        timestamp: kernel_ts_secs(ev.ts_ns),
        source: EventSource::Ebpf,
        inode,
    }
}

/// Load BPF object, attach tracepoint, spawn poll thread. Returns handle or error string.
pub fn spawn_ebpf_sensor(
    event_tx: Sender<ProcessEvent>,
    stats: Arc<TelemetryStats>,
) -> Result<thread::JoinHandle<()>, String> {
    let bpf_path = bpf_object_path();
    if !bpf_path.exists() {
        return Err(format!(
            "missing {} — run: bash scripts/build_bpf.sh",
            bpf_path.display()
        ));
    }

    let tx = event_tx.clone();
    let stats_cb = Arc::clone(&stats);
    let handle = thread::Builder::new()
        .name("jett-ebpf".into())
        .spawn(move || {
            if let Err(e) = run_sensor_loop(&bpf_path, tx, stats_cb) {
                eprintln!("[!] eBPF sensor thread exited: {}", e);
            }
        })
        .map_err(|e| format!("failed to spawn eBPF thread: {}", e))?;

    Ok(handle)
}

fn run_sensor_loop(
    bpf_path: &PathBuf,
    event_tx: Sender<ProcessEvent>,
    stats: Arc<TelemetryStats>,
) -> Result<(), String> {
    let open = ObjectBuilder::default()
        .open_file(bpf_path)
        .map_err(|e| format!("open BPF object: {}", e))?;
    let mut obj = open
        .load()
        .map_err(|e| format!("load BPF object: {}", e))?;

    let mut attached = false;
    let mut _link = None;
    for prog in obj.progs_mut() {
        if prog.name() == "jett_sched_exec" {
            _link = Some(
                prog.attach()
                    .map_err(|e| format!("attach jett_sched_exec: {}", e))?,
            );
            attached = true;
            break;
        }
    }
    if !attached {
        return Err("program jett_sched_exec not found".into());
    }

    let mut maps = obj.maps_mut();
    let ring = maps
        .find(|m| m.name().to_string_lossy() == "jett_events")
        .ok_or_else(|| "map jett_events not found".to_string())?;

    let tx = event_tx.clone();
    let stats_inner = Arc::clone(&stats);
    let mut rb = RingBufferBuilder::new();
    rb.add(&ring, move |data: &[u8]| {
        if data.len() < std::mem::size_of::<JettEvent>() {
            stats_inner.ringbuf_drop.fetch_add(1, Ordering::Relaxed);
            return 0;
        }
        let ev = unsafe { &*(data.as_ptr() as *const JettEvent) };
        stats_inner.ringbuf_in.fetch_add(1, Ordering::Relaxed);
        let event = jett_event_to_process(ev);
        if tx.send(event).is_err() {
            stats_inner.ringbuf_drop.fetch_add(1, Ordering::Relaxed);
        }
        0
    })
    .map_err(|e| format!("ringbuf add: {}", e))?;

    let ringbuf = rb
        .build()
        .map_err(|e| format!("ringbuf build: {}", e))?;

    eprintln!("[+] eBPF sensor attached (sched_process_exec → ringbuf)");
    loop {
        ringbuf
            .poll(Duration::from_millis(100))
            .map_err(|e| format!("ringbuf poll: {}", e))?;
    }
}
