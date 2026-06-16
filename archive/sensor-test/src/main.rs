//! jeTT eBPF Phase 1 smoke test.
//!
//! Loads bpf/jett_sensor.bpf.o, attaches sched_process_exec, prints successful execs.
//! Failed exec (e.g. `ls /nonexistent`) should NOT appear.
//!
//! Run:
//!   bash scripts/build_bpf.sh
//!   cd cmd/sensor-test && cargo run --release
//! Requires: CAP_BPF / root, BTF-enabled kernel.

use libbpf_rs::MapCore;
use libbpf_rs::{ObjectBuilder, RingBufferBuilder};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

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

static COUNT: AtomicU64 = AtomicU64::new(0);

fn bpf_object_path() -> PathBuf {
    if let Ok(p) = std::env::var("JETT_BPF_OBJECT") {
        return PathBuf::from(p);
    }
    // cmd/sensor-test -> repo root
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../bpf/jett_sensor.bpf.o")
}

fn handle_event(data: &[u8]) -> i32 {
    if data.len() < std::mem::size_of::<JettEvent>() {
        return 0;
    }
    let ev = unsafe { &*(data.as_ptr() as *const JettEvent) };
    let comm = unsafe { CStr::from_ptr(ev.comm.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    let path = unsafe { CStr::from_ptr(ev.path.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    let n = COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    println!(
        "[{n}] exec pid={} uid={} comm={:?} path={:?}",
        ev.pid, ev.uid, comm, path
    );
    0
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bpf_path = bpf_object_path();
    if !bpf_path.exists() {
        eprintln!("[!] missing {} — run: bash scripts/build_bpf.sh", bpf_path.display());
        std::process::exit(1);
    }

    println!("[*] jeTT sensor test — loading {}", bpf_path.display());
    let open = ObjectBuilder::default().open_file(&bpf_path)?;
    let mut obj = open.load()?;

    let mut _link = None;
    for prog in obj.progs_mut() {
        if prog.name() == "jett_sched_exec" {
            _link = Some(prog.attach()?);
            println!("[+] attached tp/sched/sched_process_exec (jett_sched_exec)");
            break;
        }
    }
    if _link.is_none() {
        return Err("program jett_sched_exec not found in object".into());
    }

    let mut maps = obj.maps_mut();
    let ring = maps
        .find(|m| m.name().to_string_lossy() == "jett_events")
        .ok_or("map jett_events not found")?;

    let mut rb = RingBufferBuilder::new();
    rb.add(&ring, handle_event)?;
    let ringbuf = rb.build()?;

    println!("[*] listening — try: ls /tmp && ls /nonexistent");
    println!("[*] Ctrl+C to stop\n");

    loop {
        ringbuf.poll(std::time::Duration::from_millis(100))?;
    }
}
