use libbpf_rs::MapCore;
use libbpf_rs::ObjectBuilder;
use libbpf_rs::RingBufferBuilder;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use serde::Serialize;
use std::ffi::CStr;
use std::os::raw::c_char;

#[repr(C)]
#[derive(Serialize)]
struct SecurityEventPayload {
    pid: u32,
    ppid: u32,
    uid: u32,
    parent_process: String,
    binary_executed: String,
}

#[repr(C)]
struct RawKernelEvent {
    pid: u32,
    ppid: u32,
    uid: u32,
    comm: [c_char; 16],
    filename: [c_char; 256],
}

fn ship_to_command_tower(payload: SecurityEventPayload) {
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        let _ = client.post("http://127.0.0.1:8080/telemetry")
            .json(&payload)
            .send()
            .await;
    });
}

fn process_kernel_event(data: &[u8]) -> i32 {
    let event = unsafe { &*(data.as_ptr() as *const RawKernelEvent) };

    let parent_proc = unsafe { CStr::from_ptr(event.comm.as_ptr()) }.to_string_lossy().into_owned();
    let binary_executed = unsafe { CStr::from_ptr(event.filename.as_ptr()) }.to_string_lossy().into_owned();

    println!(
        "[CERBERUS AGENT] Captured Syscall Execution: {} (PID: {}) executed {}",
        parent_proc, event.pid, binary_executed
    );

    let payload = SecurityEventPayload {
        pid: event.pid,
        ppid: event.ppid,
        uid: event.uid,
        parent_process: parent_proc,
        binary_executed: binary_executed.clone(),
    };

    ship_to_command_tower(payload);

    if binary_executed.contains("/tmp/") || binary_executed.contains("nc") {
        println!("[-] CRITICAL EXPLOIT DETECTED. CERBERUS IS SNAPPING DOWN ON PID: {}", event.pid);
        let target_pid = Pid::from_raw(event.pid as i32);
        let _ = kill(target_pid, Signal::SIGKILL);
    }

    0
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("[-] Cerberus Agent (Center Head) waking up...");

    // Unified Path Fix: Looks exactly where you type the execution command
    let bpf_object_path = "./sensor.bpf.o";

    let open_object = ObjectBuilder::default().open_file(bpf_object_path)?;
    let mut loaded_object = open_object.load()?;

    let mut link = None;
    for prog in loaded_object.progs_mut() {
        if prog.name() == "intercept_execution" {
            link = Some(prog.attach()?);
            break;
        }
    }
    
    if link.is_none() {
        return Err("Failed to locate and attach eBPF program 'intercept_execution'".into());
    }
    println!("[+] Left Head (C Sensor) attached to kernel tracepoint. Monitoring all gates.");

    let mut rb_builder = RingBufferBuilder::new();
    let mut maps = loaded_object.maps_mut();
    let mut target_map = maps.find(|m| m.name().to_string_lossy() == "event_ringbuf");

    if let Some(ref mut map) = target_map {
        rb_builder.add(map, process_kernel_event)?;
    } else {
        return Err("Failed to locate shared memory map 'event_ringbuf'".into());
    }

    let ring_buffer = rb_builder.build()?;
    println!("[+] Local network pipeline connected to Go Server. Awaiting perimeter movement...");

    loop {
        ring_buffer.poll(std::time::Duration::from_millis(10))?;
    }
}
