#[cfg(feature = "ebpf")]
mod sensor;

#[cfg(feature = "ebpf")]
pub use sensor::spawn_ebpf_sensor;
