use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventSource {
    Proc,
    Ebpf,
}

#[derive(Debug, Clone)]
pub struct ProcessEvent {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub exe_path: String,
    pub uid: u32,
    pub timestamp: u64,
    pub source: EventSource,
    /// `(st_dev, st_ino)` from immediate stat when available.
    pub inode: Option<(u64, u64)>,
}

pub const JETT_EVT_EXEC: u32 = 1;

impl ProcessEvent {
    pub fn dedup_key(&self) -> (u32, u32, u64) {
        let inode = self.inode.map(|(_, ino)| ino).unwrap_or(0);
        (self.pid, JETT_EVT_EXEC, inode)
    }

    pub fn source_label(&self) -> &'static str {
        match self.source {
            EventSource::Proc => "proc",
            EventSource::Ebpf => "ebpf",
        }
    }
}

pub fn stat_inode(path: &str) -> Option<(u64, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    use std::os::unix::fs::MetadataExt;
    Some((meta.dev(), meta.ino()))
}

pub fn proc_exists(pid: u32) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
}
