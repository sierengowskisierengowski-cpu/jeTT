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

/// Strip kernel thread / wrapper parens: `(python3)` → `python3`.
pub fn normalize_proc_name(name: &str) -> String {
    let trimmed = name.trim();
    trimmed
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(trimmed)
        .to_string()
}

/// Parse `{comm} PID:… uid:… exe:{path} cmd:…` strings passed to `jeTT --guard`.
pub fn parse_guard_event_fields(event: &str) -> (String, String) {
    let comm = event
        .split(" PID:")
        .next()
        .unwrap_or("")
        .trim()
        .to_string();

    let exe_path = event
        .split_once(" exe:")
        .and_then(|(_, after_exe)| after_exe.split_once(" cmd:"))
        .map(|(path, _)| path.trim().to_string())
        .unwrap_or_default();

    (comm, exe_path)
}

/// Prefer exe path basename; fall back to comm when path is empty or has no basename.
pub fn proc_name_from_exe(exe_path: &str, fallback_comm: &str) -> String {
    Path::new(exe_path)
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .map(normalize_proc_name)
        .unwrap_or_else(|| normalize_proc_name(fallback_comm))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_proc_name_strips_parens() {
        assert_eq!(normalize_proc_name("(python3)"), "python3");
        assert_eq!(normalize_proc_name("python3"), "python3");
        assert_eq!(normalize_proc_name("  bash  "), "bash");
    }

    #[test]
    fn proc_name_from_exe_uses_basename() {
        assert_eq!(
            proc_name_from_exe("/usr/bin/git-remote-https", "git"),
            "git-remote-https"
        );
        assert_eq!(proc_name_from_exe("", "rg"), "rg");
    }

    #[test]
    fn parse_guard_event_fields_extracts_comm_and_exe() {
        let event = "python3 PID:999 uid:1000 exe:/usr/bin/python3.14 cmd:python3 -c 'import socket' time:1 behavior:none_observed";
        let (comm, exe) = parse_guard_event_fields(event);
        assert_eq!(comm, "python3");
        assert_eq!(exe, "/usr/bin/python3.14");
    }
}
