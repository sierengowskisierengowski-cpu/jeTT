use std::collections::HashSet;
use std::fs;
use std::thread;
use std::time::Duration;

use crate::telemetry::event::proc_exists;

/// Parse a hex IP:port from /proc/PID/net/tcp into a readable string.
fn parse_hex_addr(hex: &str) -> Option<String> {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let ip_hex = parts[0];
    let port_hex = parts[1];
    if ip_hex.len() != 8 {
        return None;
    }
    let b1 = u8::from_str_radix(&ip_hex[6..8], 16).ok()?;
    let b2 = u8::from_str_radix(&ip_hex[4..6], 16).ok()?;
    let b3 = u8::from_str_radix(&ip_hex[2..4], 16).ok()?;
    let b4 = u8::from_str_radix(&ip_hex[0..2], 16).ok()?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some(format!("{}.{}.{}.{}:{}", b1, b2, b3, b4, port))
}

/// Parse `socket:[inode]` from a `/proc/{pid}/fd/*` readlink target.
fn socket_inode_from_fd_link(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

fn collect_socket_inodes_for_pid(pid: u32) -> HashSet<u64> {
    let mut inodes = HashSet::new();
    let fd_dir = format!("/proc/{}/fd", pid);
    if let Ok(entries) = fs::read_dir(&fd_dir) {
        for entry in entries.flatten() {
            if let Ok(target) = fs::read_link(entry.path()) {
                if let Some(ino) = socket_inode_from_fd_link(&target.to_string_lossy()) {
                    inodes.insert(ino);
                }
            }
        }
    }
    inodes
}

/// Socket inodes owned by `pid` and its direct children (`/proc/.../children`).
fn collect_socket_inodes(pid: u32) -> HashSet<u64> {
    let mut inodes = collect_socket_inodes_for_pid(pid);
    let path = format!("/proc/{}/task/{}/children", pid, pid);
    if let Ok(text) = fs::read_to_string(&path) {
        for child_pid in text.split_whitespace() {
            if let Ok(cp) = child_pid.parse::<u32>() {
                inodes.extend(collect_socket_inodes_for_pid(cp));
            }
        }
    }
    inodes
}

/// Return remote address from a `/proc/net/tcp` row when its inode is in `inodes`.
fn connection_addr_from_tcp_line(line: &str, inodes: &HashSet<u64>) -> Option<String> {
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() <= 9 {
        return None;
    }
    let inode: u64 = cols[9].parse().ok()?;
    if !inodes.contains(&inode) {
        return None;
    }
    let state = cols[3];
    if state != "01" && state != "02" {
        return None;
    }
    let addr = parse_hex_addr(cols[2])?;
    if addr.starts_with("127.") || addr.starts_with("0.0.0.0") {
        return None;
    }
    Some(addr)
}

fn collect_connections(pid: u32) -> Vec<String> {
    let inodes = collect_socket_inodes(pid);
    if inodes.is_empty() {
        return Vec::new();
    }

    let mut conns = Vec::new();
    for proto in &["tcp", "tcp6"] {
        let path = format!("/proc/{}/net/{}", pid, proto);
        if let Ok(text) = fs::read_to_string(&path) {
            for line in text.lines().skip(1) {
                if let Some(addr) = connection_addr_from_tcp_line(line, &inodes) {
                    conns.push(addr);
                }
            }
        }
    }
    conns.sort();
    conns.dedup();
    conns
}

fn collect_open_files(pid: u32) -> Vec<String> {
    let mut files = Vec::new();
    let fd_dir = format!("/proc/{}/fd", pid);
    if let Ok(entries) = fs::read_dir(&fd_dir) {
        for entry in entries.flatten() {
            if let Ok(target) = fs::read_link(entry.path()) {
                let p = target.to_string_lossy().to_string();
                if p.starts_with("/etc/")
                    || p.contains("/.ssh/")
                    || p.starts_with("/root/")
                    || p.contains("shadow")
                    || p.contains("passwd")
                    || p.starts_with("/var/spool/cron")
                    || p.contains("/cron.d/")
                {
                    files.push(p);
                }
            }
        }
    }
    files.sort();
    files.dedup();
    files
}

fn collect_children(pid: u32) -> Vec<String> {
    let mut kids = Vec::new();
    let path = format!("/proc/{}/task/{}/children", pid, pid);
    if let Ok(text) = fs::read_to_string(&path) {
        for child_pid in text.split_whitespace() {
            if let Ok(name) = fs::read_to_string(format!("/proc/{}/comm", child_pid)) {
                kids.push(name.trim().to_string());
            }
        }
    }
    kids.sort();
    kids.dedup();
    kids
}

fn behavior_profile_from(
    all_conns: HashSet<String>,
    all_files: HashSet<String>,
    all_kids: HashSet<String>,
) -> String {
    let mut profile = String::new();
    if !all_conns.is_empty() {
        let mut v: Vec<String> = all_conns.into_iter().collect();
        v.sort();
        profile.push_str(&format!(" outbound_connections:[{}]", v.join(",")));
    }
    if !all_files.is_empty() {
        let mut v: Vec<String> = all_files.into_iter().collect();
        v.sort();
        profile.push_str(&format!(" sensitive_files:[{}]", v.join(",")));
    }
    if !all_kids.is_empty() {
        let mut v: Vec<String> = all_kids.into_iter().collect();
        v.sort();
        profile.push_str(&format!(" spawned_children:[{}]", v.join(",")));
    }
    if profile.is_empty() {
        profile.push_str(" behavior:none_observed");
    }
    profile
}

fn snapshot_once(pid: u32) -> (HashSet<String>, HashSet<String>, HashSet<String>) {
    let mut all_conns = HashSet::new();
    let mut all_files = HashSet::new();
    let mut all_kids = HashSet::new();
    for c in collect_connections(pid) {
        all_conns.insert(c);
    }
    for f in collect_open_files(pid) {
        all_files.insert(f);
    }
    for k in collect_children(pid) {
        all_kids.insert(k);
    }
    (all_conns, all_files, all_kids)
}

/// Immediate /proc read for eBPF path (<10ms). Returns profile suffix and whether PID was gone.
pub fn snapshot_behavior(pid: u32) -> (String, bool) {
    if !proc_exists(pid) {
        return (" behavior:exited_before_snapshot".to_string(), true);
    }
    let (conns, files, kids) = snapshot_once(pid);
    (
        behavior_profile_from(conns, files, kids),
        false,
    )
}

fn behavior_mode_snapshot() -> bool {
    std::env::var("JETT_BEHAVIOR_MODE")
        .map(|m| m.eq_ignore_ascii_case("snapshot"))
        .unwrap_or(true)
}

/// /proc-only path: single snapshot or ~1.5s poll window.
pub fn collect_behavior(pid: u32) -> String {
    let mut all_conns: HashSet<String> = HashSet::new();
    let mut all_files: HashSet<String> = HashSet::new();
    let mut all_kids: HashSet<String> = HashSet::new();

    if behavior_mode_snapshot() {
        let (c, f, k) = snapshot_once(pid);
        return behavior_profile_from(c, f, k);
    }

    for _ in 0..3 {
        let (c, f, k) = snapshot_once(pid);
        all_conns.extend(c);
        all_files.extend(f);
        all_kids.extend(k);
        if !proc_exists(pid) {
            break;
        }
        thread::sleep(Duration::from_millis(500));
    }

    behavior_profile_from(all_conns, all_files, all_kids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn parse_hex_addr_ipv4() {
        assert_eq!(
            parse_hex_addr("0100007F:0050"),
            Some("127.0.0.1:80".to_string())
        );
        assert_eq!(
            parse_hex_addr("5855A8C0:01BB"),
            Some("192.168.85.88:443".to_string())
        );
        assert_eq!(parse_hex_addr("bad"), None);
        assert_eq!(parse_hex_addr("0100007F"), None);
    }

    #[test]
    fn socket_inode_from_fd_link_parses_proc_format() {
        assert_eq!(socket_inode_from_fd_link("socket:[955338]"), Some(955338));
        assert_eq!(socket_inode_from_fd_link("/etc/passwd"), None);
        assert_eq!(socket_inode_from_fd_link("socket:[not-a-number]"), None);
    }

    #[test]
    fn connection_addr_from_tcp_line_filters_by_inode_and_state() {
        let line = "   1: 00000000:0016 5855A8C0:01BB 01 00000000:00000000 00:00000000 00000000     0        0 955338 1 00000000c7e78223 100 0 0 10 0";
        let mut inodes = HashSet::new();
        inodes.insert(955338);
        assert_eq!(
            connection_addr_from_tcp_line(line, &inodes),
            Some("192.168.85.88:443".to_string())
        );

        inodes.clear();
        inodes.insert(999999);
        assert_eq!(connection_addr_from_tcp_line(line, &inodes), None);

        let listen = "   0: 0100007F:AB31 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 955338 1 00000000c7e78223 100 0 0 10 0";
        inodes.insert(955338);
        assert_eq!(connection_addr_from_tcp_line(listen, &inodes), None);
    }

    #[test]
    fn connection_addr_from_tcp_line_skips_loopback_remote() {
        let line = "   2: 00000000:0016 0100007F:8FCE 01 00000000:00000000 00:00000000 00000000     0        0 42 1 00000000c7e78223 100 0 0 10 0";
        let mut inodes = HashSet::new();
        inodes.insert(42);
        assert_eq!(connection_addr_from_tcp_line(line, &inodes), None);
    }

    /// When a process has no socket fds, outbound_connections must not appear in the profile.
    #[test]
    fn empty_socket_inodes_omit_outbound_connections_from_profile() {
        let profile = behavior_profile_from(HashSet::new(), HashSet::new(), HashSet::new());
        assert!(!profile.contains("outbound_connections"));
        assert!(profile.contains("behavior:none_observed"));
    }
}
