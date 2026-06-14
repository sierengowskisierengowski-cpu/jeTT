//! Syscall / behavior intent fingerprinting from event strings.

use serde::{Deserialize, Serialize};

/// Intent signals extracted from behavior text appended to guard events.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyscallIntent {
    pub connect: bool,
    pub exec: bool,
    pub memfd: bool,
    pub outbound: bool,
    pub file_touch: bool,
    pub spawn_child: bool,
}

/// Parse intent signals from a full event/behavior string.
pub fn fingerprint_from_event(event_str: &str) -> SyscallIntent {
    let lower = event_str.to_lowercase();
    SyscallIntent {
        connect: lower.contains("connect")
            || lower.contains("outbound")
            || lower.contains("socket"),
        exec: lower.contains("exec")
            || lower.contains("execve")
            || lower.contains("spawned_children"),
        memfd: lower.contains("memfd") || lower.contains("memfd_create"),
        outbound: lower.contains("outbound") || lower.contains("egress"),
        file_touch: lower.contains("file_touch")
            || lower.contains("openat")
            || lower.contains("writes:")
            || lower.contains("/etc/shadow")
            || lower.contains("/etc/passwd"),
        spawn_child: lower.contains("spawned_children") || lower.contains("child_pid"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_connect_and_memfd() {
        let fp = fingerprint_from_event(
            "bash PID:1 uid:0 exe:/bin/bash cmd:bash behavior:outbound connect memfd_create",
        );
        assert!(fp.connect);
        assert!(fp.memfd);
        assert!(fp.outbound);
    }

    #[test]
    fn detects_spawn_and_file_touch() {
        let fp = fingerprint_from_event(
            "sh PID:2 uid:1000 exe:/bin/sh cmd:sh behavior:spawned_children file_touch /etc/shadow",
        );
        assert!(fp.spawn_child);
        assert!(fp.file_touch);
        assert!(fp.exec);
    }

    #[test]
    fn benign_event_is_empty_intent() {
        let fp = fingerprint_from_event("git PID:3 uid:1000 exe:/usr/bin/git cmd:git status");
        assert!(!fp.connect);
        assert!(!fp.memfd);
    }
}
