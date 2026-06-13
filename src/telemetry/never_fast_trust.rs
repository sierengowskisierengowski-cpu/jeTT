//! Binaries that must never use TRUSTED_PATH / TRUSTED_HASH or daemon Trusted disposition.

use std::path::Path;

use super::event::normalize_proc_name;

/// Shells, interpreters, downloaders, and privesc tools — shared by daemon + guard().
pub const NEVER_FAST_TRUST: &[&str] = &[
    "bash", "sh", "zsh", "dash", "fish", "ksh", "tcsh",
    "python", "python3", "perl", "ruby", "node", "php", "lua",
    "nc", "ncat", "netcat", "socat", "telnet", "ssh", "awk", "xterm",
    "curl", "wget", "base64", "pkexec",
];

/// Match exe/comm names including versioned distros (`python3.13`, `node22`).
pub fn matches_never_fast_trust(name: &str) -> bool {
    let raw = Path::new(name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(name);
    let base = normalize_proc_name(raw);
    if NEVER_FAST_TRUST.iter().any(|&n| base == n) {
        return true;
    }
    if let Some(stem) = base.split('.').next() {
        if stem != base.as_str() && NEVER_FAST_TRUST.iter().any(|&n| stem == n) {
            return true;
        }
    }
    for &n in NEVER_FAST_TRUST {
        if base.len() > n.len() && base.starts_with(n) {
            let next = base.as_bytes()[n.len()];
            if next.is_ascii_digit() || next == b'.' || next == b'-' {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versioned_interpreters_match() {
        for name in ["python3.13", "python3.12", "node22", "node20", "ruby3.3"] {
            assert!(
                matches_never_fast_trust(name),
                "{name} should never fast-trust"
            );
        }
    }

    #[test]
    fn unrelated_binaries_do_not_match() {
        for name in ["git-remote-https", "moke.sh", "rg", "docker", "rustc"] {
            assert!(
                !matches_never_fast_trust(name),
                "{name} should not match"
            );
        }
    }

    #[test]
    fn paren_wrapped_and_lolbins_match() {
        assert!(matches_never_fast_trust("(python3)"));
        assert!(matches_never_fast_trust("/usr/bin/curl"));
        assert!(matches_never_fast_trust("wget"));
    }
}
