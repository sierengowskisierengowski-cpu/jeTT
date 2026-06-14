//! jeTT allowlist + daemon trust config — `/etc/jett/allowlist.conf` or `JETT_ALLOWLIST`.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use super::event::{normalize_proc_name, ProcessEvent};
use super::never_fast_trust::matches_never_fast_trust;

const DEFAULT_CONFIG: &str = "/etc/jett/allowlist.conf";

struct ParsedConfig {
    exe: Vec<String>,
    script: Vec<String>,
    trusted_path: Vec<String>,
    trusted_proc: Vec<String>,
    toolchain_marker: Vec<String>,
    toolchain_bin: Vec<String>,
    has_exe: bool,
    has_script: bool,
    has_trusted_path: bool,
    has_trusted_proc: bool,
    has_toolchain_marker: bool,
    has_toolchain_bin: bool,
}

static PARSED: OnceLock<Option<ParsedConfig>> = OnceLock::new();
static EXE_PREFIXES: OnceLock<Vec<String>> = OnceLock::new();
static SCRIPT_CMDLINE_PREFIXES: OnceLock<Vec<String>> = OnceLock::new();
static TRUSTED_PATHS: OnceLock<Vec<String>> = OnceLock::new();
static TRUSTED_PROCS: OnceLock<Vec<String>> = OnceLock::new();
static TOOLCHAIN_MARKERS: OnceLock<Vec<String>> = OnceLock::new();
static TOOLCHAIN_BINS: OnceLock<Vec<String>> = OnceLock::new();

fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/root"))
}

fn home_join(relative: &str) -> String {
    home_dir()
        .join(relative.trim_start_matches('/'))
        .to_string_lossy()
        .into_owned()
}

fn default_exe_prefixes() -> Vec<String> {
    vec![
        home_join("Scripts/utilities/"),
        home_join("Scripts/deployed/"),
        home_join("Projects/GNI/"),
        home_join("Projects/jeTT/"),
        home_join("Projects/bifrost/"),
        home_join("Projects/c2/"),
        home_join("Projects/meli-fresh/"),
        home_join("Projects/honeypot/"),
        home_join(".local/share/Steam/"),
        home_join(".cargo/"),
        home_join(".rustup/"),
        "/tmp/cargo-install".to_string(),
    ]
}

fn default_script_cmdline_prefixes() -> Vec<String> {
    vec![home_join("Scripts/")]
}

fn default_trusted_path_prefixes() -> Vec<String> {
    vec![
        home_join("Projects/"),
        home_join("Scripts/"),
        "/usr/bin/".to_string(),
        "/usr/lib/".to_string(),
        "/usr/share/".to_string(),
        "/etc/systemd/".to_string(),
        "/opt/jett/".to_string(),
    ]
}

fn default_trusted_proc_names() -> Vec<String> {
    vec![
        "bifrost", "ollama", "docker", "cowrie", "prometheus", "grafana", "loki", "promtail",
        "portainer", "mosquitto", "cosmic-comp", "cargo", "rclone", "meshtastic", "gni_server",
        "systemd", "sshd", "pacman", "yay", "jett", "wireguard", "wg", "tmux", "screen", "rustc",
        "cc1plus", "cc1", "cicc", "nvcc", "ptxas", "fatbinary", "cmake", "make", "ccache",
        "collect2", "electron", "git", "cursorsandbox",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

fn default_toolchain_exe_markers() -> Vec<String> {
    vec![
        "/target/release/build/".to_string(),
        "/target/debug/build/".to_string(),
        "cursor-sandbox-cache".to_string(),
        "/cargo-target/".to_string(),
        "/usr/lib/ccache/".to_string(),
        "/usr/lib/gcc/".to_string(),
        "/usr/lib/rustlib/".to_string(),
    ]
}

fn default_toolchain_bin_names() -> Vec<String> {
    vec![
        "as", "ld", "gcc", "g++", "c++", "cc1", "cc1plus", "collect2", "cicc", "nvcc", "ptxas",
        "fatbinary", "rustc", "cargo", "cmake", "make", "ccache", "git", "electron", "cursorsandbox",
        "ld.lld", "clang", "clang++",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

fn config_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("JETT_ALLOWLIST") {
        if !path.is_empty() {
            return Some(PathBuf::from(path));
        }
    }
    let system = Path::new(DEFAULT_CONFIG);
    if system.is_file() {
        return Some(system.to_path_buf());
    }
    None
}

fn parse_config_file(path: &Path) -> Option<ParsedConfig> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut cfg = ParsedConfig {
        exe: Vec::new(),
        script: Vec::new(),
        trusted_path: Vec::new(),
        trusted_proc: Vec::new(),
        toolchain_marker: Vec::new(),
        toolchain_bin: Vec::new(),
        has_exe: false,
        has_script: false,
        has_trusted_path: false,
        has_trusted_proc: false,
        has_toolchain_marker: false,
        has_toolchain_bin: false,
    };
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("exe:") {
            if !rest.is_empty() {
                cfg.exe.push(rest.to_string());
                cfg.has_exe = true;
            }
        } else if let Some(rest) = line.strip_prefix("script:") {
            if !rest.is_empty() {
                cfg.script.push(rest.to_string());
                cfg.has_script = true;
            }
        } else if let Some(rest) = line.strip_prefix("trusted_path:") {
            if !rest.is_empty() {
                cfg.trusted_path.push(rest.to_string());
                cfg.has_trusted_path = true;
            }
        } else if let Some(rest) = line.strip_prefix("trusted_proc:") {
            if !rest.is_empty() {
                cfg.trusted_proc.push(rest.to_string());
                cfg.has_trusted_proc = true;
            }
        } else if let Some(rest) = line.strip_prefix("toolchain_marker:") {
            if !rest.is_empty() {
                cfg.toolchain_marker.push(rest.to_string());
                cfg.has_toolchain_marker = true;
            }
        } else if let Some(rest) = line.strip_prefix("toolchain_bin:") {
            if !rest.is_empty() {
                cfg.toolchain_bin.push(rest.to_string());
                cfg.has_toolchain_bin = true;
            }
        } else if line.starts_with('/') {
            cfg.exe.push(line.to_string());
            cfg.has_exe = true;
        }
    }
    Some(cfg)
}

fn parsed_config() -> Option<&'static ParsedConfig> {
    PARSED
        .get_or_init(|| config_path().and_then(|p| parse_config_file(&p)))
        .as_ref()
}

fn pick(section: Option<&ParsedConfig>, has: bool, from: impl Fn(&ParsedConfig) -> Vec<String>, default: fn() -> Vec<String>) -> Vec<String> {
    if let Some(cfg) = section {
        if has {
            return from(cfg);
        }
    }
    default()
}

fn load_exe_prefixes() -> Vec<String> {
    pick(
        parsed_config(),
        parsed_config().map(|c| c.has_exe).unwrap_or(false),
        |c| c.exe.clone(),
        default_exe_prefixes,
    )
}

fn load_script_cmdline_prefixes() -> Vec<String> {
    pick(
        parsed_config(),
        parsed_config().map(|c| c.has_script).unwrap_or(false),
        |c| c.script.clone(),
        default_script_cmdline_prefixes,
    )
}

fn load_trusted_paths() -> Vec<String> {
    pick(
        parsed_config(),
        parsed_config().map(|c| c.has_trusted_path).unwrap_or(false),
        |c| c.trusted_path.clone(),
        default_trusted_path_prefixes,
    )
}

fn load_trusted_procs() -> Vec<String> {
    pick(
        parsed_config(),
        parsed_config().map(|c| c.has_trusted_proc).unwrap_or(false),
        |c| c.trusted_proc.clone(),
        default_trusted_proc_names,
    )
}

fn load_toolchain_markers() -> Vec<String> {
    pick(
        parsed_config(),
        parsed_config().map(|c| c.has_toolchain_marker).unwrap_or(false),
        |c| c.toolchain_marker.clone(),
        default_toolchain_exe_markers,
    )
}

fn load_toolchain_bins() -> Vec<String> {
    pick(
        parsed_config(),
        parsed_config().map(|c| c.has_toolchain_bin).unwrap_or(false),
        |c| c.toolchain_bin.clone(),
        default_toolchain_bin_names,
    )
}

pub fn own_stack_exe_prefixes() -> &'static [String] {
    EXE_PREFIXES.get_or_init(load_exe_prefixes)
}

pub fn own_stack_script_cmdline_prefixes() -> &'static [String] {
    SCRIPT_CMDLINE_PREFIXES.get_or_init(load_script_cmdline_prefixes)
}

pub fn daemon_trusted_path_prefixes() -> &'static [String] {
    TRUSTED_PATHS.get_or_init(load_trusted_paths)
}

pub fn daemon_trusted_proc_names() -> &'static [String] {
    TRUSTED_PROCS.get_or_init(load_trusted_procs)
}

pub fn daemon_toolchain_exe_markers() -> &'static [String] {
    TOOLCHAIN_MARKERS.get_or_init(load_toolchain_markers)
}

pub fn daemon_toolchain_bin_names() -> &'static [String] {
    TOOLCHAIN_BINS.get_or_init(load_toolchain_bins)
}

pub fn exe_has_own_stack_prefix(exe_path: &str) -> bool {
    own_stack_exe_prefixes()
        .iter()
        .any(|prefix| exe_path.starts_with(prefix))
}

pub fn python3_script_cmdline_allowed(exe_path: &str, cmdline: &str) -> bool {
    if exe_path != "/usr/bin/python3" {
        return false;
    }
    own_stack_script_cmdline_prefixes().iter().any(|prefix| {
        cmdline.starts_with(prefix) || cmdline.starts_with(&format!("python3 {prefix}"))
    })
}

fn is_never_fast_trust_event(event: &ProcessEvent) -> bool {
    matches_never_fast_trust(&event.name) || matches_never_fast_trust(&event.exe_path)
}

pub fn daemon_is_toolchain_build(event: &ProcessEvent) -> bool {
    let exe_lower = event.exe_path.to_lowercase();
    if daemon_toolchain_exe_markers()
        .iter()
        .any(|m| exe_lower.contains(m))
    {
        return true;
    }
    let base = normalize_proc_name(
        Path::new(&event.exe_path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&event.name),
    );
    if daemon_toolchain_bin_names()
        .iter()
        .any(|n| base == n.as_str() || base.starts_with(n))
        && (exe_lower.starts_with("/usr/")
            || exe_lower.contains("/target/")
            || exe_lower.contains("sandbox-cache")
            || exe_lower.contains("/build/"))
    {
        return true;
    }
    (event.name.len() <= 4 || event.name == "++")
        && (exe_lower.contains("/target/")
            || exe_lower.contains("sandbox-cache")
            || exe_lower.contains("/build/"))
}

/// Daemon Trusted disposition — config-driven; never fast-trusts lolbins/interpreters.
pub fn daemon_is_trusted(event: &ProcessEvent) -> bool {
    if is_never_fast_trust_event(event) {
        return false;
    }
    if daemon_is_toolchain_build(event) {
        return true;
    }
    for trusted in daemon_trusted_proc_names() {
        if event.name.contains(trusted) || event.cmdline.contains(trusted) {
            return true;
        }
    }
    for path in daemon_trusted_path_prefixes() {
        if event.exe_path.starts_with(path) || event.cmdline.contains(path) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::event::EventSource;

    fn pe(name: &str, cmdline: &str, exe_path: &str) -> ProcessEvent {
        ProcessEvent {
            pid: 1,
            name: name.to_string(),
            cmdline: cmdline.to_string(),
            exe_path: exe_path.to_string(),
            uid: 1000,
            timestamp: 1,
            source: EventSource::Proc,
            inode: None,
        }
    }

    #[test]
    fn default_prefixes_use_home() {
        let prefixes = default_exe_prefixes();
        let home = home_dir().to_string_lossy().into_owned();
        assert!(prefixes.iter().any(|p| p.starts_with(&home)));
    }

    #[test]
    fn parse_all_section_types() {
        let dir = std::env::temp_dir().join("jett_allowlist_full_test.conf");
        std::fs::write(
            &dir,
            "trusted_path:/opt/acme/\ntrusted_proc:myagent\ntoolchain_marker:/build/\ntoolchain_bin:rustc\n",
        )
        .unwrap();
        let cfg = parse_config_file(&dir).unwrap();
        assert!(cfg.has_trusted_path);
        assert_eq!(cfg.trusted_path, vec!["/opt/acme/"]);
        assert!(cfg.has_trusted_proc);
        assert_eq!(cfg.trusted_proc, vec!["myagent"]);
        let _ = std::fs::remove_file(dir);
    }

    #[test]
    fn bash_not_trusted() {
        assert!(!daemon_is_trusted(&pe("bash", "bash", "/usr/bin/bash")));
    }

    #[test]
    fn git_from_usr_bin_trusted() {
        assert!(daemon_is_trusted(&pe("git", "git status", "/usr/bin/git")));
    }

    #[test]
    fn curl_not_trusted() {
        assert!(!daemon_is_trusted(&pe("curl", "curl evil", "/usr/bin/curl")));
    }
}
