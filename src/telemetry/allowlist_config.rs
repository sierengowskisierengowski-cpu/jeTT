//! Own-stack ALLOW prefixes — loaded from config or derived from `$HOME`.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const DEFAULT_CONFIG: &str = "/etc/jett/allowlist.conf";

static EXE_PREFIXES: OnceLock<Vec<String>> = OnceLock::new();
static SCRIPT_CMDLINE_PREFIXES: OnceLock<Vec<String>> = OnceLock::new();

fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/root"))
}

fn default_exe_prefixes() -> Vec<String> {
    let home = home_dir();
    let join = |p: &str| home.join(p.trim_start_matches('/')).to_string_lossy().into_owned();
    vec![
        join("Scripts/utilities/"),
        join("Scripts/deployed/"),
        join("Projects/GNI/"),
        join("Projects/jeTT/"),
        join("Projects/bifrost/"),
        join("Projects/c2/"),
        join("Projects/meli-fresh/"),
        join("Projects/honeypot/"),
        join(".local/share/Steam/"),
        join(".cargo/"),
        join(".rustup/"),
        // Not home-relative — cargo install staging dirs.
        "/tmp/cargo-install".to_string(),
    ]
}

fn default_script_cmdline_prefixes() -> Vec<String> {
    let home = home_dir();
    vec![format!(
        "{}/Scripts/",
        home.to_string_lossy()
    )]
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

fn parse_config_file(path: &Path) -> Option<(Vec<String>, Vec<String>)> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut exe = Vec::new();
    let mut script = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("exe:") {
            if !rest.is_empty() {
                exe.push(rest.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("script:") {
            if !rest.is_empty() {
                script.push(rest.to_string());
            }
        } else if line.starts_with('/') {
            // Bare path defaults to exe prefix for backward compatibility.
            exe.push(line.to_string());
        }
    }
    if exe.is_empty() && script.is_empty() {
        None
    } else {
        Some((exe, script))
    }
}

fn load_exe_prefixes() -> Vec<String> {
    if let Some(path) = config_path() {
        if let Some((exe, _)) = parse_config_file(&path) {
            return exe;
        }
    }
    default_exe_prefixes()
}

fn load_script_cmdline_prefixes() -> Vec<String> {
    if let Some(path) = config_path() {
        if let Some((_, script)) = parse_config_file(&path) {
            return script;
        }
    }
    default_script_cmdline_prefixes()
}

/// Exe path prefixes that fast-ALLOW before model inference.
pub fn own_stack_exe_prefixes() -> &'static [String] {
    EXE_PREFIXES.get_or_init(load_exe_prefixes)
}

/// For `exe:/usr/bin/python3` — cmdline must start with one of these prefixes.
pub fn own_stack_script_cmdline_prefixes() -> &'static [String] {
    SCRIPT_CMDLINE_PREFIXES.get_or_init(load_script_cmdline_prefixes)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_prefixes_use_home() {
        let prefixes = default_exe_prefixes();
        let home = home_dir().to_string_lossy().into_owned();
        assert!(prefixes.iter().any(|p| p.starts_with(&home)));
        assert!(prefixes.iter().any(|p| p.starts_with("/tmp/cargo-install")));
    }

    #[test]
    fn parse_config_lines() {
        let dir = std::env::temp_dir().join("jett_allowlist_test.conf");
        std::fs::write(
            &dir,
            "exe:/opt/acme/bin/\nscript:/opt/acme/scripts/\n# comment\n",
        )
        .unwrap();
        let (exe, script) = parse_config_file(&dir).unwrap();
        assert_eq!(exe, vec!["/opt/acme/bin/"]);
        assert_eq!(script, vec!["/opt/acme/scripts/"]);
        let _ = std::fs::remove_file(dir);
    }
}
