//! `agentguard doctor`: read-only host capability checks.
//!
//! Every check reads files under `/proc`, `/sys`, `/etc` or looks for executables on `PATH`.
//! Nothing is executed, nothing is written, and no privileged access is requested. The checks
//! are pure functions over strings so they are unit-testable without a particular host.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use agentguard_common::paths::{check_private_dir, AppPaths};
use agentguard_common::{AgentGuardError, ExitCode};
use clap::Args;
use serde::Serialize;

use crate::commands::locate_policy;
use crate::output;
use crate::Context;

/// Arguments for `doctor`.
#[derive(Debug, Args, Default)]
pub struct DoctorArgs {
    /// Exit non-zero if any check, including those for later phases, is missing.
    #[arg(long)]
    pub strict: bool,
}

/// Outcome of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Present and acceptable.
    Ok,
    /// Present but with a caveat.
    Warn,
    /// Absent or unacceptable.
    Missing,
    /// Could not be determined.
    Unknown,
}

/// One check result.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    /// Short name.
    pub name: &'static str,
    /// Outcome.
    pub status: Status,
    /// Human-readable detail.
    pub detail: String,
    /// The phase from which AgentGuard needs this.
    pub needed_from: &'static str,
    /// Whether the current phase needs it; later-phase items are informational.
    pub required_now: bool,
}

impl Check {
    fn new(
        name: &'static str,
        status: Status,
        detail: impl Into<String>,
        needed_from: &'static str,
    ) -> Self {
        let required_now = needed_from == "Phase 1";
        Self {
            name,
            status,
            detail: detail.into(),
            needed_from,
            required_now,
        }
    }
}

/// Parse `/sys/kernel/security/lsm` (comma-separated) into active module names.
#[must_use]
pub fn parse_lsm(contents: &str) -> Vec<String> {
    contents
        .trim()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Whether a `cgroup.controllers` file lists all of `cpu`, `memory` and `pids`.
#[must_use]
pub fn controllers_delegated(contents: &str) -> bool {
    let set: Vec<&str> = contents.split_whitespace().collect();
    ["cpu", "memory", "pids"].iter().all(|c| set.contains(c))
}

/// Interpret the `kernel.unprivileged_userns_clone` sysctl (absent means enabled on most
/// kernels) together with `user.max_user_namespaces`.
#[must_use]
pub fn userns_available(clone_sysctl: Option<&str>, max_user_ns: Option<&str>) -> Status {
    let max = max_user_ns.and_then(|m| m.trim().parse::<u64>().ok());
    match (clone_sysctl.map(str::trim), max) {
        (Some("0"), _) | (_, Some(0)) => Status::Missing,
        (Some("1") | None, Some(_)) => Status::Ok,
        _ => Status::Unknown,
    }
}

/// Find an executable on `PATH` without running it.
#[must_use]
pub fn find_on_path(name: &str, path_var: Option<&str>) -> Option<PathBuf> {
    let path_var = path_var?;
    path_var
        .split(':')
        .filter(|d| !d.is_empty())
        .map(|d| Path::new(d).join(name))
        .find(|candidate| {
            fs::metadata(candidate)
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
}

fn read(path: &str) -> Option<String> {
    fs::read_to_string(path).ok()
}

fn os_pretty_name() -> String {
    read("/etc/os-release")
        .and_then(|t| {
            t.lines().find_map(|l| {
                l.strip_prefix("PRETTY_NAME=")
                    .map(|v| v.trim_matches('"').to_owned())
            })
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

fn current_uid() -> u32 {
    // Owner of the process's own /proc entry is its effective uid.
    fs::metadata("/proc/self").map_or(0, |m| m.uid())
}

fn os_checks(out: &mut Vec<Check>) {
    out.push(Check::new(
        "operating system",
        Status::Ok,
        format!(
            "{} (kernel {})",
            os_pretty_name(),
            read("/proc/sys/kernel/osrelease")
                .unwrap_or_default()
                .trim()
        ),
        "Phase 1",
    ));
}

fn lsm_checks(out: &mut Vec<Check>) {
    let lsm = read("/sys/kernel/security/lsm")
        .map(|t| parse_lsm(&t))
        .unwrap_or_default();
    for (module, label, needed) in [
        ("landlock", "landlock LSM", "Phase 5"),
        ("apparmor", "apparmor LSM", "Phase 4"),
    ] {
        let present = lsm.iter().any(|m| m == module);
        out.push(Check::new(
            label,
            if present { Status::Ok } else { Status::Missing },
            if present {
                "active"
            } else {
                "not in /sys/kernel/security/lsm"
            },
            needed,
        ));
    }
}

fn cgroup_checks(out: &mut Vec<Check>) {
    let cgroup_v2 = Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
    out.push(Check::new(
        "cgroup v2",
        if cgroup_v2 {
            Status::Ok
        } else {
            Status::Missing
        },
        if cgroup_v2 {
            "unified hierarchy mounted"
        } else {
            "not mounted at /sys/fs/cgroup"
        },
        "Phase 4",
    ));
    let uid = current_uid();
    let path =
        format!("/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/cgroup.controllers");
    let (status, detail) = match read(&path).map(|t| controllers_delegated(&t)) {
        Some(true) => (Status::Ok, "delegated to the user session".to_owned()),
        Some(false) => (
            Status::Warn,
            "user session lacks one of cpu/memory/pids; limits would be unenforceable".to_owned(),
        ),
        None => (Status::Unknown, format!("cannot read {path}")),
    };
    out.push(Check::new(
        "cgroup delegation (cpu memory pids)",
        status,
        detail,
        "Phase 4",
    ));
}

fn userns_checks(out: &mut Vec<Check>) {
    let status = userns_available(
        read("/proc/sys/kernel/unprivileged_userns_clone").as_deref(),
        read("/proc/sys/user/max_user_namespaces").as_deref(),
    );
    out.push(Check::new(
        "unprivileged user namespaces",
        status,
        match status {
            Status::Ok => "available (required by rootless Docker)",
            Status::Missing => "disabled by sysctl; rootless Docker cannot run",
            Status::Warn | Status::Unknown => "could not determine",
        },
        "Phase 4",
    ));
    if let Some(v) = read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") {
        let restricted = v.trim() == "1";
        out.push(Check::new(
            "apparmor userns restriction",
            if restricted { Status::Warn } else { Status::Ok },
            if restricted {
                "apparmor_restrict_unprivileged_userns=1; unconfined tools need a profile"
            } else {
                "not restricting unprivileged user namespaces"
            },
            "Phase 4",
        ));
    }
}

const TOOLS: [(&str, &str, &str, &str); 5] = [
    ("git", "git on PATH", "Phase 1", "host-side Git operations"),
    (
        "docker",
        "docker on PATH",
        "Phase 4",
        "rootless Docker client",
    ),
    ("gitleaks", "gitleaks on PATH", "Phase 8", "secret scanning"),
    (
        "trivy",
        "trivy on PATH",
        "Phase 8",
        "vulnerability scanning",
    ),
    (
        "runsc",
        "runsc on PATH",
        "Phase 4",
        "gVisor runtime (optional)",
    ),
];

fn tool_checks(out: &mut Vec<Check>, paths: &AppPaths) {
    let path_var = std::env::var("PATH").ok();
    for (tool, label, needed, note) in TOOLS {
        let found = find_on_path(tool, path_var.as_deref());
        out.push(Check::new(
            label,
            if found.is_some() {
                Status::Ok
            } else {
                Status::Missing
            },
            found.map_or_else(
                || format!("not on PATH ({note})"),
                |p| p.display().to_string(),
            ),
            needed,
        ));
    }
    let docker_sock = paths
        .runtime_dir
        .as_ref()
        .and_then(|r| r.parent().map(|p| p.join("docker.sock")))
        .filter(|p| p.exists());
    out.push(Check::new(
        "rootless docker socket",
        if docker_sock.is_some() {
            Status::Ok
        } else {
            Status::Missing
        },
        docker_sock.map_or_else(
            || "no docker.sock under XDG_RUNTIME_DIR (presence only; not contacted)".to_owned(),
            |p| format!("{} (presence only; not contacted)", p.display()),
        ),
        "Phase 4",
    ));
}

fn state_checks(out: &mut Vec<Check>, paths: &AppPaths, policy: Option<&Path>) {
    let state = &paths.state_dir;
    let (status, note) = if state.exists() {
        match check_private_dir(state) {
            Ok(()) => (Status::Ok, "exists with private permissions".to_owned()),
            Err(e) => (Status::Warn, e.to_string()),
        }
    } else {
        (
            Status::Warn,
            "not created yet (created on first use)".to_owned(),
        )
    };
    out.push(Check::new(
        "state directory",
        status,
        format!("{} {note}", state.display()),
        "Phase 1",
    ));
    out.push(match policy {
        Some(p) => Check::new(
            "project policy",
            Status::Ok,
            p.display().to_string(),
            "Phase 1",
        ),
        None => Check::new(
            "project policy",
            Status::Warn,
            "no .agent-security.yml found from the current directory (run `agentguard init`)",
            "Phase 1",
        ),
    });
}

/// Run every check against this host.
#[must_use]
pub fn host_checks(paths: &AppPaths, policy: Option<&Path>) -> Vec<Check> {
    let mut checks = Vec::new();
    os_checks(&mut checks);
    lsm_checks(&mut checks);
    cgroup_checks(&mut checks);
    userns_checks(&mut checks);
    tool_checks(&mut checks, paths);
    state_checks(&mut checks, paths, policy);
    checks
}

#[derive(Debug, Serialize)]
struct DoctorOutput {
    checks: Vec<Check>,
    ok: bool,
}

/// Run `doctor`.
pub fn run(ctx: &Context, args: &DoctorArgs) -> Result<ExitCode, AgentGuardError> {
    let paths = AppPaths::from_env()?;
    let policy = locate_policy(ctx).ok().map(|d| d.policy_path);
    let checks = host_checks(&paths, policy.as_deref());
    let blocking = checks
        .iter()
        .any(|c| c.required_now && c.status == Status::Missing);
    let out = DoctorOutput {
        ok: !blocking,
        checks,
    };
    if ctx.json {
        output::json(&out);
    } else {
        for c in &out.checks {
            let tag = match c.status {
                Status::Ok => "OK     ",
                Status::Warn => "WARN   ",
                Status::Missing => "MISSING",
                Status::Unknown => "UNKNOWN",
            };
            output::line(&format!(
                "{tag} {:<40} {} [{}]",
                c.name, c.detail, c.needed_from
            ));
        }
        output::line("");
        output::line(
            "doctor reads /proc, /sys, /etc and PATH only; it executes nothing and changes nothing.",
        );
        output::line("Items for later phases are informational until that phase is implemented.");
    }
    let any_missing = out.checks.iter().any(|c| c.status == Status::Missing);
    if blocking || (args.strict && any_missing) {
        return Ok(ExitCode::PreflightFailed);
    }
    Ok(ExitCode::Success)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lsm_parsing() {
        assert_eq!(
            parse_lsm("lockdown,capability,landlock,yama,apparmor\n"),
            vec!["lockdown", "capability", "landlock", "yama", "apparmor"]
        );
        assert_eq!(parse_lsm(""), Vec::<String>::new());
    }

    #[test]
    fn controllers() {
        assert!(controllers_delegated("cpuset cpu io memory pids\n"));
        assert!(!controllers_delegated("cpu memory\n"));
    }

    #[test]
    fn userns_logic() {
        assert_eq!(userns_available(Some("1\n"), Some("125083\n")), Status::Ok);
        assert_eq!(userns_available(None, Some("1000")), Status::Ok);
        assert_eq!(userns_available(Some("0"), Some("1000")), Status::Missing);
        assert_eq!(userns_available(Some("1"), Some("0")), Status::Missing);
        assert_eq!(userns_available(None, None), Status::Unknown);
    }

    #[test]
    fn find_on_path_requires_executable_file() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("tool");
        fs::write(&exe, b"#!/bin/sh\n").unwrap();
        let path_var = dir.path().display().to_string();
        assert!(find_on_path("tool", Some(&path_var)).is_none());
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(find_on_path("tool", Some(&path_var)), Some(exe));
        assert!(find_on_path("tool", None).is_none());
    }

    #[test]
    fn host_checks_run_without_panicking() {
        let paths = AppPaths::resolve(Some("/nonexistent-home".into()), None, None, None).unwrap();
        let checks = host_checks(&paths, None);
        assert!(checks
            .iter()
            .any(|c| c.name == "project policy" && c.status == Status::Warn));
        assert!(checks.iter().any(|c| c.name == "operating system"));
    }
}
