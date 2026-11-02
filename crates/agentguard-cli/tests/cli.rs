//! End-to-end tests of the `agentguard` binary.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;

fn agentguard() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_agentguard"));
    cmd.env_remove("AGENTGUARD_LOG");
    cmd
}

fn write_policy(dir: &Path, text: &str) {
    fs::write(dir.join(".agent-security.yml"), text).unwrap();
}

#[test]
fn version_and_help() {
    agentguard()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("agentguard "));
    agentguard()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("init"))
        .stdout(predicate::str::contains("validate"))
        .stdout(predicate::str::contains("inspect"))
        .stdout(predicate::str::contains("doctor"))
        .stdout(predicate::str::contains("status"));
}

#[test]
fn unknown_command_is_usage_error() {
    agentguard().arg("frobnicate").assert().code(2);
}

#[test]
fn init_then_validate_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    agentguard()
        .args(["init", "--path"])
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Created"));
    assert!(dir.path().join(".agent-security.yml").is_file());

    // Second init refuses to overwrite.
    agentguard()
        .args(["init", "--path"])
        .arg(dir.path())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("refusing to overwrite"));

    agentguard()
        .current_dir(dir.path())
        .arg("validate")
        .assert()
        .success()
        .stdout(predicate::str::contains("Result: valid"))
        .stdout(predicate::str::contains("Mode: DEVELOPMENT"));
}

#[test]
fn validate_rejects_unknown_key_with_exit_4() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(
        dir.path(),
        "version: 1\nmode: DEVELOPMENT\nallow_everything: true\n",
    );
    agentguard()
        .current_dir(dir.path())
        .arg("validate")
        .assert()
        .code(4)
        .stderr(predicate::str::contains("allow_everything"));
}

#[test]
fn validate_reports_structural_problems() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "version: 1\nmode: RESTRICTED\ngit: 42\n");
    agentguard()
        .current_dir(dir.path())
        .arg("validate")
        .assert()
        .code(4)
        .stdout(predicate::str::contains("ERROR `git`"))
        .stdout(predicate::str::contains("Result: INVALID"));
}

#[test]
fn validate_unsupported_version() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "version: 7\nmode: DEVELOPMENT\n");
    agentguard()
        .current_dir(dir.path())
        .arg("validate")
        .assert()
        .code(4)
        .stderr(predicate::str::contains("version 7 is not supported"));
}

#[test]
fn validate_json_output() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "version: 1\nmode: READ_ONLY\nnetwork:\n");
    let out = agentguard()
        .current_dir(dir.path())
        .args(["--json", "validate"])
        .assert()
        .success();
    let text = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["mode"], "READ_ONLY");
    assert_eq!(v["ok"], true);
    assert_eq!(v["problems"][0]["severity"], "warning");
}

#[test]
fn validate_without_policy_fails_clearly() {
    let dir = tempfile::tempdir().unwrap();
    agentguard()
        .current_dir(dir.path())
        .arg("validate")
        .assert()
        .code(4)
        .stderr(predicate::str::contains("no .agent-security.yml found"));
}

#[test]
fn explicit_config_path() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("custom.yml");
    fs::write(&file, "version: 1\nmode: DEVELOPER_AUTHORIZED\n").unwrap();
    agentguard()
        .arg("--config")
        .arg(&file)
        .arg("validate")
        .assert()
        .success()
        .stdout(predicate::str::contains("DEVELOPER_AUTHORIZED"));
    agentguard()
        .arg("--config")
        .arg(dir.path().join("missing.yml"))
        .arg("validate")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("opening policy file"));
}

#[test]
fn inspect_shows_locations_and_unimplemented() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(
        dir.path(),
        "version: 1\nmode: DEVELOPMENT\ngit:\n  remotes: [origin]\n",
    );
    let home = tempfile::tempdir().unwrap();
    agentguard()
        .current_dir(dir.path())
        .env("HOME", home.path())
        .env_remove("XDG_STATE_HOME")
        .arg("inspect")
        .assert()
        .success()
        .stdout(predicate::str::contains("Sections present  git"))
        .stdout(predicate::str::contains("Not implemented yet"))
        .stdout(predicate::str::contains(".local/state/agentguard"));
}

#[test]
fn doctor_runs_and_is_read_only() {
    let home = tempfile::tempdir().unwrap();
    let before = fs::read_dir(home.path()).unwrap().count();
    agentguard()
        .env("HOME", home.path())
        .env_remove("XDG_STATE_HOME")
        .env_remove("XDG_RUNTIME_DIR")
        .current_dir(home.path())
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("operating system"))
        .stdout(predicate::str::contains("executes nothing"));
    let after = fs::read_dir(home.path()).unwrap().count();
    assert_eq!(before, after, "doctor must not create files");
}

#[test]
fn doctor_json() {
    let home = tempfile::tempdir().unwrap();
    let out = agentguard()
        .env("HOME", home.path())
        .current_dir(home.path())
        .args(["--json", "doctor"])
        .assert()
        .success();
    let text = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(v["checks"].as_array().unwrap().len() > 5);
}

#[test]
fn status_without_state_or_policy() {
    let home = tempfile::tempdir().unwrap();
    agentguard()
        .env("HOME", home.path())
        .env_remove("XDG_STATE_HOME")
        .current_dir(home.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("not created"))
        .stdout(predicate::str::contains("none found"))
        .stdout(predicate::str::contains("Not available yet"));
}

#[test]
fn logs_redact_secrets_in_verbose_mode() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir
        .path()
        .join("token-ghp_0123456789abcdefghijklmnopqrstuvwxyz.yml");
    fs::write(&file, "version: 1\nmode: DEVELOPMENT\n").unwrap();
    // The path contains a secret-looking token; verbose logging must not echo it.
    let out = agentguard()
        .arg("-vv")
        .arg("--config")
        .arg(&file)
        .arg("validate")
        .assert()
        .success();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        !stderr.contains("ghp_0123456789"),
        "stderr leaked a token-like string: {stderr}"
    );
}

#[test]
fn output_sanitises_terminal_escapes_from_policy_path() {
    let dir = tempfile::tempdir().unwrap();
    let evil = dir.path().join("a\u{1b}[2Jb");
    fs::create_dir(&evil).unwrap();
    write_policy(&evil, "version: 1\nmode: DEVELOPMENT\n");
    let out = agentguard()
        .current_dir(&evil)
        .arg("validate")
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(!stdout.contains('\u{1b}'), "raw escape reached stdout");
    assert!(stdout.contains("\\u{1b}"));
}
