//! Phase 6: `secrets.scan`, `secrets.status`, `secrets.explain` through the engine protocol,
//! against isolated temporary state. Every credential below is fake and nonfunctional.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::needless_pass_by_value,
    clippy::disallowed_methods,
    clippy::print_stderr,
    clippy::field_reassign_with_default,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::cast_possible_truncation,
    clippy::large_stack_arrays
)]

use std::fs;
use std::path::{Path, PathBuf};

use agentguard_engine_cli::{handle, Environment};
use agentguard_trust::keyfile::KdfCost;
use serde_json::{json, Value};

const PASS: &str = "correct horse battery staple";
const GITHUB: &str = "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0000";
const PG: &str = "Sup3rS3cretPw9";

struct World {
    _base: tempfile::TempDir,
    env: Environment,
    project: PathBuf,
    trust_root: PathBuf,
}

fn write(root: &Path, rel: &str, content: &str) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, content).unwrap();
}

fn world() -> World {
    let base = tempfile::tempdir().unwrap();
    let canonical = agentguard_platform::fs::canonicalize(base.path()).unwrap();
    let project = canonical.join("project");
    write(&project, "Cargo.toml", "[package]\n");
    write(&project, "src/main.rs", "fn main() {}\n");
    write(
        &project,
        "src/config.rs",
        &format!("const T: &str = \"{GITHUB}\";\n"),
    );
    write(
        &project,
        ".env",
        &format!("DATABASE_URL=postgres://app:{PG}@db/app\n"),
    );
    write(
        &project,
        "fixtures/sample.env",
        &format!("TOKEN={GITHUB}\n"),
    );
    fs::create_dir_all(project.join(".git")).unwrap();
    let trust_root = canonical.join("config/agentguard");
    World {
        env: Environment::isolated(trust_root.clone(), KdfCost::MINIMUM),
        project,
        trust_root,
        _base: base,
    }
}

fn call(w: &World, command: &str, arguments: Value) -> Value {
    let request = json!({ "protocol_version": 1, "request_id": "s1", "command": command, "arguments": arguments });
    let value =
        serde_json::to_value(handle(&serde_json::to_vec(&request).unwrap(), &w.env)).unwrap();
    let text = value.to_string();
    for secret in [&GITHUB[4..], PG, PASS] {
        assert!(
            !text.contains(secret),
            "secret material in a response: {text}"
        );
    }
    value
}

fn dir(w: &World) -> &str {
    w.project.to_str().unwrap()
}

fn init(w: &World) {
    let r = call(
        w,
        "project.init",
        json!({ "working_directory": dir(w), "confirm": true, "setup_trust": true, "requested_by": "dev", "passphrase": PASS }),
    );
    assert_eq!(r["success"], true, "{r}");
}

#[test]
fn scan_reports_redacted_findings_and_records_without_values() {
    let w = world();
    let before = call(&w, "secrets.scan", json!({ "working_directory": dir(&w) }));
    assert_eq!(before["success"], true, "{before}");
    assert_eq!(
        before["data"]["recorded"], false,
        "nothing is recorded before initialisation"
    );

    init(&w);
    let r = call(&w, "secrets.scan", json!({ "working_directory": dir(&w) }));
    let data = &r["data"];
    assert_eq!(data["recorded"], true);
    assert_eq!(data["audit_recorded"], true);
    let findings = data["report"]["findings"].as_array().unwrap();
    let paths: Vec<_> = findings
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    assert!(
        paths.contains(&"src/config.rs")
            && paths.contains(&".env")
            && paths.contains(&"fixtures/sample.env"),
        "{paths:?}"
    );
    assert!(data["report"]["excluded"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["path"] == ".git"));

    let audit = fs::read_to_string(w.trust_root.join("audit/trust.jsonl")).unwrap();
    for kind in [
        "scan-started",
        "secret-candidate-detected",
        "scan-completed",
        "excluded-file-encountered",
    ] {
        assert!(audit.contains(kind), "{kind}");
    }
    let stored: String = fs::read_dir(w.trust_root.join("scans"))
        .unwrap()
        .map(|e| fs::read_to_string(e.unwrap().path()).unwrap())
        .collect();
    assert!(!audit.contains(&GITHUB[4..]) && !audit.contains(PG));
    assert!(
        !stored.contains(&GITHUB[4..]) && !stored.contains(PG),
        "scan records hold no values"
    );
}

#[test]
fn explain_describes_a_finding_without_its_value() {
    let w = world();
    init(&w);
    let r = call(&w, "secrets.scan", json!({ "working_directory": dir(&w) }));
    let finding = r["data"]["report"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"] == "src/config.rs")
        .unwrap()
        .clone();
    let id = finding["id"].as_str().unwrap();
    let e = call(
        &w,
        "secrets.explain",
        json!({ "working_directory": dir(&w), "finding_id": id }),
    );
    assert_eq!(e["success"], true, "{e}");
    assert_eq!(e["data"]["finding"]["preview"], "ghp_****REDACTED");
    assert!(e["data"]["guidance"].as_str().unwrap().contains("Revoke"));
    assert!(e["data"]["false_positive"]
        .as_str()
        .unwrap()
        .contains("does not make its contents safe"));
    let bad = call(
        &w,
        "secrets.explain",
        json!({ "working_directory": dir(&w), "finding_id": "../../etc/passwd" }),
    );
    assert_eq!(bad["error"]["code"], "invalid-request");
    let missing = call(
        &w,
        "secrets.explain",
        json!({ "working_directory": dir(&w), "finding_id": "f_0000000000000000" }),
    );
    assert_eq!(missing["error"]["code"], "invalid-request");
}

#[test]
fn paths_are_confined_to_the_project_and_exclusions_are_reported() {
    let w = world();
    init(&w);
    for bad in ["../outside", "/etc/passwd", "src/../../x"] {
        let r = call(
            &w,
            "secrets.scan",
            json!({ "working_directory": dir(&w), "paths": [bad] }),
        );
        assert_eq!(r["error"]["code"], "invalid-request", "{bad}: {r}");
    }
    let r = call(
        &w,
        "secrets.scan",
        json!({ "working_directory": dir(&w), "paths": ["src"], "exclude": ["fixtures/**"] }),
    );
    let paths: Vec<_> = r["data"]["report"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(paths, ["src/config.rs"]);

    // Project configuration can add scan exclusions once a human approves it; excluded files
    // are listed, never reported clean.
    write(
        &w.project,
        ".agentguard/config.yaml",
        "version: 1\nsensitive:\n  scan_exclusions: [\"fixtures/**\"]\n",
    );
    let t = call(
        &w,
        "project.trust",
        json!({ "working_directory": dir(&w), "confirm": true, "requested_by": "dev", "passphrase": PASS }),
    );
    assert_eq!(t["success"], true, "{t}");
    let r = call(&w, "secrets.scan", json!({ "working_directory": dir(&w) }));
    let data = &r["data"];
    assert!(data["exclusions"]["patterns"]
        .as_array()
        .unwrap()
        .contains(&json!("fixtures/**")));
    assert!(
        data["report"]["excluded"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["path"] == "fixtures" && e["rule"] == "fixtures/**"),
        "{data}"
    );
    assert!(!data["report"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["path"].as_str().unwrap().starts_with("fixtures/")));
}

#[test]
fn status_lists_detectors_policy_and_last_scan() {
    let w = world();
    init(&w);
    let s = call(
        &w,
        "secrets.status",
        json!({ "working_directory": dir(&w) }),
    );
    let data = &s["data"];
    assert_eq!(data["policy"]["state"], "verified");
    assert_eq!(data["policy"]["sensitive_read"], "DENY");
    assert!(data["engine"]["detectors"].as_array().unwrap().len() > 15);
    assert!(data["last_scan"].is_null());
    call(&w, "secrets.scan", json!({ "working_directory": dir(&w) }));
    let s = call(
        &w,
        "secrets.status",
        json!({ "working_directory": dir(&w) }),
    );
    assert!(s["data"]["last_scan"]["findings"].as_u64().unwrap() >= 3);
}

fn git(dir: &Path, args: &[&str]) -> bool {
    std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[test]
fn staged_scan_reads_only_staged_changes() {
    let w = world();
    fs::remove_dir_all(w.project.join(".git")).unwrap();
    if !git(&w.project, &["init", "-q"]) {
        eprintln!("git not installed; staged scan test skipped");
        return;
    }
    assert!(
        git(&w.project, &["add", "src/main.rs", "Cargo.toml"])
            && git(&w.project, &["commit", "-qm", "init"])
    );
    assert!(git(&w.project, &["add", "src/config.rs"]));
    let r = call(
        &w,
        "secrets.scan",
        json!({ "working_directory": dir(&w), "staged": true }),
    );
    assert_eq!(r["success"], true, "{r}");
    let paths: Vec<_> = r["data"]["report"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    assert_eq!(
        paths,
        ["src/config.rs"],
        "unstaged .env and fixtures are not part of a staged scan"
    );
    let none = tempfile::tempdir().unwrap();
    let r = call(
        &w,
        "secrets.scan",
        json!({ "working_directory": none.path().to_str().unwrap(), "staged": true }),
    );
    assert_eq!(r["error"]["code"], "invalid-request");
}
