//! The engine protocol and project workflows, in-process against isolated temporary state.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::needless_pass_by_value
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use agentguard_engine_cli::protocol::MAX_REQUEST_BYTES;
use agentguard_engine_cli::{handle, Environment};
use agentguard_trust::keyfile::KdfCost;
use serde_json::{json, Value};

const PASS: &str = "correct horse battery staple";

struct World {
    _base: tempfile::TempDir,
    env: Environment,
    project: PathBuf,
    trust_root: PathBuf,
}

fn world() -> World {
    let base = tempfile::tempdir().unwrap();
    let canonical = fs::canonicalize(base.path()).unwrap();
    let project = canonical.join("project");
    fs::create_dir_all(project.join(".git")).unwrap();
    fs::create_dir_all(project.join("src")).unwrap();
    fs::write(project.join("Cargo.toml"), "[package]\n").unwrap();
    let trust_root = canonical.join("config/agentguard");
    World {
        env: Environment::isolated(trust_root.clone(), KdfCost::MINIMUM),
        project,
        trust_root,
        _base: base,
    }
}

fn call(w: &World, command: &str, arguments: Value) -> Value {
    let request = json!({ "protocol_version": 1, "request_id": "t1", "command": command, "arguments": arguments });
    let response = handle(&serde_json::to_vec(&request).unwrap(), &w.env);
    let value = serde_json::to_value(&response).unwrap();
    assert_eq!(value["protocol_version"], 1);
    assert_eq!(value["request_id"], "t1");
    assert_eq!(
        value["success"].as_bool().unwrap(),
        value["error"].is_null()
    );
    assert_eq!(
        value["success"].as_bool().unwrap(),
        !value["data"].is_null()
    );
    let text = value.to_string();
    assert!(!text.contains(PASS), "passphrase echoed");
    value
}

fn at(path: &Path) -> Value {
    json!({ "working_directory": path.to_str().unwrap() })
}

fn init_args(w: &World, extra: Value) -> Value {
    let mut a = json!({ "working_directory": w.project.to_str().unwrap(), "confirm": true, "setup_trust": true, "requested_by": "dev" });
    a.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    a
}

fn code(v: &Value) -> &str {
    v["error"]["code"].as_str().unwrap_or("")
}

fn initialised() -> World {
    let w = world();
    let r = call(
        &w,
        "project.init",
        init_args(&w, json!({ "passphrase": PASS })),
    );
    assert!(r["success"].as_bool().unwrap(), "{r}");
    w
}

// ---------------------------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------------------------

#[test]
fn protocol_rejects_malformed_oversized_and_incompatible_requests() {
    let w = world();
    let raw = |bytes: &[u8]| serde_json::to_value(handle(bytes, &w.env)).unwrap();
    for bytes in [
        b"".to_vec(),
        b"not json".to_vec(),
        b"{}".to_vec(),
        br#"{"protocol_version":1,"request_id":"x","command":"version","extra":1}"#.to_vec(),
        br#"{"protocol_version":1,"request_id":"bad id!","command":"version"}"#.to_vec(),
        br#"{"protocol_version":1,"request_id":"x","command":"version","arguments":{"surprise":true}}"#.to_vec(),
        vec![b' '; MAX_REQUEST_BYTES + 1],
    ] {
        let r = raw(&bytes);
        assert_eq!(r["success"], false, "{}", String::from_utf8_lossy(&bytes[..bytes.len().min(80)]));
        assert_eq!(r["error"]["code"], "invalid-request");
    }
    let r = raw(br#"{"protocol_version":2,"request_id":"x","command":"version"}"#);
    assert_eq!(r["error"]["code"], "unsupported-protocol");
    let r = raw(br#"{"protocol_version":1,"request_id":"x","command":"evaluate"}"#);
    assert_eq!(r["error"]["code"], "unknown-command");
    let r = raw(br#"{"protocol_version":1,"request_id":"x","command":"version"}"#);
    assert_eq!(r["data"]["engine_protocol_version"], 1);
    assert_eq!(r["data"]["authorization_protocol"], "agentguard.authz.v1");
}

// ---------------------------------------------------------------------------------------------
// Initialisation
// ---------------------------------------------------------------------------------------------

#[test]
fn init_requires_confirmation_and_passphrase_before_writing_anything() {
    let w = world();
    let r = call(
        &w,
        "project.init",
        init_args(&w, json!({ "confirm": false, "passphrase": PASS })),
    );
    assert_eq!(code(&r), "confirmation-required");
    let r = call(&w, "project.init", init_args(&w, json!({})));
    assert_eq!(code(&r), "authorization-required");
    let r = call(
        &w,
        "project.init",
        init_args(&w, json!({ "setup_trust": false, "passphrase": PASS })),
    );
    assert_eq!(code(&r), "trust-not-initialized");
    let r = call(
        &w,
        "project.init",
        init_args(&w, json!({ "passphrase": "short" })),
    );
    assert_eq!(code(&r), "authorization-failed");
    assert!(
        !w.project.join(".agentguard").exists(),
        "nothing written on refusal"
    );
    assert!(!w.trust_root.exists(), "no trust store on refusal");
}

#[test]
fn init_sets_up_trust_registers_and_is_idempotent() {
    let w = world();
    let r = call(
        &w,
        "project.init",
        init_args(&w, json!({ "passphrase": PASS, "name": "Demo App" })),
    );
    assert!(r["success"].as_bool().unwrap(), "{r}");
    assert_eq!(r["data"]["trust_store"]["created"], true);
    assert_eq!(r["data"]["registration"]["created"], true);
    assert_eq!(r["data"]["config"]["created"], true);
    assert_eq!(r["data"]["kind"], "rust");
    assert_eq!(r["data"]["profile"]["effective"], "balanced");
    let config_path = w.project.join(".agentguard/config.yaml");
    let original = fs::read_to_string(&config_path).unwrap();
    assert!(original.contains("Demo App"));

    // A human edits the configuration; re-running init (no passphrase needed: nothing to change)
    // keeps it.
    let edited = original.replace("rules: []", "rules: []\n# my note\n");
    fs::write(&config_path, &edited).unwrap();
    let r = call(&w, "project.init", init_args(&w, json!({})));
    assert!(r["success"].as_bool().unwrap(), "{r}");
    assert_eq!(r["data"]["registration"]["created"], false);
    assert_eq!(r["data"]["config"]["created"], false);
    assert_eq!(
        fs::read_to_string(&config_path).unwrap(),
        edited,
        "never silently overwritten"
    );
    for key in ["root.key", "policy.key"] {
        let mode = fs::metadata(w.trust_root.join("signing").join(key))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        assert!(!fs::read_to_string(w.trust_root.join("signing").join(key))
            .unwrap()
            .contains(PASS));
    }
}

#[test]
fn wrong_passphrase_registers_nothing_and_writes_no_config() {
    let w = initialised();
    let other = w.project.parent().unwrap().join("other");
    fs::create_dir_all(other.join(".git")).unwrap();
    let mut a = init_args(&w, json!({ "passphrase": "wrong horse battery staple" }));
    a["working_directory"] = json!(other.to_str().unwrap());
    let r = call(&w, "project.init", a);
    assert_eq!(code(&r), "authorization-failed");
    assert!(!other.join(".agentguard").exists());
    let list = call(&w, "project.list", json!({}));
    assert_eq!(list["data"]["projects"].as_array().unwrap().len(), 1);
}

#[test]
fn repeated_wrong_passphrases_lock_out_even_the_correct_one_until_the_delay_passes() {
    let w = initialised();
    let other = w.project.parent().unwrap().join("other");
    fs::create_dir_all(other.join(".git")).unwrap();
    let attempt = |passphrase: &str| {
        let mut a = init_args(&w, json!({ "passphrase": passphrase }));
        a["working_directory"] = json!(other.to_str().unwrap());
        call(&w, "project.init", a)
    };
    for _ in 0..5 {
        assert_eq!(
            code(&attempt("wrong horse battery staple")),
            "authorization-failed"
        );
    }
    let locked = attempt(PASS);
    assert_eq!(code(&locked), "authorization-failed", "{locked}");
    let message = locked["error"]["message"].as_str().unwrap();
    assert!(message.contains("5 wrong passphrases"), "{message}");
    assert!(!other.join(".agentguard").exists());
    // Backdating the record stands in for waiting 30 seconds.
    let record = w.trust_root.join("keys/attempts.json");
    let mut state: Value = serde_json::from_slice(&fs::read(&record).unwrap()).unwrap();
    state["last_failure"] = json!(state["last_failure"].as_i64().unwrap() - 31);
    fs::write(&record, serde_json::to_vec(&state).unwrap()).unwrap();
    let ok = attempt(PASS);
    assert!(ok["success"].as_bool().unwrap(), "{ok}");
    assert!(!record.exists(), "a correct passphrase resets the count");
}

#[test]
fn project_restrictions_are_approved_and_drift_is_reported() {
    let w = initialised();
    let config = w.project.join(".agentguard/config.yaml");
    let text = fs::read_to_string(&config).unwrap().replace(
        "rules: []",
        "rules:\n- id: no-network\n  decision: DENY\n  reason: offline project\n  match:\n    category: network\n",
    );
    fs::write(&config, text).unwrap();
    let check = call(&w, "check", at(&w.project));
    assert!(check["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["id"] == "policy-drift"));
    let r = call(
        &w,
        "project.trust",
        json!({ "working_directory": w.project.to_str().unwrap(), "confirm": true, "requested_by": "dev", "passphrase": PASS }),
    );
    assert!(r["success"].as_bool().unwrap(), "{r}");
    assert!(r["data"]["project_policy"]["approved"].is_string());
    let policy = call(&w, "policy.show", at(&w.project));
    let project_rules = policy["data"]["layers"]["project"].as_array().unwrap();
    assert_eq!(project_rules[0]["id"], "project:no-network");
    let mandatory = policy["data"]["layers"]["mandatory"].as_array();
    assert!(mandatory.is_some_and(|rules| !rules.is_empty()), "{policy}");
    assert_eq!(policy["data"]["integrity"], "verified");
}

#[test]
fn project_config_cannot_weaken_the_baseline() {
    let w = world();
    fs::create_dir_all(w.project.join(".agentguard")).unwrap();
    fs::write(
        w.project.join(".agentguard/config.yaml"),
        "version: 1\nrules:\n- id: allow-everything-terminal\n  decision: ALLOW\n  reason: yolo\n  match:\n    category: terminal\n",
    )
    .unwrap();
    let r = call(
        &w,
        "project.init",
        init_args(&w, json!({ "passphrase": PASS })),
    );
    assert_eq!(code(&r), "invalid-configuration");
    assert!(!w.trust_root.exists(), "rejected before trust setup");
    let v = call(&w, "config.validate", at(&w.project));
    assert_eq!(v["data"]["valid"], false);
}

// ---------------------------------------------------------------------------------------------
// Revocation and trust
// ---------------------------------------------------------------------------------------------

#[test]
fn revoke_requires_confirmation_and_authorization_and_is_not_skipped() {
    let w = initialised();
    let base = json!({ "working_directory": w.project.to_str().unwrap(), "requested_by": "dev" });
    let with = |extra: Value| {
        let mut a = base.clone();
        a.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        a
    };
    assert_eq!(
        code(&call(
            &w,
            "project.revoke",
            with(json!({ "confirm": false, "passphrase": PASS }))
        )),
        "confirmation-required"
    );
    assert_eq!(
        code(&call(
            &w,
            "project.revoke",
            with(json!({ "confirm": true }))
        )),
        "authorization-required"
    );
    assert_eq!(
        code(&call(
            &w,
            "project.revoke",
            with(json!({ "confirm": true, "passphrase": "wrong horse battery" }))
        )),
        "authorization-failed"
    );
    let status = call(&w, "status", at(&w.project));
    assert_eq!(
        status["data"]["project"]["registration"]["state"], "registered",
        "refusals change nothing"
    );
    let r = call(
        &w,
        "project.revoke",
        with(json!({ "confirm": true, "passphrase": PASS })),
    );
    assert_eq!(r["data"]["status"], "revoked");
    let status = call(&w, "status", at(&w.project));
    assert_eq!(
        status["data"]["project"]["registration"]["state"],
        "revoked"
    );
    assert_eq!(
        code(&call(
            &w,
            "project.init",
            init_args(&w, json!({ "passphrase": PASS }))
        )),
        "project-revoked"
    );
    let r = call(
        &w,
        "project.trust",
        with(json!({ "confirm": true, "passphrase": PASS })),
    );
    assert!(r["success"].as_bool().unwrap(), "{r}");
    assert_eq!(
        call(&w, "status", at(&w.project))["data"]["project"]["registration"]["state"],
        "registered"
    );
}

#[test]
fn passphrase_file_must_be_private() {
    let w = initialised();
    let file = w.project.parent().unwrap().join("pass.txt");
    fs::write(&file, format!("{PASS}\n")).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
    let a = json!({ "working_directory": w.project.to_str().unwrap(), "confirm": true, "requested_by": "dev", "passphrase_file": file.to_str().unwrap() });
    assert_eq!(
        code(&call(&w, "project.revoke", a.clone())),
        "authorization-failed"
    );
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(call(&w, "project.revoke", a)["success"].as_bool().unwrap());
}

// ---------------------------------------------------------------------------------------------
// Integrity, identity, paths
// ---------------------------------------------------------------------------------------------

#[test]
fn tampered_trust_is_reported_and_blocks_changes() {
    let w = initialised();
    let registry_dir = w.trust_root.join("registry");
    let latest = fs::read_dir(&registry_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .max()
        .unwrap();
    let text = fs::read_to_string(&latest)
        .unwrap()
        .replace("\"trusted\"", "\"revoked\"");
    fs::write(&latest, text).unwrap();
    let status = call(&w, "status", at(&w.project));
    assert_eq!(status["data"]["trust_store"]["state"], "integrity-failure");
    assert_ne!(status["data"]["policy"]["state"], "verified");
    let check = call(&w, "check", at(&w.project));
    assert_eq!(check["data"]["ok"], false);
    assert_eq!(
        code(&call(&w, "policy.show", at(&w.project))),
        "integrity-failure"
    );
    assert_eq!(
        code(&call(
            &w,
            "project.init",
            init_args(&w, json!({ "passphrase": PASS }))
        )),
        "integrity-failure"
    );
}

#[test]
fn unregistered_directory_is_reported_and_cannot_be_inspected() {
    let w = initialised();
    let other = w.project.parent().unwrap().join("elsewhere");
    fs::create_dir_all(&other).unwrap();
    let status = call(&w, "status", at(&other));
    assert_eq!(
        status["data"]["project"]["registration"]["state"],
        "unregistered"
    );
    assert_eq!(
        code(&call(&w, "project.inspect", at(&other))),
        "not-registered"
    );
}

#[test]
fn symlinked_config_directory_and_unsafe_roots_are_refused() {
    let w = world();
    let outside = w.project.parent().unwrap().join("outside");
    fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, w.project.join(".agentguard")).unwrap();
    let r = call(
        &w,
        "project.init",
        init_args(&w, json!({ "passphrase": PASS })),
    );
    assert_eq!(code(&r), "invalid-configuration");
    assert!(!outside.join("config.yaml").exists());

    // A directory containing the trust store cannot become a project.
    let w = world();
    let base = w
        .trust_root
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let mut a = init_args(&w, json!({ "passphrase": PASS }));
    a["working_directory"] = json!(base.to_str().unwrap());
    let r = call(&w, "project.init", a);
    assert_eq!(code(&r), "unsupported-project-root", "{r}");
    assert!(
        !base.join(".agentguard").exists(),
        "nothing written for a refused root"
    );

    let r = call(
        &w,
        "status",
        json!({ "working_directory": "relative/path" }),
    );
    assert_eq!(code(&r), "invalid-request");
    let r = call(
        &w,
        "status",
        json!({ "working_directory": "/does/not/../exist" }),
    );
    assert_eq!(code(&r), "invalid-request");
}

#[test]
fn status_never_claims_enforcement() {
    let w = initialised();
    let status = call(&w, "status", at(&w.project));
    assert_eq!(status["data"]["integration"]["state"], "not-configured");
    assert_eq!(status["data"]["enforcement"]["state"], "inactive");
    assert_eq!(status["data"]["policy"]["state"], "verified");
    assert_eq!(status["data"]["audit"]["state"], "available");
}
