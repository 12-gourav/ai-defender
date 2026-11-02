//! Phase 5: the approval workflow through the engine protocol, in-process (human and agent
//! environments over one isolated trust store) and across real engine processes.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::needless_pass_by_value
)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use agentguard_audit::AuditSink;
use agentguard_core::AgentKind;
use agentguard_engine::{ManualClock, TrustedInvocation};
use agentguard_engine_cli::{handle, Environment};
use agentguard_trust::keyfile::KdfCost;
use serde_json::{json, Value};
use time::OffsetDateTime;

const PASS: &str = "correct horse battery staple";

struct World {
    base: tempfile::TempDir,
    human: Environment,
    agent: Environment,
    project: PathBuf,
    trust_root: PathBuf,
    clock: Arc<ManualClock>,
}

fn env_for(root: &Path, agent: Option<AgentKind>, clock: &Arc<ManualClock>) -> Environment {
    let mut env = Environment::isolated(root.to_path_buf(), KdfCost::MINIMUM);
    env.invocation = agent.map(|agent| TrustedInvocation { agent });
    env.clock = Arc::clone(clock) as Arc<dyn agentguard_engine::Clock>;
    env
}

fn world() -> World {
    let base = tempfile::tempdir().unwrap();
    let canonical = agentguard_platform::fs::canonicalize(base.path()).unwrap();
    let project = canonical.join("project");
    fs::create_dir_all(project.join(".git")).unwrap();
    fs::write(project.join("Cargo.toml"), "[package]\n").unwrap();
    let trust_root = canonical.join("config/agentguard");
    let clock = Arc::new(ManualClock::new(OffsetDateTime::now_utc()));
    let w = World {
        human: env_for(&trust_root, None, &clock),
        agent: env_for(&trust_root, Some(AgentKind::ClaudeCode), &clock),
        project,
        trust_root,
        clock,
        base,
    };
    let r = call(
        &w.human,
        "project.init",
        json!({ "working_directory": w.dir(), "confirm": true, "setup_trust": true, "requested_by": "dev", "passphrase": PASS }),
    );
    assert!(ok(&r), "{r}");
    w
}

fn call(env: &Environment, command: &str, arguments: Value) -> Value {
    let request = json!({ "protocol_version": 1, "request_id": "t1", "command": command, "arguments": arguments });
    let value = serde_json::to_value(handle(&serde_json::to_vec(&request).unwrap(), env)).unwrap();
    assert!(!value.to_string().contains(PASS), "passphrase echoed");
    value
}

fn ok(v: &Value) -> bool {
    v["success"].as_bool().unwrap()
}

fn code(v: &Value) -> &str {
    v["error"]["code"].as_str().unwrap_or("")
}

fn message(v: &Value) -> &str {
    v["error"]["message"].as_str().unwrap_or("")
}

impl World {
    fn dir(&self) -> &str {
        self.project.to_str().unwrap()
    }

    fn policy_version(&self) -> String {
        let s = call(
            &self.human,
            "status",
            json!({ "working_directory": self.dir() }),
        );
        s["data"]["policy"]["version"].as_str().unwrap().to_owned()
    }

    fn operation(&self, action: Value, agent: &str) -> Value {
        json!({
            "protocol": agentguard_proto::PROTOCOL_VERSION,
            "request_id": uuid(),
            "agent": { "kind": agent },
            "project": { "root": self.dir() },
            "action": action,
            "working_directory": self.dir(),
            "policy_version": self.policy_version(),
            "context": { "tool": "Bash" },
        })
    }

    fn request(&self, action: Value) -> Value {
        call(
            &self.agent,
            "approval.request",
            json!({ "request": self.operation(action, "claude") }),
        )
    }

    fn requested(&self, action: Value) -> (String, String, String) {
        let r = self.request(action);
        assert!(ok(&r), "{r}");
        assert_eq!(
            r["data"]["evaluation"]["decision"], "REQUIRE_APPROVAL",
            "{r}"
        );
        let approval = &r["data"]["approval"];
        let id = approval["approval_id"].as_str().unwrap().to_owned();
        let token = approval["claim_token"].as_str().unwrap().to_owned();
        let shown = call(&self.human, "approval.show", json!({ "approval_id": id }));
        let digest = shown["data"]["approval"]["operation_digest"]
            .as_str()
            .unwrap()
            .to_owned();
        (id, token, digest)
    }

    fn approve(&self, id: &str, digest: &str) -> Value {
        call(
            &self.human,
            "approval.approve",
            json!({ "approval_id": id, "operation_digest": digest, "requested_by": "dev", "confirm": true, "passphrase": PASS }),
        )
    }

    fn consume_as(
        &self,
        env: &Environment,
        action: Value,
        agent: &str,
        id: &str,
        token: &str,
    ) -> Value {
        call(
            env,
            "authorization.consume",
            json!({ "request": self.operation(action, agent), "approval_id": id, "claim_token": token }),
        )
    }

    fn consume(&self, action: Value, id: &str, token: &str) -> Value {
        self.consume_as(&self.agent, action, "claude", id, token)
    }

    fn audit_text(&self) -> String {
        fs::read_to_string(self.trust_root.join("audit/trust.jsonl")).unwrap()
    }
}

fn uuid() -> String {
    agentguard_core::RequestId::generate().to_string()
}

fn push(target: &str) -> Value {
    json!({ "category": "git", "operation": "push", "remote": "origin", "target_ref": target })
}

// ---------------------------------------------------------------------------------------------

#[test]
fn end_to_end_request_approve_consume_once() {
    let w = world();
    let (id, token, digest) = w.requested(push("feature-a"));
    let listing = call(&w.human, "approval.list", json!({}));
    assert!(ok(&listing), "{listing}");
    let entry = &listing["data"]["approvals"][0];
    assert_eq!(entry["approval_id"], id.as_str());
    assert_eq!(entry["status"], "pending");
    assert_eq!(entry["operation"]["label"], "Git push");
    assert_eq!(entry["agent"]["name"], "Claude Code");
    assert!(
        !listing.to_string().contains(&token),
        "listings never carry claim tokens"
    );

    let approved = w.approve(&id, &digest);
    assert!(ok(&approved), "{approved}");
    assert_eq!(approved["data"]["approval"]["status"], "approved");
    assert!(!approved.to_string().contains(&token));

    let used = w.consume(push("feature-a"), &id, &token);
    assert!(ok(&used), "{used}");
    assert_eq!(used["data"]["authorized"], true);
    assert_eq!(used["data"]["consumed"], true);

    let replay = w.consume(push("feature-a"), &id, &token);
    assert_eq!(code(&replay), "authorization-denied");
    assert!(message(&replay).contains("approval.replay"), "{replay}");

    let audit = w.audit_text();
    assert!(
        !audit.contains(&token[5..]),
        "claim tokens never reach the audit log"
    );
    for kind in [
        "approval-request-created",
        "approval-approved",
        "authorization-grant-issued",
        "authorization-consumed",
        "authorization-replay-detected",
    ] {
        assert!(audit.contains(kind), "{kind}");
    }
}

#[test]
fn an_agent_cannot_approve_even_with_the_passphrase() {
    let w = world();
    let (id, _, digest) = w.requested(push("feature-a"));
    let r = call(
        &w.agent,
        "approval.approve",
        json!({ "approval_id": id, "operation_digest": digest, "requested_by": "dev", "confirm": true, "passphrase": PASS }),
    );
    assert_eq!(code(&r), "authorization-failed");
    assert!(message(&r).contains("approval.self-approval"));
    let shown = call(&w.human, "approval.show", json!({ "approval_id": id }));
    assert_eq!(shown["data"]["approval"]["status"], "pending");
}

#[test]
fn approval_needs_confirmation_and_the_passphrase_never_a_flag_or_file() {
    let w = world();
    let (id, _, digest) = w.requested(push("feature-a"));
    let base = json!({ "approval_id": id, "operation_digest": digest, "requested_by": "dev" });
    let with = |extra: Value| {
        let mut a = base.clone();
        a.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        call(&w.human, "approval.approve", a)
    };
    assert_eq!(
        code(&with(json!({ "confirm": false, "passphrase": PASS }))),
        "confirmation-required"
    );
    assert_eq!(
        code(&with(json!({ "confirm": true }))),
        "authorization-required"
    );
    assert_eq!(
        code(&with(
            json!({ "confirm": true, "passphrase": "wrong passphrase!!" })
        )),
        "authorization-failed"
    );
    let file = w.base.path().join("pass.txt");
    fs::write(&file, PASS).unwrap();
    assert_eq!(
        code(&with(
            json!({ "confirm": true, "passphrase_file": file.to_str().unwrap() })
        )),
        "invalid-request",
        "approvals do not accept a passphrase file"
    );
    assert_eq!(
        code(&with(
            json!({ "confirm": true, "passphrase": PASS, "approved": true, "yes": true })
        )),
        "invalid-request"
    );
    let shown = call(&w.human, "approval.show", json!({ "approval_id": id }));
    assert_eq!(
        shown["data"]["approval"]["status"], "pending",
        "refusals change nothing"
    );
    let wrong_digest = "0".repeat(64);
    let r = with(json!({ "confirm": true, "passphrase": PASS, "operation_digest": wrong_digest }));
    assert_eq!(code(&r), "approval-conflict");
}

#[test]
fn an_approval_binds_the_exact_operation_and_agent() {
    let w = world();
    let (id, token, digest) = w.requested(push("feature-a"));
    assert!(ok(&w.approve(&id, &digest)));
    let r = w.consume(push("main"), &id, &token);
    assert_eq!(code(&r), "authorization-denied");
    assert!(message(&r).contains("approval.operation-mismatch"), "{r}");

    let codex = env_for(&w.trust_root, Some(AgentKind::Codex), &w.clock);
    let r = w.consume_as(&codex, push("feature-a"), "codex", &id, &token);
    assert!(message(&r).contains("approval.agent-mismatch"), "{r}");
    let r = w.consume_as(&codex, push("feature-a"), "claude", &id, &token);
    assert!(
        message(&r).contains("identity.agent-mismatch"),
        "a claimed agent is not believed: {r}"
    );

    let forged = agentguard_core::ApprovalId::generate().to_string();
    assert_eq!(
        code(&w.consume(push("feature-a"), &forged, &token)),
        "approval-not-found"
    );
    let guessed = format!("agc1_{}", "ab".repeat(32));
    assert!(
        message(&w.consume(push("feature-a"), &id, &guessed)).contains("approval.token-mismatch")
    );

    assert!(
        ok(&w.consume(push("feature-a"), &id, &token)),
        "mismatches did not burn the grant"
    );
}

#[test]
fn deny_after_approval_wins_and_policy_changes_void_grants() {
    let w = world();
    let (id, token, digest) = w.requested(push("feature-a"));
    assert!(ok(&w.approve(&id, &digest)));
    // The project adds a restriction denying pushes; a human trusts the new configuration.
    fs::write(
        w.project.join(".agentguard/config.yaml"),
        "version: 1\nrules:\n- id: no-push\n  decision: DENY\n  reason: pushes are frozen\n  match: { category: git, operation: push }\n",
    )
    .unwrap();
    let t = call(
        &w.human,
        "project.trust",
        json!({ "working_directory": w.dir(), "confirm": true, "requested_by": "dev", "passphrase": PASS }),
    );
    assert!(ok(&t), "{t}");
    let r = w.consume(push("feature-a"), &id, &token);
    assert_eq!(code(&r), "authorization-denied");
    assert!(
        message(&r).contains("no-push"),
        "the current DENY wins: {r}"
    );
    let shown = call(&w.human, "approval.show", json!({ "approval_id": id }));
    assert_eq!(
        shown["data"]["approval"]["status"], "cancelled",
        "the voided approval stays void"
    );
    assert!(w
        .audit_text()
        .contains("approval-invalidated-by-policy-change"));
}

#[test]
fn a_policy_change_between_approval_and_use_voids_the_grant() {
    let w = world();
    let (id, token, digest) = w.requested(push("feature-a"));
    assert!(ok(&w.approve(&id, &digest)));
    fs::write(
        w.project.join(".agentguard/config.yaml"),
        "version: 1\nrules:\n- id: no-db\n  decision: DENY\n  reason: no databases here\n  match: { category: database }\n",
    )
    .unwrap();
    assert!(ok(&call(
        &w.human,
        "project.trust",
        json!({ "working_directory": w.dir(), "confirm": true, "requested_by": "dev", "passphrase": PASS })
    )));
    let r = w.consume(push("feature-a"), &id, &token);
    assert!(message(&r).contains("approval.policy-changed"), "{r}");
}

#[test]
fn denied_and_unbindable_operations_never_create_approvals() {
    let w = world();
    for action in [
        json!({ "category": "filesystem", "operation": "write", "path": ".agentguard/config.yaml" }),
        json!({ "category": "terminal", "command": "agentguard approve 1234" }),
        json!({ "category": "terraform", "operation": "apply", "workspace": "prod", "environment": "production" }),
        json!({ "category": "git", "operation": "push", "remote": "origin" }),
    ] {
        let r = w.request(action.clone());
        assert!(ok(&r), "{r}");
        assert_eq!(
            r["data"]["evaluation"]["decision"], "DENY",
            "{action} -> {r}"
        );
        assert!(r["data"]["approval"].is_null());
    }
    let listing = call(&w.human, "approval.list", json!({}));
    assert_eq!(listing["data"]["approvals"].as_array().unwrap().len(), 0);
}

#[test]
fn agent_commands_need_an_integration_launch() {
    let w = world();
    let r = call(
        &w.human,
        "approval.request",
        json!({ "request": w.operation(push("x"), "claude") }),
    );
    assert_eq!(code(&r), "identity-unavailable");
}

#[test]
fn expiry_reject_cancel_and_revoke() {
    let w = world();
    let (id, token, digest) = w.requested(push("a"));
    w.clock.advance(time::Duration::minutes(6));
    let r = w.approve(&id, &digest);
    assert_eq!(code(&r), "approval-conflict");
    assert!(message(&r).contains("approval.expired"));

    let (id, token2, _) = w.requested(push("b"));
    let r = call(
        &w.human,
        "approval.reject",
        json!({ "approval_id": id, "requested_by": "dev", "confirm": false }),
    );
    assert_eq!(code(&r), "confirmation-required");
    let r = call(
        &w.human,
        "approval.reject",
        json!({ "approval_id": id, "requested_by": "dev", "confirm": true, "reason": "not today" }),
    );
    assert_eq!(r["data"]["approval"]["status"], "rejected");
    assert!(message(&w.consume(push("b"), &id, &token2)).contains("approval.not-approved"));

    let (id, token3, _) = w.requested(push("c"));
    let r = call(
        &w.human,
        "approval.cancel",
        json!({ "approval_id": id, "claim_token": token }),
    );
    assert!(
        message(&r).contains("approval.token-mismatch"),
        "another request's token cannot cancel"
    );
    let r = call(
        &w.human,
        "approval.cancel",
        json!({ "approval_id": id, "claim_token": token3 }),
    );
    assert_eq!(r["data"]["approval"]["status"], "cancelled");

    let (id, token4, digest) = w.requested(push("d"));
    assert!(ok(&w.approve(&id, &digest)));
    let r = call(
        &w.human,
        "authorization.revoke",
        json!({ "approval_id": id, "requested_by": "dev", "confirm": true }),
    );
    assert!(ok(&r), "{r}");
    assert!(message(&w.consume(push("d"), &id, &token4)).contains("approval.not-approved"));

    let (id, token5, digest) = w.requested(push("e"));
    assert!(ok(&w.approve(&id, &digest)));
    w.clock.advance(time::Duration::minutes(3));
    assert!(message(&w.consume(push("e"), &id, &token5)).contains("approval.expired"));
}

/// Real engine processes racing to consume one grant: exactly one wins.
#[test]
#[allow(clippy::disallowed_methods)] // spawns the engine binary under test, never a host tool
fn concurrent_engine_processes_consume_a_grant_at_most_once() {
    let w = world();
    let (id, token, digest) = w.requested(push("race"));
    assert!(ok(&w.approve(&id, &digest)));
    let home = agentguard_platform::fs::canonicalize(w.base.path()).unwrap();
    let request = json!({
        "protocol_version": 1, "request_id": "race", "command": "authorization.consume",
        "arguments": { "request": w.operation(push("race"), "claude"), "approval_id": id, "claim_token": token },
    })
    .to_string();
    let children: Vec<_> = (0..8)
        .map(|_| {
            let mut child = Command::new(env!("CARGO_BIN_EXE_agentguard-engine"))
                .args(["--agent", "claude"])
                .env_clear()
                .env("HOME", &home)
                .env("XDG_CONFIG_HOME", home.join("config"))
                .env("XDG_STATE_HOME", home.join("state"))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(request.as_bytes())
                .unwrap();
            child
        })
        .collect();
    let outputs: Vec<Value> = children
        .into_iter()
        .map(|c| serde_json::from_slice(&c.wait_with_output().unwrap().stdout).unwrap())
        .collect();
    let wins = outputs.iter().filter(|o| o["success"] == true).count();
    assert_eq!(wins, 1, "{outputs:?}");
    assert!(outputs
        .iter()
        .filter(|o| o["success"] == false)
        .all(|o| message(o).contains("approval.replay")));
    // Every process appended to one audit chain without forking it.
    let audit = agentguard_audit::JsonlSink::open(&w.trust_root.join("audit/trust.jsonl")).unwrap();
    assert!(audit.verify().is_ok());
}

#[test]
fn tampered_trusted_state_never_produces_or_honours_a_grant() {
    let w = world();
    let (id, token, digest) = w.requested(push("feature-a"));
    let (id2, _, digest2) = w.requested(push("feature-b"));
    assert!(ok(&w.approve(&id, &digest)));
    // Prepared before tampering: status has no policy version once trust fails to verify.
    let use_a = w.operation(push("feature-a"), "claude");
    let ask_c = w.operation(push("feature-c"), "claude");
    let registry = w.trust_root.join("registry");
    let mut files: Vec<_> = fs::read_dir(&registry)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    let latest = files.last().unwrap();
    let text = fs::read_to_string(latest).unwrap();
    fs::write(latest, text.replace("\"trusted\"", "\"revoked\"")).unwrap();

    let r = call(
        &w.agent,
        "authorization.consume",
        json!({ "request": use_a, "approval_id": id, "claim_token": token }),
    );
    assert_eq!(code(&r), "integrity-failure", "{r}");
    let r = w.approve(&id2, &digest2);
    assert_eq!(code(&r), "integrity-failure", "{r}");
    let r = call(&w.agent, "approval.request", json!({ "request": ask_c }));
    assert_eq!(code(&r), "integrity-failure", "{r}");
}
