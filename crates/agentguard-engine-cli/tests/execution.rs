//! Phase 7: managed execution, Git security and command governance through the engine
//! protocol, against isolated trust stores, temporary repositories and a local bare remote.
//! Every credential below is fake and nonfunctional; nothing touches the developer's own
//! repositories or configuration.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::needless_pass_by_value,
    clippy::disallowed_methods,
    clippy::print_stderr,
    clippy::too_many_lines,
    clippy::similar_names
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use agentguard_core::{AgentKind, BoundedText, Decision};
use agentguard_engine::{ProfileSettings, TrustedInvocation};
use agentguard_engine_cli::{handle, Environment};
use agentguard_trust::keyfile::{KdfCost, Passphrase, SigningRole};
use agentguard_trust::{update_policy, PolicyDocument, PolicyScope, PolicyUpdateRequest};
use serde_json::{json, Value};

const PASS: &str = "correct horse battery staple";
const GITHUB: &str = "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0000";
const ENV_SECRET: &str = "FakeEnvSecretValue-0123456789";

struct World {
    _base: tempfile::TempDir,
    human: Environment,
    agent: Environment,
    project: PathBuf,
    home: PathBuf,
    remote: PathBuf,
    outside: PathBuf,
    trust_root: PathBuf,
}

fn caller_env(home: &Path) -> Vec<(String, String)> {
    vec![
        ("PATH".to_owned(), std::env::var("PATH").unwrap_or_default()),
        ("HOME".to_owned(), home.to_string_lossy().into_owned()),
        ("LANG".to_owned(), "C".to_owned()),
        ("GITHUB_TOKEN".to_owned(), GITHUB.to_owned()),
        ("MY_SERVICE_PASSWORD".to_owned(), ENV_SECRET.to_owned()),
        ("LD_PRELOAD".to_owned(), "/nonexistent/evil.so".to_owned()),
    ]
}

fn git(dir: &Path, home: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .stdout(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn world() -> Option<World> {
    if !git_available() {
        eprintln!("git not installed; managed Git tests skipped");
        return None;
    }
    let base = tempfile::tempdir().unwrap();
    let canonical = fs::canonicalize(base.path()).unwrap();
    let project = canonical.join("project");
    let home = canonical.join("home");
    let remote = canonical.join("remote.git");
    let outside = canonical.join("outside");
    for d in [&project, &home, &outside] {
        fs::create_dir_all(d).unwrap();
    }
    fs::write(
        home.join(".gitconfig"),
        "[user]\n\tname = Test\n\temail = test@example.invalid\n[init]\n\tdefaultBranch = main\n",
    )
    .unwrap();
    fs::write(project.join("Cargo.toml"), "[package]\n").unwrap();
    fs::write(project.join("README.md"), "hello\n").unwrap();
    fs::write(outside.join("keep.txt"), "keep\n").unwrap();
    assert!(git(
        &canonical,
        &home,
        &["init", "-q", "--bare", remote.to_str().unwrap()]
    ));
    assert!(git(&project, &home, &["init", "-q"]));
    assert!(git(&project, &home, &["add", "Cargo.toml", "README.md"]));
    assert!(git(&project, &home, &["commit", "-qm", "init"]));
    assert!(git(
        &project,
        &home,
        &["remote", "add", "origin", remote.to_str().unwrap()]
    ));
    assert!(git(&project, &home, &["push", "-q", "origin", "main"]));
    assert!(git(&project, &home, &["checkout", "-qb", "feature-a"]));
    let trust_root = canonical.join("config/agentguard");
    let mut human = Environment::isolated(trust_root.clone(), KdfCost::MINIMUM);
    human.process_env = caller_env(&home);
    let mut agent = Environment::isolated(trust_root.clone(), KdfCost::MINIMUM);
    agent.process_env = caller_env(&home);
    agent.invocation = Some(TrustedInvocation {
        agent: AgentKind::ClaudeCode,
    });
    let w = World {
        _base: base,
        human,
        agent,
        project,
        home,
        remote,
        outside,
        trust_root,
    };
    let r = call(
        &w.human,
        "project.init",
        json!({ "working_directory": w.dir(), "confirm": true, "setup_trust": true, "requested_by": "dev", "passphrase": PASS }),
    );
    assert!(ok(&r), "{r}");
    Some(w)
}

fn call(env: &Environment, command: &str, arguments: Value) -> Value {
    let request = json!({ "protocol_version": 1, "request_id": "x1", "command": command, "arguments": arguments });
    let value = serde_json::to_value(handle(&serde_json::to_vec(&request).unwrap(), env)).unwrap();
    let text = value.to_string();
    for secret in [&GITHUB[4..], ENV_SECRET, PASS] {
        assert!(
            !text.contains(secret),
            "secret material in a response: {text}"
        );
    }
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

fn key() -> String {
    agentguard_core::RequestId::generate().to_string()
}

impl World {
    fn dir(&self) -> &str {
        self.project.to_str().unwrap()
    }

    fn git(&self, args: &[&str]) -> bool {
        git(&self.project, &self.home, args)
    }

    fn rev(&self, rev: &str) -> String {
        let out = Command::new("git")
            .args(["rev-parse", rev])
            .current_dir(&self.project)
            .env("HOME", &self.home)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    fn run_as(
        &self,
        env: &Environment,
        argv: &[&str],
        approval: Option<(&str, &str)>,
        key: &str,
    ) -> Value {
        let mut args =
            json!({ "working_directory": self.dir(), "argv": argv, "idempotency_key": key });
        if let Some((id, token)) = approval {
            args["approval"] = json!({ "approval_id": id, "claim_token": token });
        }
        call(env, "execution.run", args)
    }

    fn run(&self, argv: &[&str]) -> Value {
        self.run_as(&self.human, argv, None, &key())
    }

    fn shell(&self, script: &str) -> Value {
        call(
            &self.human,
            "execution.run",
            json!({ "working_directory": self.dir(), "shell": { "interpreter": "sh", "script": script }, "idempotency_key": key() }),
        )
    }

    /// Request approval, have a human approve it; returns (approval ID, claim token).
    fn approved(&self, argv: &[&str]) -> (String, String) {
        let r = self.run(argv);
        assert!(ok(&r), "{r}");
        assert_eq!(r["data"]["outcome"], "approval-required", "{r}");
        let id = r["data"]["approval"]["approval_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let token = r["data"]["approval"]["claim_token"]
            .as_str()
            .unwrap()
            .to_owned();
        let shown = call(&self.human, "approval.show", json!({ "approval_id": id }));
        let digest = shown["data"]["approval"]["operation_digest"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(digest, r["data"]["operation_digest"].as_str().unwrap());
        let a = call(
            &self.human,
            "approval.approve",
            json!({ "approval_id": id, "operation_digest": digest, "requested_by": "dev", "confirm": true, "passphrase": PASS }),
        );
        assert!(ok(&a), "{a}");
        (id, token)
    }

    fn audit(&self) -> String {
        fs::read_to_string(self.trust_root.join("audit/trust.jsonl")).unwrap()
    }

    fn records(&self) -> String {
        let dir = self.trust_root.join("executions/records");
        fs::read_dir(dir)
            .map(|d| {
                d.flatten()
                    .map(|e| fs::read_to_string(e.path()).unwrap_or_default())
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn outcome(r: &Value) -> &str {
    r["data"]["outcome"].as_str().unwrap_or("")
}

// ---------------------------------------------------------------------------------------------

#[test]
fn read_only_and_development_commands_run_and_are_recorded() {
    let Some(w) = world() else { return };
    let r = w.run(&["git", "status"]);
    assert!(ok(&r), "{r}");
    assert_eq!(outcome(&r), "executed", "{r}");
    assert_eq!(r["data"]["state"], "completed");
    assert!(r["data"]["stdout"].as_str().unwrap().contains("feature-a"));
    assert_eq!(r["data"]["plan"]["category"], "read-only");
    let id = r["data"]["execution_id"].as_str().unwrap();
    let inspected = call(
        &w.human,
        "execution.inspect",
        json!({ "execution_id": &id[..10] }),
    );
    assert_eq!(
        inspected["data"]["execution"]["state"], "completed",
        "{inspected}"
    );
    let history = call(&w.human, "execution.history", json!({}));
    assert_eq!(history["data"]["executions"][0]["execution_id"], id);
    let audit = w.audit();
    for kind in [
        "execution-request-received",
        "command-classified",
        "execution-policy-decision",
        "execution-started",
        "execution-completed",
    ] {
        assert!(audit.contains(kind), "{kind}");
    }
}

/// Invariants 1, 3, 11: push needs approval; a grant is bound to its remote and branch; a
/// consumed grant cannot be reused.
#[test]
fn push_requires_approval_bound_to_remote_and_branch_once() {
    let Some(w) = world() else { return };
    let (id, token) = w.approved(&["git", "push", "origin", "feature-a"]);
    let other = w.run_as(
        &w.human,
        &["git", "push", "origin", "main"],
        Some((&id, &token)),
        &key(),
    );
    assert_eq!(code(&other), "authorization-denied", "{other}");
    assert!(
        message(&other).contains("approval.operation-mismatch"),
        "{other}"
    );
    let used = w.run_as(
        &w.human,
        &["git", "push", "origin", "feature-a"],
        Some((&id, &token)),
        &key(),
    );
    assert!(ok(&used), "{used}");
    assert_eq!(outcome(&used), "executed", "{used}");
    assert_eq!(used["data"]["state"], "completed", "{used}");
    assert_eq!(used["data"]["verification"]["status"], "verified", "{used}");
    assert!(used["data"]["grant_id"].is_string());
    let replay = w.run_as(
        &w.human,
        &["git", "push", "origin", "feature-a"],
        Some((&id, &token)),
        &key(),
    );
    assert_eq!(code(&replay), "authorization-denied");
    assert!(message(&replay).contains("approval.replay"), "{replay}");
    assert!(w.audit().contains("authorization-consumed"));
}

/// Invariant 12: a new commit on the branch after approval invalidates a push grant.
#[test]
fn a_moved_branch_invalidates_a_push_approval() {
    let Some(w) = world() else { return };
    let (id, token) = w.approved(&["git", "push", "origin", "feature-a"]);
    fs::write(w.project.join("later.txt"), "later\n").unwrap();
    assert!(w.git(&["add", "later.txt"]) && w.git(&["commit", "-qm", "later"]));
    let r = w.run_as(
        &w.human,
        &["git", "push", "origin", "feature-a"],
        Some((&id, &token)),
        &key(),
    );
    assert_eq!(code(&r), "authorization-denied", "{r}");
    assert!(message(&r).contains("approval.operation-mismatch"), "{r}");
}

/// Invariant 12: re-pointing the pushed branch invalidates a push grant even when nothing
/// else (HEAD, staged content, the commits not yet on the remote) changes.
#[test]
fn a_repointed_source_branch_invalidates_a_push_approval() {
    let Some(w) = world() else { return };
    fs::write(w.project.join("second.txt"), "2\n").unwrap();
    assert!(w.git(&["add", "second.txt"]) && w.git(&["commit", "-qm", "second"]));
    assert!(w.git(&["push", "-q", "origin", "feature-a"]));
    assert!(w.git(&["branch", "other", "main"]));
    let (id, token) = w.approved(&["git", "push", "origin", "other"]);
    assert!(w.git(&["branch", "-f", "other", "feature-a"]));
    let r = w.run_as(
        &w.human,
        &["git", "push", "origin", "other"],
        Some((&id, &token)),
        &key(),
    );
    assert_eq!(code(&r), "authorization-denied", "{r}");
    assert!(message(&r).contains("approval.operation-mismatch"), "{r}");
}

/// Invariant 2: force push is denied by default; a stronger trusted policy can lower it to
/// approval, never to allow.
#[test]
fn force_push_is_denied_unless_trusted_policy_permits_approval() {
    let Some(w) = world() else { return };
    for argv in [
        &["git", "push", "--force", "origin", "feature-a"][..],
        &["git", "push", "--force-with-lease", "origin", "feature-a"],
        &["git", "push", "origin", "+feature-a"],
        &["git", "push", "--delete", "origin", "main"],
    ] {
        let r = w.run(argv);
        assert_eq!(outcome(&r), "denied", "{argv:?}: {r}");
        assert_eq!(
            r["data"]["decision"]["rule"], "profile:git-force-push",
            "{r}"
        );
    }
    let signer = agentguard_engine_cli::support::unlock(
        &w.human.store,
        SigningRole::Policy,
        &Passphrase::new(PASS.to_owned()).unwrap(),
    )
    .unwrap();
    let audit = w.human.store.open_audit_log().unwrap();
    update_policy(
        &w.human.store,
        PolicyUpdateRequest {
            scope: PolicyScope::Global,
            policy: PolicyDocument {
                profile: Some(ProfileSettings {
                    git_force_push: Decision::RequireApproval,
                    ..ProfileSettings::default()
                }),
                ..PolicyDocument::default()
            },
            requested_by: agentguard_engine::Approver::Human {
                name: agentguard_core::Name::new("dev").unwrap(),
            },
            reason: BoundedText::new("allow reviewed force pushes").unwrap(),
        },
        &signer,
        time::OffsetDateTime::now_utc(),
        &audit,
    )
    .unwrap();
    let r = w.run(&["git", "push", "--force", "origin", "feature-a"]);
    assert_eq!(outcome(&r), "approval-required", "{r}");
    let allow = PolicyDocument {
        profile: Some(ProfileSettings {
            git_force_push: Decision::Allow,
            ..ProfileSettings::default()
        }),
        ..PolicyDocument::default()
    };
    assert!(
        agentguard_trust::hierarchy::validate_document(agentguard_trust::Layer::Global, &allow)
            .is_err(),
        "force pushes can never be allowed outright"
    );
}

/// Invariants 4 and 12: a commit approval is bound to the staged content.
#[test]
fn a_commit_approval_cannot_include_changed_staged_content() {
    let Some(w) = world() else { return };
    fs::write(w.project.join("a.txt"), "a\n").unwrap();
    assert!(w.git(&["add", "a.txt"]));
    let (id, token) = w.approved(&["git", "commit", "-m", "add a"]);
    fs::write(w.project.join("b.txt"), "b\n").unwrap();
    assert!(w.git(&["add", "b.txt"]));
    let r = w.run_as(
        &w.human,
        &["git", "commit", "-m", "add a"],
        Some((&id, &token)),
        &key(),
    );
    assert_eq!(code(&r), "authorization-denied", "{r}");
    assert!(message(&r).contains("approval.operation-mismatch"), "{r}");
    let head = w.rev("HEAD");
    let (id, token) = w.approved(&["git", "commit", "-m", "add a and b"]);
    let r = w.run_as(
        &w.human,
        &["git", "commit", "-m", "add a and b"],
        Some((&id, &token)),
        &key(),
    );
    assert_eq!(outcome(&r), "executed", "{r}");
    assert_eq!(r["data"]["verification"]["status"], "verified", "{r}");
    assert_ne!(w.rev("HEAD"), head);
    for unsupported in [
        &["git", "commit", "-a", "-m", "x"][..],
        &["git", "commit", "-m", "x", "a.txt"],
        &["git", "commit"],
    ] {
        let r = w.run(unsupported);
        assert_eq!(outcome(&r), "refused", "{unsupported:?}: {r}");
    }
}

/// Invariant 5: detected secrets block commits and pushes.
#[test]
fn detected_secrets_prevent_commits_and_pushes() {
    let Some(w) = world() else { return };
    fs::write(
        w.project.join("config.rs"),
        format!("const T: &str = \"{GITHUB}\";\n"),
    )
    .unwrap();
    assert!(w.git(&["add", "config.rs"]));
    let r = w.run(&["git", "commit", "-m", "config"]);
    assert_eq!(outcome(&r), "denied", "{r}");
    assert_eq!(
        r["data"]["decision"]["rule"], "mandatory:secret-commit",
        "{r}"
    );
    assert!(
        r["data"]["plan"]["git"]["secret_scan"]["detections"]
            .as_u64()
            .unwrap()
            >= 1
    );
    // Committed outside AgentGuard; the push is still inspected and blocked.
    assert!(w.git(&["commit", "-qm", "config"]));
    let r = w.run(&["git", "push", "origin", "feature-a"]);
    assert_eq!(outcome(&r), "denied", "{r}");
    assert_eq!(
        r["data"]["decision"]["rule"], "mandatory:secret-disclosure",
        "{r}"
    );
    assert!(w.audit().contains("pre-execution-scan-completed"));
}

/// Invariant 6: destructive operations against protected locations are denied, and nothing
/// is deleted.
#[test]
fn destructive_commands_against_protected_locations_are_denied() {
    let Some(w) = world() else { return };
    let outside = format!("{}", w.outside.display());
    for argv in [
        vec!["rm", "-rf", outside.as_str()],
        vec!["rm", "-rf", "../outside"],
        vec!["rm", "-rf", ".git"],
        vec!["rm", "-rf", "/"],
        vec!["chmod", "-R", "777", "../outside"],
    ] {
        let r = w.run(&argv);
        assert_eq!(outcome(&r), "denied", "{argv:?}: {r}");
    }
    assert!(w.outside.join("keep.txt").exists());
    assert!(w.project.join(".git").exists());
    let r = w.run(&["rm", "-rf", "README.md"]);
    assert_eq!(
        outcome(&r),
        "approval-required",
        "ordinary project files need approval: {r}"
    );
    assert!(w.project.join("README.md").exists());
}

/// Invariant 7: arguments are never interpreted by a shell.
#[test]
fn arguments_cannot_escape_their_structure() {
    let Some(w) = world() else { return };
    let r = w.run(&[
        "echo",
        "x; touch pwned1",
        "$(touch pwned2)",
        "`touch pwned3`",
        "a && touch pwned4",
    ]);
    assert_eq!(outcome(&r), "executed", "{r}");
    assert_eq!(
        r["data"]["stdout"].as_str().unwrap().trim_end(),
        "x; touch pwned1 $(touch pwned2) `touch pwned3` a && touch pwned4"
    );
    for f in ["pwned1", "pwned2", "pwned3", "pwned4", "touch"] {
        assert!(!w.project.join(f).exists(), "{f}");
    }
}

/// Invariant 8: unsupported shell syntax never executes.
#[test]
fn unsupported_shell_syntax_never_executes() {
    let Some(w) = world() else { return };
    for script in [
        "echo $(touch pwned)",
        "echo `touch pwned`",
        "touch pwned &",
        "true; eval 'touch pwned'",
        "echo ok > $HOME/pwned",
        "(touch pwned)",
        "cat <<EOF\ntouch pwned\nEOF",
        "FOO=1 touch pwned",
        "git commit -m x",
    ] {
        let r = w.shell(script);
        assert!(ok(&r), "{script}: {r}");
        assert_eq!(outcome(&r), "refused", "{script}: {r}");
    }
    assert!(!w.project.join("pwned").exists());
    assert!(w.audit().contains("unsupported-operation-detected"));
    let r = w.shell("echo hello && echo world | cat");
    assert_eq!(outcome(&r), "executed", "{r}");
    assert_eq!(r["data"]["stdout"], "hello\nworld\n");
}

/// Invariant 9: agent identity comes from the launch, never the request.
#[test]
fn agent_identity_cannot_be_forged() {
    let Some(w) = world() else { return };
    let forged = call(
        &w.human,
        "execution.run",
        json!({ "working_directory": w.dir(), "argv": ["git", "status"], "idempotency_key": key(), "agent": { "kind": "claude" } }),
    );
    assert_eq!(code(&forged), "invalid-request", "{forged}");
    // Approved for the command-line caller; an agent integration cannot redeem it.
    let (id, token) = w.approved(&["git", "push", "origin", "feature-a"]);
    let r = w.run_as(
        &w.agent,
        &["git", "push", "origin", "feature-a"],
        Some((&id, &token)),
        &key(),
    );
    assert_eq!(code(&r), "authorization-denied", "{r}");
    let r = w.run_as(&w.agent, &["git", "status"], None, &key());
    assert_eq!(outcome(&r), "executed", "{r}");
    let record = call(
        &w.human,
        "execution.inspect",
        json!({ "execution_id": r["data"]["execution_id"] }),
    );
    assert_eq!(
        record["data"]["execution"]["agent"]["kind"], "claude-code",
        "{record}"
    );
    assert_eq!(
        record["data"]["execution"]["invocation"],
        "agent-integration"
    );
}

/// Invariant 10: project identity comes from the registry, never the request.
#[test]
fn project_identity_cannot_be_forged() {
    let Some(w) = world() else { return };
    let r = call(
        &w.human,
        "execution.run",
        json!({ "working_directory": w.outside.to_str().unwrap(), "argv": ["ls"], "idempotency_key": key() }),
    );
    assert_eq!(code(&r), "not-registered", "{r}");
    let forged = call(
        &w.human,
        "execution.run",
        json!({ "working_directory": w.dir(), "argv": ["ls"], "idempotency_key": key(), "project": { "root": w.outside.to_str().unwrap() } }),
    );
    assert_eq!(code(&forged), "invalid-request");
    std::os::unix::fs::symlink(&w.outside, w.project.join("escape")).unwrap();
    let via_link = call(
        &w.human,
        "execution.run",
        json!({ "working_directory": w.project.join("escape").to_str().unwrap(), "argv": ["ls"], "idempotency_key": key() }),
    );
    assert_eq!(
        code(&via_link),
        "not-registered",
        "a symlinked directory resolves to its target: {via_link}"
    );
}

/// Invariant 13: environment secrets never reach output, records or the audit log.
#[test]
fn environment_secrets_are_not_exposed() {
    let Some(w) = world() else { return };
    let (id, token) = w.approved(&["env"]);
    let r = w.run_as(&w.human, &["env"], Some((&id, &token)), &key());
    assert_eq!(outcome(&r), "executed", "{r}");
    let out = r["data"]["stdout"].as_str().unwrap();
    for absent in ["GITHUB_TOKEN", "MY_SERVICE_PASSWORD", "LD_PRELOAD"] {
        assert!(!out.contains(absent), "{absent} in {out}");
    }
    assert!(out.contains("HOME="));
    assert!(
        r["data"]["plan"]["environment"]["withheld"]
            .as_u64()
            .unwrap()
            >= 3
    );
    // A secret the process prints itself is redacted.
    let printed = w.run(&["printf", "%s\\n", GITHUB]);
    assert_eq!(outcome(&printed), "executed", "{printed}");
    assert!(
        printed["data"]["stdout"]
            .as_str()
            .unwrap()
            .contains("REDACTED"),
        "{printed}"
    );
    let stored = format!("{}{}", w.records(), w.audit());
    for secret in [&GITHUB[4..], ENV_SECRET] {
        assert!(!stored.contains(secret), "secret stored");
    }
}

/// Invariant 14: child output is bounded.
#[test]
fn child_output_is_bounded() {
    let Some(w) = world() else { return };
    fs::write(
        w.project.join("big.txt"),
        "0123456789abcdef\n".repeat(128 * 1024),
    )
    .unwrap();
    let r = w.run(&["cat", "big.txt"]);
    assert_eq!(outcome(&r), "executed", "{r}");
    assert_eq!(r["data"]["result"]["stdout_bytes"], 17 * 128 * 1024);
    assert_eq!(r["data"]["result"]["stdout_truncated"], true);
    assert!(r["data"]["stdout"].as_str().unwrap().len() <= 130 * 1024);
    assert!(w.records().len() < 200 * 1024);
}

/// Invariant 15: time limits terminate the process and are recorded as such.
#[test]
fn timeouts_are_handled_safely() {
    let Some(w) = world() else { return };
    let r = call(
        &w.human,
        "execution.run",
        json!({ "working_directory": w.dir(), "argv": ["sleep", "30"], "timeout_seconds": 1, "idempotency_key": key() }),
    );
    assert_eq!(outcome(&r), "executed", "{r}");
    assert_eq!(r["data"]["state"], "timed-out", "{r}");
    assert!(r["data"]["result"]["duration_ms"].as_u64().unwrap() < 10_000);
    assert!(w.audit().contains("execution-timed-out"));
}

/// Invariant 16: when the audit log cannot be written, nothing runs.
#[test]
fn a_failed_audit_write_never_produces_a_run() {
    let Some(w) = world() else { return };
    let log = w.trust_root.join("audit/trust.jsonl");
    fs::remove_file(&log).unwrap();
    fs::create_dir(&log).unwrap();
    let r = w.run(&["touch", "marker"]);
    assert!(!ok(&r), "{r}");
    assert_eq!(code(&r), "audit-unavailable", "{r}");
    assert!(!w.project.join("marker").exists());
}

/// Invariant 17: managed execution never reports itself as global protection.
#[test]
fn direct_execution_is_never_reported_as_protected() {
    let Some(w) = world() else { return };
    let s = call(&w.human, "status", json!({ "working_directory": w.dir() }));
    assert_eq!(s["data"]["enforcement"]["global_enforcement"], false);
    assert!(s["data"]["enforcement"]["direct_terminal"]
        .as_str()
        .unwrap()
        .contains("not intercepted"));
    let r = w.run(&["git", "status"]);
    assert_eq!(r["data"]["enforcement"]["global_enforcement"], false);
    assert_eq!(
        r["data"]["enforcement"]["direct_execution_protected"],
        false
    );
}

/// Invariant 18: no command reaches the executor without authorization.
#[test]
fn internal_executors_cannot_be_invoked_directly() {
    let Some(w) = world() else { return };
    for command in [
        "execution.spawn",
        "execution.execute",
        "process.run",
        "execution.start",
    ] {
        let r = call(&w.human, command, json!({ "argv": ["touch", "pwned"] }));
        assert_eq!(code(&r), "unknown-command", "{command}");
    }
    for argv in [
        &["agentguard", "approve", "x"][..],
        &["agentguard-engine", "--agent", "claude"],
        &["sudo", "touch", "pwned"],
        &["su", "-c", "touch pwned"],
    ] {
        let r = w.run(argv);
        assert_eq!(outcome(&r), "refused", "{argv:?}: {r}");
    }
    let denied = w.run(&["rm", "-rf", "../outside"]);
    assert_eq!(outcome(&denied), "denied");
    assert!(
        !w.records().contains("\"started\""),
        "a refused or denied request never starts"
    );
    assert!(!w.project.join("pwned").exists());
}

/// Invariant 19: executables are resolved through trusted directories only.
#[test]
fn executable_path_manipulation_is_handled() {
    let Some(mut w) = world() else { return };
    let bin = w.project.join("bin");
    fs::create_dir_all(&bin).unwrap();
    // Owner-only write, so only the project-root rule can exclude it from the search path.
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    let fake = bin.join("git");
    fs::write(&fake, format!("#!/bin/sh\ntouch {}/pwned\n", w.dir())).unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!(
        ".:{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    w.human.process_env.retain(|(k, _)| k != "PATH");
    w.human.process_env.push(("PATH".to_owned(), path));
    let r = w.run(&["git", "status"]);
    assert_eq!(outcome(&r), "executed", "{r}");
    assert!(
        !w.project.join("pwned").exists(),
        "the planted git never ran"
    );
    assert!(!r["data"]["plan"]["executable"]["path"]
        .as_str()
        .unwrap()
        .starts_with(w.dir()));
    let explicit = w.run(&["./bin/git", "status"]);
    assert_eq!(
        outcome(&explicit),
        "approval-required",
        "a project script is not trusted: {explicit}"
    );
    assert!(!w.project.join("pwned").exists());
}

/// Invariant 20: nothing runs twice and nothing is retried.
#[test]
fn requests_are_never_run_twice() {
    let Some(w) = world() else { return };
    let k = key();
    let first = call(
        &w.human,
        "execution.run",
        json!({ "working_directory": w.dir(), "shell": { "interpreter": "sh", "script": "echo once >> count.txt" }, "idempotency_key": k }),
    );
    assert_eq!(outcome(&first), "executed", "{first}");
    let second = call(
        &w.human,
        "execution.run",
        json!({ "working_directory": w.dir(), "shell": { "interpreter": "sh", "script": "echo once >> count.txt" }, "idempotency_key": k }),
    );
    assert_eq!(code(&second), "execution-duplicate", "{second}");
    assert_eq!(
        fs::read_to_string(w.project.join("count.txt")).unwrap(),
        "once\n"
    );
}

/// A repository whose working tree extends beyond the registered project cannot be changed
/// through managed execution: its changes could not be bound to this project.
#[test]
fn a_repository_larger_than_the_project_is_read_only() {
    let Some(w) = world() else { return };
    // A package registered on its own; a repository is later created around it, so the
    // repository's root lies outside the registered project.
    let mono = w.outside.parent().unwrap().join("mono");
    let sub = mono.join("packages/app");
    fs::create_dir_all(&sub).unwrap();
    fs::write(sub.join("package.json"), "{}\n").unwrap();
    let r = call(
        &w.human,
        "project.init",
        json!({ "working_directory": sub.to_str().unwrap(), "confirm": true, "requested_by": "dev", "passphrase": PASS }),
    );
    assert!(ok(&r), "{r}");
    assert!(git(&mono, &w.home, &["init", "-q"]));
    assert!(git(&mono, &w.home, &["add", "packages/app/package.json"]));
    assert!(git(&mono, &w.home, &["commit", "-qm", "init"]));
    let run = |argv: &[&str]| {
        call(
            &w.human,
            "execution.run",
            json!({ "working_directory": sub.to_str().unwrap(), "argv": argv, "idempotency_key": key() }),
        )
    };
    let read = run(&["git", "status"]);
    assert_eq!(outcome(&read), "executed", "{read}");
    let write = run(&["git", "commit", "-m", "x"]);
    assert_eq!(outcome(&write), "refused", "{write}");
    assert_eq!(
        write["data"]["refusal"]["code"],
        "execution.repository-outside-project"
    );
}

#[test]
fn git_inspection_redacts_remote_credentials() {
    let Some(w) = world() else { return };
    assert!(w.git(&[
        "remote",
        "add",
        "creds",
        &format!("https://user:{GITHUB}@example.invalid/org/repo.git")
    ]));
    let r = call(
        &w.human,
        "git.inspect",
        json!({ "working_directory": w.dir() }),
    );
    assert!(ok(&r), "{r}");
    let remotes = r["data"]["repository"]["remotes"].as_array().unwrap();
    let creds = remotes.iter().find(|r| r["name"] == "creds").unwrap();
    assert_eq!(creds["url"], "https://example.invalid/org/repo.git");
    assert_eq!(r["data"]["repository"]["branch"], "feature-a");
    let s = call(
        &w.human,
        "git.status",
        json!({ "working_directory": w.dir() }),
    );
    assert!(ok(&s), "{s}");
    assert!(s["data"]["status"]["total"].as_u64().is_some(), "{s}");
    let _ = &w.remote;
}

/// The engine binary forwards nothing it should not: run the real process once.
#[test]
fn the_engine_process_runs_a_managed_command() {
    let Some(w) = world() else { return };
    let exe = env!("CARGO_BIN_EXE_agentguard-engine");
    let request = json!({ "protocol_version": 1, "request_id": "p1", "command": "execution.run",
        "arguments": { "working_directory": w.dir(), "argv": ["git", "status"], "idempotency_key": key() } });
    let mut child = Command::new(exe)
        .env("XDG_CONFIG_HOME", w.trust_root.parent().unwrap())
        .env("XDG_STATE_HOME", w.trust_root.parent().unwrap())
        .env("XDG_DATA_HOME", w.trust_root.parent().unwrap())
        .env("HOME", &w.home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(request.to_string().as_bytes())
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    let response: Value = serde_json::from_slice(&out.stdout).unwrap();
    // The process uses the user's real configuration paths derived from XDG variables; it
    // either finds this test's trust store or reports that none exists. It never runs the
    // command without one.
    if response["success"] == true {
        assert_eq!(response["data"]["outcome"], "executed", "{response}");
    } else {
        assert!(
            matches!(
                response["error"]["code"].as_str(),
                Some("trust-not-initialized" | "not-registered" | "integrity-failure")
            ),
            "{response}"
        );
    }
}
