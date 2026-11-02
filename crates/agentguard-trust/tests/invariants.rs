//! Phase 2 security invariants: trusted policy, root of trust and tamper protection. Each test
//! works against a real trust store on disk; decision-level tests drive the engine's
//! `Authorizer` built from `load_runtime`. See docs/SECURITY_INVARIANTS.md (Phase 2 table).

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
use std::sync::Arc;

use agentguard_audit::{AuditEventKind, AuditSink, MemorySink};
use agentguard_core::{
    ActionCategory, AgentIdentity, AgentKind, BoundedText, Decision, Name, NormalizedPath,
    ProjectId, RiskLevel, RuleId,
};
use agentguard_engine::approval::Approver;
use agentguard_engine::{
    ActionMatcher, Authorizer, AuthorizerParts, FsPathResolver, MemoryApprovalStore,
    PolicyEvaluator, Rule, SystemClock, TrustedInvocation, TrustedStateGuard,
};
use agentguard_proto::{AuthorizationResponse, PROTOCOL_VERSION};
use agentguard_trust::keys::{KeyEntry, KeyRole, KeySetBody, RootAnchor, KEYSET_SCHEMA};
use agentguard_trust::{
    initialize, load_runtime, quarantine, register_project, revoke_project, rotate_keyset,
    update_policy, AnchorConfig, Ed25519Signer, PolicyDocument, PolicyScope, PolicyUpdateRequest,
    Purpose, Signed, Signer, TrustError, TrustState, TrustStore,
};
use serde_json::{json, Value};
use time::OffsetDateTime;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

fn key(b: u8) -> Ed25519Signer {
    Ed25519Signer::from_seed(&Zeroizing::new([b; 32]))
}

fn human() -> Approver {
    Approver::Human {
        name: Name::new("developer").unwrap(),
    }
}

fn agent() -> Approver {
    Approver::Agent(AgentIdentity::new(AgentKind::ClaudeCode))
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

fn np(p: &Path) -> NormalizedPath {
    NormalizedPath::new(fs::canonicalize(p).unwrap().to_str().unwrap()).unwrap()
}

fn rule(id: &str, decision: Decision, matcher: ActionMatcher) -> Rule {
    Rule {
        id: RuleId::new(id).unwrap(),
        decision,
        reason: BoundedText::new(format!("test {id}")).unwrap(),
        matcher,
        priority: 0,
    }
}

fn cat(c: ActionCategory, op: Option<&str>) -> ActionMatcher {
    ActionMatcher {
        category: Some(c),
        operation: op.map(str::to_owned),
        ..ActionMatcher::default()
    }
}

struct Env {
    base: tempfile::TempDir,
    store: TrustStore,
    root_key: Ed25519Signer,
    policy_key: Ed25519Signer,
    audit: Arc<MemorySink>,
    project: NormalizedPath,
    project_id: ProjectId,
}

fn store_at(base: &Path, anchor: AnchorConfig) -> TrustStore {
    TrustStore::new(base.join("trust"), anchor)
}

fn no_system_anchor() -> AnchorConfig {
    AnchorConfig {
        system_anchor: None,
        required_owner: agentguard_trust::AnchorOwner::System,
    }
}

fn env() -> Env {
    let base = tempfile::tempdir().unwrap();
    let store = store_at(base.path(), no_system_anchor());
    let (root_key, policy_key) = (key(1), key(2));
    initialize(
        &store,
        &root_key,
        &policy_key,
        Name::new("policy").unwrap(),
        &human(),
        now(),
    )
    .unwrap();
    let project_dir = base.path().join("project");
    fs::create_dir_all(project_dir.join("src")).unwrap();
    fs::write(project_dir.join("src/main.rs"), "fn main() {}\n").unwrap();
    let audit = Arc::new(MemorySink::new());
    let reg = register_project(
        &store,
        &project_dir,
        None,
        &human(),
        &policy_key,
        now(),
        &*audit,
    )
    .unwrap();
    Env {
        project: reg.root.clone(),
        project_id: reg.id,
        base,
        store,
        root_key,
        policy_key,
        audit,
    }
}

impl Env {
    fn update(&self, scope: PolicyScope, rules: Vec<Rule>) -> Result<(), TrustError> {
        update_policy(
            &self.store,
            PolicyUpdateRequest {
                scope,
                policy: PolicyDocument {
                    rules,
                    profile: None,
                    approvals: None,
                    sensitive: None,
                    execution: None,
                },
                requested_by: human(),
                reason: BoundedText::new("test change").unwrap(),
            },
            &self.policy_key,
            now(),
            &*self.audit,
        )
        .map(|_| ())
    }

    fn authorizer(&self, cwd: &NormalizedPath) -> (Authorizer, TrustState) {
        let audit: Arc<dyn AuditSink> = self.audit.clone();
        let rt = load_runtime(&self.store, cwd, &audit);
        let state = rt.state.clone();
        let authorizer = Authorizer::new(AuthorizerParts {
            invocation: TrustedInvocation {
                agent: AgentKind::ClaudeCode,
            },
            registry: rt.registry,
            policy: rt.policy,
            approvals: Arc::new(MemoryApprovalStore::new()),
            audit,
            resolver: Arc::new(FsPathResolver),
            guard: TrustedStateGuard::new(rt.protected_roots),
            clock: Arc::new(SystemClock),
        });
        (authorizer, state)
    }

    fn decide_in(&self, cwd: &NormalizedPath, action: Value) -> AuthorizationResponse {
        let (authorizer, _) = self.authorizer(cwd);
        let req = json!({
            "protocol": PROTOCOL_VERSION,
            "request_id": agentguard_core::RequestId::generate().to_string(),
            "agent": {"kind": "claude"},
            "project": {"root": cwd.as_str()},
            "action": action,
            "working_directory": cwd.as_str(),
            "policy_version": authorizer.policy_version().to_hex(),
        });
        let r = authorizer.authorize_bytes(&serde_json::to_vec(&req).unwrap());
        assert!(r.check().is_ok());
        r
    }

    fn decide(&self, action: Value) -> AuthorizationResponse {
        self.decide_in(&self.project, action)
    }

    fn count(&self, kind: AuditEventKind) -> usize {
        self.audit
            .records()
            .unwrap()
            .iter()
            .filter(|r| r.event.kind == kind)
            .count()
    }

    fn trust_file(&self, rel: &str) -> PathBuf {
        self.store.root().join(rel)
    }

    fn latest(&self, dir: &str) -> PathBuf {
        let mut files: Vec<_> = fs::read_dir(self.trust_file(dir))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect();
        files.sort();
        files.pop().unwrap()
    }
}

fn read_json(p: &Path) -> Value {
    serde_json::from_slice(&fs::read(p).unwrap()).unwrap()
}

fn write_json(p: &Path, v: &Value) {
    fs::write(p, serde_json::to_vec_pretty(v).unwrap()).unwrap();
}

fn read_main() -> Value {
    json!({"category": "filesystem", "operation": "read", "path": "src/main.rs"})
}

fn write_main() -> Value {
    json!({"category": "filesystem", "operation": "write", "path": "src/main.rs"})
}

fn assert_lockdown(e: &Env) {
    let r = e.decide(read_main());
    assert_eq!(r.decision, Decision::Deny, "{r:?}");
    assert_eq!(r.rule.as_str(), "trust.lockdown", "{r:?}");
}

// ---------------------------------------------------------------------------------------------
// 1. Project policy cannot weaken the mandatory baseline.
// ---------------------------------------------------------------------------------------------

#[test]
fn inv01_project_allow_rules_are_rejected() {
    let e = env();
    let err = e
        .update(
            PolicyScope::Project(e.project_id),
            vec![rule(
                "allow-terminal",
                Decision::Allow,
                cat(ActionCategory::Terminal, None),
            )],
        )
        .unwrap_err();
    assert!(matches!(err, TrustError::PolicyRejected { .. }));
    assert!(e.count(AuditEventKind::PolicyUpdateRejected) >= 1);
}

#[test]
fn inv01_restrictive_project_rule_cannot_lower_a_default() {
    let e = env();
    let destroy =
        json!({"category": "terraform", "operation": "destroy", "environment": "production"});
    assert_eq!(
        e.decide(destroy.clone()).decision,
        Decision::Deny,
        "critical default"
    );
    e.update(
        PolicyScope::Project(e.project_id),
        vec![rule(
            "tf-approval",
            Decision::RequireApproval,
            cat(ActionCategory::Terraform, None),
        )],
    )
    .unwrap();
    let r = e.decide(destroy);
    assert_eq!(
        r.decision,
        Decision::Deny,
        "a REQUIRE_APPROVAL floor must not lower DENY"
    );
}

#[test]
fn inv01_global_allow_cannot_lower_mandatory_floor() {
    let e = env();
    e.update(
        PolicyScope::Global,
        vec![rule(
            "allow-push",
            Decision::Allow,
            cat(ActionCategory::Git, Some("push")),
        )],
    )
    .unwrap();
    let r = e.decide(json!({"category": "git", "operation": "push", "remote": "origin"}));
    assert_eq!(r.decision, Decision::RequireApproval);
    assert_eq!(r.rule.as_str(), "mandatory:git-push");
}

/// Property: for random restriction-only project policies and many actions, the effective
/// decision is never less restrictive than with no project policy.
#[test]
fn inv01_property_project_layer_is_monotonic() {
    use agentguard_trust::hierarchy::{EffectivePolicy, Provenance};
    let actions = sample_actions();
    let pool = restriction_pool();
    let mut rng = fastrand::Rng::with_seed(0x0007_2057);
    let global = PolicyDocument {
        profile: None,
        approvals: None,
        sensitive: None,
        execution: None,
        rules: vec![rule(
            "allow-fs",
            Decision::Allow,
            cat(ActionCategory::Filesystem, None),
        )],
    };
    let prov = || Provenance {
        mandatory: "m",
        global: None,
        project: None,
    };
    let base = EffectivePolicy::merge(&global, None, prov()).unwrap();
    for _ in 0..300 {
        let mut rules = pool.clone();
        rng.shuffle(&mut rules);
        rules.truncate(rng.usize(0..=rules.len()));
        let project = PolicyDocument {
            rules,
            profile: None,
            approvals: None,
            sensitive: None,
            execution: None,
        };
        let merged = EffectivePolicy::merge(&global, Some(&project), prov()).unwrap();
        for (ctx, action, risk) in &actions {
            let before = base.evaluate(ctx, action, risk).unwrap().decision;
            let after = merged.evaluate(ctx, action, risk).unwrap().decision;
            assert!(after >= before, "{action:?}: {after:?} < {before:?}");
        }
    }
}

fn restriction_pool() -> Vec<Rule> {
    ActionCategory::ALL
        .into_iter()
        .enumerate()
        .flat_map(|(i, c)| {
            [
                rule(&format!("ra-{i}"), Decision::RequireApproval, cat(c, None)),
                rule(&format!("deny-{i}"), Decision::Deny, cat(c, None)),
            ]
        })
        .collect()
}

fn sample_actions() -> Vec<(
    agentguard_core::SecurityContext,
    agentguard_core::Action,
    agentguard_engine::RiskAssessment,
)> {
    use agentguard_core::path::LexicalResolver;
    let root = NormalizedPath::new("/p").unwrap();
    let project = agentguard_core::ProjectIdentity::new(root.clone(), None);
    let ctx = agentguard_core::SecurityContext::new(
        AgentIdentity::new(AgentKind::ClaudeCode),
        project.clone(),
        None,
        agentguard_core::PolicyVersion::compute(b"x"),
        root,
    )
    .unwrap();
    [
        json!({"category": "filesystem", "operation": "read", "path": "a"}),
        json!({"category": "filesystem", "operation": "write", "path": "a"}),
        json!({"category": "filesystem", "operation": "write", "path": "/etc/x"}),
        json!({"category": "terminal", "command": "ls"}),
        json!({"category": "git", "operation": "push"}),
        json!({"category": "git", "operation": "status"}),
        json!({"category": "secrets", "operation": "read", "name": "K"}),
        json!({"category": "terraform", "operation": "destroy"}),
        json!({"category": "network", "operation": "request", "host": "example.com"}),
        json!({"category": "github", "operation": "read"}),
    ]
    .into_iter()
    .map(|a| {
        let req = json!({
            "protocol": PROTOCOL_VERSION,
            "request_id": agentguard_core::RequestId::generate().to_string(),
            "agent": {"kind": "claude"}, "project": {"root": "/p"}, "action": a,
            "working_directory": "/p", "policy_version": "00".repeat(32),
        });
        let parsed =
            agentguard_proto::parse_request(&serde_json::to_vec(&req).unwrap(), &LexicalResolver)
                .unwrap();
        let risk = agentguard_engine::classify(&parsed.action, &project);
        (ctx.clone(), parsed.action, risk)
    })
    .collect()
}

// ---------------------------------------------------------------------------------------------
// 2. Invalid signatures are rejected.
// ---------------------------------------------------------------------------------------------

#[test]
fn inv02_corrupted_signature_rejected() {
    let e = env();
    let path = e.latest("trusted/global");
    let mut v = read_json(&path);
    let sig = v["signature"].as_str().unwrap().to_owned();
    let flipped = format!(
        "{}{}",
        if sig.starts_with('0') { "1" } else { "0" },
        &sig[1..]
    );
    v["signature"] = json!(flipped);
    write_json(&path, &v);
    assert!(matches!(
        e.store.load(),
        Err(TrustError::SignatureInvalid { .. })
    ));
    assert_lockdown(&e);
    assert!(e.count(AuditEventKind::SignatureVerificationFailed) >= 1);
}

#[test]
fn inv02_manifest_signed_by_untrusted_key_rejected() {
    let e = env();
    let path = e.latest("trusted/global");
    let v = read_json(&path);
    let body: agentguard_trust::manifest::ManifestBody =
        serde_json::from_value(v["body"].clone()).unwrap();
    let forged = Signed::sign(body, Purpose::PolicyManifest, &key(66)).unwrap();
    write_json(&path, &serde_json::to_value(&forged).unwrap());
    assert!(matches!(
        e.store.load(),
        Err(TrustError::UntrustedSigner { .. })
    ));
}

// ---------------------------------------------------------------------------------------------
// 3. Modified trusted policies are detected.
// ---------------------------------------------------------------------------------------------

#[test]
fn inv03_policy_edit_detected_but_reformatting_is_not_an_edit() {
    let e = env();
    e.update(
        PolicyScope::Global,
        vec![rule(
            "deny-net",
            Decision::Deny,
            cat(ActionCategory::Network, None),
        )],
    )
    .unwrap();
    let path = e.latest("trusted/global");
    let mut v = read_json(&path);
    // Reformatting only (compact, same content) still verifies.
    fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
    assert!(e.store.load().is_ok());
    // Weakening the rule without the signing key is detected.
    v["body"]["policy"]["rules"][0]["decision"] = json!("ALLOW");
    write_json(&path, &v);
    assert!(matches!(
        e.store.load(),
        Err(TrustError::SignatureInvalid { .. })
    ));
    assert_lockdown(&e);
}

#[test]
fn inv03_trusted_file_permission_and_symlink_tampering_detected() {
    let e = env();
    let path = e.latest("trusted/global");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(matches!(e.store.load(), Err(TrustError::Insecure { .. })));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(e.store.load().is_ok());
    let real = e.base.path().join("elsewhere.json");
    fs::rename(&path, &real).unwrap();
    std::os::unix::fs::symlink(&real, &path).unwrap();
    assert!(matches!(e.store.load(), Err(TrustError::Insecure { .. })));
}

// ---------------------------------------------------------------------------------------------
// 4. Missing trusted state never falls back to permissive defaults.
// ---------------------------------------------------------------------------------------------

#[test]
fn inv04_uninitialised_store_locks_down() {
    let base = tempfile::tempdir().unwrap();
    let store = store_at(base.path(), no_system_anchor());
    let project = base.path().join("p");
    fs::create_dir(&project).unwrap();
    let audit: Arc<dyn AuditSink> = Arc::new(MemorySink::new());
    let rt = load_runtime(&store, &np(&project), &audit);
    assert!(matches!(
        rt.state,
        TrustState::Lockdown(TrustError::Unavailable { .. })
    ));
}

#[test]
fn inv04_each_missing_trusted_file_locks_down() {
    for rel in [
        "integrity/state.json",
        "integrity/high-water.json",
        "keys/root.json",
    ] {
        let e = env();
        fs::remove_file(e.trust_file(rel)).unwrap();
        assert!(
            matches!(e.store.load(), Err(TrustError::Unavailable { .. })),
            "{rel}"
        );
        assert_lockdown(&e);
    }
    for dir in ["keys/keyset", "trusted/global", "registry"] {
        let e = env();
        fs::remove_file(e.latest(dir)).unwrap();
        assert!(e.store.load().is_err(), "{dir}");
        assert_lockdown(&e);
    }
    let e = env();
    fs::remove_dir_all(e.store.root()).unwrap();
    assert_lockdown(&e);
    assert!(e.count(AuditEventKind::TrustedStateUnavailable) >= 1);
}

// ---------------------------------------------------------------------------------------------
// 5. Older policy versions cannot silently replace newer ones.
// ---------------------------------------------------------------------------------------------

#[test]
fn inv05_older_manifest_in_place_of_current_is_rollback() {
    let e = env();
    let v1 = fs::read(e.latest("trusted/global")).unwrap();
    e.update(
        PolicyScope::Global,
        vec![rule(
            "deny-net",
            Decision::Deny,
            cat(ActionCategory::Network, None),
        )],
    )
    .unwrap();
    fs::write(e.latest("trusted/global"), v1).unwrap();
    assert!(matches!(
        e.store.load(),
        Err(TrustError::Rollback {
            found: 1,
            pinned: 2,
            ..
        })
    ));
    assert_lockdown(&e);
    assert!(e.count(AuditEventKind::RollbackDetected) >= 1);
}

#[test]
fn inv05_replaying_an_older_integrity_state_is_rollback() {
    let e = env();
    let old_state = fs::read(e.trust_file("integrity/state.json")).unwrap();
    e.update(
        PolicyScope::Global,
        vec![rule(
            "deny-net",
            Decision::Deny,
            cat(ActionCategory::Network, None),
        )],
    )
    .unwrap();
    fs::write(e.trust_file("integrity/state.json"), old_state).unwrap();
    assert!(matches!(
        e.store.load(),
        Err(TrustError::Rollback {
            object: "integrity state",
            ..
        })
    ));
}

#[test]
fn inv05_project_manifest_rollback_detected() {
    let e = env();
    let scope = PolicyScope::Project(e.project_id);
    e.update(
        scope,
        vec![rule(
            "ra-net",
            Decision::RequireApproval,
            cat(ActionCategory::Network, None),
        )],
    )
    .unwrap();
    let dir = format!("trusted/projects/{}", e.project_id.to_hex());
    let v1 = fs::read(e.latest(&dir)).unwrap();
    e.update(
        scope,
        vec![rule(
            "deny-net",
            Decision::Deny,
            cat(ActionCategory::Network, None),
        )],
    )
    .unwrap();
    fs::write(e.latest(&dir), v1).unwrap();
    assert!(matches!(e.store.load(), Err(TrustError::Rollback { .. })));
}

// ---------------------------------------------------------------------------------------------
// 6. An AI agent cannot authorise its own policy changes.
// ---------------------------------------------------------------------------------------------

#[test]
fn inv06_agent_requester_rejected() {
    let e = env();
    let err = update_policy(
        &e.store,
        PolicyUpdateRequest {
            scope: PolicyScope::Global,
            policy: PolicyDocument::default(),
            requested_by: agent(),
            reason: BoundedText::new("please").unwrap(),
        },
        &e.policy_key,
        now(),
        &*e.audit,
    )
    .unwrap_err();
    assert_eq!(err, TrustError::SelfApproval);
    assert!(e.count(AuditEventKind::PolicyUpdateRejected) >= 1);
    assert!(matches!(
        register_project(
            &e.store,
            e.base.path(),
            None,
            &agent(),
            &e.policy_key,
            now(),
            &*e.audit
        ),
        Err(TrustError::SelfApproval)
    ));
}

#[test]
fn inv06_unauthorised_key_cannot_sign_an_update() {
    let e = env();
    let agent_key = key(99);
    let err = update_policy(
        &e.store,
        PolicyUpdateRequest {
            scope: PolicyScope::Global,
            policy: PolicyDocument::default(),
            requested_by: human(),
            reason: BoundedText::new("x").unwrap(),
        },
        &agent_key,
        now(),
        &*e.audit,
    )
    .unwrap_err();
    assert_eq!(err, TrustError::UnauthorizedSigner);
}

#[test]
fn inv06_engine_denies_agent_writes_to_trust_store_and_policy_commands() {
    let e = env();
    let target = e.trust_file("integrity/state.json");
    let r = e.decide(json!({"category": "filesystem", "operation": "write",
        "path": target.to_str().unwrap()}));
    assert_eq!(r.rule.as_str(), "guard.trusted-state");
    let r = e.decide(json!({"category": "terminal", "command": "agentguard policy approve"}));
    assert_eq!(r.rule.as_str(), "guard.self-approval");
}

// ---------------------------------------------------------------------------------------------
// 7. An unregistered project cannot claim trusted identity.
// ---------------------------------------------------------------------------------------------

#[test]
fn inv07_unregistered_and_revoked_projects_denied() {
    let e = env();
    let other = e.base.path().join("other");
    fs::create_dir(&other).unwrap();
    let r = e.decide_in(&np(&other), read_main());
    assert_eq!(r.rule.as_str(), "identity.project-unregistered");

    assert_eq!(e.decide(read_main()).decision, Decision::Allow);
    revoke_project(
        &e.store,
        &e.project_id,
        &human(),
        &e.policy_key,
        now(),
        &*e.audit,
    )
    .unwrap();
    assert_eq!(
        e.decide(read_main()).rule.as_str(),
        "identity.project-unregistered"
    );
    assert!(e.count(AuditEventKind::ProjectTrustRevoked) >= 1);
}

#[test]
fn inv07_injected_registry_entry_detected() {
    let e = env();
    let other = e.base.path().join("intruder");
    fs::create_dir(&other).unwrap();
    let path = e.latest("registry");
    let mut v = read_json(&path);
    let mut entry = v["body"]["projects"][0].clone();
    let root = np(&other);
    entry["root"] = json!(root.as_str());
    entry["id"] = json!(ProjectId::derive(&root).to_hex());
    v["body"]["projects"].as_array_mut().unwrap().push(entry);
    write_json(&path, &v);
    assert!(matches!(
        e.store.load(),
        Err(TrustError::SignatureInvalid { .. })
    ));
    let r = e.decide_in(&root, read_main());
    assert_eq!(r.decision, Decision::Deny);
}

// ---------------------------------------------------------------------------------------------
// 8. Project path manipulation cannot impersonate a registered project.
// ---------------------------------------------------------------------------------------------

#[test]
fn inv08_recreated_directory_at_same_path_is_not_the_project() {
    let e = env();
    fs::remove_dir_all(e.project.as_path()).unwrap();
    fs::create_dir_all(e.project.as_path().join("src")).unwrap();
    fs::write(e.project.as_path().join("src/main.rs"), "").unwrap();
    let r = e.decide(read_main());
    assert_eq!(r.rule.as_str(), "identity.project-unregistered");
    assert!(e.count(AuditEventKind::ProjectIdentityMismatch) >= 1);
}

#[test]
fn inv08_root_swapped_for_symlink_is_not_the_project() {
    let e = env();
    let decoy = e.base.path().join("decoy");
    fs::create_dir_all(decoy.join("src")).unwrap();
    fs::rename(e.project.as_path(), e.base.path().join("moved")).unwrap();
    std::os::unix::fs::symlink(&decoy, e.project.as_path()).unwrap();
    let audit: Arc<dyn AuditSink> = e.audit.clone();
    let rt = load_runtime(&e.store, &np(&decoy), &audit);
    assert!(rt.registry.resolve(&np(&decoy)).is_none());
    assert!(rt.registry.resolve(&e.project).is_none());
}

#[test]
fn inv08_prefix_sibling_and_bad_registrations_rejected() {
    let e = env();
    let sibling = PathBuf::from(format!("{}-evil", e.project));
    fs::create_dir(&sibling).unwrap();
    assert_eq!(
        e.decide_in(&np(&sibling), read_main()).rule.as_str(),
        "identity.project-unregistered"
    );

    let reg =
        |p: &Path| register_project(&e.store, p, None, &human(), &e.policy_key, now(), &*e.audit);
    assert!(matches!(
        reg(Path::new("/")),
        Err(TrustError::ProjectRejected { .. })
    ));
    assert!(matches!(
        reg(e.store.root()),
        Err(TrustError::ProjectRejected { .. })
    ));
    assert!(
        matches!(reg(e.base.path()), Err(TrustError::ProjectRejected { .. })),
        "contains the trust store"
    );
    assert!(matches!(
        reg(&e.base.path().join("missing")),
        Err(TrustError::ProjectRejected { .. })
    ));

    // Registering through a symlink and `..` stores the canonical path.
    let real = e.base.path().join("real");
    fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, e.base.path().join("alias")).unwrap();
    let via = e.base.path().join("alias/../alias");
    let registration = reg(&via).unwrap();
    assert_eq!(registration.root, np(&real));
}

// ---------------------------------------------------------------------------------------------
// 9. Policy merge results are deterministic.
// ---------------------------------------------------------------------------------------------

#[test]
fn inv09_property_merge_is_order_independent_and_repeatable() {
    use agentguard_trust::hierarchy::{EffectivePolicy, Provenance};
    let actions = sample_actions();
    let mut rng = fastrand::Rng::with_seed(0x0003_e79e);
    let mut globals: Vec<Rule> = ActionCategory::ALL
        .into_iter()
        .enumerate()
        .map(|(i, c)| {
            rule(
                &format!("g{i}"),
                [Decision::Allow, Decision::Deny, Decision::RequireApproval][i % 3],
                cat(c, None),
            )
        })
        .collect();
    let mut projects = restriction_pool();
    let prov = || Provenance {
        mandatory: "m",
        global: None,
        project: None,
    };
    let reference = EffectivePolicy::merge(
        &PolicyDocument {
            rules: globals.clone(),
            profile: None,
            approvals: None,
            sensitive: None,
            execution: None,
        },
        Some(&PolicyDocument {
            rules: projects.clone(),
            profile: None,
            approvals: None,
            sensitive: None,
            execution: None,
        }),
        prov(),
    )
    .unwrap();
    for _ in 0..100 {
        rng.shuffle(&mut globals);
        rng.shuffle(&mut projects);
        let merged = EffectivePolicy::merge(
            &PolicyDocument {
                rules: globals.clone(),
                profile: None,
                approvals: None,
                sensitive: None,
                execution: None,
            },
            Some(&PolicyDocument {
                rules: projects.clone(),
                profile: None,
                approvals: None,
                sensitive: None,
                execution: None,
            }),
            prov(),
        )
        .unwrap();
        assert_eq!(merged.version(), reference.version());
        for (ctx, action, risk) in &actions {
            assert_eq!(
                merged.evaluate(ctx, action, risk).unwrap(),
                reference.evaluate(ctx, action, risk).unwrap()
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 10. Integrity failures prevent protected operations.
// ---------------------------------------------------------------------------------------------

#[test]
fn inv10_any_integrity_failure_denies_everything() {
    let e = env();
    assert_eq!(e.decide(read_main()).decision, Decision::Allow, "control");
    let path = e.latest("registry");
    let mut v = read_json(&path);
    v["body"]["issued_at"] = json!("2000-01-01T00:00:00Z");
    write_json(&path, &v);
    for action in [
        read_main(),
        write_main(),
        json!({"category": "git", "operation": "status"}),
    ] {
        let r = e.decide(action);
        assert_eq!(r.decision, Decision::Deny);
        assert_eq!(r.rule.as_str(), "trust.lockdown");
    }
    assert!(e.count(AuditEventKind::SignatureVerificationFailed) >= 1);
    // Updates are refused against a tampered store, too.
    assert!(e.update(PolicyScope::Global, Vec::new()).is_err());
}

// ---------------------------------------------------------------------------------------------
// 11. Trusted public keys cannot be replaced by untrusted configuration.
// ---------------------------------------------------------------------------------------------

#[test]
fn inv11_keys_and_manifests_in_the_project_are_ignored() {
    let e = env();
    let attacker = key(77);
    let fake = e.project.as_path().join(".agentguard/keys");
    fs::create_dir_all(&fake).unwrap();
    write_json(
        &fake.join("root.json"),
        &serde_json::to_value(RootAnchor::new(
            attacker.public_key(),
            OffsetDateTime::UNIX_EPOCH,
        ))
        .unwrap(),
    );
    fs::write(
        e.project.as_path().join(".agent-security.yml"),
        "version: 1\nmode: DEVELOPMENT\nrules: []\n",
    )
    .unwrap();
    assert!(e.store.load().is_ok());
    assert_eq!(e.decide(read_main()).decision, Decision::Allow);
    let r = e.decide(json!({"category": "git", "operation": "push"}));
    assert_eq!(
        r.decision,
        Decision::RequireApproval,
        "mandatory floor unaffected"
    );
}

#[test]
fn inv11_replacing_root_or_keyset_in_the_store_is_a_key_change() {
    let e = env();
    let attacker = key(78);
    let root_path = e.trust_file("keys/root.json");
    let original = fs::read(&root_path).unwrap();
    write_json(
        &root_path,
        &serde_json::to_value(RootAnchor::new(
            attacker.public_key(),
            OffsetDateTime::UNIX_EPOCH,
        ))
        .unwrap(),
    );
    assert!(matches!(e.store.load(), Err(TrustError::KeyChange { .. })));
    fs::write(&root_path, original).unwrap();

    let keyset = KeySetBody {
        schema: KEYSET_SCHEMA.to_owned(),
        sequence: 1,
        previous: None,
        keys: vec![KeyEntry {
            public_key: attacker.public_key(),
            role: KeyRole::PolicySigner,
            label: Name::new("evil").unwrap(),
            added_at: OffsetDateTime::UNIX_EPOCH,
        }],
        issued_at: OffsetDateTime::UNIX_EPOCH,
    };
    let forged = Signed::sign(keyset, Purpose::KeySet, &attacker).unwrap();
    write_json(
        &e.latest("keys/keyset"),
        &serde_json::to_value(&forged).unwrap(),
    );
    assert!(matches!(e.store.load(), Err(TrustError::KeyChange { .. })));
    assert_lockdown(&e);
    assert!(e.count(AuditEventKind::KeyChangeRejected) >= 1);
}

#[test]
fn inv11_rotation_requires_the_root_key() {
    let e = env();
    let err = rotate_keyset(
        &e.store,
        vec![(key(80).public_key(), Name::new("new").unwrap())],
        &human(),
        &e.policy_key,
        now(),
        &*e.audit,
    )
    .unwrap_err();
    assert!(matches!(err, TrustError::KeyChange { .. }));
    assert!(e.count(AuditEventKind::KeyChangeRejected) >= 1);
}

#[test]
fn inv11_system_anchor_pins_the_root_key() {
    let base = tempfile::tempdir().unwrap();
    let anchor_path = base.path().join("system-root.json");
    write_json(
        &anchor_path,
        &serde_json::to_value(RootAnchor::new(
            key(1).public_key(),
            OffsetDateTime::UNIX_EPOCH,
        ))
        .unwrap(),
    );
    let pinned = AnchorConfig {
        system_anchor: Some(anchor_path.clone()),
        required_owner: agentguard_trust::AnchorOwner::CurrentUser,
    };
    // A group-writable anchor is refused outright.
    fs::set_permissions(&anchor_path, fs::Permissions::from_mode(0o664)).unwrap();
    assert!(matches!(
        initialize(
            &store_at(&base.path().join("c"), pinned.clone()),
            &key(1),
            &key(2),
            Name::new("p").unwrap(),
            &human(),
            now()
        ),
        Err(TrustError::Insecure { .. })
    ));
    fs::set_permissions(&anchor_path, fs::Permissions::from_mode(0o644)).unwrap();
    // A store initialised with a different root key is refused.
    let wrong = store_at(base.path(), pinned.clone());
    assert!(matches!(
        initialize(
            &wrong,
            &key(5),
            &key(2),
            Name::new("p").unwrap(),
            &human(),
            now()
        ),
        Err(TrustError::KeyChange { .. })
    ));
    // The matching root key works, and later replacing it is caught.
    let store = store_at(&base.path().join("b"), pinned.clone());
    fs::create_dir_all(base.path().join("b")).unwrap();
    initialize(
        &store,
        &key(1),
        &key(2),
        Name::new("p").unwrap(),
        &human(),
        now(),
    )
    .unwrap();
    assert!(store.load().is_ok());
    // An anchor not owned by the required owner (the administrator) is refused.
    if !nix::unistd::Uid::current().is_root() {
        let strict = store_at(
            &base.path().join("b"),
            AnchorConfig {
                system_anchor: Some(anchor_path),
                required_owner: agentguard_trust::AnchorOwner::System,
            },
        );
        assert!(matches!(strict.load(), Err(TrustError::Insecure { .. })));
    }
}

// ---------------------------------------------------------------------------------------------
// 12. A valid project policy adds restrictions without weakening global rules.
// ---------------------------------------------------------------------------------------------

#[test]
fn inv12_project_restrictions_apply_on_top_of_global() {
    let e = env();
    e.update(
        PolicyScope::Global,
        vec![rule(
            "allow-project-writes",
            Decision::Allow,
            ActionMatcher {
                category: Some(ActionCategory::Filesystem),
                operation: Some("write".into()),
                inside_project: Some(true),
                ..ActionMatcher::default()
            },
        )],
    )
    .unwrap();
    assert_eq!(e.decide(write_main()).decision, Decision::Allow);
    let src = e.project.join("src").unwrap();
    e.update(
        PolicyScope::Project(e.project_id),
        vec![rule(
            "src-needs-review",
            Decision::RequireApproval,
            ActionMatcher {
                category: Some(ActionCategory::Filesystem),
                path_prefix: Some(src),
                ..ActionMatcher::default()
            },
        )],
    )
    .unwrap();
    let r = e.decide(write_main());
    assert_eq!(r.decision, Decision::RequireApproval);
    assert_eq!(r.rule.as_str(), "project:src-needs-review");
    let other =
        e.decide(json!({"category": "filesystem", "operation": "write", "path": "README.md"}));
    assert_eq!(
        other.decision,
        Decision::Allow,
        "global allow still applies elsewhere"
    );
    assert!(e.count(AuditEventKind::PolicyUpdateAuthorized) >= 2);
}

#[test]
fn inv12_policy_file_changes_are_drift_not_policy() {
    let e = env();
    e.update(
        PolicyScope::Project(e.project_id),
        vec![rule(
            "deny-net",
            Decision::Deny,
            cat(ActionCategory::Network, None),
        )],
    )
    .unwrap();
    // The agent "relaxes" the repository copy; nothing changes except a drift event.
    fs::write(
        e.project.as_path().join(".agent-security.yml"),
        "version: 1\nmode: DEVELOPMENT\nrules: []\n",
    )
    .unwrap();
    let r = e.decide(json!({"category": "network", "operation": "request", "host": "example.com"}));
    assert_eq!(r.decision, Decision::Deny);
    assert_eq!(r.rule.as_str(), "project:deny-net");
    assert!(e.count(AuditEventKind::ProjectPolicyDrift) >= 1);
}

// ---------------------------------------------------------------------------------------------
// Key rotation and recovery.
// ---------------------------------------------------------------------------------------------

#[test]
fn rotation_retires_old_key_and_keeps_policy() {
    let e = env();
    e.update(
        PolicyScope::Project(e.project_id),
        vec![rule(
            "deny-net",
            Decision::Deny,
            cat(ActionCategory::Network, None),
        )],
    )
    .unwrap();
    let new_key = key(81);
    rotate_keyset(
        &e.store,
        vec![(new_key.public_key(), Name::new("new").unwrap())],
        &human(),
        &e.root_key,
        now(),
        &*e.audit,
    )
    .unwrap();
    let trust = e.store.load().unwrap();
    assert_eq!(trust.keyset.sequence, 2);
    assert!(
        trust.project_policies.contains_key(&e.project_id),
        "re-issued"
    );
    assert_eq!(
        e.update(PolicyScope::Global, Vec::new()).unwrap_err(),
        TrustError::UnauthorizedSigner,
        "retired key"
    );
    update_policy(
        &e.store,
        PolicyUpdateRequest {
            scope: PolicyScope::Global,
            policy: PolicyDocument::default(),
            requested_by: human(),
            reason: BoundedText::new("with new key").unwrap(),
        },
        &new_key,
        now(),
        &*e.audit,
    )
    .unwrap();
    let r = e.decide(json!({"category": "network", "operation": "request", "host": "example.com"}));
    assert_eq!(r.decision, Decision::Deny);
    assert!(e.count(AuditEventKind::KeySetRotated) >= 1);
}

#[test]
fn recovery_is_explicit_and_never_regenerates_in_place() {
    let e = env();
    // Corrupt, then try to re-initialise over it: refused.
    fs::write(e.trust_file("integrity/state.json"), b"{}").unwrap();
    assert_lockdown(&e);
    assert_eq!(
        initialize(
            &e.store,
            &key(1),
            &key(2),
            Name::new("p").unwrap(),
            &human(),
            now()
        ),
        Err(TrustError::AlreadyInitialized)
    );
    assert!(
        quarantine(&e.store, &agent(), now()).is_err(),
        "agents cannot recover"
    );
    let moved = quarantine(&e.store, &human(), now()).unwrap();
    assert!(moved.exists() && !e.store.root().exists());
    assert_lockdown(&e);
    initialize(
        &e.store,
        &key(1),
        &key(2),
        Name::new("p").unwrap(),
        &human(),
        now(),
    )
    .unwrap();
    assert!(e.store.load().is_ok());
    assert_eq!(
        e.decide(read_main()).rule.as_str(),
        "identity.project-unregistered",
        "a recovered store starts with no trusted projects"
    );
}

#[test]
fn trust_events_never_contain_key_material() {
    let e = env();
    e.update(PolicyScope::Global, Vec::new()).unwrap();
    let log = fs::read_to_string(e.store.audit_log_path()).unwrap();
    let dump = serde_json::to_string(&e.audit.records().unwrap()).unwrap() + &log;
    for secret in [hex::encode([1u8; 32]), hex::encode([2u8; 32])] {
        assert!(!dump.contains(&secret), "seed leaked");
    }
    assert!(
        !dump.contains(&String::from(e.policy_key.public_key())),
        "full public keys are referred to by key id"
    );
    let _ = RiskLevel::Low;
}
