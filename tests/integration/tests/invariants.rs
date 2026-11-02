//! The ten security invariants, each exercised end to end through the engine: raw request
//! bytes in, response and audit records out, against a real temporary project directory and the
//! filesystem path resolver. See docs/SECURITY_INVARIANTS.md for the mapping.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::needless_pass_by_value
)]

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use agentguard_audit::{
    AuditDecision, AuditError, AuditEvent, AuditEventKind, AuditSink, ChainedRecord, MemorySink,
};
use agentguard_core::{
    Action, AgentKind, Decision, NormalizedPath, OperationFingerprint, PathResolver, PolicyVersion,
    ProjectIdentity, RiskLevel, SecurityContext,
};
use agentguard_engine::approval::{fingerprint, ApprovalError};
use agentguard_engine::policy::PolicyError;
use agentguard_engine::{
    ActionMatcher, ApprovalGrant, ApprovalStore, Approver, Authorizer, AuthorizerParts, Clock,
    FsPathResolver, ManualClock, MemoryApprovalStore, PolicyEvaluator, PolicyVerdict,
    RiskAssessment, Rule, RuleSetPolicy, StaticProjectRegistry, TrustedInvocation,
    TrustedStateGuard,
};
use agentguard_proto::{
    parse_request, AuthorizationRequest, AuthorizationResponse, PROTOCOL_VERSION,
};
use serde_json::{json, Value};
use time::OffsetDateTime;

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

struct Harness {
    _project_dir: tempfile::TempDir,
    _state_dir: tempfile::TempDir,
    root: NormalizedPath,
    state: NormalizedPath,
    audit: Arc<MemorySink>,
    approvals: Arc<MemoryApprovalStore>,
    clock: Arc<ManualClock>,
    authorizer: Authorizer,
}

fn canonical(p: &Path) -> NormalizedPath {
    NormalizedPath::new(fs::canonicalize(p).unwrap().to_str().unwrap()).unwrap()
}

fn rule(id: &str, decision: Decision, matcher: ActionMatcher) -> Rule {
    Rule {
        id: agentguard_core::RuleId::new(id).unwrap(),
        decision,
        reason: agentguard_core::BoundedText::new(format!("test rule {id}")).unwrap(),
        matcher,
        priority: 0,
    }
}

fn harness_with(policy: Arc<dyn PolicyEvaluator>) -> Harness {
    let project_dir = tempfile::tempdir().unwrap();
    let state_dir = tempfile::tempdir().unwrap();
    fs::create_dir(project_dir.path().join("src")).unwrap();
    fs::write(project_dir.path().join("src/main.rs"), "fn main() {}\n").unwrap();
    let root = canonical(project_dir.path());
    let state = canonical(state_dir.path());
    let audit = Arc::new(MemorySink::new());
    let approvals = Arc::new(MemoryApprovalStore::new());
    let clock = Arc::new(ManualClock::new(
        OffsetDateTime::UNIX_EPOCH + time::Duration::days(20_000),
    ));
    let authorizer = Authorizer::new(AuthorizerParts {
        invocation: TrustedInvocation {
            agent: AgentKind::ClaudeCode,
        },
        registry: Arc::new(StaticProjectRegistry::new(vec![ProjectIdentity::new(
            root.clone(),
            None,
        )])),
        policy,
        approvals: approvals.clone(),
        audit: audit.clone(),
        resolver: Arc::new(FsPathResolver),
        guard: TrustedStateGuard::new(vec![state.clone()]),
        clock: clock.clone(),
    });
    Harness {
        _project_dir: project_dir,
        _state_dir: state_dir,
        root,
        state,
        audit,
        approvals,
        clock,
        authorizer,
    }
}

fn harness() -> Harness {
    harness_with(Arc::new(RuleSetPolicy::baseline().unwrap()))
}

impl Harness {
    fn request(&self, action: Value) -> Value {
        json!({
            "protocol": PROTOCOL_VERSION,
            "request_id": agentguard_core::RequestId::generate().to_string(),
            "agent": {"kind": "claude"},
            "project": {"root": self.root.as_str()},
            "session_id": "0b1c2d3e-4f50-4617-8899-aabbccddeeff",
            "action": action,
            "working_directory": self.root.as_str(),
            "policy_version": self.authorizer.policy_version().to_hex(),
        })
    }

    fn send(&self, request: &Value) -> AuthorizationResponse {
        let response = self
            .authorizer
            .authorize_bytes(&serde_json::to_vec(request).unwrap());
        assert!(
            response.check().is_ok(),
            "inconsistent response {response:?}"
        );
        response
    }

    fn records(&self) -> Vec<ChainedRecord> {
        self.audit.records().unwrap()
    }

    fn events_of(&self, kind: AuditEventKind) -> Vec<AuditEvent> {
        self.records()
            .into_iter()
            .map(|r| r.event)
            .filter(|e| e.kind == kind)
            .collect()
    }

    /// The context the engine would build for `request` (a valid one).
    fn context_and_request(&self, request: &Value) -> (SecurityContext, AuthorizationRequest) {
        let parsed = parse_request(&serde_json::to_vec(request).unwrap(), &FsPathResolver).unwrap();
        let project = ProjectIdentity::new(self.root.clone(), None);
        let ctx = SecurityContext::new(
            agentguard_core::AgentIdentity::new(AgentKind::ClaudeCode),
            project,
            parsed.session,
            self.authorizer.policy_version(),
            parsed.working_directory.clone(),
        )
        .unwrap();
        (ctx, parsed)
    }

    fn approve(&self, request: &Value) -> OperationFingerprint {
        let (ctx, parsed) = self.context_and_request(request);
        let fp = fingerprint(&ctx, &parsed).unwrap();
        self.approvals
            .grant(
                ApprovalGrant::new(
                    fp,
                    Approver::Human {
                        name: agentguard_core::Name::new("developer").unwrap(),
                    },
                    self.clock.now(),
                    Duration::from_secs(60),
                )
                .unwrap(),
            )
            .unwrap();
        fp
    }
}

fn read_main() -> Value {
    json!({"category": "filesystem", "operation": "read", "path": "src/main.rs"})
}

fn write_main() -> Value {
    json!({"category": "filesystem", "operation": "write", "path": "src/main.rs"})
}

// ---------------------------------------------------------------------------------------------
// Invariant 1: missing identity never produces an unauthorized allow.
// ---------------------------------------------------------------------------------------------

#[test]
fn invariant_01_control_valid_identity_allows_read() {
    let h = harness();
    let r = h.send(&h.request(read_main()));
    assert_eq!(r.decision, Decision::Allow, "{r:?}");
    assert_eq!(r.risk, RiskLevel::Low);
}

#[test]
fn invariant_01_missing_or_wrong_identity_denies() {
    let h = harness();
    for field in ["agent", "project"] {
        let mut req = h.request(read_main());
        req.as_object_mut().unwrap().remove(field);
        let r = h.send(&req);
        assert_eq!(r.decision, Decision::Deny, "missing {field}");
        assert_eq!(r.rule.as_str(), "protocol.invalid-request");
    }
    for kind in ["", "nobody"] {
        let mut req = h.request(read_main());
        req["agent"]["kind"] = json!(kind);
        assert_eq!(h.send(&req).decision, Decision::Deny, "agent kind {kind:?}");
    }
    let mut req = h.request(read_main());
    req["agent"]["kind"] = json!("codex");
    let r = h.send(&req);
    assert_eq!(r.decision, Decision::Deny);
    assert_eq!(r.rule.as_str(), "identity.agent-mismatch");
}

// ---------------------------------------------------------------------------------------------
// Invariant 2: invalid requests never produce an allow.
// ---------------------------------------------------------------------------------------------

#[test]
fn invariant_02_invalid_requests_deny() {
    let h = harness();
    let mut cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"null".to_vec(),
        b"{}".to_vec(),
        b"not json".to_vec(),
        vec![b'{'; 70_000],
    ];
    for mutate in [
        |v: &mut Value| v["protocol"] = json!("agentguard.authz.v0"),
        |v: &mut Value| v["action"]["path"] = json!("src/\u{0}main.rs"),
        |v: &mut Value| v["action"]["extra"] = json!(1),
        |v: &mut Value| v["working_directory"] = json!("relative"),
        |v: &mut Value| v["request_id"] = json!(42),
    ] {
        let mut req = h.request(read_main());
        mutate(&mut req);
        cases.push(serde_json::to_vec(&req).unwrap());
    }
    for bytes in cases {
        let r = h.authorizer.authorize_bytes(&bytes);
        assert_eq!(r.decision, Decision::Deny);
        assert_eq!(r.risk, RiskLevel::Critical);
        assert!(!r.permits_execution());
    }
}

/// Property: corrupting bytes of a request that would be allowed yields ALLOW only when the
/// corrupted bytes still form a fully valid request.
#[test]
fn invariant_02_property_corruption_never_allows_invalid_input() {
    let h = harness();
    let base = serde_json::to_vec(&h.request(read_main())).unwrap();
    let mut rng = fastrand::Rng::with_seed(0xa11_0e0d);
    for _ in 0..1500 {
        let mut bytes = base.clone();
        for _ in 0..rng.usize(1..4) {
            let i = rng.usize(..bytes.len());
            bytes[i] = rng.u8(..);
        }
        let r = h.authorizer.authorize_bytes(&bytes);
        if r.decision == Decision::Allow {
            assert!(
                parse_request(&bytes, &FsPathResolver).is_ok(),
                "allowed an invalid request"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Invariant 3: unknown sensitive actions are denied.
// ---------------------------------------------------------------------------------------------

#[test]
fn invariant_03_unknown_operations_denied_even_if_policy_allows_category() {
    let allow_everything_in_categories = ["filesystem", "git", "secrets", "network"]
        .into_iter()
        .map(|c| {
            rule(
                &format!("allow-{c}"),
                Decision::Allow,
                ActionMatcher {
                    category: Some(serde_json::from_value(json!(c)).unwrap()),
                    ..ActionMatcher::default()
                },
            )
        })
        .collect();
    let h = harness_with(Arc::new(
        RuleSetPolicy::new(allow_everything_in_categories).unwrap(),
    ));
    for action in [
        json!({"category": "filesystem", "operation": "shred", "path": "src/main.rs"}),
        json!({"category": "git", "operation": "filter-repo"}),
        json!({"category": "secrets", "operation": "export", "name": "X"}),
        json!({"category": "network", "operation": "udp-flood", "host": "example.com"}),
    ] {
        let r = h.send(&h.request(action.clone()));
        assert_eq!(r.decision, Decision::Deny, "{action}");
        assert_eq!(r.rule.as_str(), "guard.unknown-operation");
    }
}

#[test]
fn invariant_03_unmodelled_actions_are_never_allowed_by_default() {
    let h = harness();
    for action in [
        json!({"category": "terminal", "command": "ls"}),
        json!({"category": "custom-tool", "tool": "mcp__x__do"}),
        json!({"category": "network", "operation": "request", "host": "example.com"}),
    ] {
        let r = h.send(&h.request(action.clone()));
        assert_ne!(r.decision, Decision::Allow, "{action}");
    }
}

// ---------------------------------------------------------------------------------------------
// Invariant 4: agents cannot modify trusted authorization state.
// ---------------------------------------------------------------------------------------------

#[test]
fn invariant_04_trusted_state_writes_denied_despite_allow_rule() {
    let allow_writes = vec![rule(
        "allow-project-writes",
        Decision::Allow,
        ActionMatcher {
            category: Some(agentguard_core::ActionCategory::Filesystem),
            inside_project: Some(true),
            ..ActionMatcher::default()
        },
    )];
    let h = harness_with(Arc::new(RuleSetPolicy::new(allow_writes).unwrap()));
    // Control: the rule does allow an ordinary write.
    assert_eq!(h.send(&h.request(write_main())).decision, Decision::Allow);

    let state_file = format!("{}/audit.jsonl", h.state);
    for (op, path) in [
        ("write", ".agent-security.yml"),
        ("write", ".claude/settings.json"),
        ("delete", ".agentguard/approvals.db"),
        ("write", state_file.as_str()),
        ("change-permissions", ".agent-security.yml"),
    ] {
        let action = json!({"category": "filesystem", "operation": op, "path": path});
        let r = h.send(&h.request(action));
        assert_eq!(r.decision, Decision::Deny, "{op} {path}");
        assert_eq!(r.rule.as_str(), "guard.trusted-state");
    }
    assert!(h.events_of(AuditEventKind::TamperDetected).len() >= 5);
}

#[test]
fn invariant_04_symlink_into_trusted_state_is_resolved_and_denied() {
    let h = harness();
    std::os::unix::fs::symlink(h.state.as_path(), h.root.as_path().join("innocent")).unwrap();
    let action =
        json!({"category": "filesystem", "operation": "write", "path": "innocent/policy.json"});
    let r = h.send(&h.request(action));
    assert_eq!(r.decision, Decision::Deny);
    assert_eq!(r.rule.as_str(), "guard.trusted-state");
}

#[test]
fn invariant_04_rename_onto_policy_and_terminal_edits_denied() {
    let h = harness();
    let rename = json!({"category": "filesystem", "operation": "rename",
        "path": "src/main.rs", "destination": ".agent-security.yml"});
    assert_eq!(
        h.send(&h.request(rename)).rule.as_str(),
        "guard.trusted-state"
    );
    let term =
        json!({"category": "terminal", "command": "sed -i s/DENY/ALLOW/ .agent-security.yml"});
    assert_eq!(
        h.send(&h.request(term)).rule.as_str(),
        "guard.trusted-state"
    );
}

// ---------------------------------------------------------------------------------------------
// Invariant 5: agents cannot approve their own privileged operations.
// ---------------------------------------------------------------------------------------------

#[test]
fn invariant_05_requests_cannot_carry_approvals() {
    let h = harness();
    for (k, v) in [
        ("approved", json!(true)),
        ("approval", json!({"required": false})),
        ("decision", json!("ALLOW")),
    ] {
        let mut req = h.request(write_main());
        req[k] = v;
        assert_eq!(h.send(&req).decision, Decision::Deny, "{k}");
    }
}

#[test]
fn invariant_05_agent_principals_cannot_grant() {
    let err = ApprovalGrant::new(
        OperationFingerprint::from_bytes([0; 32]),
        Approver::Agent(agentguard_core::AgentIdentity::new(AgentKind::ClaudeCode)),
        OffsetDateTime::UNIX_EPOCH,
        Duration::from_secs(30),
    )
    .unwrap_err();
    assert_eq!(err, ApprovalError::SelfApproval);
}

#[test]
fn invariant_05_agent_cannot_run_approval_commands() {
    let h = harness();
    for cmd in [
        "agentguard approve 6f1c1f0e",
        "cd /tmp && agentguard policy allow all",
        "$(which agentguard) uninstall",
    ] {
        let r = h.send(&h.request(json!({"category": "terminal", "command": cmd})));
        assert_eq!(r.decision, Decision::Deny, "{cmd}");
    }
    assert_ne!(h.events_of(AuditEventKind::TamperDetected).len(), 0);
}

// ---------------------------------------------------------------------------------------------
// Invariant 6: an approval is bound to one specific operation.
// ---------------------------------------------------------------------------------------------

#[test]
fn invariant_06_approval_applies_once_to_exactly_its_operation() {
    let h = harness();
    let approved = h.request(write_main());
    let first = h.send(&approved);
    assert_eq!(first.decision, Decision::RequireApproval);
    let fp = h.approve(&approved);
    assert_eq!(
        first.approval.fingerprint,
        Some(fp),
        "response names the binding"
    );

    let other =
        h.request(json!({"category": "filesystem", "operation": "write", "path": "src/lib.rs"}));
    assert_eq!(
        h.send(&other).decision,
        Decision::RequireApproval,
        "different path"
    );
    let delete =
        h.request(json!({"category": "filesystem", "operation": "delete", "path": "src/main.rs"}));
    assert_eq!(
        h.send(&delete).decision,
        Decision::RequireApproval,
        "different operation"
    );

    // A new request ID for the same operation still matches: the binding is the operation.
    let retry = h.request(write_main());
    let allowed = h.send(&retry);
    assert_eq!(allowed.decision, Decision::Allow);
    assert_eq!(allowed.rule.as_str(), "approval.granted");
    assert_eq!(
        h.send(&h.request(write_main())).decision,
        Decision::RequireApproval,
        "single use"
    );
}

#[test]
fn invariant_06_approval_cannot_override_a_denial() {
    let h = harness();
    let force_push = h.request(json!({"category": "git", "operation": "push", "remote": "origin", "target_ref": "main", "force": true}));
    assert_eq!(h.send(&force_push).decision, Decision::Deny);
    h.approve(&force_push);
    assert_eq!(h.send(&force_push).decision, Decision::Deny);
}

// ---------------------------------------------------------------------------------------------
// Invariant 7: a changed authorization context requires re-evaluation.
// ---------------------------------------------------------------------------------------------

#[test]
fn invariant_07_session_or_directory_change_invalidates_approval() {
    let h = harness();
    let original = h.request(write_main());
    h.approve(&original);

    let mut other_session = h.request(write_main());
    other_session["session_id"] = json!("11111111-2222-4333-8444-555555555555");
    assert_eq!(h.send(&other_session).decision, Decision::RequireApproval);

    let mut other_cwd =
        h.request(json!({"category": "filesystem", "operation": "write", "path": "main.rs"}));
    other_cwd["working_directory"] = json!(format!("{}/src", h.root));
    assert_eq!(h.send(&other_cwd).decision, Decision::RequireApproval);

    assert_eq!(
        h.send(&original).decision,
        Decision::Allow,
        "unchanged context still matches"
    );
}

#[test]
fn invariant_07_expired_approval_requires_new_approval() {
    let h = harness();
    let req = h.request(write_main());
    h.approve(&req);
    h.clock.advance(time::Duration::seconds(61));
    assert_eq!(h.send(&req).decision, Decision::RequireApproval);
}

#[test]
fn invariant_07_policy_change_invalidates_requests_and_approvals() {
    let h = harness();
    let req = h.request(write_main());
    h.approve(&req);
    let changed = RuleSetPolicy::new(vec![rule(
        "deny-net",
        Decision::Deny,
        ActionMatcher {
            category: Some(agentguard_core::ActionCategory::Network),
            ..ActionMatcher::default()
        },
    )])
    .unwrap();
    let new_version = changed.version();
    let authorizer = Authorizer::new(AuthorizerParts {
        invocation: TrustedInvocation {
            agent: AgentKind::ClaudeCode,
        },
        registry: Arc::new(StaticProjectRegistry::new(vec![ProjectIdentity::new(
            h.root.clone(),
            None,
        )])),
        policy: Arc::new(changed),
        approvals: h.approvals.clone(),
        audit: h.audit.clone(),
        resolver: Arc::new(FsPathResolver),
        guard: TrustedStateGuard::default(),
        clock: h.clock.clone(),
    });
    let stale = authorizer.authorize_bytes(&serde_json::to_vec(&req).unwrap());
    assert_eq!(stale.decision, Decision::Deny);
    assert_eq!(stale.rule.as_str(), "policy.version-mismatch");
    assert_eq!(stale.policy_version, Some(new_version));

    let mut fresh = req.clone();
    fresh["policy_version"] = json!(new_version.to_hex());
    let r = authorizer.authorize_bytes(&serde_json::to_vec(&fresh).unwrap());
    assert_eq!(
        r.decision,
        Decision::RequireApproval,
        "approval from the old policy does not apply"
    );
}

// ---------------------------------------------------------------------------------------------
// Invariant 8: security errors never silently permit execution.
// ---------------------------------------------------------------------------------------------

struct BrokenPolicy;
impl PolicyEvaluator for BrokenPolicy {
    fn version(&self) -> PolicyVersion {
        PolicyVersion::compute(b"broken")
    }
    fn evaluate(
        &self,
        _: &SecurityContext,
        _: &Action,
        _: &RiskAssessment,
    ) -> Result<PolicyVerdict, PolicyError> {
        Err(PolicyError::Evaluation)
    }
}

struct BrokenStore;
impl ApprovalStore for BrokenStore {
    fn grant(&self, _: ApprovalGrant) -> Result<(), ApprovalError> {
        Err(ApprovalError::Unavailable)
    }
    fn consume(
        &self,
        _: &OperationFingerprint,
        _: OffsetDateTime,
    ) -> Result<Option<ApprovalGrant>, ApprovalError> {
        Err(ApprovalError::Unavailable)
    }
}

struct BrokenAudit;
impl AuditSink for BrokenAudit {
    fn record(&self, _: AuditEvent) -> Result<ChainedRecord, AuditError> {
        Err(AuditError::Unavailable)
    }
    fn records(&self) -> Result<Vec<ChainedRecord>, AuditError> {
        Err(AuditError::Unavailable)
    }
}

/// Fails only on decision records, after the request record succeeded.
struct FailsOnDecision(MemorySink);
impl AuditSink for FailsOnDecision {
    fn record(&self, event: AuditEvent) -> Result<ChainedRecord, AuditError> {
        if event.decision.is_some() {
            return Err(AuditError::Unavailable);
        }
        self.0.record(event)
    }
    fn records(&self) -> Result<Vec<ChainedRecord>, AuditError> {
        self.0.records()
    }
}

fn replace_parts(h: &Harness, f: impl FnOnce(&mut AuthorizerParts)) -> Authorizer {
    let mut parts = AuthorizerParts {
        invocation: TrustedInvocation {
            agent: AgentKind::ClaudeCode,
        },
        registry: Arc::new(StaticProjectRegistry::new(vec![ProjectIdentity::new(
            h.root.clone(),
            None,
        )])),
        policy: Arc::new(RuleSetPolicy::baseline().unwrap()),
        approvals: Arc::new(MemoryApprovalStore::new()),
        audit: Arc::new(MemorySink::new()),
        resolver: Arc::new(FsPathResolver),
        guard: TrustedStateGuard::default(),
        clock: h.clock.clone(),
    };
    f(&mut parts);
    Authorizer::new(parts)
}

#[test]
fn invariant_08_policy_store_and_audit_failures_deny() {
    let h = harness();
    let audit = Arc::new(MemorySink::new());
    let broken_policy = replace_parts(&h, |p| {
        p.policy = Arc::new(BrokenPolicy);
        p.audit = audit.clone();
    });
    let mut req = h.request(read_main());
    req["policy_version"] = json!(PolicyVersion::compute(b"broken").to_hex());
    let r = broken_policy.authorize_bytes(&serde_json::to_vec(&req).unwrap());
    assert_eq!(r.decision, Decision::Deny);
    assert_eq!(r.rule.as_str(), "engine.error");
    assert!(audit
        .records()
        .unwrap()
        .iter()
        .any(|r| r.event.kind == AuditEventKind::SecurityError));

    let broken_store = replace_parts(&h, |p| p.approvals = Arc::new(BrokenStore));
    let r = broken_store.authorize_bytes(&serde_json::to_vec(&h.request(write_main())).unwrap());
    assert_eq!(r.decision, Decision::Deny);

    // An action that would be allowed is denied when it cannot be audited, whether the
    // request record or the decision record fails.
    let no_audit = replace_parts(&h, |p| p.audit = Arc::new(BrokenAudit));
    let r = no_audit.authorize_bytes(&serde_json::to_vec(&h.request(read_main())).unwrap());
    assert_eq!(r.decision, Decision::Deny);
    assert_eq!(r.rule.as_str(), "audit.unavailable");
    let late_failure = replace_parts(&h, |p| {
        p.audit = Arc::new(FailsOnDecision(MemorySink::new()));
    });
    let r = late_failure.authorize_bytes(&serde_json::to_vec(&h.request(read_main())).unwrap());
    assert_eq!(r.decision, Decision::Deny);
    assert_eq!(r.rule.as_str(), "audit.unavailable");
}

// ---------------------------------------------------------------------------------------------
// Invariant 9: project identity is verified independently.
// ---------------------------------------------------------------------------------------------

#[test]
fn invariant_09_project_claims_must_match_registry() {
    let h = harness();
    let other = tempfile::tempdir().unwrap();
    let other_root = canonical(other.path());

    let mut wrong_root = h.request(read_main());
    wrong_root["project"]["root"] = json!(other_root.as_str());
    assert_eq!(
        h.send(&wrong_root).rule.as_str(),
        "identity.project-mismatch"
    );

    let mut wrong_id = h.request(read_main());
    wrong_id["project"]["id"] = json!(agentguard_core::ProjectId::derive(&other_root).to_hex());
    assert_eq!(h.send(&wrong_id).rule.as_str(), "identity.project-mismatch");

    let mut right_id = h.request(read_main());
    right_id["project"]["id"] = json!(agentguard_core::ProjectId::derive(&h.root).to_hex());
    assert_eq!(h.send(&right_id).decision, Decision::Allow);

    // Claiming the registered project while working elsewhere.
    let mut outside =
        h.request(json!({"category": "filesystem", "operation": "read", "path": "x"}));
    outside["working_directory"] = json!(other_root.as_str());
    assert_eq!(
        h.send(&outside).rule.as_str(),
        "identity.project-unregistered"
    );
}

#[test]
fn invariant_09_working_directory_symlink_cannot_fake_membership() {
    let h = harness();
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), h.root.as_path().join("portal")).unwrap();
    let mut req = h.request(json!({"category": "filesystem", "operation": "read", "path": "x"}));
    req["working_directory"] = json!(format!("{}/portal", h.root));
    assert_eq!(h.send(&req).rule.as_str(), "identity.project-unregistered");
}

// ---------------------------------------------------------------------------------------------
// Invariant 10: security decisions are auditable.
// ---------------------------------------------------------------------------------------------

#[test]
fn invariant_10_every_decision_is_recorded_correlated_and_chained() {
    let h = harness();
    let requests = [
        h.request(read_main()),
        h.request(write_main()),
        h.request(json!({"category": "git", "operation": "push", "force": true})),
        h.request(json!({"category": "terminal",
            "command": "curl -H 'Authorization: Bearer s3cr3t-value' https://x DB_PASSWORD=hunter2"})),
    ];
    let mut expected = Vec::new();
    for req in &requests {
        let r = h.send(req);
        expected.push((
            r.request_id.unwrap(),
            r.decision,
            r.rule.as_str().to_owned(),
        ));
    }
    let garbage = h.authorizer.authorize_bytes(b"{");
    assert_eq!(garbage.decision, Decision::Deny);

    let records = h.records();
    agentguard_audit::chain::verify(&records).unwrap();
    let decisions: Vec<&AuditEvent> = records
        .iter()
        .map(|r| &r.event)
        .filter(|e| e.decision.is_some())
        .collect();
    assert_eq!(
        decisions.len(),
        requests.len() + 1,
        "one decision record per request"
    );
    for (id, decision, rule_id) in expected {
        let e = decisions
            .iter()
            .find(|e| e.request_id == Some(id))
            .expect("recorded");
        assert_eq!(e.decision, Some(AuditDecision::from(decision)));
        assert_eq!(e.rule.as_ref().unwrap().as_str(), rule_id);
        assert!(e.policy_version.is_some());
        assert!(e.risk.is_some());
    }
    let requested = h.events_of(AuditEventKind::AuthorizationRequested);
    assert_eq!(requested.len(), requests.len() + 1);

    let dump = serde_json::to_string(&records).unwrap();
    assert!(
        !dump.contains("s3cr3t-value"),
        "bearer token leaked into audit"
    );
    assert!(!dump.contains("hunter2"), "password leaked into audit");
}

// ---------------------------------------------------------------------------------------------
// Risk is separate from authorization.
// ---------------------------------------------------------------------------------------------

#[test]
fn risk_and_authorization_are_independent() {
    let deny_low = rule(
        "deny-src-reads",
        Decision::Deny,
        ActionMatcher {
            category: Some(agentguard_core::ActionCategory::Filesystem),
            operation: Some("read".to_owned()),
            ..ActionMatcher::default()
        },
    );
    let approve_push = rule(
        "push-needs-approval",
        Decision::RequireApproval,
        ActionMatcher {
            category: Some(agentguard_core::ActionCategory::Git),
            operation: Some("push".to_owned()),
            ..ActionMatcher::default()
        },
    );
    let allow_destroy = rule(
        "allow-destroy",
        Decision::Allow,
        ActionMatcher {
            category: Some(agentguard_core::ActionCategory::Terraform),
            operation: Some("destroy".to_owned()),
            ..ActionMatcher::default()
        },
    );
    let h = harness_with(Arc::new(
        RuleSetPolicy::new(vec![deny_low, approve_push, allow_destroy]).unwrap(),
    ));

    let r = h.send(&h.request(read_main()));
    assert_eq!(
        (r.decision, r.risk),
        (Decision::Deny, RiskLevel::Low),
        "low risk, denied by policy"
    );

    let r = h.send(&h.request(json!({"category": "git", "operation": "push", "remote": "origin"})));
    assert_eq!(
        (r.decision, r.risk),
        (Decision::RequireApproval, RiskLevel::High)
    );

    let r = h.send(&h.request(
        json!({"category": "terraform", "operation": "destroy", "environment": "production"}),
    ));
    assert_eq!(r.risk, RiskLevel::Critical);
    assert_eq!(
        r.decision,
        Decision::RequireApproval,
        "critical floor overrides ALLOW"
    );
    assert_eq!(r.rule.as_str(), "floor.critical-requires-approval");
}

#[test]
fn unbounded_allow_rules_are_refused() {
    let r = RuleSetPolicy::new(vec![rule(
        "allow-all",
        Decision::Allow,
        ActionMatcher::default(),
    )]);
    assert_eq!(r.unwrap_err(), PolicyError::UnboundedAllow);
    let r = RuleSetPolicy::new(vec![rule(
        "allow-low",
        Decision::Allow,
        ActionMatcher {
            max_risk: Some(RiskLevel::Low),
            ..ActionMatcher::default()
        },
    )]);
    assert_eq!(
        r.unwrap_err(),
        PolicyError::UnboundedAllow,
        "risk alone does not bound a rule"
    );
}

#[test]
fn lexical_resolver_is_not_used_by_default() {
    // Guard against a regression to textual resolution: the engine must see through symlinks.
    let h = harness();
    std::os::unix::fs::symlink("/etc", h.root.as_path().join("etc-link")).unwrap();
    let r = FsPathResolver
        .resolve(Some(&h.root), "etc-link/passwd")
        .unwrap();
    assert!(!r.is_within(&h.root));
    let resp = h.send(&h.request(
        json!({"category": "filesystem", "operation": "read", "path": "etc-link/passwd"}),
    ));
    assert_ne!(
        resp.risk,
        RiskLevel::Low,
        "outside-project read is not low risk"
    );
}
