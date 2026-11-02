//! Phase 5: the approval store and lifecycle against a real trust store on disk. Each test
//! uses its own temporary trust root. See docs/SECURITY_INVARIANTS.md (Phase 5 table).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Barrier};

use agentguard_audit::{
    AuditError, AuditEvent, AuditEventKind, AuditSink, ChainedRecord, MemorySink,
};
use agentguard_core::{
    ActionCategory, AgentIdentity, AgentKind, ApprovalId, ApprovalStatus, ApprovalTiming,
    BoundedText, Name, NormalizedPath, OperationFingerprint, PolicyVersion, ProjectId, RequestId,
    RiskLevel, RuleId,
};
use agentguard_engine::approval::Approver;
use agentguard_trust::approvals::{
    Approval, ApprovalError, ApprovalStore, ClaimToken, GrantState, NewRequest, OperationSummary,
    Redemption, Withdrawer,
};
use agentguard_trust::{
    initialize, AnchorConfig, Ed25519Signer, PublicKey, Purpose, Signed, Signer, TrustStore,
};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

fn key(b: u8) -> Ed25519Signer {
    Ed25519Signer::from_seed(&Zeroizing::new([b; 32]))
}

fn t0() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

struct Env {
    _base: tempfile::TempDir,
    trust: TrustStore,
    store: ApprovalStore,
    policy_key: Ed25519Signer,
    signers: Vec<PublicKey>,
    audit: MemorySink,
    project: ProjectId,
    root: NormalizedPath,
}

fn env() -> Env {
    let base = tempfile::tempdir().unwrap();
    let trust = TrustStore::new(
        base.path().join("trust"),
        AnchorConfig {
            system_anchor: None,
            required_owner: agentguard_trust::AnchorOwner::System,
        },
    );
    let (root_key, policy_key) = (key(1), key(2));
    initialize(
        &trust,
        &root_key,
        &policy_key,
        Name::new("policy").unwrap(),
        &Approver::Human {
            name: Name::new("developer").unwrap(),
        },
        t0(),
    )
    .unwrap();
    let signers = trust.load().unwrap().signers;
    let root = NormalizedPath::new(base.path().join("project").to_str().unwrap()).unwrap();
    Env {
        store: ApprovalStore::new(&trust),
        trust,
        _base: base,
        policy_key,
        signers,
        audit: MemorySink::new(),
        project: ProjectId::derive(&root),
        root,
    }
}

fn policy() -> PolicyVersion {
    PolicyVersion::compute(b"policy-1")
}

fn digest(b: u8) -> OperationFingerprint {
    OperationFingerprint::from_bytes([b; 32])
}

fn claude() -> AgentIdentity {
    AgentIdentity::new(AgentKind::ClaudeCode)
}

impl Env {
    fn new_request(&self, op: u8) -> NewRequest {
        NewRequest {
            request_id: RequestId::generate(),
            operation_digest: digest(op),
            agent: claude(),
            project: self.project,
            project_root: self.root.clone(),
            session: None,
            summary: OperationSummary {
                category: ActionCategory::Git,
                operation: Name::new("push").unwrap(),
                label: BoundedText::lossy("Git push"),
                target: BoundedText::lossy("origin feature-a"),
                target_truncated: false,
                impact: BoundedText::lossy("Sends local commits to a remote repository."),
                reason: BoundedText::lossy("pushing sends commits to a remote"),
                tool: None,
            },
            risk: RiskLevel::High,
            rule: RuleId::builtin("baseline.git-push"),
            policy_version: policy(),
        }
    }

    fn create(&self, op: u8, now: OffsetDateTime) -> (ApprovalId, ClaimToken) {
        let created = self
            .store
            .create(
                self.new_request(op),
                ApprovalTiming::default(),
                now,
                &self.audit,
            )
            .unwrap();
        (created.record.request.approval_id, created.token)
    }

    fn approval<'a>(&'a self, id: ApprovalId, op: u8, signer: &'a dyn Signer) -> Approval<'a> {
        Approval {
            approval_id: id,
            reviewed_digest: digest(op),
            account: Name::new("developer").unwrap(),
            signer,
            trusted_signers: &self.signers,
            current_policy: policy(),
        }
    }

    fn approve(&self, id: ApprovalId, op: u8, now: OffsetDateTime) {
        self.store
            .approve(
                &self.approval(id, op, &self.policy_key),
                ApprovalTiming::default(),
                now,
                &self.audit,
            )
            .unwrap();
    }

    fn redemption<'a>(&'a self, id: ApprovalId, token: &'a ClaimToken, op: u8) -> Redemption<'a> {
        Redemption {
            approval_id: id,
            token,
            request_id: RequestId::generate(),
            operation_digest: digest(op),
            project: self.project,
            agent: claude(),
            policy_version: policy(),
            trusted_signers: &self.signers,
        }
    }

    fn approved(&self, op: u8) -> (ApprovalId, ClaimToken) {
        let (id, token) = self.create(op, t0());
        self.approve(id, op, t0());
        (id, token)
    }

    fn kinds(&self) -> Vec<AuditEventKind> {
        self.audit
            .records()
            .unwrap()
            .into_iter()
            .map(|r| r.event.kind)
            .collect()
    }

    fn record_path(&self, id: ApprovalId) -> std::path::PathBuf {
        self.store
            .root()
            .join("requests")
            .join(format!("{id}.json"))
    }
}

struct FailingSink;

impl AuditSink for FailingSink {
    fn record(&self, _: AuditEvent) -> Result<ChainedRecord, AuditError> {
        Err(AuditError::Unavailable)
    }
    fn records(&self) -> Result<Vec<ChainedRecord>, AuditError> {
        Ok(Vec::new())
    }
}

// ---------------------------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------------------------

#[test]
fn full_lifecycle_approve_then_consume_exactly_once() {
    let e = env();
    let (id, token) = e.create(1, t0());
    assert_eq!(
        e.store
            .show(&id.to_string(), t0(), &e.audit)
            .unwrap()
            .status,
        ApprovalStatus::Pending
    );
    e.approve(id, 1, t0());
    let checked = e
        .store
        .validate(&e.redemption(id, &token, 1), t0(), &e.audit);
    assert!(checked.is_ok(), "{checked:?}");
    let used = e
        .store
        .consume(&e.redemption(id, &token, 1), t0(), &e.audit)
        .unwrap();
    assert_eq!(used.record.status, ApprovalStatus::Consumed);
    assert!(matches!(
        used.record.grant_state,
        Some(GrantState::Consumed { .. })
    ));
    assert_eq!(
        e.store
            .consume(&e.redemption(id, &token, 1), t0(), &e.audit)
            .unwrap_err(),
        ApprovalError::Replay
    );
    let kinds = e.kinds();
    for k in [
        AuditEventKind::ApprovalRequestCreated,
        AuditEventKind::ApprovalRequestViewed,
        AuditEventKind::ApprovalApproved,
        AuditEventKind::AuthorizationGrantIssued,
        AuditEventKind::AuthorizationValidationSucceeded,
        AuditEventKind::AuthorizationConsumed,
        AuditEventKind::AuthorizationReplayDetected,
    ] {
        assert!(kinds.contains(&k), "{k:?} missing from {kinds:?}");
    }
}

#[test]
fn pending_rejected_and_cancelled_requests_authorize_nothing() {
    let e = env();
    let (pending, t1) = e.create(1, t0());
    assert_eq!(
        e.store
            .consume(&e.redemption(pending, &t1, 1), t0(), &e.audit)
            .unwrap_err(),
        ApprovalError::NotApproved(ApprovalStatus::Pending)
    );

    let (rejected, t2) = e.create(2, t0());
    e.store
        .reject(
            rejected,
            Name::new("dev").unwrap(),
            Some("not now"),
            t0(),
            &e.audit,
        )
        .unwrap();
    assert_eq!(
        e.store
            .consume(&e.redemption(rejected, &t2, 2), t0(), &e.audit)
            .unwrap_err(),
        ApprovalError::NotApproved(ApprovalStatus::Rejected)
    );
    let err = e
        .store
        .approve(
            &e.approval(rejected, 2, &e.policy_key),
            ApprovalTiming::default(),
            t0(),
            &e.audit,
        )
        .unwrap_err();
    assert_eq!(err, ApprovalError::NotPending(ApprovalStatus::Rejected));

    let (cancelled, t3) = e.create(3, t0());
    e.store
        .cancel(cancelled, &Withdrawer::Requester(&t3), t0(), &e.audit)
        .unwrap();
    assert_eq!(
        e.store
            .approve(
                &e.approval(cancelled, 3, &e.policy_key),
                ApprovalTiming::default(),
                t0(),
                &e.audit
            )
            .unwrap_err(),
        ApprovalError::NotPending(ApprovalStatus::Cancelled)
    );
    let kinds = e.kinds();
    assert!(kinds.contains(&AuditEventKind::ApprovalRejected));
    assert!(kinds.contains(&AuditEventKind::ApprovalCancelled));
    assert!(kinds.contains(&AuditEventKind::AuthorizationValidationFailed));
}

#[test]
fn cancelling_needs_the_requesters_token_or_a_human() {
    let e = env();
    let (id, _) = e.create(1, t0());
    let stranger = ClaimToken::generate().unwrap();
    assert_eq!(
        e.store
            .cancel(id, &Withdrawer::Requester(&stranger), t0(), &e.audit)
            .unwrap_err(),
        ApprovalError::TokenMismatch
    );
    e.store
        .cancel(
            id,
            &Withdrawer::Human(Name::new("dev").unwrap()),
            t0(),
            &e.audit,
        )
        .unwrap();
}

#[test]
fn expired_requests_cannot_be_approved_and_expired_grants_cannot_be_consumed() {
    let e = env();
    let (id, _) = e.create(1, t0());
    let later = t0() + Duration::minutes(6);
    assert_eq!(
        e.store
            .approve(
                &e.approval(id, 1, &e.policy_key),
                ApprovalTiming::default(),
                later,
                &e.audit
            )
            .unwrap_err(),
        ApprovalError::Expired
    );
    assert_eq!(
        e.store
            .show(&id.to_string(), later, &e.audit)
            .unwrap()
            .status,
        ApprovalStatus::Expired
    );

    let (granted, token) = e.approved(2);
    let late = t0() + Duration::minutes(3);
    assert_eq!(
        e.store
            .consume(&e.redemption(granted, &token, 2), late, &e.audit)
            .unwrap_err(),
        ApprovalError::Expired
    );
    // Expiry is permanent: going back in time does not revive the grant.
    assert_eq!(
        e.store
            .consume(&e.redemption(granted, &token, 2), t0(), &e.audit)
            .unwrap_err(),
        ApprovalError::NotApproved(ApprovalStatus::Expired)
    );
    assert!(e.kinds().contains(&AuditEventKind::ApprovalExpired));
}

#[test]
fn revoked_grants_cannot_be_consumed() {
    let e = env();
    let (id, token) = e.approved(1);
    e.store
        .revoke(id, &Name::new("dev").unwrap(), t0(), &e.audit)
        .unwrap();
    assert_eq!(
        e.store
            .consume(&e.redemption(id, &token, 1), t0(), &e.audit)
            .unwrap_err(),
        ApprovalError::NotApproved(ApprovalStatus::Cancelled)
    );
    assert!(e
        .kinds()
        .contains(&AuditEventKind::AuthorizationGrantRevoked));
}

// ---------------------------------------------------------------------------------------------
// Binding
// ---------------------------------------------------------------------------------------------

#[test]
fn a_grant_authorizes_only_its_exact_operation_project_and_agent() {
    let e = env();
    let (id, token) = e.approved(1);
    let mut other_op = e.redemption(id, &token, 2);
    assert_eq!(
        e.store.consume(&other_op, t0(), &e.audit).unwrap_err(),
        ApprovalError::OperationMismatch
    );
    other_op.operation_digest = digest(1);
    other_op.project = ProjectId::derive(&NormalizedPath::new("/elsewhere").unwrap());
    assert_eq!(
        e.store.consume(&other_op, t0(), &e.audit).unwrap_err(),
        ApprovalError::ProjectMismatch
    );
    let mut other_agent = e.redemption(id, &token, 1);
    other_agent.agent = AgentIdentity::new(AgentKind::Codex);
    assert_eq!(
        e.store.consume(&other_agent, t0(), &e.audit).unwrap_err(),
        ApprovalError::AgentMismatch
    );
    // Mismatched attempts do not burn the grant for the approved operation.
    assert!(e
        .store
        .consume(&e.redemption(id, &token, 1), t0(), &e.audit)
        .is_ok());
}

#[test]
fn policy_changes_invalidate_pending_requests_and_grants() {
    let e = env();
    let (pending, _) = e.create(1, t0());
    let mut approval = e.approval(pending, 1, &e.policy_key);
    approval.current_policy = PolicyVersion::compute(b"policy-2");
    assert_eq!(
        e.store
            .approve(&approval, ApprovalTiming::default(), t0(), &e.audit)
            .unwrap_err(),
        ApprovalError::PolicyChanged
    );

    let (granted, token) = e.approved(2);
    let mut later = e.redemption(granted, &token, 2);
    later.policy_version = PolicyVersion::compute(b"policy-2");
    assert_eq!(
        e.store.consume(&later, t0(), &e.audit).unwrap_err(),
        ApprovalError::PolicyChanged
    );
    // The grant is void even if the old policy comes back.
    assert_eq!(
        e.store
            .consume(&e.redemption(granted, &token, 2), t0(), &e.audit)
            .unwrap_err(),
        ApprovalError::NotApproved(ApprovalStatus::Cancelled)
    );
    let kinds = e.kinds();
    assert_eq!(
        kinds
            .iter()
            .filter(|k| **k == AuditEventKind::ApprovalInvalidatedByPolicyChange)
            .count(),
        2
    );
}

#[test]
fn the_reviewed_operation_must_be_the_stored_one() {
    let e = env();
    let (id, _) = e.create(1, t0());
    assert_eq!(
        e.store
            .approve(
                &e.approval(id, 9, &e.policy_key),
                ApprovalTiming::default(),
                t0(),
                &e.audit
            )
            .unwrap_err(),
        ApprovalError::ReviewMismatch
    );
}

// ---------------------------------------------------------------------------------------------
// Forgery
// ---------------------------------------------------------------------------------------------

#[test]
fn only_a_trusted_policy_key_can_approve() {
    let e = env();
    let (id, _) = e.create(1, t0());
    let attacker = key(66);
    assert_eq!(
        e.store
            .approve(
                &e.approval(id, 1, &attacker),
                ApprovalTiming::default(),
                t0(),
                &e.audit
            )
            .unwrap_err(),
        ApprovalError::UntrustedApprover
    );
}

#[test]
fn a_forged_approval_id_or_token_authorizes_nothing() {
    let e = env();
    let (id, token) = e.approved(1);
    let forged = ApprovalId::generate();
    assert_eq!(
        e.store
            .consume(&e.redemption(forged, &token, 1), t0(), &e.audit)
            .unwrap_err(),
        ApprovalError::NotFound
    );
    let guessed = ClaimToken::generate().unwrap();
    assert_eq!(
        e.store
            .consume(&e.redemption(id, &guessed, 1), t0(), &e.audit)
            .unwrap_err(),
        ApprovalError::TokenMismatch
    );
}

/// An agent that can write the record file still cannot manufacture a grant: it would need a
/// signature from a trusted policy key.
#[test]
fn a_manufactured_or_edited_grant_is_rejected() {
    let e = env();
    let (id, token) = e.create(1, t0());
    let path = e.record_path(id);

    // Mark the pending record approved with a grant signed by an untrusted key.
    e.approve(id, 1, t0());
    let mut record: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let body: agentguard_trust::approvals::AuthorizationGrant =
        serde_json::from_value(record["grant"]["body"].clone()).unwrap();
    let forged = Signed::sign(body.clone(), Purpose::ApprovalGrant, &key(66)).unwrap();
    record["grant"] = serde_json::to_value(&forged).unwrap();
    fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    assert_eq!(
        e.store
            .consume(&e.redemption(id, &token, 1), t0(), &e.audit)
            .unwrap_err(),
        ApprovalError::GrantInvalid
    );

    // Edit a genuinely signed grant to point at another operation.
    let mut edited = body;
    edited.operation_digest = digest(2);
    let mut signed = Signed::sign(edited, Purpose::ApprovalGrant, &e.policy_key).unwrap();
    signed.body.expires_at += Duration::hours(1);
    record["grant"] = serde_json::to_value(&signed).unwrap();
    fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    assert_eq!(
        e.store
            .consume(&e.redemption(id, &token, 2), t0(), &e.audit)
            .unwrap_err(),
        ApprovalError::GrantInvalid
    );

    // A grant signed with a key for another purpose is rejected too.
    let mut record2 = record.clone();
    let body2: agentguard_trust::approvals::AuthorizationGrant =
        serde_json::from_value(record["grant"]["body"].clone()).unwrap();
    record2["grant"] =
        serde_json::to_value(Signed::sign(body2, Purpose::Registry, &e.policy_key).unwrap())
            .unwrap();
    fs::write(&path, serde_json::to_vec(&record2).unwrap()).unwrap();
    assert_eq!(
        e.store
            .consume(&e.redemption(id, &token, 1), t0(), &e.audit)
            .unwrap_err(),
        ApprovalError::GrantInvalid
    );
}

// ---------------------------------------------------------------------------------------------
// Concurrency, replay and restart
// ---------------------------------------------------------------------------------------------

#[test]
fn concurrent_consumers_cannot_both_succeed() {
    for round in 0..5u8 {
        let e = Arc::new(env());
        let (id, token) = e.approved(round);
        let token = Arc::new(token.reveal().to_string());
        let barrier = Arc::new(Barrier::new(16));
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let (e, token, barrier) =
                    (Arc::clone(&e), Arc::clone(&token), Arc::clone(&barrier));
                std::thread::spawn(move || {
                    // A separate store handle per thread: nothing shared but the files.
                    let store = ApprovalStore::new(&e.trust);
                    let token = ClaimToken::parse(&token).unwrap();
                    barrier.wait();
                    store.consume(&e.redemption(id, &token, round), t0(), &e.audit)
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let wins = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(wins, 1, "round {round}: {wins} of 16 consumers succeeded");
        assert!(results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .all(|err| *err == ApprovalError::Replay));
    }
}

#[test]
fn state_survives_restart_and_replay_is_still_refused() {
    let e = env();
    let (id, token) = e.create(1, t0());
    let token_text = token.reveal().to_string();
    drop(token);
    // "Restart": fresh handles over the same directory.
    let reopened = ApprovalStore::new(&TrustStore::new(
        e.trust.root().to_path_buf(),
        AnchorConfig {
            system_anchor: None,
            required_owner: agentguard_trust::AnchorOwner::System,
        },
    ));
    reopened
        .approve(
            &e.approval(id, 1, &e.policy_key),
            ApprovalTiming::default(),
            t0(),
            &e.audit,
        )
        .unwrap();
    let token = ClaimToken::parse(&token_text).unwrap();
    reopened
        .consume(&e.redemption(id, &token, 1), t0(), &e.audit)
        .unwrap();
    let again = ApprovalStore::new(&e.trust);
    assert_eq!(
        again
            .consume(&e.redemption(id, &token, 1), t0(), &e.audit)
            .unwrap_err(),
        ApprovalError::Replay
    );
}

#[test]
fn duplicate_requests_join_one_approval_that_still_authorizes_once() {
    let e = env();
    let (id, t1) = e.create(1, t0());
    let joined = e
        .store
        .create(e.new_request(1), ApprovalTiming::default(), t0(), &e.audit)
        .unwrap();
    assert!(joined.duplicate);
    assert_eq!(joined.record.request.approval_id, id);
    e.approve(id, 1, t0());
    assert!(e
        .store
        .consume(&e.redemption(id, &joined.token, 1), t0(), &e.audit)
        .is_ok());
    assert_eq!(
        e.store
            .consume(&e.redemption(id, &t1, 1), t0(), &e.audit)
            .unwrap_err(),
        ApprovalError::Replay
    );
    // After a decision, the same operation needs a new request.
    let fresh = e
        .store
        .create(e.new_request(1), ApprovalTiming::default(), t0(), &e.audit)
        .unwrap();
    assert!(!fresh.duplicate);
    assert_ne!(fresh.record.request.approval_id, id);
}

// ---------------------------------------------------------------------------------------------
// Persistence failures and secrets
// ---------------------------------------------------------------------------------------------

#[test]
fn audit_failure_never_yields_a_usable_grant_or_a_reported_success() {
    let e = env();
    let (id, token) = e.create(1, t0());
    assert_eq!(
        e.store
            .approve(
                &e.approval(id, 1, &e.policy_key),
                ApprovalTiming::default(),
                t0(),
                &FailingSink
            )
            .unwrap_err(),
        ApprovalError::AuditFailed
    );
    assert_eq!(
        e.store
            .consume(&e.redemption(id, &token, 1), t0(), &e.audit)
            .unwrap_err(),
        ApprovalError::NotApproved(ApprovalStatus::Cancelled),
        "the grant issued before the audit failure is revoked"
    );

    let (id, token) = e.approved(2);
    assert_eq!(
        e.store
            .consume(&e.redemption(id, &token, 2), t0(), &FailingSink)
            .unwrap_err(),
        ApprovalError::AuditFailed
    );
    assert_eq!(
        e.store
            .consume(&e.redemption(id, &token, 2), t0(), &e.audit)
            .unwrap_err(),
        ApprovalError::Replay,
        "a consumed grant is never restored after a failure"
    );

    assert_eq!(
        e.store
            .create(
                e.new_request(3),
                ApprovalTiming::default(),
                t0(),
                &FailingSink
            )
            .unwrap_err(),
        ApprovalError::AuditFailed
    );
}

#[test]
fn storage_failures_fail_closed() {
    let e = env();
    let (id, token) = e.approved(1);
    let dir = e.store.root().join("requests");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        e.store
            .consume(&e.redemption(id, &token, 1), t0(), &e.audit),
        Err(ApprovalError::Unavailable(_))
    ));
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();

    fs::write(e.record_path(id), b"{ not json").unwrap();
    assert_eq!(
        e.store
            .consume(&e.redemption(id, &token, 1), t0(), &e.audit)
            .unwrap_err(),
        ApprovalError::Corrupt
    );

    fs::write(e.store.root().join("schema.json"), br#"{"schema": 2}"#).unwrap();
    assert_eq!(
        e.store.list(t0(), &e.audit).unwrap_err(),
        ApprovalError::SchemaUnsupported
    );
}

#[test]
fn no_token_or_verifier_reaches_audit_records_or_views() {
    let e = env();
    let (id, token) = e.approved(1);
    e.store
        .consume(&e.redemption(id, &token, 1), t0(), &e.audit)
        .unwrap();
    let secret = token.reveal().to_string();
    let hex = &secret[5..];
    let verifier = serde_json::to_string(&token.verifier()).unwrap();
    let verifier = verifier.trim_matches('"');
    let audit = serde_json::to_string(&e.audit.records().unwrap()).unwrap();
    assert!(!audit.contains(hex) && !audit.contains(verifier));
    let listing = e.store.list(t0(), &e.audit).unwrap();
    for record in &listing.records {
        let view = record.view(true).to_string();
        assert!(!view.contains(hex) && !view.contains(verifier) && !view.contains("signature"));
    }
    let stored = fs::read_to_string(e.record_path(id)).unwrap();
    assert!(!stored.contains(hex), "the raw token is never stored");
    let mode = fs::metadata(e.record_path(id))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn ids_resolve_by_unique_prefix_only() {
    let e = env();
    let (id, _) = e.create(1, t0());
    let full = id.to_string();
    assert_eq!(
        e.store
            .show(&full[..8], t0(), &e.audit)
            .unwrap()
            .request
            .approval_id,
        id
    );
    assert_eq!(
        e.store.show("1234", t0(), &e.audit).unwrap_err(),
        ApprovalError::NotFound,
        "short prefixes are refused"
    );
    assert_eq!(
        e.store
            .show("../../etc/passwd", t0(), &e.audit)
            .unwrap_err(),
        ApprovalError::NotFound
    );
}

#[test]
fn listing_prunes_old_closed_records() {
    let e = env();
    let (id, _) = e.create(1, t0());
    e.store
        .reject(id, Name::new("dev").unwrap(), None, t0(), &e.audit)
        .unwrap();
    assert_eq!(e.store.list(t0(), &e.audit).unwrap().records.len(), 1);
    let much_later = t0() + Duration::days(8);
    assert_eq!(e.store.list(much_later, &e.audit).unwrap().records.len(), 0);
    assert!(!e.record_path(id).exists());
}
