//! Approval lifecycle transitions.
//!
//! Each public operation is one [`Transaction`]: load, check, transition, save, audit, release.
//! Transitions only move forward (see [`ApprovalStatus`]); nothing returns a request to
//! `pending` or a grant to `active`.
//!
//! Audit policy:
//! - An event that grants authority (approval and grant issue, successful validation,
//!   consumption, request creation) is required. If it cannot be written the operation
//!   reports failure and authority is withdrawn: an issued grant is revoked, a consumed grant
//!   stays consumed, a created request is cancelled.
//! - An event that records a refusal or a withdrawal of authority (validation failure, expiry,
//!   rejection, cancellation) is best effort: the outcome is already the safe one.

use agentguard_audit::{
    ApprovalEventKind, ApprovalRecord as AuditRecord, AuditSink, SecurityEvent,
};
use agentguard_core::{
    AgentIdentity, ApprovalId, ApprovalStatus, ApprovalTiming, BoundedText, Decision, GrantId,
    Name, NormalizedPath, OperationFingerprint, PolicyVersion, ProjectId, RequestId, RiskLevel,
    RuleId, SessionId,
};
use time::OffsetDateTime;

use crate::canonical::Signed;
use crate::crypto::{PublicKey, Purpose, Signer};

use super::error::ApprovalError;
use super::model::{
    ApprovalDecision, ApprovalRecord, ApprovalRequest, ApproverAuthentication, ApproverIdentity,
    AuthorizationGrant, Closure, GrantState, HumanDecision, OperationSummary, RECORD_SCHEMA,
};
use super::store::{ApprovalStore, Transaction};
use super::token::{ClaimToken, TokenVerifier};

/// Most open (pending or approved) requests at once.
pub const MAX_OPEN_REQUESTS: usize = 256;
/// Most claim tokens issued for one pending request (duplicate requests while it waits).
pub const MAX_CLAIMS: usize = 8;
/// How long closed records are kept before pruning. The audit log keeps the history.
pub const RETENTION: time::Duration = time::Duration::days(7);

/// A new request, built by the engine from a verified evaluation.
#[derive(Debug, Clone)]
pub struct NewRequest {
    /// The authorization request that required approval.
    pub request_id: RequestId,
    /// The engine-computed digest.
    pub operation_digest: OperationFingerprint,
    /// Verified agent.
    pub agent: AgentIdentity,
    /// Verified project.
    pub project: ProjectId,
    /// Its registered root.
    pub project_root: NormalizedPath,
    /// Session.
    pub session: Option<SessionId>,
    /// What a human reviews.
    pub summary: OperationSummary,
    /// Risk.
    pub risk: RiskLevel,
    /// The rule that required approval.
    pub rule: RuleId,
    /// Policy version evaluated under.
    pub policy_version: PolicyVersion,
}

/// A created (or joined) request and the claim token for its requester.
#[derive(Debug)]
pub struct Created {
    /// The record after the transition.
    pub record: ApprovalRecord,
    /// The requester's claim token. Returned once; never stored.
    pub token: ClaimToken,
    /// Whether an identical pending request already existed and was joined.
    pub duplicate: bool,
}

/// A human approval.
pub struct Approval<'a> {
    /// The request, by full ID.
    pub approval_id: ApprovalId,
    /// The digest the human was shown; must equal the stored one.
    pub reviewed_digest: OperationFingerprint,
    /// Account name from the trusted channel.
    pub account: Name,
    /// The unlocked policy-signing key that authenticates the approver.
    pub signer: &'a dyn Signer,
    /// Keys currently trusted to sign for this trust store.
    pub trusted_signers: &'a [PublicKey],
    /// Policy version currently in force for the request's project.
    pub current_policy: PolicyVersion,
}

/// Who withdraws a request.
pub enum Withdrawer<'a> {
    /// A human at the CLI.
    Human(Name),
    /// The requester, proving itself with its claim token.
    Requester(&'a ClaimToken),
}

/// A redemption attempt: the operation as presented now, in its freshly verified context.
pub struct Redemption<'a> {
    /// The request, by full ID.
    pub approval_id: ApprovalId,
    /// The requester's claim token.
    pub token: &'a ClaimToken,
    /// The authorization request presenting the operation now.
    pub request_id: RequestId,
    /// Digest recomputed by the engine from the presented operation.
    pub operation_digest: OperationFingerprint,
    /// Verified project now.
    pub project: ProjectId,
    /// Verified agent now.
    pub agent: AgentIdentity,
    /// Policy version in force now.
    pub policy_version: PolicyVersion,
    /// Keys currently trusted to sign for this trust store.
    pub trusted_signers: &'a [PublicKey],
}

/// The result of a successful redemption.
#[derive(Debug)]
pub struct Redeemed {
    /// The record after the transition.
    pub record: ApprovalRecord,
    /// The grant that authorized the operation.
    pub grant_id: GrantId,
}

/// A listing.
#[derive(Debug)]
pub struct Listing {
    /// Records, newest first.
    pub records: Vec<ApprovalRecord>,
    /// Records that failed to load (never shown, never usable).
    pub unreadable: usize,
}

fn rule(code: &'static str) -> RuleId {
    RuleId::builtin(code)
}

fn event(
    kind: ApprovalEventKind,
    record: &ApprovalRecord,
    reason_code: RuleId,
    detail: impl Into<String>,
) -> AuditRecord {
    let r = &record.request;
    AuditRecord {
        kind,
        request_id: Some(r.request_id),
        approval_id: Some(r.approval_id),
        grant_id: record.grant.as_ref().map(|g| g.body.grant_id),
        agent: Some(r.agent.clone()),
        project: Some(r.project),
        approver: record.human_decision().map(|d| d.approver.account.clone()),
        digest: Some(r.operation_digest),
        policy_version: Some(r.policy_version),
        category: Some(r.summary.category),
        operation: Some(r.summary.operation.clone()),
        decision: None,
        reason_code,
        detail: detail.into(),
    }
}

fn record_required(audit: &dyn AuditSink, record: AuditRecord) -> Result<(), ApprovalError> {
    audit
        .record(SecurityEvent::Approval(Box::new(record)).into_audit_event())
        .map(|_| ())
        .map_err(|_| ApprovalError::AuditFailed)
}

fn record_best_effort(audit: &dyn AuditSink, record: AuditRecord) {
    let _ = audit.record(SecurityEvent::Approval(Box::new(record)).into_audit_event());
}

fn close(
    record: &mut ApprovalRecord,
    status: ApprovalStatus,
    now: OffsetDateTime,
    code: &'static str,
) {
    record.status = status;
    record.closure = Some(Closure {
        at: now,
        reason_code: rule(code),
    });
    record.updated_at = now;
}

/// Apply time-based expiry. Returns whether the record changed.
fn expire_if_due(record: &mut ApprovalRecord, now: OffsetDateTime) -> bool {
    match record.status {
        ApprovalStatus::Pending if now >= record.request.expires_at => {
            close(
                record,
                ApprovalStatus::Expired,
                now,
                "approval.pending-expired",
            );
            true
        }
        ApprovalStatus::Approved => {
            let due = record
                .grant
                .as_ref()
                .is_some_and(|g| now >= g.body.expires_at);
            if due && record.grant_state == Some(GrantState::Active) {
                record.grant_state = Some(GrantState::Expired { at: now });
                close(
                    record,
                    ApprovalStatus::Expired,
                    now,
                    "approval.grant-expired",
                );
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Expire `record` if due, persist and audit the expiry. Returns whether it expired.
fn sweep(
    tx: &Transaction<'_>,
    record: &mut ApprovalRecord,
    now: OffsetDateTime,
    audit: &dyn AuditSink,
) -> Result<bool, ApprovalError> {
    if !expire_if_due(record, now) {
        return Ok(false);
    }
    tx.save(record)?;
    let code = record
        .closure
        .as_ref()
        .map_or_else(|| rule("approval.expired"), |c| c.reason_code.clone());
    record_best_effort(
        audit,
        event(
            ApprovalEventKind::Expired,
            record,
            code,
            "expired without being used",
        ),
    );
    Ok(true)
}

fn is_open(record: &ApprovalRecord) -> bool {
    matches!(
        record.status,
        ApprovalStatus::Pending | ApprovalStatus::Approved
    )
}

fn timestamp_after(
    now: OffsetDateTime,
    by: std::time::Duration,
) -> Result<OffsetDateTime, ApprovalError> {
    time::Duration::try_from(by)
        .ok()
        .and_then(|d| now.checked_add(d))
        .ok_or(ApprovalError::Unavailable("timed"))
}

impl ApprovalStore {
    /// Create a pending request for `new`, or join an identical pending one (same digest,
    /// so same operation, project, agent, session and policy). Either way the requester gets
    /// a fresh claim token.
    pub fn create(
        &self,
        new: NewRequest,
        timing: ApprovalTiming,
        now: OffsetDateTime,
        audit: &dyn AuditSink,
    ) -> Result<Created, ApprovalError> {
        let token = ClaimToken::generate().map_err(|_| ApprovalError::Unavailable("created"))?;
        let tx = self.transaction()?;
        let (mut records, _) = tx.all()?;
        for record in &mut records {
            sweep(&tx, record, now, audit)?;
        }
        if let Some(existing) = records.iter_mut().find(|r| {
            r.status == ApprovalStatus::Pending
                && r.request.operation_digest == new.operation_digest
        }) {
            if existing.claims.len() >= MAX_CLAIMS {
                return Err(ApprovalError::TooManyClaims);
            }
            existing.claims.push(token.verifier());
            existing.updated_at = now;
            tx.save(existing)?;
            record_required(
                audit,
                event(
                    ApprovalEventKind::RequestCreated,
                    existing,
                    rule("approval.duplicate-joined"),
                    "an identical pending request was joined",
                ),
            )?;
            return Ok(Created {
                record: existing.clone(),
                token,
                duplicate: true,
            });
        }
        if records.iter().filter(|r| is_open(r)).count() >= MAX_OPEN_REQUESTS {
            return Err(ApprovalError::TooManyOpen);
        }
        let mut record = ApprovalRecord {
            schema: RECORD_SCHEMA,
            request: ApprovalRequest {
                approval_id: ApprovalId::generate(),
                request_id: new.request_id,
                operation_digest: new.operation_digest,
                agent: new.agent,
                project: new.project,
                project_root: new.project_root,
                session: new.session,
                summary: new.summary,
                risk: new.risk,
                rule: new.rule,
                policy_version: new.policy_version,
                created_at: now,
                expires_at: timestamp_after(now, timing.pending_timeout)?,
            },
            claims: vec![token.verifier()],
            status: ApprovalStatus::Pending,
            decision: None,
            grant: None,
            grant_state: None,
            closure: None,
            updated_at: now,
        };
        tx.save(&record)?;
        let created = event(
            ApprovalEventKind::RequestCreated,
            &record,
            rule("approval.request-created"),
            "approval requested for one exact operation",
        );
        if let Err(e) = record_required(audit, created) {
            close(
                &mut record,
                ApprovalStatus::Cancelled,
                now,
                "approval.audit-failed",
            );
            let _ = tx.save(&record);
            return Err(e);
        }
        Ok(Created {
            record,
            token,
            duplicate: false,
        })
    }

    /// Pending and recent requests, newest first. Expires what is due and prunes closed
    /// records past [`RETENTION`].
    pub fn list(
        &self,
        now: OffsetDateTime,
        audit: &dyn AuditSink,
    ) -> Result<Listing, ApprovalError> {
        let tx = self.transaction()?;
        let (records, unreadable) = tx.all()?;
        let mut kept = Vec::with_capacity(records.len());
        for mut record in records {
            sweep(&tx, &mut record, now, audit)?;
            if record.status.is_terminal() && now - record.updated_at > RETENTION {
                tx.remove(record.request.approval_id)?;
            } else {
                kept.push(record);
            }
        }
        kept.sort_by_key(|r| std::cmp::Reverse(r.request.created_at));
        Ok(Listing {
            records: kept,
            unreadable,
        })
    }

    /// One request by full ID, without recording a view (internal lookups).
    pub fn peek(&self, approval_id: ApprovalId) -> Result<ApprovalRecord, ApprovalError> {
        self.transaction()?.load(approval_id)
    }

    /// One request by full ID or unique prefix; records that it was viewed.
    pub fn show(
        &self,
        reference: &str,
        now: OffsetDateTime,
        audit: &dyn AuditSink,
    ) -> Result<ApprovalRecord, ApprovalError> {
        let tx = self.transaction()?;
        let id = tx.resolve(reference)?;
        let mut record = tx.load(id)?;
        sweep(&tx, &mut record, now, audit)?;
        record_best_effort(
            audit,
            event(
                ApprovalEventKind::RequestViewed,
                &record,
                rule("approval.viewed"),
                "displayed for review",
            ),
        );
        Ok(record)
    }

    /// Approve a pending request and issue its signed, one-time grant.
    pub fn approve(
        &self,
        approval: &Approval<'_>,
        timing: ApprovalTiming,
        now: OffsetDateTime,
        audit: &dyn AuditSink,
    ) -> Result<ApprovalRecord, ApprovalError> {
        let key = approval.signer.public_key();
        if !approval.trusted_signers.contains(&key) {
            return Err(ApprovalError::UntrustedApprover);
        }
        let tx = self.transaction()?;
        let mut record = tx.load(approval.approval_id)?;
        if sweep(&tx, &mut record, now, audit)? {
            return Err(ApprovalError::Expired);
        }
        if record.status != ApprovalStatus::Pending {
            return Err(ApprovalError::NotPending(record.status));
        }
        if record.request.operation_digest != approval.reviewed_digest {
            return Err(ApprovalError::ReviewMismatch);
        }
        if record.request.policy_version != approval.current_policy {
            close(
                &mut record,
                ApprovalStatus::Cancelled,
                now,
                "approval.policy-changed",
            );
            tx.save(&record)?;
            record_best_effort(
                audit,
                event(
                    ApprovalEventKind::InvalidatedByPolicyChange,
                    &record,
                    rule("approval.policy-changed"),
                    "the policy changed while the request was pending",
                ),
            );
            return Err(ApprovalError::PolicyChanged);
        }
        let grant_id = GrantId::generate();
        let r = &record.request;
        let grant = AuthorizationGrant {
            grant_id,
            approval_id: r.approval_id,
            request_id: r.request_id,
            operation_digest: r.operation_digest,
            project: r.project,
            agent: r.agent.clone(),
            session: r.session,
            policy_version: r.policy_version,
            claims: record.claims.clone(),
            decision: ApprovalDecision {
                approval_id: r.approval_id,
                decision: HumanDecision::Approve,
                approver: ApproverIdentity {
                    account: approval.account.clone(),
                    authentication: ApproverAuthentication::SigningKeyPassphrase {
                        key_id: key.key_id(),
                    },
                },
                decided_at: now,
                reason: None,
                grant_id: Some(grant_id),
            },
            issued_at: now,
            expires_at: timestamp_after(now, timing.token_validity)?,
        };
        let signed = Signed::sign(grant, Purpose::ApprovalGrant, approval.signer)
            .map_err(|_| ApprovalError::Unavailable("signed"))?;
        record.grant = Some(signed);
        record.grant_state = Some(GrantState::Active);
        record.status = ApprovalStatus::Approved;
        record.updated_at = now;
        tx.save(&record)?;
        let audited = record_required(
            audit,
            event(
                ApprovalEventKind::Approved,
                &record,
                rule("approval.approved"),
                "approved by an authenticated human",
            ),
        )
        .and_then(|()| {
            record_required(
                audit,
                event(
                    ApprovalEventKind::GrantIssued,
                    &record,
                    rule("approval.grant-issued"),
                    "one-time grant issued for the exact operation",
                ),
            )
        });
        if let Err(e) = audited {
            record.grant_state = Some(GrantState::Revoked {
                at: now,
                reason_code: rule("approval.audit-failed"),
            });
            close(
                &mut record,
                ApprovalStatus::Cancelled,
                now,
                "approval.audit-failed",
            );
            let _ = tx.save(&record);
            return Err(e);
        }
        Ok(record)
    }

    /// Reject a pending request.
    pub fn reject(
        &self,
        approval_id: ApprovalId,
        account: Name,
        reason: Option<&str>,
        now: OffsetDateTime,
        audit: &dyn AuditSink,
    ) -> Result<ApprovalRecord, ApprovalError> {
        let tx = self.transaction()?;
        let mut record = tx.load(approval_id)?;
        if sweep(&tx, &mut record, now, audit)? {
            return Err(ApprovalError::Expired);
        }
        if record.status != ApprovalStatus::Pending {
            return Err(ApprovalError::NotPending(record.status));
        }
        record.decision = Some(ApprovalDecision {
            approval_id,
            decision: HumanDecision::Reject,
            approver: ApproverIdentity {
                account,
                authentication: ApproverAuthentication::InteractiveConfirmation,
            },
            decided_at: now,
            reason: reason.map(|r| BoundedText::lossy(&agentguard_core::redact::redact_text(r))),
            grant_id: None,
        });
        close(
            &mut record,
            ApprovalStatus::Rejected,
            now,
            "approval.rejected",
        );
        tx.save(&record)?;
        record_best_effort(
            audit,
            event(
                ApprovalEventKind::Rejected,
                &record,
                rule("approval.rejected"),
                "rejected by a human",
            ),
        );
        Ok(record)
    }

    /// Cancel a pending request: by a human, or by its requester with its claim token.
    pub fn cancel(
        &self,
        approval_id: ApprovalId,
        by: &Withdrawer<'_>,
        now: OffsetDateTime,
        audit: &dyn AuditSink,
    ) -> Result<ApprovalRecord, ApprovalError> {
        let tx = self.transaction()?;
        let mut record = tx.load(approval_id)?;
        let (account, authentication) = match by {
            Withdrawer::Human(account) => (
                account.clone(),
                ApproverAuthentication::InteractiveConfirmation,
            ),
            Withdrawer::Requester(token) => {
                if !TokenVerifier::any_matches(&record.claims, token) {
                    return Err(ApprovalError::TokenMismatch);
                }
                (
                    Name::new("requester").map_err(|_| ApprovalError::Corrupt)?,
                    ApproverAuthentication::RequesterClaim,
                )
            }
        };
        if sweep(&tx, &mut record, now, audit)? {
            return Err(ApprovalError::Expired);
        }
        if record.status != ApprovalStatus::Pending {
            return Err(ApprovalError::NotPending(record.status));
        }
        record.decision = Some(ApprovalDecision {
            approval_id,
            decision: HumanDecision::Cancel,
            approver: ApproverIdentity {
                account,
                authentication,
            },
            decided_at: now,
            reason: None,
            grant_id: None,
        });
        close(
            &mut record,
            ApprovalStatus::Cancelled,
            now,
            "approval.cancelled",
        );
        tx.save(&record)?;
        record_best_effort(
            audit,
            event(
                ApprovalEventKind::Cancelled,
                &record,
                rule("approval.cancelled"),
                "cancelled before a decision",
            ),
        );
        Ok(record)
    }

    /// Revoke an approved request's unused grant.
    pub fn revoke(
        &self,
        approval_id: ApprovalId,
        account: &Name,
        now: OffsetDateTime,
        audit: &dyn AuditSink,
    ) -> Result<ApprovalRecord, ApprovalError> {
        let tx = self.transaction()?;
        let mut record = tx.load(approval_id)?;
        if sweep(&tx, &mut record, now, audit)? {
            return Err(ApprovalError::Expired);
        }
        if record.status != ApprovalStatus::Approved
            || record.grant_state != Some(GrantState::Active)
        {
            return Err(ApprovalError::NotApproved(record.status));
        }
        record.grant_state = Some(GrantState::Revoked {
            at: now,
            reason_code: rule("approval.revoked"),
        });
        close(
            &mut record,
            ApprovalStatus::Cancelled,
            now,
            "approval.revoked",
        );
        tx.save(&record)?;
        record_best_effort(
            audit,
            event(
                ApprovalEventKind::GrantRevoked,
                &record,
                rule("approval.revoked"),
                format!("grant revoked by {account} before use"),
            ),
        );
        Ok(record)
    }

    /// Withdraw an open request because the operation is now denied by policy. Needs the
    /// requester's claim token, so nobody else can void a request.
    pub fn void_denied(
        &self,
        approval_id: ApprovalId,
        token: &ClaimToken,
        now: OffsetDateTime,
        audit: &dyn AuditSink,
    ) -> Result<(), ApprovalError> {
        let tx = self.transaction()?;
        let mut record = tx.load(approval_id)?;
        if !TokenVerifier::any_matches(&record.claims, token) || !is_open(&record) {
            return Ok(());
        }
        if record.grant_state == Some(GrantState::Active) {
            record.grant_state = Some(GrantState::Revoked {
                at: now,
                reason_code: rule("approval.now-denied"),
            });
        }
        close(
            &mut record,
            ApprovalStatus::Cancelled,
            now,
            "approval.now-denied",
        );
        tx.save(&record)?;
        record_best_effort(
            audit,
            event(
                ApprovalEventKind::InvalidatedByPolicyChange,
                &record,
                rule("approval.now-denied"),
                "the current policy denies the operation; the approval no longer applies",
            ),
        );
        Ok(())
    }

    /// Check a redemption without consuming the grant.
    pub fn validate(
        &self,
        redemption: &Redemption<'_>,
        now: OffsetDateTime,
        audit: &dyn AuditSink,
    ) -> Result<Redeemed, ApprovalError> {
        self.redeem(redemption, false, now, audit)
    }

    /// Check a redemption and, in the same transaction, consume the grant. At most one
    /// consumption of a grant ever succeeds.
    pub fn consume(
        &self,
        redemption: &Redemption<'_>,
        now: OffsetDateTime,
        audit: &dyn AuditSink,
    ) -> Result<Redeemed, ApprovalError> {
        self.redeem(redemption, true, now, audit)
    }

    fn redeem(
        &self,
        redemption: &Redemption<'_>,
        consume: bool,
        now: OffsetDateTime,
        audit: &dyn AuditSink,
    ) -> Result<Redeemed, ApprovalError> {
        let tx = self.transaction()?;
        let mut record = tx.load(redemption.approval_id)?;
        let fail = |record: &ApprovalRecord, error: ApprovalError| {
            let kind = if error == ApprovalError::Replay {
                ApprovalEventKind::ReplayDetected
            } else {
                ApprovalEventKind::ValidationFailed
            };
            let mut e = event(kind, record, rule(error.reason_code()), error.to_string());
            e.request_id = Some(redemption.request_id);
            e.decision = Some(Decision::Deny);
            record_best_effort(audit, e);
            error
        };
        if !TokenVerifier::any_matches(&record.claims, redemption.token) {
            return Err(fail(&record, ApprovalError::TokenMismatch));
        }
        if sweep(&tx, &mut record, now, audit)? {
            return Err(fail(&record, ApprovalError::Expired));
        }
        match record.status {
            ApprovalStatus::Approved => {}
            ApprovalStatus::Consumed => return Err(fail(&record, ApprovalError::Replay)),
            status => return Err(fail(&record, ApprovalError::NotApproved(status))),
        }
        let Some(signed) = record.grant.clone() else {
            return Err(fail(&record, ApprovalError::GrantInvalid));
        };
        let grant = match signed.verify(
            Purpose::ApprovalGrant,
            redemption.trusted_signers,
            "authorization grant",
        ) {
            Ok(g) => g.clone(),
            Err(_) => return Err(fail(&record, ApprovalError::GrantInvalid)),
        };
        let r = &record.request;
        let consistent = grant.approval_id == r.approval_id
            && grant.operation_digest == r.operation_digest
            && grant.project == r.project
            && grant.agent == r.agent
            && grant.policy_version == r.policy_version
            && grant.decision.decision == HumanDecision::Approve
            && matches!(
                grant.decision.approver.authentication,
                ApproverAuthentication::SigningKeyPassphrase { key_id } if key_id == signed.signer
            )
            && TokenVerifier::any_matches(&grant.claims, redemption.token)
            && grant.issued_at <= now;
        if !consistent {
            return Err(fail(&record, ApprovalError::GrantInvalid));
        }
        match record.grant_state {
            Some(GrantState::Active) => {}
            Some(GrantState::Consumed { .. }) => return Err(fail(&record, ApprovalError::Replay)),
            _ => return Err(fail(&record, ApprovalError::NotApproved(record.status))),
        }
        if redemption.project != grant.project {
            return Err(fail(&record, ApprovalError::ProjectMismatch));
        }
        if redemption.agent != grant.agent {
            return Err(fail(&record, ApprovalError::AgentMismatch));
        }
        if redemption.policy_version != grant.policy_version {
            record.grant_state = Some(GrantState::Revoked {
                at: now,
                reason_code: rule("approval.policy-changed"),
            });
            close(
                &mut record,
                ApprovalStatus::Cancelled,
                now,
                "approval.policy-changed",
            );
            tx.save(&record)?;
            record_best_effort(
                audit,
                event(
                    ApprovalEventKind::InvalidatedByPolicyChange,
                    &record,
                    rule("approval.policy-changed"),
                    "the policy changed after approval; the grant is void",
                ),
            );
            return Err(ApprovalError::PolicyChanged);
        }
        if redemption.operation_digest != grant.operation_digest {
            return Err(fail(&record, ApprovalError::OperationMismatch));
        }
        if consume {
            record.grant_state = Some(GrantState::Consumed {
                at: now,
                request_id: redemption.request_id,
            });
            close(
                &mut record,
                ApprovalStatus::Consumed,
                now,
                "approval.consumed",
            );
            tx.save(&record)?;
        }
        let (kind, code, detail) = if consume {
            (
                ApprovalEventKind::Consumed,
                "approval.consumed",
                "grant consumed by the exact approved operation",
            )
        } else {
            (
                ApprovalEventKind::ValidationSucceeded,
                "approval.validated",
                "grant valid for the presented operation (not consumed)",
            )
        };
        let mut success = event(kind, &record, rule(code), detail);
        success.request_id = Some(redemption.request_id);
        success.decision = Some(Decision::Allow);
        // A consumed grant stays consumed if this fails: authority is never restored.
        record_required(audit, success)?;
        Ok(Redeemed {
            record,
            grant_id: grant.grant_id,
        })
    }
}
