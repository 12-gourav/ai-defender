//! The audit event model.

use agentguard_core::redact::redact_text;
use agentguard_core::{
    ActionCategory, AgentIdentity, ApprovalId, BoundedText, Decision, GrantId, Name,
    OperationFingerprint, OperationType, PolicyVersion, ProjectId, RequestId, RiskLevel, RuleId,
    SessionId, TaskId,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Families of audited facts, matching the specification's tracking list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum AuditEventKind {
    /// A session began.
    SessionStarted,
    /// A session ended.
    SessionEnded,
    /// A task context was created.
    TaskCreated,
    /// A policy was loaded and pinned.
    PolicyLoaded,
    /// A permission decision was made.
    PolicyDecision,
    /// A permission was requested.
    PermissionRequested,
    /// An approval reached a terminal state.
    ApprovalDecision,
    /// A file operation crossed the boundary.
    FileOperation,
    /// A command was executed through the gateway.
    CommandExecution,
    /// A Git operation.
    GitOperation,
    /// A network access.
    NetworkAccess,
    /// A database operation.
    DatabaseOperation,
    /// A deployment operation.
    DeploymentOperation,
    /// A security violation was detected.
    SecurityViolation,
    /// The sandbox failed an integrity check or crashed.
    SandboxFailure,
    /// A configuration or environment check (for example `doctor`) ran.
    HostCheck,
    /// An authorization request arrived (recorded before evaluation).
    AuthorizationRequested,
    /// An authorization request was allowed.
    AuthorizationAllowed,
    /// An authorization request was denied.
    AuthorizationDenied,
    /// An authorization request was deferred to a human approval.
    ApprovalRequested,
    /// The result of executing an authorized action.
    ExecutionResult,
    /// An attempt to modify trusted state, or an integrity check failure, was detected.
    TamperDetected,
    /// The engine failed internally and denied as a result.
    SecurityError,
    /// A trust store was initialised with a root key.
    TrustInitialized,
    /// Trusted state was loaded and every signature, reference and version verified.
    PolicyIntegrityVerified,
    /// Trusted state failed verification (modified, replaced, inconsistent or insecure).
    PolicyIntegrityFailed,
    /// A signature did not verify or was made by a key that is not trusted for the purpose.
    SignatureVerificationFailed,
    /// An older version of a trusted object was presented in place of the pinned one.
    RollbackDetected,
    /// Trusted state is missing or unreadable.
    TrustedStateUnavailable,
    /// A change to the trusted keys was attempted without the root key's authorisation.
    KeyChangeRejected,
    /// The signing key set was rotated with the root key's authorisation.
    KeySetRotated,
    /// A project was registered.
    ProjectRegistered,
    /// A project's trust was revoked.
    ProjectTrustRevoked,
    /// A registered project's directory no longer matches its registration.
    ProjectIdentityMismatch,
    /// A policy update was requested.
    PolicyUpdateRequested,
    /// A policy update was authorised and committed.
    PolicyUpdateAuthorized,
    /// A policy update was rejected.
    PolicyUpdateRejected,
    /// A project's policy file differs from its approved policy (not applied).
    ProjectPolicyDrift,
    /// A request failed protocol validation.
    RequestValidationFailed,
    /// A request's agent or project identity failed verification.
    IdentityValidationFailed,
    /// The target resource of a request was classified.
    ResourceClassified,
    /// The risk of a request was assessed.
    RiskAssessed,
    /// Policy rules matched a request.
    PolicyRuleMatched,
    /// Matching policy rules disagreed and were resolved to the more restrictive decision.
    PolicyConflictDetected,
    /// A pending approval request was created for a `REQUIRE_APPROVAL` operation.
    ApprovalRequestCreated,
    /// An approval request was displayed for review.
    ApprovalRequestViewed,
    /// A human approved a request.
    ApprovalApproved,
    /// A human rejected a request.
    ApprovalRejected,
    /// A pending request or an unused grant expired.
    ApprovalExpired,
    /// A pending request was cancelled.
    ApprovalCancelled,
    /// A one-time authorization grant was issued.
    AuthorizationGrantIssued,
    /// A grant was validated against an operation without being consumed.
    AuthorizationValidationSucceeded,
    /// A grant failed validation (mismatch, expiry, state, token, identity or policy).
    AuthorizationValidationFailed,
    /// A grant was consumed by exactly one operation.
    AuthorizationConsumed,
    /// A consumed grant was presented again.
    AuthorizationReplayDetected,
    /// A grant was revoked before use.
    AuthorizationGrantRevoked,
    /// A policy change invalidated a pending request or a grant.
    ApprovalInvalidatedByPolicyChange,
    /// An operation touches a sensitive resource (category recorded, never content).
    SensitiveResourceIdentified,
    /// Secret candidates were detected (counts, detector and severity; never values).
    SecretCandidateDetected,
    /// Access to a sensitive resource was denied.
    SensitiveAccessDenied,
    /// An operation on a sensitive resource requires approval.
    SensitiveOperationRequiresApproval,
    /// Secret data was about to leave for an external or unknown destination and was blocked.
    DisclosureBlocked,
    /// Secret-bearing text was redacted before it was recorded or displayed.
    SecretRedacted,
    /// A secret scan started.
    ScanStarted,
    /// A secret scan completed with every included file scanned.
    ScanCompleted,
    /// A secret scan finished with files skipped or limits reached.
    ScanPartial,
    /// A secret scan could not run.
    ScanError,
    /// A scan excluded files (count recorded; excluded files are never reported as clean).
    ExcludedFileEncountered,
    /// A managed execution request arrived.
    ExecutionRequestReceived,
    /// A managed execution request was classified (category, executable, mode).
    CommandClassified,
    /// The repository state a Git operation depends on was inspected.
    GitContextInspected,
    /// Content an execution would commit or push was scanned for secrets before execution.
    PreExecutionScanCompleted,
    /// The policy decision for a managed execution.
    ExecutionPolicyDecision,
    /// A managed process was started (recorded before the process is spawned).
    ExecutionStarted,
    /// A managed process exited with status 0.
    ExecutionCompleted,
    /// A managed process exited unsuccessfully, was killed by a signal, or could not start.
    ExecutionFailed,
    /// A managed process exceeded its time limit and was terminated.
    ExecutionTimedOut,
    /// The outcome of a managed process could not be determined.
    ExecutionIndeterminate,
    /// An execution request used syntax or options managed execution does not support, or
    /// tried to bypass its controls; nothing was executed.
    UnsupportedOperationDetected,
    /// The state an approved operation was bound to changed before it ran; nothing was
    /// executed.
    ExecutionContextChanged,
    /// A completed operation's result did not match what was approved (for example a hook
    /// changed what a commit recorded).
    ExecutionVerificationFailed,
    /// An agent hook was invoked (provider, event, tool).
    HookInvoked,
    /// A hook payload failed validation; protected operations are blocked.
    HookPayloadRejected,
    /// A tool call was normalized into AgentGuard operations.
    HookOperationNormalized,
    /// The decision for a hooked tool call, with its enforcement status.
    HookDecision,
    /// The provider response was produced.
    HookResponseGenerated,
    /// The hook failed internally; protected operations are blocked.
    HookFailed,
    /// A hook was invoked for an event or tool AgentGuard does not support.
    HookUnsupportedEvent,
    /// A tool call was observed after execution (audit only; nothing was enforced).
    HookToolObserved,
}

/// Outcome recorded with a decision-bearing event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditDecision {
    /// Allowed.
    Allow,
    /// Denied.
    Deny,
    /// Deferred to a human approval.
    RequiresApproval,
}

impl From<Decision> for AuditDecision {
    fn from(value: Decision) -> Self {
        match value {
            Decision::Allow => AuditDecision::Allow,
            Decision::Deny => AuditDecision::Deny,
            Decision::RequireApproval => AuditDecision::RequiresApproval,
        }
    }
}

/// One audited fact. Construct with [`AuditEvent::new`] and the `with_*` builders; the
/// constructor redacts `resource` and `reason`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// When the event was recorded (UTC).
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    /// Event family.
    pub kind: AuditEventKind,
    /// Session, when the event belongs to one.
    pub session_id: Option<SessionId>,
    /// Task, when known.
    pub task_id: Option<TaskId>,
    /// Agent, when known.
    pub agent: Option<AgentIdentity>,
    /// Policy version in force.
    pub policy_version: Option<PolicyVersion>,
    /// Operation, for decision-bearing events.
    pub operation: Option<OperationType>,
    /// What the event concerns (path, branch, host, ...). Redacted.
    pub resource: BoundedText<1024>,
    /// Decision, for decision-bearing events.
    pub decision: Option<AuditDecision>,
    /// Why. Redacted.
    pub reason: BoundedText<1024>,
    /// Authorization request this event belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
    /// Verified project.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<ProjectId>,
    /// Action category, for authorization events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<ActionCategory>,
    /// Risk classification, for authorization events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<RiskLevel>,
    /// Rule that produced the decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<RuleId>,
    /// Operation within the category, for authorization events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_name: Option<Name>,
    /// Approval request, for approval events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<ApprovalId>,
    /// Authorization grant, for grant events. A reference only; token material is never
    /// recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<GrantId>,
    /// Digest of the bound operation, for approval events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_digest: Option<OperationFingerprint>,
    /// Authenticated human approver, for approval decisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver: Option<Name>,
    /// Stable machine-readable reason, for approval events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<RuleId>,
    /// Secret finding, for scan events (`f_` and 16 hex characters; derived from the location).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<Name>,
    /// Managed execution, for execution events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_id: Option<Name>,
}

impl AuditEvent {
    /// Create an event now, redacting `resource` and `reason`. Oversized or control-laden
    /// text is truncated and cleaned rather than rejected so an audit record is always
    /// produced.
    #[must_use]
    pub fn new(kind: AuditEventKind, resource: &str, reason: &str) -> Self {
        Self {
            timestamp: OffsetDateTime::now_utc(),
            kind,
            session_id: None,
            task_id: None,
            agent: None,
            policy_version: None,
            operation: None,
            resource: BoundedText::lossy(&redact_text(resource)),
            decision: None,
            reason: BoundedText::lossy(&redact_text(reason)),
            request_id: None,
            project_id: None,
            category: None,
            risk: None,
            rule: None,
            operation_name: None,
            approval_id: None,
            grant_id: None,
            operation_digest: None,
            approver: None,
            reason_code: None,
            finding_id: None,
            execution_id: None,
        }
    }

    /// Attach a session.
    #[must_use]
    pub const fn with_session(mut self, session_id: SessionId) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Attach a task.
    #[must_use]
    pub fn with_task(mut self, task_id: TaskId) -> Self {
        self.task_id = Some(task_id);
        self
    }

    /// Attach an agent identity.
    #[must_use]
    pub fn with_agent(mut self, agent: AgentIdentity) -> Self {
        self.agent = Some(agent);
        self
    }

    /// Attach the policy version.
    #[must_use]
    pub const fn with_policy_version(mut self, version: PolicyVersion) -> Self {
        self.policy_version = Some(version);
        self
    }

    /// Attach an operation and decision.
    #[must_use]
    pub const fn with_decision(
        mut self,
        operation: OperationType,
        decision: AuditDecision,
    ) -> Self {
        self.operation = Some(operation);
        self.decision = Some(decision);
        self
    }

    /// Attach the authorization request this event belongs to.
    #[must_use]
    pub const fn with_request(mut self, request_id: RequestId) -> Self {
        self.request_id = Some(request_id);
        self
    }

    /// Attach the verified project.
    #[must_use]
    pub const fn with_project(mut self, project_id: ProjectId) -> Self {
        self.project_id = Some(project_id);
        self
    }

    /// Attach an authorization outcome: category, decision, risk and rule.
    #[must_use]
    pub fn with_authorization(
        mut self,
        category: Option<ActionCategory>,
        decision: Decision,
        risk: RiskLevel,
        rule: RuleId,
    ) -> Self {
        self.category = category;
        self.decision = Some(decision.into());
        self.risk = Some(risk);
        self.rule = Some(rule);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentguard_core::AgentKind;

    #[test]
    fn constructor_redacts_and_bounds() {
        let e = AuditEvent::new(
            AuditEventKind::GitOperation,
            "push with ghp_0123456789abcdefghijklmnopqrstuvwxyz",
            "\u{1b}[31mreason\u{1b}[0m",
        );
        assert_eq!(e.resource.as_str(), "push with [REDACTED]");
        assert_eq!(e.reason.as_str(), "[31mreason[0m");
        assert!(e.session_id.is_none());
    }

    #[test]
    fn builders_and_serde() {
        let sid = SessionId::generate();
        let e = AuditEvent::new(AuditEventKind::PolicyDecision, "feature/x", "task scope")
            .with_session(sid)
            .with_task(TaskId::new("AH-1").unwrap())
            .with_agent(AgentIdentity::new(AgentKind::ClaudeCode))
            .with_policy_version(PolicyVersion::compute(b"p"))
            .with_decision(OperationType::GitPush, AuditDecision::RequiresApproval);
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"requires-approval\""));
        assert!(json.contains("\"git-push\""));
        let back: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);
    }
}
