//! Typed security events.
//!
//! The engine describes what happened as a [`SecurityEvent`]; [`SecurityEvent::into_audit_event`]
//! turns it into an [`AuditEvent`], which redacts free text at construction. Every security
//! event therefore reaches storage through the same redaction and hash chain as every other
//! audit record. Events never carry secret values: secrets are referred to by name, and free
//! text (resources, commands) is redacted.

use agentguard_core::{
    ActionCategory, AgentIdentity, ApprovalDecisionKind, ApprovalId, Decision, GrantId, Name,
    OperationFingerprint, PolicyVersion, ProjectId, RequestId, RiskLevel, RuleId, SessionId,
};

use crate::event::{AuditEvent, AuditEventKind};

/// The outcome of one authorization request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionRecord {
    /// Correlation ID, when the request could be correlated.
    pub request_id: Option<RequestId>,
    /// Final decision.
    pub decision: Decision,
    /// Risk classification.
    pub risk: RiskLevel,
    /// Rule that produced the decision.
    pub rule: RuleId,
    /// Action category, when the request parsed.
    pub category: Option<ActionCategory>,
    /// Operation within the category, when the request parsed.
    pub operation: Option<Name>,
    /// Verified project, when verification got that far.
    pub project: Option<ProjectId>,
    /// Verified agent, when verification got that far.
    pub agent: Option<AgentIdentity>,
    /// Session, when supplied and verification got that far.
    pub session: Option<SessionId>,
    /// Active policy.
    pub policy_version: Option<PolicyVersion>,
    /// Target description (redacted on conversion).
    pub resource: String,
    /// Why (redacted on conversion).
    pub reason: String,
}

/// Intermediate evaluation steps recorded alongside the decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepKind {
    /// See [`AuditEventKind::RequestValidationFailed`].
    RequestValidationFailed,
    /// See [`AuditEventKind::IdentityValidationFailed`].
    IdentityValidationFailed,
    /// See [`AuditEventKind::ResourceClassified`].
    ResourceClassified,
    /// See [`AuditEventKind::RiskAssessed`].
    RiskAssessed,
    /// See [`AuditEventKind::PolicyRuleMatched`].
    PolicyRuleMatched,
    /// See [`AuditEventKind::PolicyConflictDetected`].
    PolicyConflictDetected,
    /// See [`AuditEventKind::PolicyIntegrityFailed`].
    PolicyIntegrityFailed,
    /// See [`AuditEventKind::SensitiveResourceIdentified`].
    SensitiveResourceIdentified,
    /// See [`AuditEventKind::SecretCandidateDetected`].
    SecretCandidateDetected,
    /// See [`AuditEventKind::SensitiveAccessDenied`].
    SensitiveAccessDenied,
    /// See [`AuditEventKind::SensitiveOperationRequiresApproval`].
    SensitiveOperationRequiresApproval,
    /// See [`AuditEventKind::DisclosureBlocked`].
    DisclosureBlocked,
    /// See [`AuditEventKind::SecretRedacted`].
    SecretRedacted,
}

impl StepKind {
    /// The audit family.
    #[must_use]
    pub const fn audit_kind(self) -> AuditEventKind {
        match self {
            StepKind::RequestValidationFailed => AuditEventKind::RequestValidationFailed,
            StepKind::IdentityValidationFailed => AuditEventKind::IdentityValidationFailed,
            StepKind::ResourceClassified => AuditEventKind::ResourceClassified,
            StepKind::RiskAssessed => AuditEventKind::RiskAssessed,
            StepKind::PolicyRuleMatched => AuditEventKind::PolicyRuleMatched,
            StepKind::PolicyConflictDetected => AuditEventKind::PolicyConflictDetected,
            StepKind::PolicyIntegrityFailed => AuditEventKind::PolicyIntegrityFailed,
            StepKind::SensitiveResourceIdentified => AuditEventKind::SensitiveResourceIdentified,
            StepKind::SecretCandidateDetected => AuditEventKind::SecretCandidateDetected,
            StepKind::SensitiveAccessDenied => AuditEventKind::SensitiveAccessDenied,
            StepKind::SensitiveOperationRequiresApproval => {
                AuditEventKind::SensitiveOperationRequiresApproval
            }
            StepKind::DisclosureBlocked => AuditEventKind::DisclosureBlocked,
            StepKind::SecretRedacted => AuditEventKind::SecretRedacted,
        }
    }
}

/// One evaluation step. Carries no decision, so step records are never mistaken for the
/// decision record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepRecord {
    /// Which step.
    pub kind: StepKind,
    /// Correlation ID, when known.
    pub request_id: Option<RequestId>,
    /// Action category, when known.
    pub category: Option<ActionCategory>,
    /// Operation, when known.
    pub operation: Option<Name>,
    /// Risk level, when assessed.
    pub risk: Option<RiskLevel>,
    /// Rule concerned, when one is.
    pub rule: Option<RuleId>,
    /// Verified project, when known.
    pub project: Option<ProjectId>,
    /// Verified agent, when known.
    pub agent: Option<AgentIdentity>,
    /// Active policy, when known.
    pub policy_version: Option<PolicyVersion>,
    /// Target description (redacted on conversion).
    pub resource: String,
    /// What the step found (redacted on conversion).
    pub detail: String,
}

/// What executing an authorized action produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionOutcome {
    /// The action completed successfully.
    Succeeded,
    /// The action ran and failed.
    Failed,
    /// The integration could not report an outcome.
    Unknown,
}

impl ExecutionOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            ExecutionOutcome::Succeeded => "succeeded",
            ExecutionOutcome::Failed => "failed",
            ExecutionOutcome::Unknown => "unknown",
        }
    }
}

/// Kinds of tampering the engine detects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TamperKind {
    /// An action targeted AgentGuard's trusted state (policy, approvals, audit, hook settings).
    TrustedStateModification,
    /// An action tried to approve or reconfigure AgentGuard from the agent's side.
    SelfApprovalAttempt,
    /// A stored audit chain failed verification.
    AuditChainBroken,
}

impl TamperKind {
    const fn as_str(self) -> &'static str {
        match self {
            TamperKind::TrustedStateModification => "trusted-state-modification",
            TamperKind::SelfApprovalAttempt => "self-approval-attempt",
            TamperKind::AuditChainBroken => "audit-chain-broken",
        }
    }
}

/// Trust-store events. Each maps one-to-one onto an [`AuditEventKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustEventKind {
    /// See [`AuditEventKind::TrustInitialized`].
    TrustInitialized,
    /// See [`AuditEventKind::PolicyIntegrityVerified`].
    IntegrityVerified,
    /// See [`AuditEventKind::PolicyIntegrityFailed`].
    IntegrityFailed,
    /// See [`AuditEventKind::SignatureVerificationFailed`].
    SignatureInvalid,
    /// See [`AuditEventKind::RollbackDetected`].
    RollbackDetected,
    /// See [`AuditEventKind::TrustedStateUnavailable`].
    TrustedStateUnavailable,
    /// See [`AuditEventKind::KeyChangeRejected`].
    KeyChangeRejected,
    /// See [`AuditEventKind::KeySetRotated`].
    KeySetRotated,
    /// See [`AuditEventKind::ProjectRegistered`].
    ProjectRegistered,
    /// See [`AuditEventKind::ProjectTrustRevoked`].
    ProjectTrustRevoked,
    /// See [`AuditEventKind::ProjectIdentityMismatch`].
    ProjectIdentityMismatch,
    /// See [`AuditEventKind::PolicyUpdateRequested`].
    PolicyUpdateRequested,
    /// See [`AuditEventKind::PolicyUpdateAuthorized`].
    PolicyUpdateAuthorized,
    /// See [`AuditEventKind::PolicyUpdateRejected`].
    PolicyUpdateRejected,
    /// See [`AuditEventKind::ProjectPolicyDrift`].
    ProjectPolicyDrift,
}

impl TrustEventKind {
    /// The audit family.
    #[must_use]
    pub const fn audit_kind(self) -> AuditEventKind {
        match self {
            TrustEventKind::TrustInitialized => AuditEventKind::TrustInitialized,
            TrustEventKind::IntegrityVerified => AuditEventKind::PolicyIntegrityVerified,
            TrustEventKind::IntegrityFailed => AuditEventKind::PolicyIntegrityFailed,
            TrustEventKind::SignatureInvalid => AuditEventKind::SignatureVerificationFailed,
            TrustEventKind::RollbackDetected => AuditEventKind::RollbackDetected,
            TrustEventKind::TrustedStateUnavailable => AuditEventKind::TrustedStateUnavailable,
            TrustEventKind::KeyChangeRejected => AuditEventKind::KeyChangeRejected,
            TrustEventKind::KeySetRotated => AuditEventKind::KeySetRotated,
            TrustEventKind::ProjectRegistered => AuditEventKind::ProjectRegistered,
            TrustEventKind::ProjectTrustRevoked => AuditEventKind::ProjectTrustRevoked,
            TrustEventKind::ProjectIdentityMismatch => AuditEventKind::ProjectIdentityMismatch,
            TrustEventKind::PolicyUpdateRequested => AuditEventKind::PolicyUpdateRequested,
            TrustEventKind::PolicyUpdateAuthorized => AuditEventKind::PolicyUpdateAuthorized,
            TrustEventKind::PolicyUpdateRejected => AuditEventKind::PolicyUpdateRejected,
            TrustEventKind::ProjectPolicyDrift => AuditEventKind::ProjectPolicyDrift,
        }
    }
}

/// A trust-store event. Never carries key material: keys are referred to by key ID, policies
/// by version and content hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRecord {
    /// What happened.
    pub kind: TrustEventKind,
    /// The trusted object concerned, for example `global policy` or `registry`.
    pub subject: String,
    /// Rule-level description (an error's `Display`, which never contains values).
    pub detail: String,
    /// Version before the event, when relevant.
    pub old_version: Option<String>,
    /// Version after the event, when relevant.
    pub new_version: Option<String>,
    /// Who acted: a human name from the trusted channel, an agent identity, or a key ID.
    pub actor: Option<String>,
    /// Project concerned, when relevant.
    pub project: Option<ProjectId>,
}

/// Approval lifecycle events. Each maps one-to-one onto an [`AuditEventKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalEventKind {
    /// See [`AuditEventKind::ApprovalRequestCreated`].
    RequestCreated,
    /// See [`AuditEventKind::ApprovalRequestViewed`].
    RequestViewed,
    /// See [`AuditEventKind::ApprovalApproved`].
    Approved,
    /// See [`AuditEventKind::ApprovalRejected`].
    Rejected,
    /// See [`AuditEventKind::ApprovalExpired`].
    Expired,
    /// See [`AuditEventKind::ApprovalCancelled`].
    Cancelled,
    /// See [`AuditEventKind::AuthorizationGrantIssued`].
    GrantIssued,
    /// See [`AuditEventKind::AuthorizationValidationSucceeded`].
    ValidationSucceeded,
    /// See [`AuditEventKind::AuthorizationValidationFailed`].
    ValidationFailed,
    /// See [`AuditEventKind::AuthorizationConsumed`].
    Consumed,
    /// See [`AuditEventKind::AuthorizationReplayDetected`].
    ReplayDetected,
    /// See [`AuditEventKind::AuthorizationGrantRevoked`].
    GrantRevoked,
    /// See [`AuditEventKind::ApprovalInvalidatedByPolicyChange`].
    InvalidatedByPolicyChange,
}

impl ApprovalEventKind {
    /// The audit family.
    #[must_use]
    pub const fn audit_kind(self) -> AuditEventKind {
        match self {
            ApprovalEventKind::RequestCreated => AuditEventKind::ApprovalRequestCreated,
            ApprovalEventKind::RequestViewed => AuditEventKind::ApprovalRequestViewed,
            ApprovalEventKind::Approved => AuditEventKind::ApprovalApproved,
            ApprovalEventKind::Rejected => AuditEventKind::ApprovalRejected,
            ApprovalEventKind::Expired => AuditEventKind::ApprovalExpired,
            ApprovalEventKind::Cancelled => AuditEventKind::ApprovalCancelled,
            ApprovalEventKind::GrantIssued => AuditEventKind::AuthorizationGrantIssued,
            ApprovalEventKind::ValidationSucceeded => {
                AuditEventKind::AuthorizationValidationSucceeded
            }
            ApprovalEventKind::ValidationFailed => AuditEventKind::AuthorizationValidationFailed,
            ApprovalEventKind::Consumed => AuditEventKind::AuthorizationConsumed,
            ApprovalEventKind::ReplayDetected => AuditEventKind::AuthorizationReplayDetected,
            ApprovalEventKind::GrantRevoked => AuditEventKind::AuthorizationGrantRevoked,
            ApprovalEventKind::InvalidatedByPolicyChange => {
                AuditEventKind::ApprovalInvalidatedByPolicyChange
            }
        }
    }
}

/// An approval lifecycle event. Identifies the operation by category, operation name and
/// digest only: operation arguments, claim tokens and token verifiers are never recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRecord {
    /// What happened.
    pub kind: ApprovalEventKind,
    /// The authorization request concerned, when there is one.
    pub request_id: Option<RequestId>,
    /// The approval request.
    pub approval_id: Option<ApprovalId>,
    /// The grant, for grant events.
    pub grant_id: Option<GrantId>,
    /// Verified agent.
    pub agent: Option<AgentIdentity>,
    /// Verified project.
    pub project: Option<ProjectId>,
    /// Authenticated human approver.
    pub approver: Option<Name>,
    /// Digest of the bound operation.
    pub digest: Option<OperationFingerprint>,
    /// Policy version concerned.
    pub policy_version: Option<PolicyVersion>,
    /// Action category.
    pub category: Option<ActionCategory>,
    /// Operation within the category.
    pub operation: Option<Name>,
    /// Decision reported to the caller, when the event carries one.
    pub decision: Option<Decision>,
    /// Stable reason code.
    pub reason_code: RuleId,
    /// Rule-level description, never a value (redacted on conversion).
    pub detail: String,
}

/// Secret-scan events. Each maps one-to-one onto an [`AuditEventKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanEventKind {
    /// See [`AuditEventKind::ScanStarted`].
    Started,
    /// See [`AuditEventKind::ScanCompleted`].
    Completed,
    /// See [`AuditEventKind::ScanPartial`].
    Partial,
    /// See [`AuditEventKind::ScanError`].
    Error,
    /// See [`AuditEventKind::ExcludedFileEncountered`].
    ExcludedFileEncountered,
    /// See [`AuditEventKind::SecretCandidateDetected`].
    SecretCandidateDetected,
}

impl ScanEventKind {
    /// The audit family.
    #[must_use]
    pub const fn audit_kind(self) -> AuditEventKind {
        match self {
            ScanEventKind::Started => AuditEventKind::ScanStarted,
            ScanEventKind::Completed => AuditEventKind::ScanCompleted,
            ScanEventKind::Partial => AuditEventKind::ScanPartial,
            ScanEventKind::Error => AuditEventKind::ScanError,
            ScanEventKind::ExcludedFileEncountered => AuditEventKind::ExcludedFileEncountered,
            ScanEventKind::SecretCandidateDetected => AuditEventKind::SecretCandidateDetected,
        }
    }
}

/// A secret-scan event: where and what kind, never a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRecord {
    /// What happened.
    pub kind: ScanEventKind,
    /// Project scanned, when registered.
    pub project: Option<ProjectId>,
    /// Finding, for candidate events.
    pub finding_id: Option<Name>,
    /// Stable reason code (detector ID for candidates, `scan.*` otherwise).
    pub reason_code: RuleId,
    /// Path or scan scope (redacted on conversion).
    pub resource: String,
    /// Counts and severities (redacted on conversion).
    pub detail: String,
}

/// Managed execution events. Each maps one-to-one onto an [`AuditEventKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionEventKind {
    /// See [`AuditEventKind::ExecutionRequestReceived`].
    RequestReceived,
    /// See [`AuditEventKind::CommandClassified`].
    CommandClassified,
    /// See [`AuditEventKind::GitContextInspected`].
    GitContextInspected,
    /// See [`AuditEventKind::PreExecutionScanCompleted`].
    SecretScanCompleted,
    /// See [`AuditEventKind::ExecutionPolicyDecision`].
    PolicyDecision,
    /// See [`AuditEventKind::ExecutionStarted`].
    Started,
    /// See [`AuditEventKind::ExecutionCompleted`].
    Completed,
    /// See [`AuditEventKind::ExecutionFailed`].
    Failed,
    /// See [`AuditEventKind::ExecutionTimedOut`].
    TimedOut,
    /// See [`AuditEventKind::ExecutionIndeterminate`].
    Indeterminate,
    /// See [`AuditEventKind::UnsupportedOperationDetected`].
    Unsupported,
    /// See [`AuditEventKind::ExecutionContextChanged`].
    ContextChanged,
    /// See [`AuditEventKind::ExecutionVerificationFailed`].
    VerificationFailed,
}

impl ExecutionEventKind {
    /// The audit family.
    #[must_use]
    pub const fn audit_kind(self) -> AuditEventKind {
        match self {
            ExecutionEventKind::RequestReceived => AuditEventKind::ExecutionRequestReceived,
            ExecutionEventKind::CommandClassified => AuditEventKind::CommandClassified,
            ExecutionEventKind::GitContextInspected => AuditEventKind::GitContextInspected,
            ExecutionEventKind::SecretScanCompleted => AuditEventKind::PreExecutionScanCompleted,
            ExecutionEventKind::PolicyDecision => AuditEventKind::ExecutionPolicyDecision,
            ExecutionEventKind::Started => AuditEventKind::ExecutionStarted,
            ExecutionEventKind::Completed => AuditEventKind::ExecutionCompleted,
            ExecutionEventKind::Failed => AuditEventKind::ExecutionFailed,
            ExecutionEventKind::TimedOut => AuditEventKind::ExecutionTimedOut,
            ExecutionEventKind::Indeterminate => AuditEventKind::ExecutionIndeterminate,
            ExecutionEventKind::Unsupported => AuditEventKind::UnsupportedOperationDetected,
            ExecutionEventKind::ContextChanged => AuditEventKind::ExecutionContextChanged,
            ExecutionEventKind::VerificationFailed => AuditEventKind::ExecutionVerificationFailed,
        }
    }
}

/// A managed execution event: identifiers, decision and outcome, never raw arguments,
/// environment values or unredacted output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionRecord {
    /// What happened.
    pub kind: ExecutionEventKind,
    /// The execution.
    pub execution_id: Name,
    /// The authorization request evaluated for it, when there is one.
    pub request_id: Option<RequestId>,
    /// Verified project.
    pub project: Option<ProjectId>,
    /// Verified agent identity the execution acts for.
    pub agent: Option<AgentIdentity>,
    /// Policy version the decision was made under.
    pub policy_version: Option<PolicyVersion>,
    /// Decision, for decision and outcome events.
    pub decision: Option<Decision>,
    /// The bound operation.
    pub digest: Option<OperationFingerprint>,
    /// The approval, when one authorized the execution.
    pub approval_id: Option<ApprovalId>,
    /// The consumed grant, when one authorized the execution.
    pub grant_id: Option<GrantId>,
    /// Stable reason code (`execution.*`, a rule identifier, or a detector).
    pub reason_code: RuleId,
    /// Redacted command summary (redacted again on conversion).
    pub resource: String,
    /// What the event found or produced: counts, exit status, durations (redacted on
    /// conversion).
    pub detail: String,
}

/// Agent hook events. Each maps one-to-one onto an [`AuditEventKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookEventKind {
    /// See [`AuditEventKind::HookInvoked`].
    Invoked,
    /// See [`AuditEventKind::HookPayloadRejected`].
    PayloadRejected,
    /// See [`AuditEventKind::HookOperationNormalized`].
    Normalized,
    /// See [`AuditEventKind::HookDecision`].
    Decision,
    /// See [`AuditEventKind::HookResponseGenerated`].
    ResponseGenerated,
    /// See [`AuditEventKind::HookFailed`].
    Failed,
    /// See [`AuditEventKind::HookUnsupportedEvent`].
    Unsupported,
    /// See [`AuditEventKind::HookToolObserved`].
    Observed,
}

impl HookEventKind {
    /// The audit family.
    #[must_use]
    pub const fn audit_kind(self) -> AuditEventKind {
        match self {
            HookEventKind::Invoked => AuditEventKind::HookInvoked,
            HookEventKind::PayloadRejected => AuditEventKind::HookPayloadRejected,
            HookEventKind::Normalized => AuditEventKind::HookOperationNormalized,
            HookEventKind::Decision => AuditEventKind::HookDecision,
            HookEventKind::ResponseGenerated => AuditEventKind::HookResponseGenerated,
            HookEventKind::Failed => AuditEventKind::HookFailed,
            HookEventKind::Unsupported => AuditEventKind::HookUnsupportedEvent,
            HookEventKind::Observed => AuditEventKind::HookToolObserved,
        }
    }
}

/// An agent hook event: provider, event, tool and outcome; never tool arguments, file
/// contents or tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookRecord {
    /// What happened.
    pub kind: HookEventKind,
    /// `claude` or `codex`.
    pub provider: &'static str,
    /// Provider event name.
    pub event: &'static str,
    /// Tool name, for tool events (redacted on conversion).
    pub tool: Option<String>,
    /// First 16 hex characters of SHA-256 over the provider session ID, when present.
    pub session: Option<String>,
    /// The AgentGuard request evaluated, when there is one.
    pub request_id: Option<RequestId>,
    /// Verified project.
    pub project: Option<ProjectId>,
    /// Agent identity the hook acts for (from its installed command line).
    pub agent: Option<AgentIdentity>,
    /// Policy version.
    pub policy_version: Option<PolicyVersion>,
    /// Decision, for decision events.
    pub decision: Option<Decision>,
    /// The approval involved, if any.
    pub approval_id: Option<ApprovalId>,
    /// `enforced-before-execution`, `observed-after-execution`, `informational` or
    /// `not-governed`.
    pub enforcement: &'static str,
    /// Stable reason code.
    pub reason_code: RuleId,
    /// Rule-level description (redacted on conversion).
    pub detail: String,
}

/// A structured security event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityEvent {
    /// A request arrived. Recorded before evaluation so that a request whose evaluation fails
    /// still leaves a trace.
    AuthorizationRequested {
        /// Correlation ID, when the request could be correlated.
        request_id: Option<RequestId>,
        /// Action category, when the request parsed.
        category: Option<ActionCategory>,
        /// Target description (redacted on conversion).
        resource: String,
    },
    /// A decision was made: allow, deny, or approval required.
    Decision(Box<DecisionRecord>),
    /// A human decided an approval through a trusted channel.
    ApprovalDecided {
        /// The approval.
        approval_id: ApprovalId,
        /// The operation it is bound to.
        fingerprint: OperationFingerprint,
        /// What was decided.
        outcome: ApprovalDecisionKind,
    },
    /// An authorized action finished.
    ExecutionResult {
        /// The request that authorized it.
        request_id: RequestId,
        /// How it ended.
        outcome: ExecutionOutcome,
        /// Process exit code, when there is one.
        exit_code: Option<i32>,
    },
    /// Tampering was detected.
    TamperDetected {
        /// Correlation ID, when there is a request.
        request_id: Option<RequestId>,
        /// What kind.
        kind: TamperKind,
        /// What was targeted (redacted on conversion).
        resource: String,
    },
    /// The engine failed internally and denied.
    SecurityError {
        /// Correlation ID, when there is a request.
        request_id: Option<RequestId>,
        /// Which stage failed.
        stage: &'static str,
        /// Rule-level description, never a value.
        detail: &'static str,
    },
    /// A trust-store event.
    Trust(Box<TrustRecord>),
    /// An intermediate evaluation step.
    Step(Box<StepRecord>),
    /// An approval lifecycle event.
    Approval(Box<ApprovalRecord>),
    /// A secret-scan event.
    Scan(Box<ScanRecord>),
    /// A managed execution event.
    Execution(Box<ExecutionRecord>),
    /// An agent hook event.
    Hook(Box<HookRecord>),
}

impl SecurityEvent {
    /// The audit event family this event is stored under.
    #[must_use]
    pub const fn kind(&self) -> AuditEventKind {
        match self {
            SecurityEvent::AuthorizationRequested { .. } => AuditEventKind::AuthorizationRequested,
            SecurityEvent::Decision(record) => match record.decision {
                Decision::Allow => AuditEventKind::AuthorizationAllowed,
                Decision::Deny => AuditEventKind::AuthorizationDenied,
                Decision::RequireApproval => AuditEventKind::ApprovalRequested,
            },
            SecurityEvent::ApprovalDecided { .. } => AuditEventKind::ApprovalDecision,
            SecurityEvent::ExecutionResult { .. } => AuditEventKind::ExecutionResult,
            SecurityEvent::TamperDetected { .. } => AuditEventKind::TamperDetected,
            SecurityEvent::SecurityError { .. } => AuditEventKind::SecurityError,
            SecurityEvent::Trust(record) => record.kind.audit_kind(),
            SecurityEvent::Step(record) => record.kind.audit_kind(),
            SecurityEvent::Approval(record) => record.kind.audit_kind(),
            SecurityEvent::Scan(record) => record.kind.audit_kind(),
            SecurityEvent::Execution(record) => record.kind.audit_kind(),
            SecurityEvent::Hook(record) => record.kind.audit_kind(),
        }
    }

    /// Convert to a redacted audit event.
    #[must_use]
    pub fn into_audit_event(self) -> AuditEvent {
        let kind = self.kind();
        match self {
            SecurityEvent::AuthorizationRequested {
                request_id,
                category,
                resource,
            } => {
                let mut event = AuditEvent::new(kind, &resource, "");
                event.request_id = request_id;
                event.category = category;
                event
            }
            SecurityEvent::Decision(record) => {
                let record = *record;
                let mut event = AuditEvent::new(kind, &record.resource, &record.reason)
                    .with_authorization(record.category, record.decision, record.risk, record.rule);
                event.request_id = record.request_id;
                event.project_id = record.project;
                event.agent = record.agent;
                event.session_id = record.session;
                event.policy_version = record.policy_version;
                event.operation_name = record.operation;
                event
            }
            SecurityEvent::Step(record) => {
                let record = *record;
                let mut event = AuditEvent::new(kind, &record.resource, &record.detail);
                event.request_id = record.request_id;
                event.category = record.category;
                event.operation_name = record.operation;
                event.risk = record.risk;
                event.rule = record.rule;
                event.project_id = record.project;
                event.agent = record.agent;
                event.policy_version = record.policy_version;
                event
            }
            SecurityEvent::ApprovalDecided {
                approval_id,
                fingerprint,
                outcome,
            } => AuditEvent::new(
                kind,
                &format!("approval {approval_id} for operation {fingerprint}"),
                &format!("{outcome:?}"),
            ),
            SecurityEvent::ExecutionResult {
                request_id,
                outcome,
                exit_code,
            } => {
                let reason = match exit_code {
                    Some(code) => format!("{} (exit {code})", outcome.as_str()),
                    None => outcome.as_str().to_owned(),
                };
                AuditEvent::new(kind, "", &reason).with_request(request_id)
            }
            SecurityEvent::TamperDetected {
                request_id,
                kind: tamper,
                resource,
            } => {
                let mut event = AuditEvent::new(kind, &resource, tamper.as_str());
                event.request_id = request_id;
                event
            }
            SecurityEvent::SecurityError {
                request_id,
                stage,
                detail,
            } => {
                let mut event = AuditEvent::new(kind, stage, detail);
                event.request_id = request_id;
                event
            }
            SecurityEvent::Trust(record) => {
                let record = *record;
                let subject = record.subject;
                let resource = match (&record.old_version, &record.new_version) {
                    (Some(old), Some(new)) => format!("{subject} {old} -> {new}"),
                    (None, Some(new)) => format!("{subject} -> {new}"),
                    (Some(old), None) => format!("{subject} at {old}"),
                    (None, None) => subject,
                };
                let reason = match &record.actor {
                    Some(actor) => format!("{} (by {actor})", record.detail),
                    None => record.detail,
                };
                let mut event = AuditEvent::new(kind, &resource, &reason);
                event.project_id = record.project;
                event
            }
            SecurityEvent::Approval(record) => {
                let record = *record;
                let resource = match (record.category, &record.operation) {
                    (Some(category), Some(operation)) => format!("{category} {operation}"),
                    (Some(category), None) => category.to_string(),
                    _ => String::new(),
                };
                let mut event = AuditEvent::new(kind, &resource, &record.detail);
                event.request_id = record.request_id;
                event.approval_id = record.approval_id;
                event.grant_id = record.grant_id;
                event.agent = record.agent;
                event.project_id = record.project;
                event.approver = record.approver;
                event.operation_digest = record.digest;
                event.policy_version = record.policy_version;
                event.category = record.category;
                event.operation_name = record.operation;
                event.decision = record.decision.map(Into::into);
                event.reason_code = Some(record.reason_code);
                event
            }
            SecurityEvent::Scan(record) => {
                let record = *record;
                let mut event = AuditEvent::new(kind, &record.resource, &record.detail);
                event.project_id = record.project;
                event.finding_id = record.finding_id;
                event.reason_code = Some(record.reason_code);
                event
            }
            SecurityEvent::Execution(record) => execution_event(kind, *record),
            SecurityEvent::Hook(record) => hook_event(kind, *record),
        }
    }
}

fn execution_event(kind: AuditEventKind, record: ExecutionRecord) -> AuditEvent {
    let mut event = AuditEvent::new(kind, &record.resource, &record.detail);
    event.execution_id = Some(record.execution_id);
    event.request_id = record.request_id;
    event.project_id = record.project;
    event.agent = record.agent;
    event.policy_version = record.policy_version;
    event.decision = record.decision.map(Into::into);
    event.operation_digest = record.digest;
    event.approval_id = record.approval_id;
    event.grant_id = record.grant_id;
    event.category = Some(ActionCategory::Terminal);
    event.reason_code = Some(record.reason_code);
    event
}

fn hook_event(kind: AuditEventKind, record: HookRecord) -> AuditEvent {
    let mut resource = format!("{} {}", record.provider, record.event);
    if let Some(tool) = &record.tool {
        resource.push(' ');
        resource.push_str(tool);
    }
    if let Some(session) = &record.session {
        resource.push_str(" session ");
        resource.push_str(session);
    }
    let reason = format!("{} [{}]", record.detail, record.enforcement);
    let mut event = AuditEvent::new(kind, &resource, &reason);
    event.request_id = record.request_id;
    event.project_id = record.project;
    event.agent = record.agent;
    event.policy_version = record.policy_version;
    event.decision = record.decision.map(Into::into);
    event.approval_id = record.approval_id;
    event.reason_code = Some(record.reason_code);
    event
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(decision: Decision) -> DecisionRecord {
        DecisionRecord {
            request_id: Some(RequestId::generate()),
            decision,
            risk: RiskLevel::High,
            rule: RuleId::new("baseline.elevated").unwrap(),
            category: Some(ActionCategory::Terminal),
            operation: Some(Name::new("execute").unwrap()),
            project: None,
            agent: None,
            session: None,
            policy_version: None,
            resource: "curl -H 'Authorization: Bearer abc123' https://x".to_owned(),
            reason: "terminal commands require approval".to_owned(),
        }
    }

    #[test]
    fn execution_events_are_correlated_and_redacted() {
        let event = SecurityEvent::Execution(Box::new(ExecutionRecord {
            kind: ExecutionEventKind::Completed,
            execution_id: Name::new("ex_0123456789abcdef01234567").unwrap(),
            request_id: Some(RequestId::generate()),
            project: None,
            agent: None,
            policy_version: None,
            decision: Some(Decision::Allow),
            digest: None,
            approval_id: None,
            grant_id: None,
            reason_code: RuleId::new("execution.completed").unwrap(),
            resource: "deploy --token ghp_0123456789abcdefghijklmnopqrstuvwxyz".to_owned(),
            detail: "exit 0".to_owned(),
        }));
        assert_eq!(event.kind(), AuditEventKind::ExecutionCompleted);
        let e = event.into_audit_event();
        assert!(!e.resource.as_str().contains("0123456789abcdefghij"));
        assert_eq!(
            e.execution_id.as_ref().map(Name::as_str),
            Some("ex_0123456789abcdef01234567")
        );
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"execution-completed\""), "{json}");
    }

    #[test]
    fn decision_kind_follows_decision() {
        for (d, k) in [
            (Decision::Allow, AuditEventKind::AuthorizationAllowed),
            (Decision::Deny, AuditEventKind::AuthorizationDenied),
            (Decision::RequireApproval, AuditEventKind::ApprovalRequested),
        ] {
            let e = SecurityEvent::Decision(Box::new(record(d)));
            assert_eq!(e.kind(), k);
            assert_eq!(e.into_audit_event().kind, k);
        }
    }

    #[test]
    fn decision_event_is_redacted_and_correlated() {
        let r = record(Decision::RequireApproval);
        let id = r.request_id;
        let event = SecurityEvent::Decision(Box::new(r)).into_audit_event();
        assert!(!event.resource.as_str().contains("abc123"));
        assert_eq!(event.request_id, id);
        assert_eq!(event.risk, Some(RiskLevel::High));
        assert_eq!(event.category, Some(ActionCategory::Terminal));
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("abc123"));
    }

    #[test]
    fn trust_record_maps_kind_versions_and_project() {
        let project = ProjectId::derive(&agentguard_core::NormalizedPath::new("/p").unwrap());
        let e = SecurityEvent::Trust(Box::new(TrustRecord {
            kind: TrustEventKind::PolicyUpdateAuthorized,
            subject: "project policy".to_owned(),
            detail: "policy update committed".to_owned(),
            old_version: Some("1".to_owned()),
            new_version: Some("2".to_owned()),
            actor: Some("developer".to_owned()),
            project: Some(project),
        }));
        assert_eq!(e.kind(), AuditEventKind::PolicyUpdateAuthorized);
        let a = e.into_audit_event();
        assert_eq!(a.resource.as_str(), "project policy 1 -> 2");
        assert_eq!(a.reason.as_str(), "policy update committed (by developer)");
        assert_eq!(a.project_id, Some(project));
    }

    #[test]
    fn step_records_carry_no_decision_and_are_redacted() {
        let e = SecurityEvent::Step(Box::new(StepRecord {
            kind: StepKind::RiskAssessed,
            request_id: Some(RequestId::generate()),
            category: Some(ActionCategory::Terminal),
            operation: Some(Name::new("execute").unwrap()),
            risk: Some(RiskLevel::High),
            rule: None,
            project: None,
            agent: None,
            policy_version: None,
            resource: "deploy --token=abc123secret".to_owned(),
            detail: "risk high".to_owned(),
        }))
        .into_audit_event();
        assert_eq!(e.kind, AuditEventKind::RiskAssessed);
        assert!(e.decision.is_none());
        assert!(!e.resource.as_str().contains("abc123secret"));
        assert_eq!(e.operation_name.unwrap().as_str(), "execute");
    }

    #[test]
    fn approval_records_correlate_without_arguments() {
        let approval = ApprovalId::generate();
        let grant = GrantId::generate();
        let digest = OperationFingerprint::from_bytes([9; 32]);
        let e = SecurityEvent::Approval(Box::new(ApprovalRecord {
            kind: ApprovalEventKind::Consumed,
            request_id: Some(RequestId::generate()),
            approval_id: Some(approval),
            grant_id: Some(grant),
            agent: None,
            project: None,
            approver: Some(Name::new("dev").unwrap()),
            digest: Some(digest),
            policy_version: None,
            category: Some(ActionCategory::Git),
            operation: Some(Name::new("push").unwrap()),
            decision: Some(Decision::Allow),
            reason_code: RuleId::builtin("approval.consumed"),
            detail: "grant consumed by the bound operation".to_owned(),
        }));
        assert_eq!(e.kind(), AuditEventKind::AuthorizationConsumed);
        let a = e.into_audit_event();
        assert_eq!(a.resource.as_str(), "git push");
        assert_eq!(a.approval_id, Some(approval));
        assert_eq!(a.grant_id, Some(grant));
        assert_eq!(a.operation_digest, Some(digest));
        assert_eq!(
            a.reason_code.as_ref().unwrap().as_str(),
            "approval.consumed"
        );
        let json = serde_json::to_value(&a).unwrap();
        assert_eq!(json["approver"], "dev");
        let back: AuditEvent = serde_json::from_value(json).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn events_without_approval_fields_serialise_as_before() {
        let e = AuditEvent::new(AuditEventKind::HostCheck, "x", "y");
        let json = serde_json::to_string(&e).unwrap();
        for field in [
            "approval_id",
            "grant_id",
            "operation_digest",
            "approver",
            "reason_code",
        ] {
            assert!(!json.contains(field), "{field}");
        }
    }

    #[test]
    fn other_kinds() {
        let id = RequestId::generate();
        let e = SecurityEvent::ExecutionResult {
            request_id: id,
            outcome: ExecutionOutcome::Failed,
            exit_code: Some(2),
        }
        .into_audit_event();
        assert_eq!(e.kind, AuditEventKind::ExecutionResult);
        assert_eq!(e.reason.as_str(), "failed (exit 2)");
        let t = SecurityEvent::TamperDetected {
            request_id: None,
            kind: TamperKind::TrustedStateModification,
            resource: "/p/.agent-security.yml".to_owned(),
        }
        .into_audit_event();
        assert_eq!(t.kind, AuditEventKind::TamperDetected);
        assert_eq!(t.reason.as_str(), "trusted-state-modification");
        let s = SecurityEvent::SecurityError {
            request_id: Some(id),
            stage: "policy",
            detail: "evaluator failed",
        }
        .into_audit_event();
        assert_eq!(s.kind, AuditEventKind::SecurityError);
        assert_eq!(s.request_id, Some(id));
    }
}
