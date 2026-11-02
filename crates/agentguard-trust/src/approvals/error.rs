//! Approval errors. Each has a stable reason code for audit records and the protocol.

use agentguard_core::ApprovalStatus;

/// Why an approval operation was refused. Every variant leaves authority unchanged or
/// reduced; none grants anything.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ApprovalError {
    /// No approval request has this ID.
    #[error("no approval request matches this ID")]
    NotFound,
    /// An ID prefix matches more than one request.
    #[error("the ID prefix matches more than one approval request; give more characters")]
    Ambiguous,
    /// The request is not waiting for a decision.
    #[error("the approval request is {0}, not pending")]
    NotPending(ApprovalStatus),
    /// The request or grant has expired.
    #[error(
        "the approval request or its grant has expired; the operation must be requested again"
    )]
    Expired,
    /// The operation reviewed by the human is not the one stored.
    #[error("the reviewed operation does not match the stored request")]
    ReviewMismatch,
    /// The policy changed since the request or grant was made.
    #[error("the policy changed since this approval was made; the operation must be evaluated and approved again")]
    PolicyChanged,
    /// The project is no longer trusted, or the request's project no longer resolves to it.
    #[error("the request's project is not a trusted, registered project")]
    ProjectNotTrusted,
    /// The request has not been approved (pending, rejected, cancelled or expired).
    #[error("the approval request is {0}; it has not authorized anything")]
    NotApproved(ApprovalStatus),
    /// The grant was already consumed.
    #[error("this grant was already used; an approval authorizes exactly one operation")]
    Replay,
    /// The claim token does not belong to this request.
    #[error("the claim token is missing or does not belong to this approval request")]
    TokenMismatch,
    /// The presented operation differs from the approved one.
    #[error("the presented operation differs from the approved operation")]
    OperationMismatch,
    /// The presented project differs from the approved one.
    #[error("the operation comes from a different project than the approved one")]
    ProjectMismatch,
    /// The presented agent differs from the approved one.
    #[error("the operation comes from a different agent than the approved one")]
    AgentMismatch,
    /// The grant failed signature or consistency verification.
    #[error("the authorization grant failed verification")]
    GrantInvalid,
    /// The key that would sign the decision is not a trusted policy signer.
    #[error("the unlocked key is not a trusted policy-signing key for this trust store")]
    UntrustedApprover,
    /// An agent tried to approve.
    #[error("agents cannot approve operations")]
    SelfApproval,
    /// Too many open requests.
    #[error("too many open approval requests; decide or cancel some first")]
    TooManyOpen,
    /// Too many duplicate claims on one request.
    #[error("this operation was requested too many times while pending")]
    TooManyClaims,
    /// A stored record is malformed or of an unknown schema.
    #[error("an approval record is malformed")]
    Corrupt,
    /// The store's schema is newer than this engine.
    #[error("the approval store was written by a newer AI Defender; upgrade the engine")]
    SchemaUnsupported,
    /// The store could not be read, written or locked.
    #[error("the approval store could not be {0}")]
    Unavailable(&'static str),
    /// A required audit record could not be written.
    #[error("the approval event could not be recorded in the audit log; nothing was authorized")]
    AuditFailed,
}

impl ApprovalError {
    /// Stable reason code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            ApprovalError::NotFound => "approval.not-found",
            ApprovalError::Ambiguous => "approval.ambiguous-id",
            ApprovalError::NotPending(_) => "approval.not-pending",
            ApprovalError::Expired => "approval.expired",
            ApprovalError::ReviewMismatch => "approval.review-mismatch",
            ApprovalError::PolicyChanged => "approval.policy-changed",
            ApprovalError::ProjectNotTrusted => "approval.project-not-trusted",
            ApprovalError::NotApproved(_) => "approval.not-approved",
            ApprovalError::Replay => "approval.replay",
            ApprovalError::TokenMismatch => "approval.token-mismatch",
            ApprovalError::OperationMismatch => "approval.operation-mismatch",
            ApprovalError::ProjectMismatch => "approval.project-mismatch",
            ApprovalError::AgentMismatch => "approval.agent-mismatch",
            ApprovalError::GrantInvalid => "approval.grant-invalid",
            ApprovalError::UntrustedApprover => "approval.untrusted-approver",
            ApprovalError::SelfApproval => "approval.self-approval",
            ApprovalError::TooManyOpen => "approval.too-many-open",
            ApprovalError::TooManyClaims => "approval.too-many-claims",
            ApprovalError::Corrupt => "approval.corrupt",
            ApprovalError::SchemaUnsupported => "approval.schema-unsupported",
            ApprovalError::Unavailable(_) => "approval.unavailable",
            ApprovalError::AuditFailed => "approval.audit-failed",
        }
    }
}
