//! Execution errors. Every variant means the command did not run, except
//! [`ExecutionError::OutcomeUnrecorded`], which reports that it ran but its outcome could not be
//! recorded and must not be treated as a success.

/// Why an execution request failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecutionError {
    /// The request is malformed.
    #[error("invalid execution request: {0}")]
    InvalidRequest(&'static str),
    /// The working directory is unusable.
    #[error("the working directory {0}")]
    WorkingDirectory(&'static str),
    /// Trusted state did not verify, or is missing.
    #[error("{0}")]
    Trust(String),
    /// The verified identity of the agent or project could not be established.
    #[error("{message} ({rule})")]
    Identity {
        /// Stable rule identifier.
        rule: &'static str,
        /// Why.
        message: String,
    },
    /// The audit log could not be written, so nothing was executed.
    #[error("the audit log could not be written, so the command was not run")]
    AuditUnavailable,
    /// The execution record could not be written, so nothing was executed.
    #[error("the execution record could not be written, so the command was not run")]
    RecordUnavailable,
    /// The idempotency key was used before.
    #[error(
        "this request was already submitted (execution {0}); AI Defender never runs a request twice"
    )]
    Duplicate(String),
    /// Redeeming the approval failed.
    #[error("{message}")]
    Approval {
        /// Protocol error class.
        class: ApprovalFailure,
        /// Why, with the stable reason code.
        message: String,
    },
    /// The command ran but its outcome could not be recorded. Not a success.
    #[error("the command ran ({outcome}) but its outcome could not be recorded; treat the result as unverified")]
    OutcomeUnrecorded {
        /// What the process did, as far as is known.
        outcome: String,
    },
    /// An internal failure; nothing was executed.
    #[error("internal error: {0}")]
    Internal(&'static str),
}

/// How an approval redemption failed, for mapping onto protocol error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalFailure {
    /// The approval does not exist.
    NotFound,
    /// The approval is in the wrong state, expired, or was invalidated.
    Conflict,
    /// The grant does not authorize this operation (mismatch, replay, wrong token or agent).
    Denied,
    /// The approval store is corrupt.
    Integrity,
    /// The approval store's audit write failed.
    Audit,
    /// The store could not be used.
    Io,
}
