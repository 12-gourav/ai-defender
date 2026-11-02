//! Trust errors. Messages name the trusted object and the rule that failed; they never contain
//! key material, signatures or policy content.

use agentguard_audit::TrustEventKind;

/// Why a trust operation failed. Every variant fails closed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TrustError {
    /// A trusted object is missing.
    #[error("{object} is missing")]
    Unavailable {
        /// The trusted object.
        object: &'static str,
    },
    /// A trusted object could not be read or written.
    #[error("{object} could not be {action}")]
    Io {
        /// The trusted object.
        object: &'static str,
        /// What was attempted.
        action: &'static str,
    },
    /// A trusted file or directory has unsafe type, ownership or permissions.
    #[error("{object} is insecure: {rule}")]
    Insecure {
        /// The trusted object.
        object: &'static str,
        /// The rule it broke.
        rule: &'static str,
    },
    /// A trusted object is not valid for its schema or exceeds the size limit.
    #[error("{object} is malformed")]
    Malformed {
        /// The trusted object.
        object: &'static str,
    },
    /// A signature does not verify.
    #[error("{object} has an invalid signature")]
    SignatureInvalid {
        /// The trusted object.
        object: &'static str,
    },
    /// A signature was made by a key that is not trusted for this object.
    #[error("{object} is signed by an untrusted key")]
    UntrustedSigner {
        /// The trusted object.
        object: &'static str,
    },
    /// The trusted keys changed without the root key's authorisation.
    #[error("unauthorised key change: {rule}")]
    KeyChange {
        /// What did not match.
        rule: &'static str,
    },
    /// An older version was presented in place of the pinned one.
    #[error("{object} rolled back from version {pinned} to {found}")]
    Rollback {
        /// The trusted object.
        object: &'static str,
        /// The version found.
        found: u64,
        /// The pinned version.
        pinned: u64,
    },
    /// A newer version appeared without going through an authorised update.
    #[error("{object} changed to version {found} without an authorised update (pinned {pinned})")]
    UnexpectedVersion {
        /// The trusted object.
        object: &'static str,
        /// The version found.
        found: u64,
        /// The pinned version.
        pinned: u64,
    },
    /// The pinned version was replaced with different content.
    #[error("{object} was replaced: content does not match the pinned hash")]
    Replaced {
        /// The trusted object.
        object: &'static str,
    },
    /// A trusted object is internally inconsistent.
    #[error("{object} is inconsistent: {rule}")]
    Inconsistent {
        /// The trusted object.
        object: &'static str,
        /// The rule it broke.
        rule: &'static str,
    },
    /// Initialisation found existing trusted state and refuses to overwrite it.
    #[error("trusted state already exists; refusing to regenerate it")]
    AlreadyInitialized,
    /// An agent tried to authorise a trust change.
    #[error("agents cannot authorise trust changes")]
    SelfApproval,
    /// The signing key offered for an update is not authorised for it.
    #[error("the signing key is not authorised for this operation")]
    UnauthorizedSigner,
    /// A proposed policy failed validation.
    #[error("policy rejected: {rule}")]
    PolicyRejected {
        /// The rule it broke.
        rule: &'static str,
    },
    /// A project registration was rejected.
    #[error("project rejected: {rule}")]
    ProjectRejected {
        /// The rule it broke.
        rule: &'static str,
    },
    /// A value could not be canonically serialised.
    #[error("canonical serialisation failed")]
    Canonicalisation,
}

impl TrustError {
    /// The audit event this failure is recorded as.
    #[must_use]
    pub const fn event_kind(&self) -> TrustEventKind {
        match self {
            TrustError::Unavailable { .. } | TrustError::Io { .. } => {
                TrustEventKind::TrustedStateUnavailable
            }
            TrustError::SignatureInvalid { .. } | TrustError::UntrustedSigner { .. } => {
                TrustEventKind::SignatureInvalid
            }
            TrustError::KeyChange { .. } => TrustEventKind::KeyChangeRejected,
            TrustError::Rollback { .. } => TrustEventKind::RollbackDetected,
            TrustError::Insecure { .. }
            | TrustError::Malformed { .. }
            | TrustError::UnexpectedVersion { .. }
            | TrustError::Replaced { .. }
            | TrustError::Inconsistent { .. }
            | TrustError::Canonicalisation => TrustEventKind::IntegrityFailed,
            TrustError::AlreadyInitialized
            | TrustError::SelfApproval
            | TrustError::UnauthorizedSigner
            | TrustError::PolicyRejected { .. }
            | TrustError::ProjectRejected { .. } => TrustEventKind::PolicyUpdateRejected,
        }
    }

    /// Whether this failure means the stored trusted state cannot be relied on (as opposed
    /// to a rejected request against healthy state).
    #[must_use]
    pub const fn is_integrity_failure(&self) -> bool {
        !matches!(self.event_kind(), TrustEventKind::PolicyUpdateRejected)
    }
}
