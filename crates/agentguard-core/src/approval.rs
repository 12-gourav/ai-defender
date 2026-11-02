//! Approval scopes, statuses, decision kinds and timing bounds.
//!
//! The lifecycle itself (requests, grants, tokens, consumption) lives in the trust store
//! (`agentguard_trust::approvals`). This module pins down the vocabulary and the numeric bounds
//! so no layer can drift from the reviewed design.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::SecurityError;
use crate::operation::OperationType;

/// SHA-256 binding an approval to one exact operation in one exact context (action, agent,
/// project, session, working directory, policy version). Any change to those produces a
/// different fingerprint, so an approval can never be applied to a different operation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OperationFingerprint([u8; 32]);

impl OperationFingerprint {
    /// Wrap a digest computed by the engine.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parse 64 hexadecimal characters.
    pub fn from_hex(value: &str) -> Result<Self, SecurityError> {
        let mut bytes = [0u8; 32];
        if value.len() != 64 || hex::decode_to_slice(value, &mut bytes).is_err() {
            return Err(SecurityError::InvalidIdentifier {
                field: "OperationFingerprint",
                rule: "must be 64 hexadecimal characters",
            });
        }
        Ok(Self(bytes))
    }

    /// Lowercase hexadecimal form.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl TryFrom<String> for OperationFingerprint {
    type Error = SecurityError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_hex(&value)
    }
}

impl From<OperationFingerprint> for String {
    fn from(value: OperationFingerprint) -> Self {
        value.to_hex()
    }
}

impl fmt::Debug for OperationFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.to_hex();
        write!(f, "OperationFingerprint({})", hex.get(..12).unwrap_or(&hex))
    }
}

impl fmt::Display for OperationFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// How long an approval lasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalScope {
    /// Exactly one operation.
    SingleOperation,
    /// Repeated operations of the same kind and target within the current task.
    CurrentTask,
    /// Repeated operations of the same kind and target within the current session.
    CurrentSession,
}

impl ApprovalScope {
    /// Validate that `scope` may be used for `operation`.
    pub fn check_permitted(self, operation: OperationType) -> Result<(), SecurityError> {
        if self == ApprovalScope::SingleOperation || operation.permits_reusable_scope() {
            Ok(())
        } else {
            Err(SecurityError::ScopeNotPermitted {
                scope: self,
                operation,
            })
        }
    }

    /// Kebab-case name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ApprovalScope::SingleOperation => "single-operation",
            ApprovalScope::CurrentTask => "current-task",
            ApprovalScope::CurrentSession => "current-session",
        }
    }
}

impl fmt::Display for ApprovalScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Terminal states of an approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalDecisionKind {
    /// The developer approved.
    Approved,
    /// The developer rejected.
    Rejected,
    /// Nobody answered before the pending timeout, or the token aged out before consumption.
    Expired,
    /// Revoked, or invalidated by session end or a policy change.
    Cancelled,
}

/// Where an approval request is in its lifecycle.
///
/// ```text
/// pending ─┬─ approve ─> approved ─┬─ consume ─> consumed
///          ├─ reject ──> rejected  ├─ grant expires ─> expired
///          ├─ cancel ──> cancelled └─ revoke / policy change ─> cancelled
///          └─ timeout ─> expired
/// ```
///
/// Every transition is one-way; nothing returns to `pending` or `approved`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalStatus {
    /// Waiting for a human decision.
    Pending,
    /// Approved; the grant is live until consumed, expired or revoked.
    Approved,
    /// A human rejected it.
    Rejected,
    /// Nobody decided before the pending timeout, or the grant aged out unused.
    Expired,
    /// Cancelled before a decision, or its grant was revoked or invalidated.
    Cancelled,
    /// Its grant authorized one operation.
    Consumed,
}

impl ApprovalStatus {
    /// Kebab-case name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ApprovalStatus::Pending => "pending",
            ApprovalStatus::Approved => "approved",
            ApprovalStatus::Rejected => "rejected",
            ApprovalStatus::Expired => "expired",
            ApprovalStatus::Cancelled => "cancelled",
            ApprovalStatus::Consumed => "consumed",
        }
    }

    /// Whether no further transition is possible.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, ApprovalStatus::Pending | ApprovalStatus::Approved)
    }
}

impl fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The two time limits in the approval lifecycle (Phase 0 review, C5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalTiming {
    /// How long a prompt waits for the developer before it expires.
    pub pending_timeout: Duration,
    /// How long an approved token remains valid before it must be consumed. Consumption is
    /// atomic with execution start, so this is short.
    pub token_validity: Duration,
}

impl ApprovalTiming {
    /// Default pending timeout: five minutes.
    pub const DEFAULT_PENDING_TIMEOUT: Duration = Duration::from_mins(5);
    /// Default validity of an issued grant: two minutes.
    pub const DEFAULT_TOKEN_VALIDITY: Duration = Duration::from_mins(2);
    /// Upper bound any policy level may set for the pending timeout: fifteen minutes.
    pub const MAX_PENDING_TIMEOUT: Duration = Duration::from_mins(15);
    /// Upper bound any policy level may set for token validity: five minutes.
    pub const MAX_TOKEN_VALIDITY: Duration = Duration::from_mins(5);

    /// Build a timing, enforcing the bounds.
    pub fn new(pending_timeout: Duration, token_validity: Duration) -> Result<Self, SecurityError> {
        if pending_timeout.is_zero() {
            return Err(SecurityError::ApprovalTimingOutOfRange {
                detail: "pending timeout must be greater than zero",
            });
        }
        if pending_timeout > Self::MAX_PENDING_TIMEOUT {
            return Err(SecurityError::ApprovalTimingOutOfRange {
                detail: "pending timeout exceeds the maximum of 900 seconds",
            });
        }
        if token_validity.is_zero() {
            return Err(SecurityError::ApprovalTimingOutOfRange {
                detail: "token validity must be greater than zero",
            });
        }
        if token_validity > Self::MAX_TOKEN_VALIDITY {
            return Err(SecurityError::ApprovalTimingOutOfRange {
                detail: "token validity exceeds the maximum of 300 seconds",
            });
        }
        Ok(Self {
            pending_timeout,
            token_validity,
        })
    }

    /// Return a timing no looser than `self` in either value. Used when a lower policy layer
    /// proposes values: the result never exceeds the higher layer.
    #[must_use]
    pub fn tightened_by(self, other: Self) -> Self {
        Self {
            pending_timeout: self.pending_timeout.min(other.pending_timeout),
            token_validity: self.token_validity.min(other.token_validity),
        }
    }
}

impl Default for ApprovalTiming {
    fn default() -> Self {
        Self {
            pending_timeout: Self::DEFAULT_PENDING_TIMEOUT,
            token_validity: Self::DEFAULT_TOKEN_VALIDITY,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_hex_round_trip() {
        let f = OperationFingerprint::from_bytes([7u8; 32]);
        assert_eq!(OperationFingerprint::from_hex(&f.to_hex()).unwrap(), f);
        assert!(OperationFingerprint::from_hex("07").is_err());
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(
            serde_json::from_str::<OperationFingerprint>(&json).unwrap(),
            f
        );
    }

    #[test]
    fn status_terminality() {
        assert!(!ApprovalStatus::Pending.is_terminal());
        assert!(!ApprovalStatus::Approved.is_terminal());
        for s in [
            ApprovalStatus::Rejected,
            ApprovalStatus::Expired,
            ApprovalStatus::Cancelled,
            ApprovalStatus::Consumed,
        ] {
            assert!(s.is_terminal());
            assert_eq!(serde_json::to_value(s).unwrap(), s.as_str());
        }
    }

    #[test]
    fn single_operation_always_permitted() {
        for op in OperationType::ALL {
            assert!(ApprovalScope::SingleOperation.check_permitted(op).is_ok());
        }
    }

    #[test]
    fn reusable_scopes_only_for_network_and_filesystem() {
        assert!(ApprovalScope::CurrentTask
            .check_permitted(OperationType::NetworkAccess)
            .is_ok());
        assert!(ApprovalScope::CurrentSession
            .check_permitted(OperationType::FilesystemAccess)
            .is_ok());
        for op in [
            OperationType::GitPush,
            OperationType::GitCommit,
            OperationType::DependencyInstall,
            OperationType::DatabaseMutation,
            OperationType::Deployment,
            OperationType::PolicyModification,
            OperationType::HostExec,
        ] {
            assert_eq!(
                ApprovalScope::CurrentTask.check_permitted(op),
                Err(SecurityError::ScopeNotPermitted {
                    scope: ApprovalScope::CurrentTask,
                    operation: op
                })
            );
        }
    }

    #[test]
    fn timing_defaults_and_bounds() {
        let d = ApprovalTiming::default();
        assert_eq!(d.pending_timeout, Duration::from_secs(300));
        assert_eq!(d.token_validity, Duration::from_secs(120));
        assert!(ApprovalTiming::new(Duration::ZERO, Duration::from_secs(1)).is_err());
        assert!(ApprovalTiming::new(Duration::from_secs(901), Duration::from_secs(1)).is_err());
        assert!(ApprovalTiming::new(Duration::from_secs(1), Duration::ZERO).is_err());
        assert!(ApprovalTiming::new(Duration::from_secs(1), Duration::from_secs(301)).is_err());
        assert!(ApprovalTiming::new(Duration::from_mins(15), Duration::from_mins(5)).is_ok());
    }

    #[test]
    fn tightening_never_loosens() {
        let org = ApprovalTiming::new(Duration::from_mins(5), Duration::from_secs(30)).unwrap();
        let project = ApprovalTiming::new(Duration::from_mins(15), Duration::from_mins(5)).unwrap();
        let effective = org.tightened_by(project);
        assert_eq!(effective, org);
        let stricter =
            ApprovalTiming::new(Duration::from_secs(60), Duration::from_secs(10)).unwrap();
        assert_eq!(org.tightened_by(stricter), stricter);
    }
}
