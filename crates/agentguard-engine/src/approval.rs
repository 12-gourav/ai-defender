//! In-process approval binding for the [`crate::Authorizer`].
//!
//! An approval is bound to one [`OperationFingerprint`], computed by [`crate::binding`] over
//! the canonical operation in its verified context. Changing any bound field changes the
//! fingerprint, so a granted approval no longer matches and the request is evaluated afresh.
//! Approvals are single-use and short-lived.
//!
//! The persistent, cross-process lifecycle (pending requests, human decisions, signed grants,
//! claim tokens, atomic consumption) is `agentguard_trust::approvals`. The in-memory store
//! here serves the authorizer's tests; the request protocol has no field that can carry an
//! approval, and a grant attributed to an agent principal is refused.

use std::sync::Mutex;
use std::time::Duration;

use agentguard_core::{
    AgentIdentity, ApprovalId, ApprovalTiming, Name, OperationFingerprint, SecurityContext,
};
use agentguard_proto::AuthorizationRequest;
use time::OffsetDateTime;

use crate::binding::operation_digest;

/// The fingerprint of `request` in its verified context `ctx`.
pub fn fingerprint(
    ctx: &SecurityContext,
    request: &AuthorizationRequest,
) -> Result<OperationFingerprint, ApprovalError> {
    operation_digest(ctx, request).map_err(|_| ApprovalError::Fingerprint)
}

/// Who decided an approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Approver {
    /// A human, identified by the trusted channel that collected the decision.
    Human {
        /// Account or display name from the trusted channel.
        name: Name,
    },
    /// An agent. Never accepted: agents cannot approve operations, their own or others'.
    Agent(AgentIdentity),
}

/// Approval failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ApprovalError {
    /// The approver is an agent.
    #[error("agents cannot approve operations")]
    SelfApproval,
    /// The validity window is zero or exceeds the maximum token validity.
    #[error("approval validity must be between 1 second and {} seconds", ApprovalTiming::MAX_TOKEN_VALIDITY.as_secs())]
    InvalidValidity,
    /// The fingerprint could not be computed.
    #[error("operation fingerprint could not be computed")]
    Fingerprint,
    /// The store is unavailable.
    #[error("approval store is unavailable")]
    Unavailable,
}

/// A human approval for one operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalGrant {
    id: ApprovalId,
    fingerprint: OperationFingerprint,
    approver: Name,
    granted_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

impl ApprovalGrant {
    /// Create a grant. Refused for an agent approver and for a validity outside
    /// `(0, ApprovalTiming::MAX_TOKEN_VALIDITY]`.
    pub fn new(
        fingerprint: OperationFingerprint,
        approver: Approver,
        granted_at: OffsetDateTime,
        validity: Duration,
    ) -> Result<Self, ApprovalError> {
        let Approver::Human { name } = approver else {
            return Err(ApprovalError::SelfApproval);
        };
        if validity.is_zero() || validity > ApprovalTiming::MAX_TOKEN_VALIDITY {
            return Err(ApprovalError::InvalidValidity);
        }
        let validity =
            time::Duration::try_from(validity).map_err(|_| ApprovalError::InvalidValidity)?;
        Ok(Self {
            id: ApprovalId::generate(),
            fingerprint,
            approver: name,
            granted_at,
            expires_at: granted_at + validity,
        })
    }

    /// The approval's identifier.
    #[must_use]
    pub const fn id(&self) -> ApprovalId {
        self.id
    }

    /// The operation it is bound to.
    #[must_use]
    pub const fn fingerprint(&self) -> &OperationFingerprint {
        &self.fingerprint
    }

    /// Who approved.
    #[must_use]
    pub const fn approver(&self) -> &Name {
        &self.approver
    }

    /// Whether the grant may be used at `now`: not before it was granted, and before expiry.
    #[must_use]
    pub fn is_live(&self, now: OffsetDateTime) -> bool {
        self.granted_at <= now && now < self.expires_at
    }
}

/// Storage for pending grants.
pub trait ApprovalStore: Send + Sync {
    /// Record a grant from a trusted channel.
    fn grant(&self, grant: ApprovalGrant) -> Result<(), ApprovalError>;

    /// Remove and return a live grant bound to `fingerprint`, if any. Consumption is the only
    /// way a grant authorises anything, so each grant authorises at most one execution.
    fn consume(
        &self,
        fingerprint: &OperationFingerprint,
        now: OffsetDateTime,
    ) -> Result<Option<ApprovalGrant>, ApprovalError>;
}

/// In-memory store. Persistent storage arrives with the SQLite state store.
#[derive(Debug, Default)]
pub struct MemoryApprovalStore {
    grants: Mutex<Vec<ApprovalGrant>>,
}

impl MemoryApprovalStore {
    /// Empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of grants held (live or not).
    pub fn len(&self) -> Result<usize, ApprovalError> {
        self.grants
            .lock()
            .map(|g| g.len())
            .map_err(|_| ApprovalError::Unavailable)
    }

    /// Whether the store holds no grants.
    pub fn is_empty(&self) -> Result<bool, ApprovalError> {
        self.len().map(|n| n == 0)
    }
}

impl ApprovalStore for MemoryApprovalStore {
    fn grant(&self, grant: ApprovalGrant) -> Result<(), ApprovalError> {
        self.grants
            .lock()
            .map_err(|_| ApprovalError::Unavailable)?
            .push(grant);
        Ok(())
    }

    fn consume(
        &self,
        fingerprint: &OperationFingerprint,
        now: OffsetDateTime,
    ) -> Result<Option<ApprovalGrant>, ApprovalError> {
        let mut grants = self.grants.lock().map_err(|_| ApprovalError::Unavailable)?;
        grants.retain(|g| now < g.expires_at);
        let position = grants
            .iter()
            .position(|g| &g.fingerprint == fingerprint && g.is_live(now));
        Ok(position.map(|i| grants.swap_remove(i)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentguard_core::AgentKind;

    fn human() -> Approver {
        Approver::Human {
            name: Name::new("dev").unwrap(),
        }
    }

    fn fp(b: u8) -> OperationFingerprint {
        OperationFingerprint::from_bytes([b; 32])
    }

    #[test]
    fn agents_cannot_grant() {
        let err = ApprovalGrant::new(
            fp(1),
            Approver::Agent(AgentIdentity::new(AgentKind::ClaudeCode)),
            OffsetDateTime::UNIX_EPOCH,
            Duration::from_secs(30),
        )
        .unwrap_err();
        assert_eq!(err, ApprovalError::SelfApproval);
    }

    #[test]
    fn validity_bounds() {
        let t = OffsetDateTime::UNIX_EPOCH;
        assert!(ApprovalGrant::new(fp(1), human(), t, Duration::ZERO).is_err());
        assert!(ApprovalGrant::new(fp(1), human(), t, Duration::from_secs(301)).is_err());
        assert!(ApprovalGrant::new(fp(1), human(), t, Duration::from_secs(300)).is_ok());
    }

    #[test]
    fn single_use_bound_and_expiring() {
        let t0 = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1);
        let store = MemoryApprovalStore::new();
        store
            .grant(ApprovalGrant::new(fp(1), human(), t0, Duration::from_secs(60)).unwrap())
            .unwrap();
        assert!(
            store.consume(&fp(2), t0).unwrap().is_none(),
            "wrong operation"
        );
        assert!(
            store
                .consume(&fp(1), t0 - time::Duration::seconds(1))
                .unwrap()
                .is_none(),
            "before grant"
        );
        assert!(store.consume(&fp(1), t0).unwrap().is_some());
        assert!(store.consume(&fp(1), t0).unwrap().is_none(), "single use");

        store
            .grant(ApprovalGrant::new(fp(3), human(), t0, Duration::from_secs(60)).unwrap())
            .unwrap();
        assert!(
            store
                .consume(&fp(3), t0 + time::Duration::seconds(60))
                .unwrap()
                .is_none(),
            "expired"
        );
        assert!(store.is_empty().unwrap(), "expired grants are purged");
    }
}
