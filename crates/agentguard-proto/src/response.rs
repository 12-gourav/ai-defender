//! Authorization responses.

use agentguard_core::{
    ApprovalScope, BoundedText, Decision, OperationFingerprint, PolicyVersion, RequestId,
    RiskLevel, RuleId,
};
use serde::{Deserialize, Serialize};

use crate::PROTOCOL_VERSION;

/// Whether, and how, a human must approve before the action may proceed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequirement {
    /// True exactly when the decision is `REQUIRE_APPROVAL`.
    pub required: bool,
    /// The operation an approval must be bound to.
    pub fingerprint: Option<OperationFingerprint>,
    /// The scope an approval would carry. Always single-operation in this protocol version.
    pub scope: Option<ApprovalScope>,
}

impl ApprovalRequirement {
    /// No approval involved.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            required: false,
            fingerprint: None,
            scope: None,
        }
    }

    /// An approval bound to `fingerprint` is required.
    #[must_use]
    pub const fn bound_to(fingerprint: OperationFingerprint) -> Self {
        Self {
            required: true,
            fingerprint: Some(fingerprint),
            scope: Some(ApprovalScope::SingleOperation),
        }
    }
}

/// The engine's answer to one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationResponse {
    /// Protocol version.
    pub protocol: String,
    /// The request's ID. `None` only when the request was rejected before an ID could be read.
    pub request_id: Option<RequestId>,
    /// The decision.
    pub decision: Decision,
    /// Risk classification, independent of the decision. Requests that could not be classified
    /// report `critical`.
    pub risk: RiskLevel,
    /// Why.
    pub reason: BoundedText<512>,
    /// The rule that produced the decision.
    pub rule: RuleId,
    /// The policy version the decision was made under, when a policy was consulted.
    pub policy_version: Option<PolicyVersion>,
    /// Approval requirement.
    pub approval: ApprovalRequirement,
}

/// Inconsistencies [`AuthorizationResponse::check`] can find.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ResponseError {
    /// The protocol field is not this build's version.
    #[error("unsupported protocol version")]
    Protocol,
    /// `approval.required` disagrees with the decision, or an approval is required without
    /// a fingerprint to bind it to.
    #[error("approval requirement is inconsistent with the decision")]
    ApprovalMismatch,
}

impl AuthorizationResponse {
    /// Build a response. The approval requirement is derived from the decision so the two can
    /// never disagree: `REQUIRE_APPROVAL` needs a fingerprint, and the other decisions drop it.
    /// A `REQUIRE_APPROVAL` without a fingerprint becomes `DENY`.
    #[must_use]
    pub fn new(
        request_id: Option<RequestId>,
        decision: Decision,
        risk: RiskLevel,
        rule: RuleId,
        reason: &str,
        policy_version: Option<PolicyVersion>,
        fingerprint: Option<OperationFingerprint>,
    ) -> Self {
        let (decision, approval) = match (decision, fingerprint) {
            (Decision::RequireApproval, Some(f)) => (decision, ApprovalRequirement::bound_to(f)),
            (Decision::RequireApproval, None) => (Decision::Deny, ApprovalRequirement::none()),
            (other, _) => (other, ApprovalRequirement::none()),
        };
        Self {
            protocol: PROTOCOL_VERSION.to_owned(),
            request_id,
            decision,
            risk,
            reason: BoundedText::lossy(reason),
            rule,
            policy_version,
            approval,
        }
    }

    /// Check internal consistency. Clients should call this on every response they receive and
    /// treat a failure as `DENY`.
    pub fn check(&self) -> Result<(), ResponseError> {
        if self.protocol != PROTOCOL_VERSION {
            return Err(ResponseError::Protocol);
        }
        let wants = self.decision == Decision::RequireApproval;
        if self.approval.required != wants || (wants && self.approval.fingerprint.is_none()) {
            return Err(ResponseError::ApprovalMismatch);
        }
        Ok(())
    }

    /// Whether the client may let the action proceed now. False for anything but a consistent
    /// `ALLOW`.
    #[must_use]
    pub fn permits_execution(&self) -> bool {
        self.decision == Decision::Allow && self.check().is_ok()
    }
}
