//! The shape of a security decision.
//!
//! A decision always names the operation it concerns and the rule that produced it. A denial
//! additionally carries a reason, whether approval could change the outcome, and a safe
//! alternative. The constructors make every explanation field mandatory so a denial can never
//! reach a user half-explained.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::operation::OperationType;
use crate::risk::RiskLevel;
use crate::text::BoundedText;

/// Identifies the policy rule that produced a decision, for example
/// `git.push.protected_branches`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RuleId(BoundedText<128>);

impl RuleId {
    /// Validate and wrap a rule identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, crate::error::SecurityError> {
        BoundedText::new_non_empty(value).map(Self)
    }

    /// A rule identifier written as a literal in AgentGuard's own code. Infallible: the lossy
    /// constructor keeps a short printable literal intact. Never use it for external input.
    #[must_use]
    pub fn builtin(value: &'static str) -> Self {
        Self(BoundedText::lossy(value))
    }

    /// Borrow the identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The safe alternative offered with a denial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "text", rename_all = "kebab-case")]
pub enum Alternative {
    /// A concrete suggestion.
    Suggest(BoundedText<256>),
    /// The system has nothing safe to suggest; the prompt says so explicitly.
    NoneAvailable,
}

impl Alternative {
    /// Build a suggestion.
    pub fn suggest(text: impl Into<String>) -> Result<Self, crate::error::SecurityError> {
        BoundedText::new_non_empty(text).map(Self::Suggest)
    }
}

impl fmt::Display for Alternative {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Alternative::Suggest(t) => f.write_str(t.as_str()),
            Alternative::NoneAvailable => f.write_str("none available"),
        }
    }
}

/// The three authorization decisions. Ordered by restrictiveness, so `max` combines two
/// decisions into the stricter one: `Allow < RequireApproval < Deny`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    /// The action may proceed.
    Allow,
    /// The action may proceed only after a human approval bound to it.
    RequireApproval,
    /// The action may not proceed.
    Deny,
}

impl Decision {
    /// Wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "ALLOW",
            Decision::RequireApproval => "REQUIRE_APPROVAL",
            Decision::Deny => "DENY",
        }
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Outcome of evaluating a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum DecisionOutcome {
    /// The operation may proceed.
    Allow {
        /// Rule that allowed it.
        rule: RuleId,
    },
    /// The operation may not proceed.
    Deny {
        /// Rule that denied it.
        rule: RuleId,
        /// Why.
        reason: BoundedText<512>,
        /// Whether a human approval could change this outcome.
        approvable: bool,
        /// What to do instead.
        alternative: Alternative,
    },
    /// The operation may proceed only after a human approval.
    RequiresApproval {
        /// Rule that gated it.
        rule: RuleId,
        /// Risk level that determines the approval prompt's strictness.
        risk: RiskLevel,
    },
}

impl DecisionOutcome {
    /// The tri-state decision this outcome represents.
    #[must_use]
    pub const fn decision(&self) -> Decision {
        match self {
            DecisionOutcome::Allow { .. } => Decision::Allow,
            DecisionOutcome::Deny { .. } => Decision::Deny,
            DecisionOutcome::RequiresApproval { .. } => Decision::RequireApproval,
        }
    }
}

/// A decision about one operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityDecision {
    /// What was requested.
    pub operation: OperationType,
    /// The outcome.
    pub outcome: DecisionOutcome,
}

impl SecurityDecision {
    /// Allow `operation` under `rule`.
    #[must_use]
    pub const fn allow(operation: OperationType, rule: RuleId) -> Self {
        Self {
            operation,
            outcome: DecisionOutcome::Allow { rule },
        }
    }

    /// Deny `operation`. All explanation fields are required.
    #[must_use]
    pub const fn deny(
        operation: OperationType,
        rule: RuleId,
        reason: BoundedText<512>,
        approvable: bool,
        alternative: Alternative,
    ) -> Self {
        Self {
            operation,
            outcome: DecisionOutcome::Deny {
                rule,
                reason,
                approvable,
                alternative,
            },
        }
    }

    /// Require approval for `operation`.
    #[must_use]
    pub const fn requires_approval(
        operation: OperationType,
        rule: RuleId,
        risk: RiskLevel,
    ) -> Self {
        Self {
            operation,
            outcome: DecisionOutcome::RequiresApproval { rule, risk },
        }
    }

    /// Whether the operation may proceed without further action.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self.outcome, DecisionOutcome::Allow { .. })
    }

    /// Whether the operation is denied outright.
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        matches!(self.outcome, DecisionOutcome::Deny { .. })
    }

    /// The rule behind the decision.
    #[must_use]
    pub const fn rule(&self) -> &RuleId {
        match &self.outcome {
            DecisionOutcome::Allow { rule }
            | DecisionOutcome::Deny { rule, .. }
            | DecisionOutcome::RequiresApproval { rule, .. } => rule,
        }
    }

    /// Multi-line, user-facing explanation. For a denial this is the five-part message
    /// required by the specification: what, why, which rule, whether approval is possible,
    /// and the safe alternative.
    #[must_use]
    pub fn explanation(&self) -> String {
        match &self.outcome {
            DecisionOutcome::Allow { rule } => {
                format!("Allowed: {}\nRule:    {rule}", self.operation)
            }
            DecisionOutcome::Deny { rule, reason, approvable, alternative } => format!(
                "Denied:  {}\nReason:  {reason}\nRule:    {rule}\nApproval possible: {}\nAlternative: {alternative}",
                self.operation,
                if *approvable { "yes" } else { "no" },
            ),
            DecisionOutcome::RequiresApproval { rule, risk } => format!(
                "Requires approval: {}\nRule:    {rule}\nRisk:    {risk}",
                self.operation
            ),
        }
    }
}

impl fmt::Display for SecurityDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.explanation())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(s: &str) -> RuleId {
        RuleId::new(s).unwrap()
    }

    #[test]
    fn denial_explanation_has_all_five_parts() {
        let d = SecurityDecision::deny(
            OperationType::GitPush,
            rule("git.push.protected_branches"),
            BoundedText::new("destination branch is protected").unwrap(),
            false,
            Alternative::suggest("push to a feature branch and open a merge request").unwrap(),
        );
        let text = d.explanation();
        assert!(text.contains("Denied:  git-push"));
        assert!(text.contains("Reason:  destination branch is protected"));
        assert!(text.contains("Rule:    git.push.protected_branches"));
        assert!(text.contains("Approval possible: no"));
        assert!(text.contains("Alternative: push to a feature branch"));
        assert!(d.is_denied());
        assert!(!d.is_allowed());
    }

    #[test]
    fn none_available_alternative_is_explicit() {
        let d = SecurityDecision::deny(
            OperationType::Deployment,
            rule("deployment.default"),
            BoundedText::new("deployments are denied by default").unwrap(),
            true,
            Alternative::NoneAvailable,
        );
        assert!(d.explanation().contains("Alternative: none available"));
        assert!(d.explanation().contains("Approval possible: yes"));
    }

    #[test]
    fn allow_and_requires_approval() {
        let a = SecurityDecision::allow(OperationType::GitFetch, rule("git.fetch"));
        assert!(a.is_allowed());
        assert_eq!(a.rule().as_str(), "git.fetch");
        let r = SecurityDecision::requires_approval(
            OperationType::GitCommit,
            rule("git.commit"),
            RiskLevel::High,
        );
        assert!(!r.is_allowed());
        assert!(!r.is_denied());
        assert!(r.explanation().contains("Risk:    high"));
    }

    #[test]
    fn serde_round_trip() {
        let d = SecurityDecision::requires_approval(
            OperationType::NetworkAccess,
            rule("network.approvable"),
            RiskLevel::Medium,
        );
        let json = serde_json::to_string(&d).unwrap();
        let back: SecurityDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn decision_order_and_names() {
        assert!(Decision::Allow < Decision::RequireApproval);
        assert!(Decision::RequireApproval < Decision::Deny);
        assert_eq!(Decision::Allow.max(Decision::Deny), Decision::Deny);
        for d in [Decision::Allow, Decision::RequireApproval, Decision::Deny] {
            assert_eq!(
                serde_json::to_string(&d).unwrap(),
                format!("\"{}\"", d.as_str())
            );
        }
        assert!(serde_json::from_str::<Decision>("\"allow\"").is_err());
        let d = SecurityDecision::allow(OperationType::GitFetch, rule("git.fetch"));
        assert_eq!(d.outcome.decision(), Decision::Allow);
    }

    #[test]
    fn rule_id_rejects_empty() {
        assert!(RuleId::new("").is_err());
        assert!(RuleId::new("  ").is_err());
    }
}
