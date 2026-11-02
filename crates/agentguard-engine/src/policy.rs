//! The policy decision interface and the standalone rule-set policy.
//!
//! A [`PolicyEvaluator`] maps a verified context, a normalised action and its risk assessment
//! to a decision. Evaluation must be deterministic: the same inputs and the same policy version
//! give the same verdict. No evaluator here consults a model, the network, or the clock.
//!
//! The engine treats the evaluator's verdict as one input: guards run first and cannot be
//! overridden, the engine never lets a verdict be less restrictive than its floors, and a
//! policy whose integrity has failed is never evaluated at all.

use agentguard_core::{
    Action, BoundedText, Decision, PolicyVersion, RequestId, RiskLevel, RuleId, SecurityContext,
};
use serde::Serialize;

use crate::classify::RiskAssessment;
use crate::normalize::{normalize, Confidence};
use crate::resource::DefaultResourceClassifier;
use crate::rules::{evaluate_layer, validate_rules, RuleError, Verdict};
pub use crate::rules::{
    ActionMatcher, Condition, Conflict, ConflictKind, MatchEffect, PolicyLayer, Rule, RuleInput,
    RuleMatch,
};

/// A policy's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyVerdict {
    /// The decision.
    pub decision: Decision,
    /// The rule that produced it.
    pub rule: RuleId,
    /// Why.
    pub reason: BoundedText<512>,
}

impl From<Verdict> for PolicyVerdict {
    fn from(v: Verdict) -> Self {
        Self {
            decision: v.decision,
            rule: v.rule,
            reason: v.reason,
        }
    }
}

/// A verdict with the evidence behind it.
#[derive(Debug, Clone)]
pub struct PolicyOutcome {
    /// The verdict.
    pub verdict: PolicyVerdict,
    /// The layer that produced it.
    pub layer: PolicyLayer,
    /// Every rule that matched, in every layer, and what it did.
    pub matched: Vec<RuleMatch>,
    /// Conflicts found and how they were resolved.
    pub conflicts: Vec<Conflict>,
}

impl PolicyOutcome {
    /// An outcome from an evaluator that reports no evidence.
    #[must_use]
    pub const fn opaque(verdict: PolicyVerdict) -> Self {
        Self {
            verdict,
            layer: PolicyLayer::Rules,
            matched: Vec::new(),
            conflicts: Vec::new(),
        }
    }
}

/// What an evaluator can say about the integrity of the policy it applies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum PolicyIntegrity {
    /// Loaded from trusted state whose signatures, pins and versions all verified.
    Verified,
    /// Built in code (tests, embedded defaults); not loaded from trusted state.
    Unattested,
    /// Verification failed. The engine refuses to evaluate and denies.
    Failed {
        /// The rule identifier to report.
        rule: RuleId,
        /// Why, without values.
        reason: String,
    },
}

/// Policy failures. The engine converts every one into a denial.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// Two rules share an identifier.
    #[error("rule identifiers must be unique")]
    DuplicateRuleId,
    /// An allow rule matches every action.
    #[error("an ALLOW rule must constrain at least one of category, operation, path, host, resource or executable")]
    UnboundedAllow,
    /// A matcher is invalid.
    #[error("invalid rule: {0}")]
    InvalidRule(&'static str),
    /// The policy could not be serialised to compute its version.
    #[error("policy could not be canonicalised")]
    Canonicalisation,
    /// The evaluator failed.
    #[error("policy evaluation failed")]
    Evaluation,
}

impl From<RuleError> for PolicyError {
    fn from(e: RuleError) -> Self {
        match e {
            RuleError::DuplicateId => PolicyError::DuplicateRuleId,
            RuleError::UnboundedAllow => PolicyError::UnboundedAllow,
            RuleError::InvalidMatcher(why) => PolicyError::InvalidRule(why),
        }
    }
}

/// Deterministic policy evaluation.
pub trait PolicyEvaluator: Send + Sync {
    /// The version of the policy this evaluator applies.
    fn version(&self) -> PolicyVersion;

    /// Decide a typed action in `ctx`, given its risk assessment.
    fn evaluate(
        &self,
        ctx: &SecurityContext,
        action: &Action,
        risk: &RiskAssessment,
    ) -> Result<PolicyVerdict, PolicyError>;

    /// Decide a normalised action, with evidence. The default delegates to
    /// [`PolicyEvaluator::evaluate`] and reports no evidence.
    fn evaluate_input(&self, input: &RuleInput<'_>) -> Result<PolicyOutcome, PolicyError> {
        self.evaluate(input.ctx, &input.action.action, input.risk)
            .map(PolicyOutcome::opaque)
    }

    /// The integrity of the policy. Defaults to [`PolicyIntegrity::Unattested`].
    fn integrity(&self) -> PolicyIntegrity {
        PolicyIntegrity::Unattested
    }

    /// Sensitive-resource configuration (protected patterns, custom detectors). `None` means
    /// the built-in detectors and name rules only.
    fn sensitivity(&self) -> Option<&crate::sensitive::Sensitivity> {
        None
    }
}

/// The default behaviour for an action no rule matched:
/// - read-only, low risk, not uncertain → `ALLOW`;
/// - critical → `DENY`;
/// - uncertain classification → `uncertain` (`REQUIRE_APPROVAL` unless configured to `DENY`);
/// - everything else → `REQUIRE_APPROVAL`.
#[must_use]
pub fn default_verdict(
    action: &Action,
    risk: &RiskAssessment,
    uncertain: Decision,
) -> PolicyVerdict {
    let (decision, rule, reason) = if action.is_read_only()
        && risk.level == RiskLevel::Low
        && risk.confidence != Confidence::Low
    {
        (
            Decision::Allow,
            "baseline.read-only-low-risk",
            "read-only, low-risk action",
        )
    } else if risk.level == RiskLevel::Critical {
        (
            Decision::Deny,
            "baseline.critical",
            "critical-risk actions are denied unless a policy rule requires approval for them",
        )
    } else if risk.confidence == Confidence::Low {
        (
            uncertain.max(Decision::RequireApproval),
            "baseline.uncertain",
            "the action could not be classified with confidence; treated conservatively",
        )
    } else {
        (
            Decision::RequireApproval,
            "baseline.elevated",
            "actions with side effects or elevated risk require approval unless a policy rule allows them",
        )
    };
    PolicyVerdict {
        decision,
        rule: RuleId::builtin(rule),
        reason: BoundedText::lossy(reason),
    }
}

/// A single list of rules plus the default behaviour.
///
/// Combination follows [`crate::rules`]: a matching `DENY` wins; otherwise the highest-priority
/// matching rules decide, the more restrictive among them winning; ties cite the smallest
/// identifier. Reordering the rules never changes a verdict. With every priority at 0 this is
/// plain "most restrictive matching rule wins".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSetPolicy {
    rules: Vec<Rule>,
    version: PolicyVersion,
}

#[derive(Serialize)]
struct Canonical<'a> {
    schema: &'static str,
    rules: &'a [Rule],
}

impl RuleSetPolicy {
    /// Schema identifier mixed into the version hash.
    pub const SCHEMA: &'static str = "agentguard.ruleset.v1";

    /// Validate `rules` and compute the policy version.
    pub fn new(mut rules: Vec<Rule>) -> Result<Self, PolicyError> {
        validate_rules(&rules)?;
        // The version must not depend on the order rules were written in, because the
        // verdict does not.
        rules.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
        let canonical = serde_json::to_vec(&Canonical {
            schema: Self::SCHEMA,
            rules: &rules,
        })
        .map_err(|_| PolicyError::Canonicalisation)?;
        Ok(Self {
            rules,
            version: PolicyVersion::compute(&canonical),
        })
    }

    /// The default behaviour alone, with no rules.
    pub fn baseline() -> Result<Self, PolicyError> {
        Self::new(Vec::new())
    }

    /// The rules, sorted by identifier.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

/// Normalise a typed action lexically (no symlink resolution, no protected roots) for
/// evaluators called through the action-level [`PolicyEvaluator::evaluate`].
pub(crate) fn evaluate_via_input(
    evaluator: &dyn PolicyEvaluator,
    ctx: &SecurityContext,
    action: &Action,
    risk: &RiskAssessment,
) -> Result<PolicyVerdict, PolicyError> {
    let normalised = normalize(
        RequestId::generate(),
        action,
        ctx,
        &DefaultResourceClassifier::default(),
        None,
    );
    evaluator
        .evaluate_input(&RuleInput {
            ctx,
            action: &normalised,
            risk,
        })
        .map(|o| o.verdict)
}

impl PolicyEvaluator for RuleSetPolicy {
    fn version(&self) -> PolicyVersion {
        self.version
    }

    fn evaluate(
        &self,
        ctx: &SecurityContext,
        action: &Action,
        risk: &RiskAssessment,
    ) -> Result<PolicyVerdict, PolicyError> {
        evaluate_via_input(self, ctx, action, risk)
    }

    fn evaluate_input(&self, input: &RuleInput<'_>) -> Result<PolicyOutcome, PolicyError> {
        let outcome = evaluate_layer(&self.rules, PolicyLayer::Rules, input);
        Ok(match outcome.verdict {
            Some(verdict) => PolicyOutcome {
                verdict: verdict.into(),
                layer: PolicyLayer::Rules,
                matched: outcome.matched,
                conflicts: outcome.conflicts,
            },
            None => PolicyOutcome {
                verdict: default_verdict(
                    &input.action.action,
                    input.risk,
                    Decision::RequireApproval,
                ),
                layer: PolicyLayer::Default,
                matched: Vec::new(),
                conflicts: Vec::new(),
            },
        })
    }
}
