//! The policy hierarchy, built from verified trusted state.
//!
//! ```text
//! 1. mandatory baseline   built in (agentguard_engine::profile); floors no layer can lower
//! 2. global policy        trusted organisation/user layer; may allow, approve-gate or deny,
//!                         and selects and configures the security profile
//! 3. project policy       may only add restrictions (REQUIRE_APPROVAL or DENY); floors
//! 4. profile rules        action-specific defaults beneath the global layer
//! 5. default behaviour    for actions nothing matched
//! 6. runtime request      cannot express rules at all (the protocol has no such field)
//! ```
//!
//! Precedence and conflict resolution are implemented by
//! [`agentguard_engine::LayeredPolicy`]; this module validates the trusted documents, namespaces
//! their rule identifiers (`global:`, `project:`), and marks the result as built from verified
//! state. Merging is order-independent and the effective version is a hash of the canonical,
//! identifier-sorted layers.

use agentguard_core::{Action, Decision, PolicyVersion, RuleId, SecurityContext};
use agentguard_engine::policy::{PolicyError, PolicyOutcome};
use agentguard_engine::rules::{validate_rules, RuleError};
use agentguard_engine::{
    LayeredPolicy, PolicyEvaluator, PolicyIntegrity, PolicyVerdict, RiskAssessment, Rule, RuleInput,
};
use serde::Serialize;

pub use agentguard_engine::profile::{mandatory_rules, MANDATORY_BASELINE_VERSION};

use crate::canonical::VersionRef;
use crate::error::TrustError;
use crate::manifest::{PolicyDocument, MAX_RULES};

/// A policy layer held in the trust store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// The trusted organisation/user layer.
    Global,
    /// A project's restrictions.
    Project,
}

impl Layer {
    const fn prefix(self) -> &'static str {
        match self {
            Layer::Global => "global:",
            Layer::Project => "project:",
        }
    }
}

const UNBOUNDED: &str =
    "an ALLOW rule must constrain category, operation, path, host, resource or executable";

/// Validate a layer's document. Project layers may not contain `ALLOW` rules or select a
/// profile.
pub fn validate_document(layer: Layer, document: &PolicyDocument) -> Result<(), TrustError> {
    if document.rules.len() > MAX_RULES {
        return Err(TrustError::PolicyRejected {
            rule: "too many rules",
        });
    }
    if layer == Layer::Project {
        if document.rules.iter().any(|r| r.decision == Decision::Allow) {
            return Err(TrustError::PolicyRejected {
                rule: "project policies may only add restrictions; ALLOW rules are not permitted",
            });
        }
        if document.profile.is_some() {
            return Err(TrustError::PolicyRejected {
                rule: "only the global policy may select or configure the security profile",
            });
        }
        if document.approvals.is_some() {
            return Err(TrustError::PolicyRejected {
                rule: "only the global policy may configure approval timing",
            });
        }
        if document.execution.is_some() {
            return Err(TrustError::PolicyRejected {
                rule: "only the global policy may configure managed execution",
            });
        }
    }
    if let Some(execution) = &document.execution {
        execution
            .validate()
            .map_err(|rule| TrustError::PolicyRejected { rule })?;
    }
    document
        .approval_timing()
        .map_err(|rule| TrustError::PolicyRejected { rule })?;
    if let Some(sensitive) = &document.sensitive {
        sensitive
            .validate()
            .map_err(|rule| TrustError::PolicyRejected { rule })?;
    }
    if let Some(profile) = &document.profile {
        profile
            .validate()
            .map_err(|rule| TrustError::PolicyRejected { rule })?;
    }
    validate_rules(&namespaced(layer, document)?).map_err(|e| TrustError::PolicyRejected {
        rule: match e {
            RuleError::DuplicateId => "rule identifiers must be unique within a layer",
            RuleError::UnboundedAllow => UNBOUNDED,
            RuleError::InvalidMatcher(why) => why,
        },
    })
}

fn namespaced(layer: Layer, document: &PolicyDocument) -> Result<Vec<Rule>, TrustError> {
    document
        .rules
        .iter()
        .map(|r| {
            let id = RuleId::new(format!("{}{}", layer.prefix(), r.id)).map_err(|_| {
                TrustError::PolicyRejected {
                    rule: "rule identifier too long",
                }
            })?;
            Ok(Rule { id, ..r.clone() })
        })
        .collect()
}

fn policy_error(e: &PolicyError) -> TrustError {
    TrustError::PolicyRejected {
        rule: match e {
            PolicyError::DuplicateRuleId => "rule identifiers must be unique within a layer",
            PolicyError::UnboundedAllow => UNBOUNDED,
            PolicyError::InvalidRule(why) => why,
            _ => "policy could not be built",
        },
    }
}

/// Where the layers of an effective policy came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Provenance {
    /// Mandatory baseline version.
    pub mandatory: &'static str,
    /// Global manifest version.
    pub global: Option<VersionRef>,
    /// Project manifest version.
    pub project: Option<VersionRef>,
}

/// Mandatory + global + project + profile + defaults, built from verified trusted state.
#[derive(Debug, Clone)]
pub struct EffectivePolicy {
    inner: LayeredPolicy,
    provenance: Provenance,
}

impl EffectivePolicy {
    /// Merge the layers. Fails if any layer is invalid; never produces a partial policy.
    pub fn merge(
        global: &PolicyDocument,
        project: Option<&PolicyDocument>,
        provenance: Provenance,
    ) -> Result<Self, TrustError> {
        validate_document(Layer::Global, global)?;
        let empty = PolicyDocument::default();
        let project_doc = project.unwrap_or(&empty);
        validate_document(Layer::Project, project_doc)?;
        let inner = LayeredPolicy::new(
            namespaced(Layer::Global, global)?,
            namespaced(Layer::Project, project_doc)?,
            global.profile.clone().unwrap_or_default(),
        )
        .map_err(|e| policy_error(&e))?;
        let sensitivity = agentguard_engine::Sensitivity::merge(&[
            global.sensitive.as_ref(),
            project_doc.sensitive.as_ref(),
        ])
        .map_err(|rule| TrustError::PolicyRejected { rule })?;
        let inner = inner
            .with_sensitivity(sensitivity)
            .map_err(|e| policy_error(&e))?
            .with_integrity(PolicyIntegrity::Verified);
        Ok(Self { inner, provenance })
    }

    /// Where the layers came from.
    #[must_use]
    pub const fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    /// The layered policy as evaluated.
    #[must_use]
    pub const fn layered(&self) -> &LayeredPolicy {
        &self.inner
    }
}

impl PolicyEvaluator for EffectivePolicy {
    fn version(&self) -> PolicyVersion {
        self.inner.version()
    }

    fn evaluate(
        &self,
        ctx: &SecurityContext,
        action: &Action,
        risk: &RiskAssessment,
    ) -> Result<PolicyVerdict, PolicyError> {
        self.inner.evaluate(ctx, action, risk)
    }

    fn evaluate_input(&self, input: &RuleInput<'_>) -> Result<PolicyOutcome, PolicyError> {
        self.inner.evaluate_input(input)
    }

    fn integrity(&self) -> PolicyIntegrity {
        self.inner.integrity()
    }

    fn sensitivity(&self) -> Option<&agentguard_engine::Sensitivity> {
        self.inner.sensitivity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentguard_core::ActionCategory;
    use agentguard_engine::{ActionMatcher, ProfileSettings};

    #[test]
    fn mandatory_rules_build_and_have_unique_ids() {
        assert!(validate_rules(&mandatory_rules()).is_ok());
    }

    #[test]
    fn project_allow_rules_and_profiles_rejected() {
        let doc = PolicyDocument {
            rules: vec![Rule::new(
                RuleId::new("x").unwrap(),
                Decision::Allow,
                "r",
                ActionMatcher {
                    category: Some(ActionCategory::Terminal),
                    ..ActionMatcher::default()
                },
            )],
            profile: None,
            approvals: None,
            sensitive: None,
            execution: None,
        };
        assert!(validate_document(Layer::Global, &doc).is_ok());
        assert!(matches!(
            validate_document(Layer::Project, &doc),
            Err(TrustError::PolicyRejected { .. })
        ));
        let with_profile = PolicyDocument {
            rules: Vec::new(),
            profile: Some(ProfileSettings::default()),
            approvals: None,
            sensitive: None,
            execution: None,
        };
        assert!(validate_document(Layer::Global, &with_profile).is_ok());
        assert!(validate_document(Layer::Project, &with_profile).is_err());
    }

    #[test]
    fn approval_timing_is_global_only_and_bounded() {
        let timing = |pending, grant| PolicyDocument {
            approvals: Some(crate::manifest::ApprovalSettings {
                pending_timeout_seconds: pending,
                grant_validity_seconds: grant,
            }),
            ..PolicyDocument::default()
        };
        let ok = timing(Some(60), Some(30));
        assert!(validate_document(Layer::Global, &ok).is_ok());
        assert_eq!(
            ok.approval_timing().unwrap().token_validity,
            std::time::Duration::from_secs(30)
        );
        assert!(validate_document(Layer::Project, &ok).is_err());
        for (pending, grant) in [(Some(901), None), (None, Some(301)), (Some(0), None)] {
            assert!(
                validate_document(Layer::Global, &timing(pending, grant)).is_err(),
                "{pending:?} {grant:?}"
            );
        }
        let defaults = PolicyDocument::default().approval_timing().unwrap();
        assert_eq!(defaults, agentguard_core::ApprovalTiming::default());
    }

    #[test]
    fn effective_policy_is_verified() {
        let p = EffectivePolicy::merge(
            &PolicyDocument::default(),
            None,
            Provenance {
                mandatory: MANDATORY_BASELINE_VERSION,
                global: None,
                project: None,
            },
        )
        .unwrap();
        assert_eq!(p.integrity(), PolicyIntegrity::Verified);
    }
}
