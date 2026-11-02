//! The layered policy: precedence across mandatory baseline, global policy, project policy,
//! profile rules and defaults.
//!
//! ```text
//! authorised = global layer verdict                (if any global rule matched)
//!            | profile layer verdict               (else, if any profile rule matched)
//!            | default verdict                     (else)
//! final      = max(authorised, mandatory floor, project floor)     DENY > REQUIRE_APPROVAL > ALLOW
//! ```
//!
//! The global layer may grant exceptions to profile rules and defaults; it can never go below a
//! mandatory floor. Project rules can only add restrictions (no `ALLOW`), and like the
//! mandatory rules they are floors: they raise a decision, never lower it, even where the
//! authorised layers fell back to a default. Within the global and profile layers, priority
//! arbitrates between `ALLOW` and `REQUIRE_APPROVAL` only; a matching `DENY` always wins.

use agentguard_core::{Action, Decision, PolicyVersion, SecurityContext};
use serde::Serialize;

use crate::classify::RiskAssessment;
use crate::policy::{
    default_verdict, evaluate_via_input, PolicyError, PolicyEvaluator, PolicyIntegrity,
    PolicyOutcome, PolicyVerdict,
};
use crate::profile::{
    mandatory_rules, ProfileSettings, SecurityProfile, MANDATORY_BASELINE_VERSION,
};
use crate::rules::{
    evaluate_layer, floor_verdict, validate_rules, Conflict, ConflictKind, PolicyLayer, Rule,
    RuleInput,
};
use crate::sensitive::{SensitiveConfig, Sensitivity};

/// Mandatory + global + project + profile + defaults.
#[derive(Debug, Clone)]
pub struct LayeredPolicy {
    mandatory: Vec<Rule>,
    global: Vec<Rule>,
    project: Vec<Rule>,
    profile: SecurityProfile,
    sensitivity: Sensitivity,
    version: PolicyVersion,
    integrity: PolicyIntegrity,
}

#[derive(Serialize)]
struct Canonical<'a> {
    schema: &'static str,
    mandatory: &'static str,
    profile_version: &'static str,
    profile: &'a ProfileSettings,
    global: &'a [Rule],
    project: &'a [Rule],
    #[serde(skip_serializing_if = "is_default_sensitive")]
    sensitive: &'a SensitiveConfig,
}

// serde's `skip_serializing_if` requires a `fn(&T) -> bool`.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_default_sensitive(config: &&SensitiveConfig) -> bool {
    **config == SensitiveConfig::default()
}

fn sorted(mut rules: Vec<Rule>) -> Vec<Rule> {
    rules.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    rules
}

impl LayeredPolicy {
    /// Build a layered policy. `global` and `project` rules must already carry their layer
    /// prefix if identifiers could collide. Project rules may not `ALLOW`.
    pub fn new(
        global: Vec<Rule>,
        project: Vec<Rule>,
        settings: ProfileSettings,
    ) -> Result<Self, PolicyError> {
        validate_rules(&global)?;
        validate_rules(&project)?;
        if project.iter().any(|r| r.decision == Decision::Allow) {
            return Err(PolicyError::InvalidRule(
                "project rules may only add restrictions",
            ));
        }
        let profile = SecurityProfile::new(settings).map_err(PolicyError::InvalidRule)?;
        let (global, project) = (sorted(global), sorted(project));
        let mut policy = Self {
            mandatory: sorted(mandatory_rules()),
            global,
            project,
            profile,
            sensitivity: Sensitivity::default(),
            version: PolicyVersion::compute(b""),
            integrity: PolicyIntegrity::Unattested,
        };
        policy.version = policy.compute_version()?;
        Ok(policy)
    }

    fn compute_version(&self) -> Result<PolicyVersion, PolicyError> {
        let canonical = serde_json::to_vec(&Canonical {
            schema: "agentguard.layered-policy.v1",
            mandatory: MANDATORY_BASELINE_VERSION,
            profile_version: self.profile.settings().name.version(),
            profile: self.profile.settings(),
            global: &self.global,
            project: &self.project,
            sensitive: self.sensitivity.config(),
        })
        .map_err(|_| PolicyError::Canonicalisation)?;
        Ok(PolicyVersion::compute(&canonical))
    }

    /// Attach the merged sensitive-resource configuration. It is part of the policy version,
    /// so changing protected patterns or detectors invalidates approvals made before.
    pub fn with_sensitivity(mut self, sensitivity: Sensitivity) -> Result<Self, PolicyError> {
        self.sensitivity = sensitivity;
        self.version = self.compute_version()?;
        Ok(self)
    }

    /// The balanced profile with no global or project rules.
    pub fn balanced() -> Result<Self, PolicyError> {
        Self::new(Vec::new(), Vec::new(), ProfileSettings::default())
    }

    /// Record the integrity of the trusted state this policy was built from.
    #[must_use]
    pub fn with_integrity(mut self, integrity: PolicyIntegrity) -> Self {
        self.integrity = integrity;
        self
    }

    /// The profile.
    #[must_use]
    pub const fn profile(&self) -> &SecurityProfile {
        &self.profile
    }

    /// The layers exactly as evaluated, for display. Read-only: displaying a policy never
    /// requires reconstructing it elsewhere.
    #[must_use]
    pub fn layers(&self) -> PolicyLayers<'_> {
        PolicyLayers {
            mandatory: &self.mandatory,
            global: &self.global,
            project: &self.project,
            profile: self.profile.rules(),
            settings: self.profile.settings(),
        }
    }
}

/// A read-only view of a layered policy's rules.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct PolicyLayers<'a> {
    /// Mandatory floor rules.
    pub mandatory: &'a [Rule],
    /// Global rules.
    pub global: &'a [Rule],
    /// Project floor rules.
    pub project: &'a [Rule],
    /// Profile rules.
    pub profile: &'a [Rule],
    /// Profile settings.
    pub settings: &'a ProfileSettings,
}

impl PolicyEvaluator for LayeredPolicy {
    fn version(&self) -> PolicyVersion {
        self.version
    }

    fn sensitivity(&self) -> Option<&Sensitivity> {
        Some(&self.sensitivity)
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
        let global = evaluate_layer(&self.global, PolicyLayer::Global, input);
        let (mut verdict, mut layer, mut matched, mut conflicts): (PolicyVerdict, _, _, _) =
            if let Some(v) = global.verdict {
                (
                    v.into(),
                    PolicyLayer::Global,
                    global.matched,
                    global.conflicts,
                )
            } else {
                let profile = evaluate_layer(self.profile.rules(), PolicyLayer::Profile, input);
                match profile.verdict {
                    Some(v) => (
                        v.into(),
                        PolicyLayer::Profile,
                        profile.matched,
                        profile.conflicts,
                    ),
                    None => (
                        default_verdict(
                            &input.action.action,
                            input.risk,
                            self.profile.settings().uncertain,
                        ),
                        PolicyLayer::Default,
                        Vec::new(),
                        Vec::new(),
                    ),
                }
            };
        for (rules, floor_layer) in [
            (&self.mandatory, PolicyLayer::Mandatory),
            (&self.project, PolicyLayer::Project),
        ] {
            let floor = floor_verdict(rules, floor_layer, input);
            matched.extend(floor.matched);
            if let Some(f) = floor.verdict {
                // An equal floor is cited in place of a mere default: it is the more specific
                // explanation. It is not a conflict.
                if f.decision == verdict.decision && layer == PolicyLayer::Default {
                    verdict = f.into();
                    layer = floor_layer;
                } else if f.decision > verdict.decision {
                    conflicts.push(Conflict {
                        layer: floor_layer,
                        kind: ConflictKind::FloorRaised,
                        rules: vec![f.rule.clone(), verdict.rule.clone()],
                        resolved: f.decision,
                    });
                    verdict = f.into();
                    layer = floor_layer;
                }
            }
        }
        Ok(PolicyOutcome {
            verdict,
            layer,
            matched,
            conflicts,
        })
    }

    fn integrity(&self) -> PolicyIntegrity {
        self.integrity.clone()
    }
}
