//! Rules, matching and how matching rules combine.
//!
//! A [`Rule`] pairs an [`ActionMatcher`] (what it applies to) with a decision. Matching is a
//! fixed set of typed comparisons and bounded glob patterns; there is no expression language
//! and nothing is executed.
//!
//! Within one layer (see [`evaluate_layer`]):
//! 1. a matching `DENY` always wins, whatever the priorities;
//! 2. otherwise only the matching rules with the highest `priority` take part, and among them
//!    the more restrictive decision wins (`REQUIRE_APPROVAL` over `ALLOW`);
//! 3. ties cite the smallest rule identifier.
//!
//! Priority therefore lets a specific `ALLOW` carve an exception out of a broader
//! `REQUIRE_APPROVAL` in the same layer, but can never outrank a `DENY`, and never crosses
//! layers. Floors (mandatory and project rules, see [`floor_verdict`]) ignore priority: the
//! most restrictive matching floor rule applies.
//!
//! Restrictive rules (`DENY`, `REQUIRE_APPROVAL`) match paths, resources and executables
//! case-insensitively; `ALLOW` rules match case-sensitively. A case variation can widen what a
//! restriction covers but never what an allowance covers.

use std::collections::BTreeSet;

use agentguard_core::{
    ActionCategory, AgentKind, BoundedText, Decision, Environment, Host, NormalizedPath, ProjectId,
    RiskLevel, RuleId, SecurityContext,
};
use serde::{Deserialize, Serialize};

use crate::classify::RiskAssessment;
use crate::normalize::{Capability, CommandClass, Confidence, SecurityAction};
use crate::pattern::{glob_matches, Pattern};
use crate::resource::{ResourceKind, ResourceLocation};

/// Maximum conditions on one rule.
pub const MAX_CONDITIONS: usize = 8;

/// A typed condition. All of a rule's conditions must hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Condition {
    /// The terminal command's class is this one.
    CommandClass(CommandClass),
    /// The action exercises this capability.
    Capability(Capability),
    /// The database, Terraform or cloud target is in this environment.
    Environment(Environment),
    /// The Git operation is (or is not) forced: a typed Git action's `force`, or a terminal
    /// `git` command that forces or overwrites. Never holds for other commands.
    Force(bool),
    /// The package operation is (or is not) machine-wide.
    Global(bool),
    /// The classification confidence is at least this.
    MinConfidence(Confidence),
    /// The resource is (or is not) ordinary: source code in the project, or no local resource.
    OrdinaryResource(bool),
    /// The resource is at this location.
    Location(ResourceLocation),
    /// The action is (or is not) reversible.
    Reversible(bool),
    /// The resource is (or is not) a sensitive location: secret kinds and protected
    /// categories, not ordinary files in which a secret was detected.
    SensitiveResource(bool),
    /// The resource is in this sensitive category.
    Sensitive(crate::sensitive::SensitiveCategory),
    /// Secrets at or above this severity were detected in the content involved.
    SecretsDetected(agentguard_secrets::Severity),
    /// The data involved is (or is not) secret.
    SecretData(bool),
    /// Data would go to this destination.
    Destination(crate::disclosure::Destination),
    /// Data would (or would not) leave the machine, or go somewhere unknown.
    ExternalDestination(bool),
    /// Secret data would (or would not) be written into an ordinary local file.
    IntoOrdinaryFile(bool),
}

impl Condition {
    fn holds(&self, input: &RuleInput<'_>) -> bool {
        use agentguard_core::Action;
        let action = input.action;
        match self {
            Condition::CommandClass(class) => {
                action.command.as_ref().is_some_and(|c| c.class == *class)
            }
            Condition::Capability(cap) => action.capabilities.contains(*cap),
            Condition::Environment(env) => match &action.action {
                Action::Database(d) => d.environment == *env,
                Action::Terraform(t) => t.environment == *env,
                Action::Cloud(c) => c.environment == *env,
                _ => false,
            },
            Condition::Force(want) => match &action.action {
                Action::Git(g) => g.force == *want,
                Action::Terminal(_) => action
                    .command
                    .as_ref()
                    .and_then(|c| c.git_forced)
                    .is_some_and(|forced| forced == *want),
                _ => false,
            },
            Condition::Global(want) => {
                matches!(&action.action, Action::PackageManager(p) if p.global == *want)
            }
            Condition::MinConfidence(min) => action.confidence >= *min,
            Condition::OrdinaryResource(want) => action.resource.is_ordinary() == *want,
            Condition::Location(location) => action.resource.location == *location,
            Condition::Reversible(want) => input.risk.reversible == *want,
            Condition::SensitiveResource(want) => {
                let r = &action.resource;
                (r.kind.is_secret()
                    || r.sensitive
                        .is_some_and(crate::sensitive::SensitiveCategory::is_protected_resource))
                    == *want
            }
            Condition::Sensitive(category) => action.resource.sensitive == Some(*category),
            Condition::SecretsDetected(min) => action.disclosure.evidence.at_least(*min),
            Condition::SecretData(want) => action.disclosure.secret_data == *want,
            Condition::Destination(d) => action.disclosure.destination == Some(*d),
            Condition::ExternalDestination(want) => {
                action
                    .disclosure
                    .destination
                    .is_some_and(crate::disclosure::Destination::is_external)
                    == *want
            }
            Condition::IntoOrdinaryFile(want) => action.disclosure.into_ordinary_file == *want,
        }
    }
}

/// What a rule applies to. Every stated field must hold; an absent field matches anything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionMatcher {
    /// Action category.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<ActionCategory>,
    /// Operation name within the category, exact or a glob pattern.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    /// Every path the action names lies at or beneath this one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<NormalizedPath>,
    /// Every path is inside (`true`), or some path is outside (`false`), the project.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inside_project: Option<bool>,
    /// The network or transfer destination equals this host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<Host>,
    /// The assessed risk is at most this level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_risk: Option<RiskLevel>,
    /// The assessed risk is at least this level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_risk: Option<RiskLevel>,
    /// The resource is of this kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_kind: Option<ResourceKind>,
    /// The resource identifier matches this pattern: project-relative paths for files inside the
    /// project (`src/**`), absolute paths for files outside it, the target name otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<Pattern>,
    /// The executable or tool matches this pattern.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<Pattern>,
    /// The verified agent is of this kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentKind>,
    /// The verified project is this one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<ProjectId>,
    /// Additional typed conditions, at most [`MAX_CONDITIONS`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

/// Everything a rule can match against.
#[derive(Debug, Clone, Copy)]
pub struct RuleInput<'a> {
    /// The verified context.
    pub ctx: &'a SecurityContext,
    /// The normalised action.
    pub action: &'a SecurityAction,
    /// Its risk assessment.
    pub risk: &'a RiskAssessment,
}

impl ActionMatcher {
    /// Whether the matcher constrains *what* is matched. Risk, agent, project and conditions
    /// alone do not count: an `ALLOW` on them would allow whole classes of unrelated actions.
    #[must_use]
    pub fn is_bounded(&self) -> bool {
        self.category.is_some()
            || self.operation.is_some()
            || self.path_prefix.is_some()
            || self.host.is_some()
            || self.resource_kind.is_some()
            || self.resource.is_some()
            || self.executable.is_some()
    }

    /// Check the parts serde cannot: operation patterns and condition count.
    pub fn validate(&self) -> Result<(), &'static str> {
        if let Some(op) = &self.operation {
            Pattern::new(op.clone()).map_err(|_| "operation is not a valid pattern")?;
        }
        if self.conditions.len() > MAX_CONDITIONS {
            return Err("too many conditions");
        }
        if let (Some(min), Some(max)) = (self.min_risk, self.max_risk) {
            if min > max {
                return Err("min_risk exceeds max_risk");
            }
        }
        Ok(())
    }

    /// Whether the matcher matches `input`. `restrictive` selects case-insensitive matching.
    #[must_use]
    pub fn matches(&self, input: &RuleInput<'_>, restrictive: bool) -> bool {
        let action = input.action;
        let paths = action.action.paths();
        let ci = restrictive;
        self.category.is_none_or(|c| c == action.category())
            && self
                .operation
                .as_deref()
                .is_none_or(|op| glob_matches(op, action.operation(), false))
            && self
                .path_prefix
                .as_ref()
                .is_none_or(|prefix| !paths.is_empty() && paths.iter().all(|p| p.is_within(prefix)))
            && self.inside_project.is_none_or(|want| {
                if paths.is_empty() {
                    match action.resource.location {
                        ResourceLocation::InsideProject => want,
                        ResourceLocation::OutsideProject | ResourceLocation::TrustedState => !want,
                        _ => false,
                    }
                } else {
                    paths.iter().all(|p| input.ctx.project().contains(p)) == want
                }
            })
            && self.host.as_ref().is_none_or(|h| match &action.action {
                agentguard_core::Action::Network(n) => &n.host == h,
                agentguard_core::Action::ExternalTransfer(t) => &t.destination == h,
                _ => false,
            })
            && self.max_risk.is_none_or(|max| input.risk.level <= max)
            && self.min_risk.is_none_or(|min| input.risk.level >= min)
            && self.resource_kind.is_none_or(|k| k == action.resource.kind)
            && self.resource.as_ref().is_none_or(|pattern| {
                let targets = &action.resource.targets;
                if restrictive {
                    targets.iter().any(|t| pattern.matches(t, ci))
                } else {
                    !targets.is_empty() && targets.iter().all(|t| pattern.matches(t, ci))
                }
            })
            && self.executable.as_ref().is_none_or(|pattern| {
                action
                    .executable
                    .as_deref()
                    .is_some_and(|e| pattern.matches(e, ci))
            })
            && self.agent.is_none_or(|k| k == input.ctx.agent().kind)
            && self
                .project
                .is_none_or(|id| &id == input.ctx.project().id())
            && self.conditions.iter().all(|c| c.holds(input))
    }
}

// serde's `skip_serializing_if` requires a `fn(&T) -> bool`.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(v: &u16) -> bool {
    *v == 0
}

/// One policy rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Stable identifier, cited in decisions and audit records.
    pub id: RuleId,
    /// What the rule decides when it matches.
    pub decision: Decision,
    /// Why, shown to the developer.
    pub reason: BoundedText<512>,
    /// When it applies.
    #[serde(rename = "match")]
    pub matcher: ActionMatcher,
    /// Priority within its layer (higher first). Arbitrates only between `ALLOW` and
    /// `REQUIRE_APPROVAL`; a matching `DENY` wins regardless.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub priority: u16,
}

impl Rule {
    /// A rule with priority 0.
    #[must_use]
    pub fn new(id: RuleId, decision: Decision, reason: &str, matcher: ActionMatcher) -> Self {
        Self {
            id,
            decision,
            reason: BoundedText::lossy(reason),
            matcher,
            priority: 0,
        }
    }

    fn matches(&self, input: &RuleInput<'_>) -> bool {
        self.matcher
            .matches(input, self.decision != Decision::Allow)
    }
}

/// Validate a rule list: unique identifiers, valid matchers, no unbounded `ALLOW`.
pub fn validate_rules(rules: &[Rule]) -> Result<(), RuleError> {
    let mut seen = BTreeSet::new();
    for rule in rules {
        if !seen.insert(rule.id.as_str()) {
            return Err(RuleError::DuplicateId);
        }
        rule.matcher.validate().map_err(RuleError::InvalidMatcher)?;
        if rule.decision == Decision::Allow && !rule.matcher.is_bounded() {
            return Err(RuleError::UnboundedAllow);
        }
    }
    Ok(())
}

/// Why a rule list was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RuleError {
    /// Two rules share an identifier.
    #[error("rule identifiers must be unique")]
    DuplicateId,
    /// An `ALLOW` rule does not constrain what it matches.
    #[error("an ALLOW rule must constrain what it matches")]
    UnboundedAllow,
    /// A matcher is invalid.
    #[error("invalid matcher: {0}")]
    InvalidMatcher(&'static str),
}

/// Which layer a rule or decision came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyLayer {
    /// The built-in mandatory baseline (floors).
    Mandatory,
    /// The trusted organisation/user policy.
    Global,
    /// The approved project policy (floors).
    Project,
    /// The security profile's action rules.
    Profile,
    /// A standalone rule set.
    Rules,
    /// The default behaviour for actions no rule matched.
    Default,
    /// The engine itself (guards, floors, integrity, identity).
    Engine,
}

/// What a matching rule did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatchEffect {
    /// It produced the layer's verdict.
    Decided,
    /// It agreed with the verdict.
    Agreed,
    /// It was overruled by a more restrictive rule.
    Overruled,
    /// It was outranked by a higher-priority rule.
    Shadowed,
}

/// A rule that matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleMatch {
    /// The rule.
    pub rule: RuleId,
    /// Its decision.
    pub decision: Decision,
    /// Its priority.
    pub priority: u16,
    /// Its layer.
    pub layer: PolicyLayer,
    /// What it did.
    pub effect: MatchEffect,
}

/// How a conflict arose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConflictKind {
    /// Rules in one layer disagreed; the more restrictive won.
    SameLayer,
    /// A higher-priority rule outranked a more restrictive one in the same layer.
    PriorityOverride,
    /// A floor (mandatory or project) raised the decision above the authorised layers'.
    FloorRaised,
}

/// A disagreement between matching rules and how it was resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Conflict {
    /// Where.
    pub layer: PolicyLayer,
    /// How.
    pub kind: ConflictKind,
    /// The rules involved, winner first.
    pub rules: Vec<RuleId>,
    /// The resulting decision.
    pub resolved: Decision,
}

/// A layer's verdict, if any rule matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The decision.
    pub decision: Decision,
    /// The deciding rule.
    pub rule: RuleId,
    /// Its reason.
    pub reason: BoundedText<512>,
}

/// The outcome of evaluating one layer.
#[derive(Debug, Clone, Default)]
pub struct LayerOutcome {
    /// The verdict, when a rule matched.
    pub verdict: Option<Verdict>,
    /// Every matching rule and its effect.
    pub matched: Vec<RuleMatch>,
    /// Conflicts found.
    pub conflicts: Vec<Conflict>,
}

fn restrictive_then_id(a: &Rule, b: &Rule) -> std::cmp::Ordering {
    b.decision
        .cmp(&a.decision)
        .then_with(|| a.id.as_str().cmp(b.id.as_str()))
}

fn verdict_of(rule: &Rule) -> Verdict {
    Verdict {
        decision: rule.decision,
        rule: rule.id.clone(),
        reason: rule.reason.clone(),
    }
}

/// Evaluate an authorised layer with priority (see the module documentation).
#[must_use]
pub fn evaluate_layer(rules: &[Rule], layer: PolicyLayer, input: &RuleInput<'_>) -> LayerOutcome {
    let matching: Vec<&Rule> = rules.iter().filter(|r| r.matches(input)).collect();
    let deny = matching
        .iter()
        .filter(|r| r.decision == Decision::Deny)
        .min_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    let (winner, top) = if let Some(deny) = deny {
        (Some(*deny), None)
    } else {
        let top = matching.iter().map(|r| r.priority).max();
        let winner = matching
            .iter()
            .filter(|r| Some(r.priority) == top)
            .min_by(|a, b| restrictive_then_id(a, b))
            .copied();
        (winner, top)
    };
    let Some(winner) = winner else {
        return LayerOutcome::default();
    };
    let mut outcome = LayerOutcome {
        verdict: Some(verdict_of(winner)),
        ..LayerOutcome::default()
    };
    let mut same_layer = vec![winner.id.clone()];
    let mut overridden = vec![winner.id.clone()];
    for rule in &matching {
        let effect = if rule.id == winner.id {
            MatchEffect::Decided
        } else if top.is_some_and(|t| rule.priority < t) {
            if rule.decision > winner.decision {
                overridden.push(rule.id.clone());
            }
            MatchEffect::Shadowed
        } else if rule.decision == winner.decision {
            MatchEffect::Agreed
        } else {
            same_layer.push(rule.id.clone());
            MatchEffect::Overruled
        };
        outcome.matched.push(RuleMatch {
            rule: rule.id.clone(),
            decision: rule.decision,
            priority: rule.priority,
            layer,
            effect,
        });
    }
    if same_layer.len() > 1 {
        outcome.conflicts.push(Conflict {
            layer,
            kind: ConflictKind::SameLayer,
            rules: same_layer,
            resolved: winner.decision,
        });
    }
    if overridden.len() > 1 {
        outcome.conflicts.push(Conflict {
            layer,
            kind: ConflictKind::PriorityOverride,
            rules: overridden,
            resolved: winner.decision,
        });
    }
    outcome
}

/// Evaluate a floor layer: priority is ignored and the most restrictive matching rule applies.
#[must_use]
pub fn floor_verdict(rules: &[Rule], layer: PolicyLayer, input: &RuleInput<'_>) -> LayerOutcome {
    let matching: Vec<&Rule> = rules.iter().filter(|r| r.matches(input)).collect();
    let Some(winner) = matching
        .iter()
        .min_by(|a, b| restrictive_then_id(a, b))
        .copied()
    else {
        return LayerOutcome::default();
    };
    LayerOutcome {
        verdict: Some(verdict_of(winner)),
        matched: matching
            .iter()
            .map(|r| RuleMatch {
                rule: r.id.clone(),
                decision: r.decision,
                priority: r.priority,
                layer,
                effect: if r.id == winner.id {
                    MatchEffect::Decided
                } else if r.decision == winner.decision {
                    MatchEffect::Agreed
                } else {
                    MatchEffect::Overruled
                },
            })
            .collect(),
        conflicts: Vec::new(),
    }
}
