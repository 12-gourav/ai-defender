//! The policy evaluation API.
//!
//! ```text
//! request ─ EvaluationContext::establish (identity: trusted invocation + project registry)
//!         ─ evaluate:
//!             request/context consistency ─ policy integrity ─ normalise (operation, resource)
//!             ─ risk ─ policy version ─ guards ─ policy (layers, floors) ─ critical floor
//!         → Evaluation (decision + evidence) | EvaluationError
//! ```
//!
//! `evaluate` decides; it never executes the action, spawns a process, or writes anything. Its
//! only interaction with the outside world is read-only path resolution through the
//! context's resolver. Recording the evaluation (audit) and binding approvals are the
//! [`crate::Authorizer`]'s job.

use agentguard_core::{
    BoundedText, Decision, PathResolver, PolicyVersion, RiskLevel, RuleId, SecurityContext,
};
use agentguard_proto::AuthorizationRequest;
use serde::Serialize;

use crate::classify::{assess, RiskAssessment};
use crate::content::gather;
use crate::disclosure::{self, DisclosureInput};
use crate::guard::{GuardViolation, TrustedStateGuard};
use crate::identity::{verify, IdentityError, ProjectRegistry, TrustedInvocation};
use crate::normalize::Confidence;
use crate::normalize::{normalize, SecurityAction};
use crate::policy::{PolicyError, PolicyEvaluator, PolicyIntegrity};
use crate::resource::{path_identifier, ResourceClassifier, ResourceKind};
use crate::resource::{DefaultResourceClassifier, ResourceClassification};
use crate::rules::{Conflict, PolicyLayer, RuleInput, RuleMatch};
use crate::sensitive::{categorize, SensitiveCategory, Sensitivity};

/// The verified context an evaluation runs in. Built only by [`EvaluationContext::establish`]
/// from trusted sources; nothing in it is an unverified claim.
pub struct EvaluationContext<'a> {
    security: SecurityContext,
    guard: &'a TrustedStateGuard,
    resolver: &'a dyn PathResolver,
    inspection: Option<HostInspection>,
}

/// Content evidence the host process gathered itself before asking for a decision (the
/// managed executor scanning the commits a push would send, or the exact staged content of a
/// commit). Trusted because the engine's own process produced it; never taken from a request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HostInspection {
    /// Detected secrets.
    pub evidence: agentguard_secrets::Evidence,
    /// Something relevant could not be fully inspected.
    pub incomplete: bool,
}

impl<'a> EvaluationContext<'a> {
    /// Verify the request's identity claims against the trusted invocation and registry.
    pub fn establish(
        request: &AuthorizationRequest,
        invocation: &TrustedInvocation,
        registry: &dyn ProjectRegistry,
        guard: &'a TrustedStateGuard,
        resolver: &'a dyn PathResolver,
        policy_version: PolicyVersion,
    ) -> Result<Self, EvaluationError> {
        let security = verify(request, invocation, registry, policy_version)
            .map_err(EvaluationError::Identity)?;
        Ok(Self {
            security,
            guard,
            resolver,
            inspection: None,
        })
    }

    /// Add evidence the host process gathered itself. It can only add to what the engine's
    /// own inspection finds; it never clears it.
    #[must_use]
    pub const fn with_inspection(mut self, inspection: HostInspection) -> Self {
        self.inspection = Some(inspection);
        self
    }

    /// The verified security context.
    #[must_use]
    pub const fn security(&self) -> &SecurityContext {
        &self.security
    }
}

/// Why an evaluation could not be performed. Every variant means `DENY`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EvaluationError {
    /// Identity verification failed.
    #[error("{0}")]
    Identity(IdentityError),
    /// The request does not belong to the context it was evaluated in.
    #[error("the request does not match its verified context ({field})")]
    ContextMismatch {
        /// The field that differs.
        field: &'static str,
    },
    /// The policy's integrity has failed.
    #[error("{reason}")]
    PolicyIntegrity {
        /// Rule identifier to report.
        rule: RuleId,
        /// Why.
        reason: String,
    },
    /// The policy evaluator failed.
    #[error("policy evaluation failed")]
    Policy(PolicyError),
}

impl EvaluationError {
    /// Stable rule identifier for the denial.
    #[must_use]
    pub fn rule(&self) -> RuleId {
        match self {
            EvaluationError::Identity(e) => RuleId::builtin(e.rule()),
            EvaluationError::ContextMismatch { .. } => {
                RuleId::builtin("evaluation.context-mismatch")
            }
            EvaluationError::PolicyIntegrity { rule, .. } => rule.clone(),
            EvaluationError::Policy(_) => RuleId::builtin("engine.error"),
        }
    }
}

/// A complete, auditable evaluation.
#[derive(Debug, Clone, Serialize)]
pub struct Evaluation {
    /// The normalised action.
    pub action: SecurityAction,
    /// Its resource classification (also inside `action`, repeated for convenience).
    pub resource: ResourceClassification,
    /// Its risk assessment.
    pub risk: RiskAssessment,
    /// The decision.
    pub decision: Decision,
    /// The rule that decided.
    pub rule: RuleId,
    /// Why.
    pub reason: BoundedText<512>,
    /// The layer that decided.
    pub layer: PolicyLayer,
    /// Every matching rule and its effect.
    pub matched: Vec<RuleMatch>,
    /// Conflicts and their resolution.
    pub conflicts: Vec<Conflict>,
    /// A guard violation, when a guard decided.
    #[serde(skip)]
    pub guard: Option<GuardViolation>,
    /// The policy version evaluated under.
    pub policy_version: PolicyVersion,
}

impl Evaluation {
    fn decided_by_engine(
        action: SecurityAction,
        risk: RiskAssessment,
        rule: &'static str,
        reason: &str,
        policy_version: PolicyVersion,
    ) -> Self {
        Self {
            resource: action.resource.clone(),
            action,
            risk,
            decision: Decision::Deny,
            rule: RuleId::builtin(rule),
            reason: BoundedText::lossy(reason),
            layer: PolicyLayer::Engine,
            matched: Vec::new(),
            conflicts: Vec::new(),
            guard: None,
            policy_version,
        }
    }
}

/// Kind of one path, with configured protected patterns applied.
fn path_kind(
    path: &agentguard_core::NormalizedPath,
    ctx: &SecurityContext,
    classifier: &DefaultResourceClassifier,
    sensitivity: &Sensitivity,
) -> ResourceKind {
    let (kind, _) = classifier.classify_path(path, ctx.project());
    if !kind.is_secret() && sensitivity.is_protected(&path_identifier(path, ctx.project())) {
        ResourceKind::CredentialFile
    } else {
        kind
    }
}

/// Sensitivity, content evidence and disclosure, in that order (see [`crate::content`] and
/// [`crate::disclosure`]). Anything that could not be inspected makes the action uncertain.
fn apply_sensitivity(
    request: &AuthorizationRequest,
    ctx: &SecurityContext,
    classifier: &DefaultResourceClassifier,
    sensitivity: &Sensitivity,
    inspection: Option<&HostInspection>,
    action: &mut SecurityAction,
) {
    categorize(&mut action.resource, sensitivity);
    let (source_kind, destination_kind) = match &request.action {
        agentguard_core::Action::Filesystem(a) => {
            let source = path_kind(&a.path, ctx, classifier, sensitivity);
            // A write or append lands in its own path; copies and moves in the destination.
            let destination = match a.op {
                agentguard_core::action::FileOp::Write
                | agentguard_core::action::FileOp::Append => Some(source),
                _ => a
                    .destination
                    .as_ref()
                    .map(|d| path_kind(d, ctx, classifier, sensitivity)),
            };
            (source, destination)
        }
        _ => (action.resource.kind, None),
    };
    let mut found = gather(
        &request.action,
        action.command.as_ref(),
        ctx.project().root(),
        source_kind,
        sensitivity.detectors(),
    );
    if let Some(host) = inspection {
        found.evidence.merge(&host.evidence);
        found.incomplete |= host.incomplete;
    }
    if found.incomplete {
        action.resource.uncertain = true;
        action.confidence = action.confidence.min(Confidence::Medium);
    }
    let detected = found.evidence.at_least(sensitivity.block_severity());
    if action.resource.sensitive.is_none() && detected {
        action.resource.sensitive = Some(SensitiveCategory::SourceWithSecrets);
    }
    let source_sensitive = source_kind.is_secret() || found.sensitive_file_in_tree;
    if found.sensitive_file_in_tree && action.resource.sensitive.is_none() {
        action.resource.sensitive = Some(SensitiveCategory::ConfiguredProtected);
    }
    action.disclosure = disclosure::assess(&DisclosureInput {
        action: &request.action,
        command: action.command.as_ref(),
        resource: &action.resource,
        destination_kind,
        source_sensitive,
        evidence: found.evidence,
        block: sensitivity.block_severity(),
    });
    if found.sensitive_file_in_tree {
        action.disclosure.secret_data = true;
    }
}

fn check_consistency(
    request: &AuthorizationRequest,
    ctx: &SecurityContext,
) -> Result<(), EvaluationError> {
    let mismatch = |field| Err(EvaluationError::ContextMismatch { field });
    if request.agent.kind != ctx.agent().kind {
        return mismatch("agent");
    }
    if &request.working_directory != ctx.working_directory() {
        return mismatch("working_directory");
    }
    if &request.project.root != ctx.project().root()
        || request
            .project
            .id
            .is_some_and(|id| &id != ctx.project().id())
    {
        return mismatch("project");
    }
    if request.session.as_ref() != ctx.session() {
        return mismatch("session");
    }
    Ok(())
}

/// Evaluate `request` in `context` under `policy`.
pub fn evaluate(
    request: &AuthorizationRequest,
    context: &EvaluationContext<'_>,
    policy: &dyn PolicyEvaluator,
) -> Result<Evaluation, EvaluationError> {
    let ctx = &context.security;
    check_consistency(request, ctx)?;
    if let PolicyIntegrity::Failed { rule, reason } = policy.integrity() {
        return Err(EvaluationError::PolicyIntegrity { rule, reason });
    }
    let active = policy.version();
    let classifier = DefaultResourceClassifier::new(context.guard.protected_roots().to_vec());
    let mut action = normalize(
        request.request_id,
        &request.action,
        ctx,
        &classifier,
        Some(context.resolver),
    );
    let builtin;
    let sensitivity = if let Some(s) = policy.sensitivity() {
        s
    } else {
        builtin = Sensitivity::default();
        &builtin
    };
    apply_sensitivity(
        request,
        ctx,
        &classifier,
        sensitivity,
        context.inspection.as_ref(),
        &mut action,
    );
    let risk = assess(&action);

    if request.policy_version != active || ctx.policy_version() != &active {
        return Ok(Evaluation::decided_by_engine(
            action,
            risk,
            "policy.version-mismatch",
            "the request was prepared under a different policy version; re-evaluate under the current one",
            active,
        ));
    }
    if let Some(violation) = context.guard.check(ctx, &request.action) {
        let mut evaluation = Evaluation::decided_by_engine(
            action,
            risk,
            violation.rule(),
            violation.reason(),
            active,
        );
        evaluation.guard = Some(violation);
        return Ok(evaluation);
    }

    let outcome = policy
        .evaluate_input(&RuleInput {
            ctx,
            action: &action,
            risk: &risk,
        })
        .map_err(EvaluationError::Policy)?;
    let mut decision = outcome.verdict.decision;
    let mut rule = outcome.verdict.rule;
    let mut reason = outcome.verdict.reason;
    let mut layer = outcome.layer;
    if risk.level == RiskLevel::Critical && decision == Decision::Allow {
        decision = Decision::RequireApproval;
        rule = RuleId::builtin("floor.critical-requires-approval");
        reason = BoundedText::lossy("critical-risk actions always require approval");
        layer = PolicyLayer::Engine;
    }
    Ok(Evaluation {
        resource: action.resource.clone(),
        action,
        risk,
        decision,
        rule,
        reason,
        layer,
        matched: outcome.matched,
        conflicts: outcome.conflicts,
        guard: None,
        policy_version: active,
    })
}
