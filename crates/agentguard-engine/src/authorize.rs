//! The authorization pipeline.
//!
//! ```text
//! bytes ─ parse ─ audit(request) ─ establish context (identity) ─ evaluate
//!       ─ audit(steps) ─ approval binding ─ audit(decision) ─ response
//! ```
//!
//! [`crate::evaluate::evaluate`] makes the decision; this layer records it and binds
//! approvals. Every path produces a response; there is no error return. Any failure (invalid
//! input, identity mismatch, policy integrity failure, guard violation, policy error, approval
//! store error, audit failure) produces `DENY`. The final decision is never less restrictive
//! than a guard or the policy, and an approval can only turn `REQUIRE_APPROVAL` into `ALLOW`,
//! never `DENY` into anything.

use std::sync::Arc;

use agentguard_audit::{
    AuditSink, DecisionRecord, SecurityEvent, StepKind, StepRecord, TamperKind,
};
use agentguard_core::{
    ActionCategory, Decision, Name, OperationFingerprint, PathResolver, PolicyVersion, RequestId,
    RiskLevel, RuleId, SecurityContext,
};
use agentguard_proto::{parse_request, AuthorizationRequest, AuthorizationResponse, Rejection};

use crate::approval::{fingerprint, ApprovalStore};
use crate::clock::Clock;
use crate::evaluate::{evaluate, Evaluation, EvaluationContext, EvaluationError};
use crate::guard::{GuardViolation, TrustedStateGuard};
use crate::identity::{ProjectRegistry, TrustedInvocation};
use crate::normalize::audit_resource;
use crate::policy::PolicyEvaluator;

/// Everything the authorizer depends on. Each part is trusted configuration supplied by the
/// host process, never by a request.
pub struct AuthorizerParts {
    /// How this engine instance was launched.
    pub invocation: TrustedInvocation,
    /// Registered projects.
    pub registry: Arc<dyn ProjectRegistry>,
    /// The active policy.
    pub policy: Arc<dyn PolicyEvaluator>,
    /// Pending approvals.
    pub approvals: Arc<dyn ApprovalStore>,
    /// Where security events are recorded.
    pub audit: Arc<dyn AuditSink>,
    /// How request paths are resolved.
    pub resolver: Arc<dyn PathResolver>,
    /// Trusted-state protection.
    pub guard: TrustedStateGuard,
    /// Time source.
    pub clock: Arc<dyn Clock>,
}

/// The authorization engine.
pub struct Authorizer {
    parts: AuthorizerParts,
}

/// An internal, not-yet-recorded outcome.
struct Outcome {
    decision: Decision,
    risk: RiskLevel,
    rule: RuleId,
    reason: String,
    fingerprint: Option<OperationFingerprint>,
    context: Option<SecurityContext>,
    tamper: Option<TamperKind>,
    error: Option<(&'static str, &'static str)>,
    operation: Option<Name>,
    steps: Vec<StepRecord>,
}

impl Outcome {
    fn deny(risk: RiskLevel, rule: RuleId, reason: impl Into<String>) -> Self {
        Self {
            decision: Decision::Deny,
            risk,
            rule,
            reason: reason.into(),
            fingerprint: None,
            context: None,
            tamper: None,
            error: None,
            operation: None,
            steps: Vec::new(),
        }
    }
}

struct StepFactory<'a> {
    request_id: Option<RequestId>,
    category: Option<ActionCategory>,
    operation: Option<Name>,
    context: Option<&'a SecurityContext>,
    resource: &'a str,
}

impl StepFactory<'_> {
    fn step(
        &self,
        kind: StepKind,
        risk: Option<RiskLevel>,
        rule: Option<RuleId>,
        detail: String,
    ) -> StepRecord {
        StepRecord {
            kind,
            request_id: self.request_id,
            category: self.category,
            operation: self.operation.clone(),
            risk,
            rule,
            project: self.context.map(|c| *c.project().id()),
            agent: self.context.map(|c| c.agent().clone()),
            policy_version: self.context.map(|c| *c.policy_version()),
            resource: self.resource.to_owned(),
            detail,
        }
    }
}

/// Sensitive-resource and disclosure steps (Phase 6). Carry categories, counts, severities
/// and destinations; never content.
fn sensitivity_steps(
    evaluation: &Evaluation,
    factory: &StepFactory<'_>,
    steps: &mut Vec<StepRecord>,
) {
    let action = &evaluation.action;
    let disclosure = &action.disclosure;
    let risk = Some(evaluation.risk.level);
    let destination = disclosure
        .destination
        .map_or("none", crate::disclosure::Destination::as_str);
    let sensitive = action.resource.sensitive;
    if let Some(category) = sensitive {
        steps.push(factory.step(
            StepKind::SensitiveResourceIdentified,
            risk,
            None,
            format!("category={category} kind={:?}", action.resource.kind),
        ));
    }
    if disclosure.evidence.count > 0 {
        steps.push(factory.step(
            StepKind::SecretCandidateDetected,
            risk,
            None,
            format!(
                    "count={} max_severity={} private_key={} destination={destination}",
                    disclosure.evidence.count,
                    disclosure
                        .evidence
                        .max_severity
                        .map_or("none", agentguard_secrets::Severity::as_str),
                    disclosure.evidence.private_key,
                ),
        ));
    }
    let raw = action.action.resource();
    if agentguard_core::redact::redact_text(&raw) != raw {
        steps.push(factory.step(
            StepKind::SecretRedacted,
            risk,
            None,
            "secret-bearing text in the target was redacted before recording".to_owned(),
        ));
    }
    let involved = sensitive.is_some() || disclosure.secret_data;
    let external = disclosure
        .destination
        .is_some_and(crate::disclosure::Destination::is_external);
    let kind = match evaluation.decision {
        Decision::Deny if disclosure.secret_data && (external || disclosure.into_ordinary_file) => {
            Some(StepKind::DisclosureBlocked)
        }
        Decision::Deny if involved => Some(StepKind::SensitiveAccessDenied),
        Decision::RequireApproval if involved => Some(StepKind::SensitiveOperationRequiresApproval),
        _ => None,
    };
    if let Some(kind) = kind {
        steps.push(factory.step(
            kind,
            risk,
            Some(evaluation.rule.clone()),
            format!(
                "destination={destination} secret_data={}",
                disclosure.secret_data
            ),
        ));
    }
}

fn evaluation_steps(evaluation: &Evaluation, factory: &StepFactory<'_>) -> Vec<StepRecord> {
    let resource = &evaluation.resource;
    let risk = &evaluation.risk;
    let mut steps = vec![
        factory.step(
            StepKind::ResourceClassified,
            None,
            None,
            format!(
                "kind={:?} location={:?}{}",
                resource.kind,
                resource.location,
                if resource.uncertain { " uncertain" } else { "" }
            ),
        ),
        factory.step(
            StepKind::RiskAssessed,
            Some(risk.level),
            None,
            format!(
                "level={} confidence={:?} reversible={} scope={:?} factors={:?}",
                risk.level, risk.confidence, risk.reversible, risk.scope, risk.factors
            ),
        ),
    ];
    if !evaluation.matched.is_empty() {
        let list: Vec<String> = evaluation
            .matched
            .iter()
            .map(|m| format!("{}={}({:?},{:?})", m.rule, m.decision, m.layer, m.effect))
            .collect();
        steps.push(factory.step(
            StepKind::PolicyRuleMatched,
            Some(risk.level),
            Some(evaluation.rule.clone()),
            list.join(" "),
        ));
    }
    for conflict in &evaluation.conflicts {
        let rules: Vec<&str> = conflict.rules.iter().map(RuleId::as_str).collect();
        steps.push(factory.step(
            StepKind::PolicyConflictDetected,
            Some(risk.level),
            conflict.rules.first().cloned(),
            format!(
                "{:?} in {:?}: {} -> {}",
                conflict.kind,
                conflict.layer,
                rules.join(", "),
                conflict.resolved
            ),
        ));
    }
    sensitivity_steps(evaluation, factory, &mut steps);
    steps
}

impl Authorizer {
    /// Assemble an authorizer.
    #[must_use]
    pub const fn new(parts: AuthorizerParts) -> Self {
        Self { parts }
    }

    /// The active policy version.
    #[must_use]
    pub fn policy_version(&self) -> PolicyVersion {
        self.parts.policy.version()
    }

    /// Authorize a raw request. Never fails: malformed input is denied.
    pub fn authorize_bytes(&self, input: &[u8]) -> AuthorizationResponse {
        match parse_request(input, &*self.parts.resolver) {
            Ok(request) => self.authorize(&request),
            Err(rejection) => self.reject(&rejection),
        }
    }

    /// Authorize a parsed request. Never fails: every failure is a denial.
    pub fn authorize(&self, request: &AuthorizationRequest) -> AuthorizationResponse {
        let resource = audit_resource(&request.action);
        let requested = SecurityEvent::AuthorizationRequested {
            request_id: Some(request.request_id),
            category: Some(request.action.category()),
            resource: resource.clone(),
        };
        if self
            .parts
            .audit
            .record(requested.into_audit_event())
            .is_err()
        {
            return self.audit_unavailable(Some(request.request_id));
        }
        let outcome = self.decide(request, &resource);
        self.finish(Some(request), Some(request.request_id), resource, outcome)
    }

    fn reject(&self, rejection: &Rejection) -> AuthorizationResponse {
        let requested = SecurityEvent::AuthorizationRequested {
            request_id: rejection.request_id,
            category: None,
            resource: String::new(),
        };
        if self
            .parts
            .audit
            .record(requested.into_audit_event())
            .is_err()
        {
            return self.audit_unavailable(rejection.request_id);
        }
        let reason = format!("invalid request: {}", rejection.error);
        let mut outcome = Outcome::deny(
            RiskLevel::Critical,
            RuleId::builtin("protocol.invalid-request"),
            reason.clone(),
        );
        let factory = StepFactory {
            request_id: rejection.request_id,
            category: None,
            operation: None,
            context: None,
            resource: "",
        };
        outcome.steps.push(factory.step(
            StepKind::RequestValidationFailed,
            Some(RiskLevel::Critical),
            Some(outcome.rule.clone()),
            reason,
        ));
        self.finish(None, rejection.request_id, String::new(), outcome)
    }

    fn decide(&self, request: &AuthorizationRequest, resource: &str) -> Outcome {
        let parts = &self.parts;
        let operation = Name::new(request.action.operation()).ok();
        let mut factory = StepFactory {
            request_id: Some(request.request_id),
            category: Some(request.action.category()),
            operation: operation.clone(),
            context: None,
            resource,
        };
        let context = match EvaluationContext::establish(
            request,
            &parts.invocation,
            &*parts.registry,
            &parts.guard,
            &*parts.resolver,
            parts.policy.version(),
        ) {
            Ok(context) => context,
            Err(e) => {
                let mut outcome = Outcome::deny(RiskLevel::Critical, e.rule(), e.to_string());
                outcome.operation = operation;
                outcome.steps.push(factory.step(
                    StepKind::IdentityValidationFailed,
                    Some(RiskLevel::Critical),
                    Some(e.rule()),
                    e.to_string(),
                ));
                return outcome;
            }
        };
        let security = context.security().clone();
        factory.context = Some(&security);
        let mut outcome = match evaluate(request, &context, &*parts.policy) {
            Ok(evaluation) => {
                let steps = evaluation_steps(&evaluation, &factory);
                let outcome = Outcome {
                    decision: evaluation.decision,
                    risk: evaluation.risk.level,
                    rule: evaluation.rule,
                    reason: evaluation.reason.to_string(),
                    fingerprint: None,
                    context: None,
                    tamper: evaluation.guard.and_then(GuardViolation::tamper_kind),
                    error: None,
                    operation: None,
                    steps,
                };
                if outcome.decision == Decision::RequireApproval {
                    self.bind_approval(outcome, &security, request)
                } else {
                    outcome
                }
            }
            Err(EvaluationError::PolicyIntegrity { rule, reason }) => {
                let mut outcome = Outcome::deny(RiskLevel::Critical, rule.clone(), reason.clone());
                outcome.steps.push(factory.step(
                    StepKind::PolicyIntegrityFailed,
                    Some(RiskLevel::Critical),
                    Some(rule),
                    reason,
                ));
                outcome
            }
            Err(EvaluationError::Policy(_)) => {
                let mut outcome = Outcome::deny(
                    RiskLevel::Critical,
                    RuleId::builtin("engine.error"),
                    "the security engine failed while evaluating this action; denied",
                );
                outcome.error = Some(("policy", "evaluator failed"));
                outcome
            }
            Err(other) => Outcome::deny(RiskLevel::Critical, other.rule(), other.to_string()),
        };
        outcome.operation = operation;
        outcome.context = Some(security);
        outcome
    }

    fn bind_approval(
        &self,
        mut outcome: Outcome,
        context: &SecurityContext,
        request: &AuthorizationRequest,
    ) -> Outcome {
        let internal = |mut outcome: Outcome, detail| {
            outcome.decision = Decision::Deny;
            outcome.rule = RuleId::builtin("engine.error");
            "the security engine failed while evaluating this action; denied"
                .clone_into(&mut outcome.reason);
            outcome.error = Some(("approval", detail));
            outcome
        };
        let Ok(fp) = fingerprint(context, request) else {
            return internal(outcome, "fingerprint failed");
        };
        match self.parts.approvals.consume(&fp, self.parts.clock.now()) {
            Ok(Some(grant)) => {
                let gated_by =
                    std::mem::replace(&mut outcome.rule, RuleId::builtin("approval.granted"));
                outcome.decision = Decision::Allow;
                outcome.reason = format!(
                    "approved by {} (approval {}); gated by rule {gated_by}",
                    grant.approver(),
                    grant.id(),
                );
                outcome
            }
            Ok(None) => {
                outcome.fingerprint = Some(fp);
                outcome
            }
            Err(_) => internal(outcome, "store failed"),
        }
    }

    fn finish(
        &self,
        request: Option<&AuthorizationRequest>,
        request_id: Option<RequestId>,
        resource: String,
        mut outcome: Outcome,
    ) -> AuthorizationResponse {
        let audit = &self.parts.audit;
        // Tamper and error records are best effort: the outcome is already a denial. Step
        // records and the decision record are part of the decision: if they cannot be
        // written, the result is DENY.
        if let Some(kind) = outcome.tamper {
            let event = SecurityEvent::TamperDetected {
                request_id,
                kind,
                resource: resource.clone(),
            };
            let _ = audit.record(event.into_audit_event());
        }
        if let Some((stage, detail)) = outcome.error {
            let event = SecurityEvent::SecurityError {
                request_id,
                stage,
                detail,
            };
            let _ = audit.record(event.into_audit_event());
        }
        for step in std::mem::take(&mut outcome.steps) {
            if audit
                .record(SecurityEvent::Step(Box::new(step)).into_audit_event())
                .is_err()
            {
                return self.audit_unavailable(request_id);
            }
        }
        let context = outcome.context.as_ref();
        let policy_version =
            context.map_or_else(|| self.parts.policy.version(), |c| *c.policy_version());
        let record = DecisionRecord {
            request_id,
            decision: outcome.decision,
            risk: outcome.risk,
            rule: outcome.rule.clone(),
            category: request.map(|r| r.action.category()),
            operation: outcome.operation.clone(),
            project: context.map(|c| *c.project().id()),
            agent: context.map(|c| c.agent().clone()),
            session: context.and_then(|c| c.session().copied()),
            policy_version: Some(policy_version),
            resource,
            reason: outcome.reason.clone(),
        };
        if audit
            .record(SecurityEvent::Decision(Box::new(record)).into_audit_event())
            .is_err()
        {
            return self.audit_unavailable(request_id);
        }
        if outcome.decision != Decision::RequireApproval {
            outcome.fingerprint = None;
        }
        AuthorizationResponse::new(
            request_id,
            outcome.decision,
            outcome.risk,
            outcome.rule,
            &outcome.reason,
            Some(policy_version),
            outcome.fingerprint,
        )
    }

    fn audit_unavailable(&self, request_id: Option<RequestId>) -> AuthorizationResponse {
        AuthorizationResponse::new(
            request_id,
            Decision::Deny,
            RiskLevel::Critical,
            RuleId::builtin("audit.unavailable"),
            "the decision could not be recorded in the audit log; denied",
            Some(self.parts.policy.version()),
            None,
        )
    }
}
