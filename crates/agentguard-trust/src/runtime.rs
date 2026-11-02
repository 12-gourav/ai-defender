//! Turning the trust store into what the engine needs, fail-closed.
//!
//! [`load_runtime`] never returns an error. It returns either the verified effective policy and
//! registry, or a lockdown pair that denies every action with a reason pointing at the trust
//! failure. There is no permissive fallback: missing, unreadable, insecure, tampered or
//! rolled-back trusted state always produces the lockdown.

use std::sync::Arc;

use agentguard_audit::{AuditSink, SecurityEvent, TrustEventKind, TrustRecord};
use agentguard_core::{
    Action, BoundedText, Decision, NormalizedPath, PolicyVersion, ProjectIdentity, RuleId,
    SecurityContext,
};
use agentguard_engine::policy::PolicyError;
use agentguard_engine::{
    PolicyEvaluator, PolicyIntegrity, PolicyVerdict, ProjectRegistry, RiskAssessment,
};

use crate::error::TrustError;
use crate::hierarchy::{EffectivePolicy, Provenance, MANDATORY_BASELINE_VERSION};
use crate::project_file::has_drift;
use crate::registry::VerifiedRegistry;
use crate::store::{TrustStore, VerifiedTrust};

/// Denies everything. Used whenever trusted state cannot be verified.
#[derive(Debug, Clone)]
pub struct LockdownPolicy {
    reason: String,
    version: PolicyVersion,
}

impl LockdownPolicy {
    /// A lockdown caused by `error`.
    #[must_use]
    pub fn new(error: &TrustError) -> Self {
        let reason = format!(
            "trusted policy state could not be verified ({error}); every protected operation is denied until an authorised human recovers the trust store"
        );
        Self {
            version: PolicyVersion::compute(format!("agentguard.lockdown.v1\0{error}").as_bytes()),
            reason,
        }
    }
}

impl PolicyEvaluator for LockdownPolicy {
    fn version(&self) -> PolicyVersion {
        self.version
    }

    fn integrity(&self) -> PolicyIntegrity {
        PolicyIntegrity::Failed {
            rule: RuleId::builtin("trust.lockdown"),
            reason: self.reason.clone(),
        }
    }

    fn evaluate(
        &self,
        _: &SecurityContext,
        _: &Action,
        _: &RiskAssessment,
    ) -> Result<PolicyVerdict, PolicyError> {
        Ok(PolicyVerdict {
            decision: Decision::Deny,
            rule: RuleId::builtin("trust.lockdown"),
            reason: BoundedText::lossy(&self.reason),
        })
    }
}

/// Paired only with [`LockdownPolicy`]: treats the working directory as a provisional project
/// so the lockdown reason, rather than "unregistered project", reaches the developer. It grants
/// nothing, because the lockdown policy denies every action.
struct LockdownRegistry;

impl ProjectRegistry for LockdownRegistry {
    fn resolve(&self, working_directory: &NormalizedPath) -> Option<ProjectIdentity> {
        Some(ProjectIdentity::new(working_directory.clone(), None))
    }
}

/// Whether the runtime is backed by verified trust.
#[derive(Debug, Clone)]
pub enum TrustState {
    /// Verified; the effective policy's provenance.
    Verified(Provenance),
    /// Locked down; why.
    Lockdown(TrustError),
}

/// What the engine needs, derived from trusted state.
pub struct TrustedRuntime {
    /// The policy to evaluate with.
    pub policy: Arc<dyn PolicyEvaluator>,
    /// The project registry to verify identities against.
    pub registry: Arc<dyn ProjectRegistry>,
    /// Verified or locked down.
    pub state: TrustState,
    /// Paths the engine's trusted-state guard must protect (the trust store).
    pub protected_roots: Vec<NormalizedPath>,
}

fn record(
    audit: &dyn AuditSink,
    kind: TrustEventKind,
    subject: &str,
    detail: String,
    project: Option<agentguard_core::ProjectId>,
) {
    // Best effort: the runtime is already fail-closed, and the engine refuses to decide when
    // its own audit sink fails.
    let event = SecurityEvent::Trust(Box::new(TrustRecord {
        kind,
        subject: subject.to_owned(),
        detail,
        old_version: None,
        new_version: None,
        actor: None,
        project,
    }));
    let _ = audit.record(event.into_audit_event());
}

fn lockdown(error: TrustError, protected_roots: Vec<NormalizedPath>) -> TrustedRuntime {
    TrustedRuntime {
        policy: Arc::new(LockdownPolicy::new(&error)),
        registry: Arc::new(LockdownRegistry),
        state: TrustState::Lockdown(error),
        protected_roots,
    }
}

/// Load the trust store and build the runtime for a request from `working_directory`.
pub fn load_runtime(
    store: &TrustStore,
    working_directory: &NormalizedPath,
    audit: &Arc<dyn AuditSink>,
) -> TrustedRuntime {
    let protected_roots: Vec<_> = store.protected_root().into_iter().collect();
    let trust = match store.load() {
        Ok(trust) => trust,
        Err(e) => {
            record(&**audit, e.event_kind(), "trust store", e.to_string(), None);
            return lockdown(e, protected_roots);
        }
    };
    match build(&trust, working_directory, audit) {
        Ok((policy, registry, provenance)) => {
            record(
                &**audit,
                TrustEventKind::IntegrityVerified,
                "trust store",
                format!("verified at integrity version {}", trust.integrity.sequence),
                None,
            );
            TrustedRuntime {
                policy: Arc::new(policy),
                registry: Arc::new(registry),
                state: TrustState::Verified(provenance),
                protected_roots,
            }
        }
        Err(e) => {
            record(
                &**audit,
                TrustEventKind::IntegrityFailed,
                "effective policy",
                e.to_string(),
                None,
            );
            lockdown(e, protected_roots)
        }
    }
}

fn build(
    trust: &VerifiedTrust,
    working_directory: &NormalizedPath,
    audit: &Arc<dyn AuditSink>,
) -> Result<(EffectivePolicy, VerifiedRegistry, Provenance), TrustError> {
    let registry = VerifiedRegistry::new(&trust.registry, Some(Arc::clone(audit)));
    let project = registry.resolve(working_directory);
    let manifest = project
        .as_ref()
        .and_then(|p| trust.project_policies.get(p.id()));
    let provenance = Provenance {
        mandatory: MANDATORY_BASELINE_VERSION,
        global: Some(trust.integrity.global_policy),
        project: project
            .as_ref()
            .and_then(|p| trust.registry.get(p.id()))
            .and_then(|r| r.approved_policy),
    };
    if let Some(project) = &project {
        if has_drift(project.root(), manifest.map(|m| &m.policy_hash)) {
            record(
                &**audit,
                TrustEventKind::ProjectPolicyDrift,
                "project policy file",
                "the project's policy file differs from its approved policy; the approved policy remains in force".to_owned(),
                Some(*project.id()),
            );
        }
    }
    let policy = EffectivePolicy::merge(
        &trust.global.policy,
        manifest.map(|m| &m.policy),
        provenance.clone(),
    )?;
    Ok((policy, registry, provenance))
}
