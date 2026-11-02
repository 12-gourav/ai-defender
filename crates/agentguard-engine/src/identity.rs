//! Independent verification of the identities a request claims.
//!
//! A request *claims* an agent and a project. Neither claim is believed:
//! - the agent kind must equal the one in the [`TrustedInvocation`], which comes from how the
//!   engine was launched (set when the integration was installed), not from the request;
//! - the project is resolved from the request's resolved working directory through the
//!   [`ProjectRegistry`], which is trusted configuration; the claimed root and identifier must
//!   match what the registry resolved.

use agentguard_core::{
    AgentIdentity, AgentKind, NormalizedPath, PolicyVersion, ProjectIdentity, SecurityContext,
};
use agentguard_proto::AuthorizationRequest;

/// Facts the engine knows from how it was started, never from the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedInvocation {
    /// The agent this engine instance serves.
    pub agent: AgentKind,
}

/// The set of projects AgentGuard has been set up for. Trusted configuration: populated by the
/// developer through a trusted command, stored outside every project.
pub trait ProjectRegistry: Send + Sync {
    /// The registered project containing `working_directory`, preferring the deepest root.
    fn resolve(&self, working_directory: &NormalizedPath) -> Option<ProjectIdentity>;
}

/// An in-memory registry. Persistent storage arrives with the SQLite state store.
#[derive(Debug, Clone, Default)]
pub struct StaticProjectRegistry {
    projects: Vec<ProjectIdentity>,
}

impl StaticProjectRegistry {
    /// A registry holding `projects`.
    #[must_use]
    pub const fn new(projects: Vec<ProjectIdentity>) -> Self {
        Self { projects }
    }
}

impl ProjectRegistry for StaticProjectRegistry {
    fn resolve(&self, working_directory: &NormalizedPath) -> Option<ProjectIdentity> {
        self.projects
            .iter()
            .filter(|p| p.contains(working_directory))
            .max_by_key(|p| p.root().as_path().components().count())
            .cloned()
    }
}

/// Why identity verification failed. Each maps to a stable rule identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// The claimed agent is not the agent this engine serves.
    #[error("the requesting agent does not match the agent this integration was installed for")]
    AgentMismatch,
    /// No registered project contains the working directory.
    #[error("the working directory is not inside a registered project")]
    ProjectUnregistered,
    /// The claimed project disagrees with the registry.
    #[error("the claimed project does not match the project registered for the working directory")]
    ProjectMismatch,
}

impl IdentityError {
    /// Stable rule identifier.
    #[must_use]
    pub const fn rule(self) -> &'static str {
        match self {
            IdentityError::AgentMismatch => "identity.agent-mismatch",
            IdentityError::ProjectUnregistered => "identity.project-unregistered",
            IdentityError::ProjectMismatch => "identity.project-mismatch",
        }
    }
}

/// Verify the request's claims and build the context policy will see.
pub fn verify(
    request: &AuthorizationRequest,
    invocation: &TrustedInvocation,
    registry: &dyn ProjectRegistry,
    policy_version: PolicyVersion,
) -> Result<SecurityContext, IdentityError> {
    if request.agent.kind != invocation.agent {
        return Err(IdentityError::AgentMismatch);
    }
    let project = registry
        .resolve(&request.working_directory)
        .ok_or(IdentityError::ProjectUnregistered)?;
    if &request.project.root != project.root()
        || request.project.id.is_some_and(|id| &id != project.id())
    {
        return Err(IdentityError::ProjectMismatch);
    }
    let agent = AgentIdentity {
        kind: invocation.agent,
        version: request.agent.version.clone(),
    };
    SecurityContext::new(
        agent,
        project,
        request.session,
        policy_version,
        request.working_directory.clone(),
    )
    .map_err(|_| IdentityError::ProjectUnregistered)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn np(s: &str) -> NormalizedPath {
        NormalizedPath::new(s).unwrap()
    }

    #[test]
    fn registry_prefers_deepest_root() {
        let outer = ProjectIdentity::new(np("/work"), None);
        let inner = ProjectIdentity::new(np("/work/app"), None);
        let reg = StaticProjectRegistry::new(vec![outer.clone(), inner.clone()]);
        assert_eq!(reg.resolve(&np("/work/app/src")), Some(inner));
        assert_eq!(reg.resolve(&np("/work/other")), Some(outer));
        assert_eq!(reg.resolve(&np("/elsewhere")), None);
        assert_eq!(reg.resolve(&np("/workshop")), None);
    }
}
