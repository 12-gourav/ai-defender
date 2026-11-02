//! The verified context a decision is made in.

use serde::Serialize;

use crate::error::SecurityError;
use crate::ids::{AgentIdentity, PolicyVersion, SessionId};
use crate::path::NormalizedPath;
use crate::project::ProjectIdentity;

/// Who is asking, for which project, in which session, from where, under which policy.
///
/// Only the engine's identity verification builds one, from values it established itself
/// (the trusted invocation, the project registry, the active policy) after checking the
/// request's claims against them. Policy evaluators receive this, never the raw request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecurityContext {
    agent: AgentIdentity,
    project: ProjectIdentity,
    session: Option<SessionId>,
    policy_version: PolicyVersion,
    working_directory: NormalizedPath,
}

impl SecurityContext {
    /// Assemble a context. The working directory must lie inside the project.
    pub fn new(
        agent: AgentIdentity,
        project: ProjectIdentity,
        session: Option<SessionId>,
        policy_version: PolicyVersion,
        working_directory: NormalizedPath,
    ) -> Result<Self, SecurityError> {
        if !project.contains(&working_directory) {
            return Err(SecurityError::OutsideProject {
                field: "working_directory",
            });
        }
        Ok(Self {
            agent,
            project,
            session,
            policy_version,
            working_directory,
        })
    }

    /// The verified agent.
    #[must_use]
    pub const fn agent(&self) -> &AgentIdentity {
        &self.agent
    }

    /// The verified project.
    #[must_use]
    pub const fn project(&self) -> &ProjectIdentity {
        &self.project
    }

    /// The session, when the integration supplies one.
    #[must_use]
    pub const fn session(&self) -> Option<&SessionId> {
        self.session.as_ref()
    }

    /// The policy version in force.
    #[must_use]
    pub const fn policy_version(&self) -> &PolicyVersion {
        &self.policy_version
    }

    /// The resolved working directory.
    #[must_use]
    pub const fn working_directory(&self) -> &NormalizedPath {
        &self.working_directory
    }
}

// Unix paths throughout; the Windows path rules are tested in agentguard-core.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::ids::AgentKind;

    #[test]
    fn working_directory_must_be_inside_project() {
        let project = ProjectIdentity::new(NormalizedPath::new("/p").unwrap(), None);
        let make = |cwd: &str| {
            SecurityContext::new(
                AgentIdentity::new(AgentKind::ClaudeCode),
                project.clone(),
                None,
                PolicyVersion::compute(b"x"),
                NormalizedPath::new(cwd).unwrap(),
            )
        };
        assert!(make("/p/src").is_ok());
        assert_eq!(
            make("/elsewhere").unwrap_err(),
            SecurityError::OutsideProject {
                field: "working_directory"
            }
        );
    }
}
