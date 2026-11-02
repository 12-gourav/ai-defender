//! Classification of operations that cross the trust boundary.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The kind of operation a request represents. Every boundary crossing is one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum OperationType {
    /// Fetch from a Git remote through the broker.
    GitFetch,
    /// A commit entering the developer's repository through synchronisation.
    GitCommit,
    /// Push to a Git remote through the broker.
    GitPush,
    /// Merge into a branch.
    GitMerge,
    /// Workspace synchronisation request.
    WorkspaceSync,
    /// Installing or changing dependencies.
    DependencyInstall,
    /// A mutating database operation.
    DatabaseMutation,
    /// A deployment or infrastructure change.
    Deployment,
    /// Access to a filesystem path outside the default workspace scope.
    FilesystemAccess,
    /// Outbound network access to a host.
    NetworkAccess,
    /// Execution of a command on the host through the gateway.
    HostExec,
    /// A change to the security policy.
    PolicyModification,
    /// A change to the current task's scope.
    TaskScopeChange,
}

impl OperationType {
    /// All operation types.
    pub const ALL: [OperationType; 13] = [
        OperationType::GitFetch,
        OperationType::GitCommit,
        OperationType::GitPush,
        OperationType::GitMerge,
        OperationType::WorkspaceSync,
        OperationType::DependencyInstall,
        OperationType::DatabaseMutation,
        OperationType::Deployment,
        OperationType::FilesystemAccess,
        OperationType::NetworkAccess,
        OperationType::HostExec,
        OperationType::PolicyModification,
        OperationType::TaskScopeChange,
    ];

    /// Kebab-case name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            OperationType::GitFetch => "git-fetch",
            OperationType::GitCommit => "git-commit",
            OperationType::GitPush => "git-push",
            OperationType::GitMerge => "git-merge",
            OperationType::WorkspaceSync => "workspace-sync",
            OperationType::DependencyInstall => "dependency-install",
            OperationType::DatabaseMutation => "database-mutation",
            OperationType::Deployment => "deployment",
            OperationType::FilesystemAccess => "filesystem-access",
            OperationType::NetworkAccess => "network-access",
            OperationType::HostExec => "host-exec",
            OperationType::PolicyModification => "policy-modification",
            OperationType::TaskScopeChange => "task-scope-change",
        }
    }

    /// Whether an approval for this operation may be reused within a task or session.
    ///
    /// Structural rule from the Phase 0 review (C6): only network and filesystem access may
    /// carry a reusable scope. Everything else is approved one operation at a time.
    #[must_use]
    pub const fn permits_reusable_scope(self) -> bool {
        matches!(
            self,
            OperationType::NetworkAccess | OperationType::FilesystemAccess
        )
    }

    /// Whether this operation is handled by the privileged flow that runs outside an agent
    /// session's ordinary approval stream.
    #[must_use]
    pub const fn is_privileged_flow(self) -> bool {
        matches!(
            self,
            OperationType::PolicyModification | OperationType::TaskScopeChange
        )
    }
}

impl fmt::Display for OperationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_match_serde() {
        for op in OperationType::ALL {
            assert_eq!(
                serde_json::to_string(&op).unwrap(),
                format!("\"{}\"", op.as_str())
            );
        }
    }

    #[test]
    fn only_network_and_filesystem_are_reusable() {
        let reusable: Vec<_> = OperationType::ALL
            .into_iter()
            .filter(|o| o.permits_reusable_scope())
            .collect();
        assert_eq!(
            reusable,
            vec![
                OperationType::FilesystemAccess,
                OperationType::NetworkAccess
            ]
        );
    }

    #[test]
    fn privileged_flows() {
        assert!(OperationType::PolicyModification.is_privileged_flow());
        assert!(OperationType::TaskScopeChange.is_privileged_flow());
        assert!(!OperationType::GitPush.is_privileged_flow());
    }
}
