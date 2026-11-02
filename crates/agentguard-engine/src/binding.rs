//! Exact operation binding.
//!
//! An approval authorizes one operation, identified by an [`OperationFingerprint`]: a SHA-256
//! digest over the [`CanonicalOperation`], which holds every security-relevant field the
//! protocol can supply and the engine has verified:
//!
//! - action category, operation and the integration's tool name;
//! - every normalized argument of the action (paths already resolved), and its target;
//! - the verified project (identifier and root) and agent (kind and version);
//! - the session and working directory;
//! - the policy version the decision was made under;
//! - for managed execution, the [`ExecutionBinding`]: the resolved executable and its identity,
//!   the exact argument vector, the environment profile, and the repository state the
//!   operation depends on (HEAD, branch, staged tree, push range, remote URL identity).
//!
//! Changing any of them changes the digest. The digest is always computed here, from a
//! verified context; a digest supplied by a request is never trusted.
//!
//! Some operations need context the protocol cannot supply yet (a Terraform plan digest, the
//! commits a push sends). [`binding_gap`] names them; such operations cannot be approved until
//! an adapter supplies the missing field, so they stay denied instead of being approved on a
//! weaker binding.

use agentguard_core::action::{CloudOp, DatabaseOp, GitOp, TerraformOp};
use agentguard_core::{
    Action, ActionCategory, AgentIdentity, Environment, Name, OperationFingerprint, PolicyVersion,
    ProjectId, SecurityContext, SessionId,
};
use std::collections::BTreeMap;

use agentguard_proto::AuthorizationRequest;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Domain-separation prefix for operation digests.
const DIGEST_DOMAIN: &[u8] = b"agentguard.operation-digest.v3\0";

/// Schema tag inside the canonical form.
pub const CANONICAL_OPERATION_SCHEMA: &str = "agentguard.operation.v3";

/// Maximum entries in an [`ExecutionBinding`].
pub const MAX_BINDING_ENTRIES: usize = 64;

/// Execution context an operation is bound to beyond the action itself: facts the engine
/// observed (never values a request supplied) that must still hold when the operation runs.
/// Ordered, so equal bindings serialize to equal bytes. Values are identifiers and digests,
/// never secrets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ExecutionBinding(BTreeMap<String, String>);

impl ExecutionBinding {
    /// An empty binding.
    #[must_use]
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Bind `key` to `value`. Entries beyond [`MAX_BINDING_ENTRIES`] are refused.
    pub fn insert(&mut self, key: &str, value: impl Into<String>) -> Result<(), BindingError> {
        if self.0.len() >= MAX_BINDING_ENTRIES && !self.0.contains_key(key) {
            return Err(BindingError::TooLarge);
        }
        self.0.insert(key.to_owned(), value.into());
        Ok(())
    }

    /// The value bound to `key`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    /// Entries, in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Keys whose values differ between `self` and `other`, or exist in only one.
    #[must_use]
    pub fn differences(&self, other: &Self) -> Vec<String> {
        let mut keys: Vec<String> = self
            .0
            .iter()
            .filter(|(k, v)| other.0.get(*k) != Some(v))
            .map(|(k, _)| k.clone())
            .chain(other.0.keys().filter(|k| !self.0.contains_key(*k)).cloned())
            .collect();
        keys.sort();
        keys.dedup();
        keys
    }
}

#[derive(Debug, Serialize)]
struct ProjectBinding<'a> {
    id: &'a ProjectId,
    root: &'a str,
}

/// The canonical form an operation digest is computed over. Field order is fixed by the
/// struct, every map inside [`Action`] is ordered, and optional fields serialize as `null`
/// rather than being omitted, so equal operations serialize to equal bytes.
#[derive(Debug, Serialize)]
pub struct CanonicalOperation<'a> {
    schema: &'static str,
    category: ActionCategory,
    operation: &'a str,
    tool: Option<&'a Name>,
    action: &'a Action,
    target: String,
    project: ProjectBinding<'a>,
    agent: &'a AgentIdentity,
    session: Option<&'a SessionId>,
    working_directory: &'a str,
    policy_version: &'a PolicyVersion,
    execution: Option<&'a ExecutionBinding>,
}

impl<'a> CanonicalOperation<'a> {
    /// The canonical form of `request` in its verified `ctx`.
    #[must_use]
    pub fn new(ctx: &'a SecurityContext, request: &'a AuthorizationRequest) -> Self {
        let action = &request.action;
        Self {
            schema: CANONICAL_OPERATION_SCHEMA,
            category: action.category(),
            operation: action.operation(),
            tool: request.context.tool.as_ref(),
            action,
            target: action.resource(),
            project: ProjectBinding {
                id: ctx.project().id(),
                root: ctx.project().root().as_str(),
            },
            agent: ctx.agent(),
            session: ctx.session(),
            working_directory: ctx.working_directory().as_str(),
            policy_version: ctx.policy_version(),
            execution: None,
        }
    }

    /// Bind the execution context as well.
    #[must_use]
    pub const fn with_execution(mut self, execution: &'a ExecutionBinding) -> Self {
        self.execution = Some(execution);
        self
    }

    /// Canonical bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, BindingError> {
        serde_json::to_vec(self).map_err(|_| BindingError::Canonicalisation)
    }

    /// The digest.
    pub fn digest(&self) -> Result<OperationFingerprint, BindingError> {
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_DOMAIN);
        hasher.update(self.to_bytes()?);
        Ok(OperationFingerprint::from_bytes(hasher.finalize().into()))
    }
}

/// The digest of `request` in `ctx`.
pub fn operation_digest(
    ctx: &SecurityContext,
    request: &AuthorizationRequest,
) -> Result<OperationFingerprint, BindingError> {
    CanonicalOperation::new(ctx, request).digest()
}

/// The digest of `request` in `ctx`, bound to `execution` when there is one.
pub fn operation_digest_with(
    ctx: &SecurityContext,
    request: &AuthorizationRequest,
    execution: Option<&ExecutionBinding>,
) -> Result<OperationFingerprint, BindingError> {
    let canonical = CanonicalOperation::new(ctx, request);
    match execution {
        Some(e) => canonical.with_execution(e).digest(),
        None => canonical.digest(),
    }
}

/// Binding failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BindingError {
    /// The canonical form could not be serialized.
    #[error("the operation could not be canonicalised")]
    Canonicalisation,
    /// An execution binding has too many entries.
    #[error("the execution binding is too large")]
    TooLarge,
}

/// Context an operation needs for an exact binding that the protocol cannot supply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingGap {
    /// `terraform apply` must be bound to a reviewed plan; the protocol carries no plan digest.
    TerraformPlanDigest,
    /// A state-changing Terraform operation without a workspace or a stated environment.
    TerraformTarget,
    /// `git push` without both a remote and a target ref.
    GitPushTarget,
    /// A database change without a stated environment (staging and production would be
    /// indistinguishable).
    DatabaseEnvironment,
    /// A cloud change without a named resource or a stated environment.
    CloudTarget,
}

impl BindingGap {
    /// Stable rule identifier.
    #[must_use]
    pub const fn rule(self) -> &'static str {
        match self {
            BindingGap::TerraformPlanDigest => "approval.binding.terraform-plan",
            BindingGap::TerraformTarget => "approval.binding.terraform-target",
            BindingGap::GitPushTarget => "approval.binding.git-push-target",
            BindingGap::DatabaseEnvironment => "approval.binding.database-environment",
            BindingGap::CloudTarget => "approval.binding.cloud-target",
        }
    }

    /// Why the operation cannot be approved.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            BindingGap::TerraformPlanDigest => {
                "terraform apply can only be approved against a reviewed plan, and no adapter supplies a plan digest yet"
            }
            BindingGap::TerraformTarget => {
                "this Terraform operation names no workspace or environment, so an approval could not be bound to one target"
            }
            BindingGap::GitPushTarget => {
                "git push can only be approved with an explicit remote and target ref"
            }
            BindingGap::DatabaseEnvironment => {
                "a database change can only be approved when its environment is stated"
            }
            BindingGap::CloudTarget => {
                "a cloud change can only be approved when its resource and environment are stated"
            }
        }
    }
}

/// The context `action` would need for an exact binding, if the protocol cannot supply it.
#[must_use]
pub fn binding_gap(action: &Action) -> Option<BindingGap> {
    match action {
        Action::Terraform(a) => match a.op {
            TerraformOp::Apply => Some(BindingGap::TerraformPlanDigest),
            TerraformOp::Destroy | TerraformOp::Import | TerraformOp::StateModify
                if a.workspace.is_none() || a.environment == Environment::Unknown =>
            {
                Some(BindingGap::TerraformTarget)
            }
            _ => None,
        },
        Action::Git(a) if a.op == GitOp::Push && (a.remote.is_none() || a.target_ref.is_none()) => {
            Some(BindingGap::GitPushTarget)
        }
        Action::Database(a)
            if a.op != DatabaseOp::Read && a.environment == Environment::Unknown =>
        {
            Some(BindingGap::DatabaseEnvironment)
        }
        Action::Cloud(a)
            if !matches!(a.op, CloudOp::Read | CloudOp::List)
                && (a.resource.is_none() || a.environment == Environment::Unknown) =>
        {
            Some(BindingGap::CloudTarget)
        }
        _ => None,
    }
}

// Unix paths throughout; the Windows path rules are tested in agentguard-core.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use agentguard_core::{AgentKind, NormalizedPath, ProjectIdentity};
    use agentguard_proto::parse_request;
    use serde_json::{json, Value};

    use crate::resolve::FsPathResolver;

    fn root() -> String {
        agentguard_platform::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    #[allow(clippy::needless_pass_by_value)]
    fn request(action: Value) -> AuthorizationRequest {
        let r = root();
        let body = json!({
            "protocol": agentguard_proto::PROTOCOL_VERSION,
            "request_id": "5b0a3d0e-8f0c-4a51-9d1c-2f7f2c1a9e10",
            "agent": {"kind": "claude", "version": "1.0.0"},
            "project": {"root": r},
            "action": action,
            "working_directory": r,
            "policy_version": "0".repeat(64),
            "context": {"tool": "Bash"},
        });
        parse_request(&serde_json::to_vec(&body).unwrap(), &FsPathResolver).unwrap()
    }

    fn ctx_for(agent: AgentKind, project_root: &str, policy: &[u8]) -> SecurityContext {
        let root = NormalizedPath::new(project_root).unwrap();
        SecurityContext::new(
            AgentIdentity::new(agent),
            ProjectIdentity::new(root.clone(), None),
            None,
            PolicyVersion::compute(policy),
            root,
        )
        .unwrap()
    }

    fn push(target: &str) -> Value {
        json!({"category": "git", "operation": "push", "remote": "origin", "target_ref": target})
    }

    #[allow(clippy::needless_pass_by_value)]
    fn digest(ctx: &SecurityContext, action: Value) -> OperationFingerprint {
        operation_digest(ctx, &request(action)).unwrap()
    }

    #[test]
    fn digest_is_deterministic() {
        let ctx = ctx_for(AgentKind::ClaudeCode, &root(), b"p1");
        assert_eq!(
            digest(&ctx, push("feature-a")),
            digest(&ctx, push("feature-a"))
        );
    }

    #[test]
    fn every_bound_field_changes_the_digest() {
        let r = root();
        let ctx = ctx_for(AgentKind::ClaudeCode, &r, b"p1");
        let base = digest(&ctx, push("feature-a"));
        assert_ne!(base, digest(&ctx, push("main")), "target ref");
        assert_ne!(
            base,
            digest(
                &ctx,
                json!({"category": "git", "operation": "push", "remote": "upstream", "target_ref": "feature-a"})
            ),
            "remote"
        );
        assert_ne!(
            base,
            digest(
                &ctx,
                json!({"category": "git", "operation": "push", "remote": "origin", "target_ref": "feature-a", "force": true})
            ),
            "force"
        );
        assert_ne!(
            base,
            digest(&ctx_for(AgentKind::Codex, &r, b"p1"), push("feature-a")),
            "agent"
        );
        assert_ne!(
            base,
            digest(
                &ctx_for(AgentKind::ClaudeCode, &r, b"p2"),
                push("feature-a")
            ),
            "policy version"
        );
        let elsewhere = format!("{r}/other-project");
        assert_ne!(
            base,
            digest(
                &ctx_for(AgentKind::ClaudeCode, &elsewhere, b"p1"),
                push("feature-a")
            ),
            "project"
        );
        let mut tool = request(push("feature-a"));
        tool.context.tool = Some(Name::new("Other").unwrap());
        assert_ne!(base, operation_digest(&ctx, &tool).unwrap(), "tool");
    }

    #[test]
    fn execution_context_is_bound() {
        let ctx = ctx_for(AgentKind::ClaudeCode, &root(), b"p1");
        let r = request(json!({"category": "terminal", "command": "git commit -m x"}));
        let mut staged = ExecutionBinding::new();
        staged.insert("git.head", "a".repeat(40)).unwrap();
        staged.insert("git.staged-tree", "b".repeat(40)).unwrap();
        let mut restaged = staged.clone();
        restaged.insert("git.staged-tree", "c".repeat(40)).unwrap();
        let plain = operation_digest(&ctx, &r).unwrap();
        let bound = operation_digest_with(&ctx, &r, Some(&staged)).unwrap();
        assert_ne!(plain, bound);
        assert_ne!(
            bound,
            operation_digest_with(&ctx, &r, Some(&restaged)).unwrap()
        );
        assert_eq!(
            bound,
            operation_digest_with(&ctx, &r, Some(&staged.clone())).unwrap()
        );
        assert_eq!(staged.differences(&restaged), ["git.staged-tree"]);
        let mut full = ExecutionBinding::new();
        for i in 0..MAX_BINDING_ENTRIES {
            full.insert(&format!("k{i}"), "v").unwrap();
        }
        assert_eq!(full.insert("one-more", "v"), Err(BindingError::TooLarge));
    }

    #[test]
    fn file_and_database_targets_are_bound() {
        let ctx = ctx_for(AgentKind::ClaudeCode, &root(), b"p1");
        let del = |p: &str| json!({"category": "filesystem", "operation": "delete", "path": p});
        assert_ne!(digest(&ctx, del("a.txt")), digest(&ctx, del("b.txt")));
        let migrate = |env: &str| json!({"category": "database", "operation": "migrate", "target": "orders", "environment": env});
        assert_ne!(
            digest(&ctx, migrate("staging")),
            digest(&ctx, migrate("production"))
        );
    }

    #[test]
    fn gaps_are_reported_for_unbindable_operations() {
        let gap = |a: Value| binding_gap(&request(a).action);
        assert_eq!(
            gap(
                json!({"category": "terraform", "operation": "apply", "workspace": "w", "environment": "staging"})
            ),
            Some(BindingGap::TerraformPlanDigest)
        );
        assert_eq!(
            gap(json!({"category": "terraform", "operation": "destroy", "environment": "staging"})),
            Some(BindingGap::TerraformTarget)
        );
        assert_eq!(
            gap(json!({"category": "git", "operation": "push", "remote": "origin"})),
            Some(BindingGap::GitPushTarget)
        );
        assert_eq!(
            gap(json!({"category": "database", "operation": "migrate", "target": "orders"})),
            Some(BindingGap::DatabaseEnvironment)
        );
        assert_eq!(
            gap(
                json!({"category": "cloud", "operation": "delete", "provider": "aws", "service": "s3", "environment": "staging"})
            ),
            Some(BindingGap::CloudTarget)
        );
        assert_eq!(gap(push("feature-a")), None);
        assert_eq!(
            gap(json!({"category": "terminal", "command": "make deploy"})),
            None
        );
        assert_eq!(
            gap(json!({"category": "database", "operation": "read", "target": "orders"})),
            None
        );
    }
}
