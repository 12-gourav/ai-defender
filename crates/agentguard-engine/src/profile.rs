//! The mandatory baseline and security profiles.
//!
//! The **mandatory baseline** is a set of floor rules built into the binary. No global, project
//! or profile rule can make an action they match less restrictive than they say.
//!
//! A **profile** supplies the action-specific rules that sit beneath authorised policy: they
//! apply only where the global policy has no matching rule, and they can always be tightened by
//! project policy and the mandatory floors. The `balanced` profile keeps ordinary development
//! (reading and editing source, tests, builds, linters, formatters, development servers, Git
//! inspection) free of prompts while gating anything that leaves the project, changes history
//! or dependencies, touches security configuration or secrets, or cannot be classified.

use agentguard_core::{ActionCategory, Decision, RiskLevel, RuleId};
use serde::{Deserialize, Serialize};

use crate::disclosure::Destination;
use crate::normalize::{Capability, CommandClass, Confidence};
use crate::resource::ResourceKind;
use crate::rules::{ActionMatcher, Condition, Rule};
use crate::sensitive::SensitiveCategory;

/// Version of the built-in mandatory rules, part of every layered policy version.
pub const MANDATORY_BASELINE_VERSION: &str = "agentguard.mandatory-baseline.v4";

fn rule(id: &'static str, decision: Decision, reason: &str, matcher: ActionMatcher) -> Rule {
    Rule::new(RuleId::builtin(id), decision, reason, matcher)
}

fn op(category: ActionCategory, operation: &str) -> ActionMatcher {
    ActionMatcher {
        category: Some(category),
        operation: Some(operation.to_owned()),
        ..ActionMatcher::default()
    }
}

fn category(category: ActionCategory) -> ActionMatcher {
    ActionMatcher {
        category: Some(category),
        ..ActionMatcher::default()
    }
}

fn command(class: CommandClass, extra: &[Condition]) -> ActionMatcher {
    let mut conditions = vec![Condition::CommandClass(class)];
    conditions.extend_from_slice(extra);
    ActionMatcher {
        category: Some(ActionCategory::Terminal),
        conditions,
        ..ActionMatcher::default()
    }
}

fn kind(kind: ResourceKind) -> ActionMatcher {
    ActionMatcher {
        resource_kind: Some(kind),
        ..ActionMatcher::default()
    }
}

fn conditions(list: &[Condition]) -> ActionMatcher {
    ActionMatcher {
        conditions: list.to_vec(),
        ..ActionMatcher::default()
    }
}

const MANDATORY_RA: &str = "the mandatory security baseline requires approval for this action";
const MANDATORY_DENY: &str = "denied by the mandatory security baseline";

/// The mandatory floor rules.
// A declarative table; splitting it would scatter the baseline across functions.
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn mandatory_rules() -> Vec<Rule> {
    use ActionCategory as C;
    use Decision::{Deny, RequireApproval as Ra};
    let mut rules = vec![
        rule("mandatory:secrets", Ra, MANDATORY_RA, category(C::Secrets)),
        rule(
            "mandatory:external-transfer",
            Ra,
            MANDATORY_RA,
            category(C::ExternalTransfer),
        ),
        rule("mandatory:git-push", Ra, MANDATORY_RA, op(C::Git, "push")),
        // A force push (typed or terminal) is never allowed outright; the profile denies it
        // unless the trusted global policy lowers that to approval.
        rule(
            "mandatory:git-force-push",
            Ra,
            MANDATORY_RA,
            conditions(&[
                Condition::Force(true),
                Condition::Capability(Capability::RemoteWrite),
            ]),
        ),
        rule(
            "mandatory:git-config",
            Ra,
            MANDATORY_RA,
            op(C::Git, "config"),
        ),
        rule(
            "mandatory:github-merge",
            Ra,
            MANDATORY_RA,
            op(C::GitHub, "merge-pull-request"),
        ),
        rule(
            "mandatory:github-release",
            Ra,
            MANDATORY_RA,
            op(C::GitHub, "create-release"),
        ),
        rule(
            "mandatory:github-workflow",
            Ra,
            MANDATORY_RA,
            op(C::GitHub, "trigger-workflow"),
        ),
        rule(
            "mandatory:github-settings",
            Ra,
            MANDATORY_RA,
            op(C::GitHub, "modify-settings"),
        ),
        rule(
            "mandatory:github-delete",
            Deny,
            MANDATORY_DENY,
            op(C::GitHub, "delete-repository"),
        ),
        rule(
            "mandatory:database-write",
            Ra,
            MANDATORY_RA,
            op(C::Database, "write"),
        ),
        rule(
            "mandatory:database-schema",
            Ra,
            MANDATORY_RA,
            op(C::Database, "schema-change"),
        ),
        rule(
            "mandatory:database-drop",
            Ra,
            MANDATORY_RA,
            op(C::Database, "drop"),
        ),
        rule(
            "mandatory:database-admin",
            Ra,
            MANDATORY_RA,
            op(C::Database, "admin"),
        ),
        rule(
            "mandatory:terraform-apply",
            Ra,
            MANDATORY_RA,
            op(C::Terraform, "apply"),
        ),
        rule(
            "mandatory:terraform-destroy",
            Ra,
            MANDATORY_RA,
            op(C::Terraform, "destroy"),
        ),
        rule(
            "mandatory:terraform-import",
            Ra,
            MANDATORY_RA,
            op(C::Terraform, "import"),
        ),
        rule(
            "mandatory:terraform-state",
            Ra,
            MANDATORY_RA,
            op(C::Terraform, "state-modify"),
        ),
        rule(
            "mandatory:cloud-create",
            Ra,
            MANDATORY_RA,
            op(C::Cloud, "create"),
        ),
        rule(
            "mandatory:cloud-modify",
            Ra,
            MANDATORY_RA,
            op(C::Cloud, "modify"),
        ),
        rule(
            "mandatory:cloud-delete",
            Ra,
            MANDATORY_RA,
            op(C::Cloud, "delete"),
        ),
        rule(
            "mandatory:cloud-iam",
            Ra,
            MANDATORY_RA,
            op(C::Cloud, "modify-iam"),
        ),
        rule(
            "mandatory:package-publish",
            Ra,
            MANDATORY_RA,
            op(C::PackageManager, "publish"),
        ),
        rule(
            "mandatory:private-key",
            Ra,
            MANDATORY_RA,
            kind(ResourceKind::PrivateKey),
        ),
        rule(
            "mandatory:credential-file",
            Ra,
            MANDATORY_RA,
            kind(ResourceKind::CredentialFile),
        ),
        rule(
            "mandatory:environment-file",
            Ra,
            MANDATORY_RA,
            kind(ResourceKind::EnvironmentFile),
        ),
        // Secret data never leaves the machine or goes somewhere unknown: not to an AI
        // service, a remote, a registry or an allow-listed host.
        rule(
            "mandatory:secret-disclosure",
            Deny,
            "secret data (a sensitive file or a detected credential) may not be sent to an external or unknown destination",
            conditions(&[Condition::SecretData(true), Condition::ExternalDestination(true)]),
        ),
        rule(
            "mandatory:secret-commit",
            Deny,
            "the staged changes contain a detected credential; remove it before committing",
            conditions(&[
                Condition::Destination(Destination::GitHistory),
                Condition::SecretData(true),
            ]),
        ),
        rule(
            "mandatory:secret-into-ordinary-file",
            Deny,
            "secret data may not be copied or written into an ordinary project file",
            conditions(&[Condition::IntoOrdinaryFile(true)]),
        ),
        // Terminal equivalents, so a typed floor cannot be avoided by using a shell.
        rule(
            "mandatory:terminal-vcs-remote",
            Ra,
            MANDATORY_RA,
            command(CommandClass::VcsRemote, &[]),
        ),
        rule(
            "mandatory:terminal-infra-change",
            Ra,
            MANDATORY_RA,
            command(CommandClass::InfraChange, &[]),
        ),
        rule(
            "mandatory:terminal-package-publish",
            Ra,
            MANDATORY_RA,
            command(CommandClass::PackagePublish, &[]),
        ),
        rule(
            "mandatory:terminal-secret-access",
            Ra,
            MANDATORY_RA,
            command(CommandClass::SecretAccess, &[]),
        ),
        rule(
            "mandatory:terminal-privileged",
            Ra,
            MANDATORY_RA,
            command(CommandClass::Privileged, &[]),
        ),
        rule(
            "mandatory:terminal-bypass",
            Deny,
            "attempts to disable or bypass AI Defender or the agent's safety controls are denied",
            command(CommandClass::Bypass, &[]),
        ),
    ];
    let mut destructive = command(CommandClass::Destructive, &[]);
    destructive.min_risk = Some(RiskLevel::Critical);
    rules.push(rule(
        "mandatory:terminal-destructive-critical",
        Deny,
        "explicitly prohibited destructive operation",
        destructive,
    ));
    for (id, operation) in [
        ("mandatory:outside-write", "write"),
        ("mandatory:outside-delete", "delete"),
        ("mandatory:outside-rename", "rename"),
        ("mandatory:outside-permissions", "change-permissions"),
    ] {
        let mut m = op(C::Filesystem, operation);
        m.inside_project = Some(false);
        rules.push(rule(id, Ra, MANDATORY_RA, m));
    }
    rules
}

/// Named profiles.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileName {
    /// Productive defaults with approval for sensitive operations.
    #[default]
    Balanced,
}

impl ProfileName {
    /// Version string of the profile's rule set.
    #[must_use]
    pub const fn version(self) -> &'static str {
        match self {
            ProfileName::Balanced => "agentguard.profile.balanced.v3",
        }
    }
}

const fn approval() -> Decision {
    Decision::RequireApproval
}

const fn deny() -> Decision {
    Decision::Deny
}

/// The configurable parts of a profile. Set in the trusted global policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSettings {
    /// Which profile.
    #[serde(default)]
    pub name: ProfileName,
    /// Installing, removing or updating project dependencies.
    #[serde(default = "approval")]
    pub dependency_changes: Decision,
    /// Recording commits.
    #[serde(default = "approval")]
    pub git_commit: Decision,
    /// Creating, switching, merging, rebasing or resetting branches; tags; stashes.
    #[serde(default = "approval")]
    pub git_branching: Decision,
    /// Push, pull, fetch, clone (push stays approval-gated by the mandatory baseline).
    #[serde(default = "approval")]
    pub git_remote: Decision,
    /// Database migrations and bulk loads.
    #[serde(default = "approval")]
    pub database_migrations: Decision,
    /// Actions whose classification is uncertain. `ALLOW` is not accepted.
    #[serde(default = "approval")]
    pub uncertain: Decision,
    /// Private keys and credential files. `ALLOW` is not accepted (the mandatory baseline
    /// requires approval at least).
    #[serde(default = "deny")]
    pub secret_files: Decision,
    /// Reading a sensitive resource (`.env`, keys, credentials, protected patterns, secret
    /// stores). `ALLOW` is not accepted. Omitted from the canonical form at its default, so
    /// policies written before it existed keep their signatures.
    #[serde(default = "deny", skip_serializing_if = "is_deny")]
    pub sensitive_read: Decision,
    /// Modifying a sensitive resource. `ALLOW` is not accepted.
    #[serde(default = "approval", skip_serializing_if = "is_approval")]
    pub sensitive_write: Decision,
    /// Deleting a sensitive resource. `ALLOW` is not accepted.
    #[serde(default = "deny", skip_serializing_if = "is_deny")]
    pub sensitive_delete: Decision,
    /// Reading an ordinary file in which a credential was detected.
    #[serde(default = "approval", skip_serializing_if = "is_approval")]
    pub source_with_secrets: Decision,
    /// Force pushes and remote ref deletion (`--force`, `--force-with-lease`, `+refspec`,
    /// `--mirror`, `--delete`). `ALLOW` is not accepted; the mandatory baseline requires
    /// approval at least, so `REQUIRE_APPROVAL` is the most this can grant.
    #[serde(default = "deny", skip_serializing_if = "is_deny")]
    pub git_force_push: Decision,
    /// Destructive or permission-changing commands aimed at anything other than ordinary
    /// project files (outside the project, the Git repository, sensitive or security files).
    /// `ALLOW` is not accepted.
    #[serde(default = "deny", skip_serializing_if = "is_deny")]
    pub protected_destruction: Decision,
}

// serde's `skip_serializing_if` requires a `fn(&T) -> bool`.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_deny(d: &Decision) -> bool {
    *d == Decision::Deny
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_approval(d: &Decision) -> bool {
    *d == Decision::RequireApproval
}

impl Default for ProfileSettings {
    fn default() -> Self {
        Self {
            name: ProfileName::Balanced,
            dependency_changes: approval(),
            git_commit: approval(),
            git_branching: approval(),
            git_remote: approval(),
            database_migrations: approval(),
            uncertain: approval(),
            secret_files: deny(),
            sensitive_read: deny(),
            sensitive_write: approval(),
            sensitive_delete: deny(),
            source_with_secrets: approval(),
            git_force_push: deny(),
            protected_destruction: deny(),
        }
    }
}

impl ProfileSettings {
    /// Reject settings that would allow what must never be allowed by default.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.uncertain == Decision::Allow {
            return Err("uncertain actions cannot be allowed by default");
        }
        if self.secret_files == Decision::Allow {
            return Err("secret files cannot be allowed by default");
        }
        if [
            self.sensitive_read,
            self.sensitive_write,
            self.sensitive_delete,
        ]
        .contains(&Decision::Allow)
        {
            return Err("sensitive resources cannot be allowed by default");
        }
        if self.git_force_push == Decision::Allow {
            return Err("force pushes cannot be allowed by default");
        }
        if self.protected_destruction == Decision::Allow {
            return Err("destroying protected resources cannot be allowed by default");
        }
        Ok(())
    }
}

/// A profile: its settings and the rules they produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityProfile {
    settings: ProfileSettings,
    rules: Vec<Rule>,
}

impl SecurityProfile {
    /// Build the profile named by `settings`.
    pub fn new(settings: ProfileSettings) -> Result<Self, &'static str> {
        settings.validate()?;
        let rules = match settings.name {
            ProfileName::Balanced => balanced_rules(&settings),
        };
        Ok(Self { settings, rules })
    }

    /// The settings.
    #[must_use]
    pub const fn settings(&self) -> &ProfileSettings {
        &self.settings
    }

    /// The rules.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

// A declarative table; splitting it would scatter the profile across functions.
#[allow(clippy::too_many_lines)]
fn balanced_rules(s: &ProfileSettings) -> Vec<Rule> {
    use ActionCategory as C;
    use CommandClass as K;
    use Decision::{Allow, RequireApproval as Ra};
    let ordinary_command = |class: K| {
        command(
            class,
            &[
                Condition::MinConfidence(Confidence::Medium),
                Condition::OrdinaryResource(true),
            ],
        )
    };
    let source = |operation: &str| {
        let mut m = op(C::Filesystem, operation);
        m.resource_kind = Some(ResourceKind::SourceCode);
        m.inside_project = Some(true);
        m
    };
    let mut rules = vec![
        rule(
            "profile:read-source",
            Allow,
            "reading ordinary project files",
            source("read"),
        ),
        rule(
            "profile:list-source",
            Allow,
            "listing project directories",
            source("list"),
        ),
        rule(
            "profile:edit-source",
            Allow,
            "editing ordinary project files",
            source("write"),
        ),
        rule(
            "profile:rename-source",
            Allow,
            "renaming ordinary project files",
            source("rename"),
        ),
        rule(
            "profile:append-source",
            Allow,
            "appending to ordinary project files",
            source("append"),
        ),
        rule(
            "profile:copy-source",
            Allow,
            "copying ordinary project files",
            source("copy"),
        ),
        rule(
            "profile:traverse-source",
            Allow,
            "searching project directories",
            source("traverse"),
        ),
        rule(
            "profile:dev-tools",
            Allow,
            "tests, builds, linters, formatters and development servers",
            ordinary_command(K::DevTool),
        ),
        rule(
            "profile:read-commands",
            Allow,
            "read-only commands on ordinary files",
            ordinary_command(K::ReadOnly),
        ),
        rule(
            "profile:vcs-read-commands",
            Allow,
            "Git inspection",
            ordinary_command(K::VcsRead),
        ),
        rule(
            "profile:vcs-local-commands",
            Allow,
            "staging changes",
            ordinary_command(K::VcsLocal),
        ),
        rule(
            "profile:file-commands",
            Allow,
            "creating, copying and moving ordinary project files",
            ordinary_command(K::FileWrite),
        ),
        rule(
            "profile:git-add",
            Allow,
            "staging changes",
            op(C::Git, "add"),
        ),
        rule(
            "profile:git-branch-list",
            Allow,
            "listing branches",
            op(C::Git, "branch-list"),
        ),
        rule(
            "profile:git-commit",
            s.git_commit,
            "recording a commit",
            op(C::Git, "commit"),
        ),
        rule(
            "profile:vcs-write-commands",
            s.git_commit.max(s.git_branching),
            "changing Git history",
            command(K::VcsWrite, &[]),
        ),
        rule(
            "profile:vcs-remote-commands",
            s.git_remote,
            "talking to a Git remote",
            command(K::VcsRemote, &[]),
        ),
        rule(
            "profile:package-commands",
            s.dependency_changes,
            "changing dependencies",
            command(K::PackageChange, &[]),
        ),
        rule(
            "profile:secret-commands",
            Ra,
            "reading secrets from the environment or a store",
            command(K::SecretAccess, &[]),
        ),
        rule(
            "profile:database-migrate",
            s.database_migrations,
            "running database migrations",
            op(C::Database, "migrate"),
        ),
        rule(
            "profile:database-bulk-load",
            s.database_migrations,
            "bulk-loading data",
            op(C::Database, "bulk-load"),
        ),
        rule(
            "profile:terraform-apply",
            Ra,
            "applying infrastructure changes",
            op(C::Terraform, "apply"),
        ),
        rule(
            "profile:github-comment",
            Ra,
            "posting to GitHub",
            op(C::GitHub, "comment"),
        ),
        rule(
            "profile:github-issue",
            Ra,
            "opening a GitHub issue",
            op(C::GitHub, "create-issue"),
        ),
        rule(
            "profile:github-pull-request",
            Ra,
            "opening a pull request",
            op(C::GitHub, "create-pull-request"),
        ),
        rule(
            "profile:sensitive-read",
            s.sensitive_read,
            "reading a sensitive file would expose its secrets to the agent",
            conditions(&[
                Condition::SensitiveResource(true),
                Condition::Capability(Capability::Read),
            ]),
        ),
        rule(
            "profile:sensitive-write",
            s.sensitive_write,
            "changing a sensitive file",
            conditions(&[
                Condition::SensitiveResource(true),
                Condition::Capability(Capability::Write),
            ]),
        ),
        rule(
            "profile:sensitive-delete",
            s.sensitive_delete,
            "deleting a sensitive file",
            conditions(&[
                Condition::SensitiveResource(true),
                Condition::Capability(Capability::Delete),
            ]),
        ),
        rule(
            "profile:source-with-secrets",
            s.source_with_secrets,
            "this file contains a detected credential; reading it would expose it to the agent",
            {
                let mut m = kind(ResourceKind::SourceCode);
                m.conditions = vec![
                    Condition::Sensitive(SensitiveCategory::SourceWithSecrets),
                    Condition::Capability(Capability::Read),
                ];
                m
            },
        ),
        rule(
            "profile:private-keys",
            s.secret_files,
            "access to private keys is not authorised",
            kind(ResourceKind::PrivateKey),
        ),
        rule(
            "profile:credential-files",
            s.secret_files,
            "access to credential files is not authorised",
            kind(ResourceKind::CredentialFile),
        ),
    ];
    rules.push(rule(
        "profile:git-force-push",
        s.git_force_push,
        "force pushes and remote ref deletion overwrite shared history",
        conditions(&[
            Condition::Force(true),
            Condition::Capability(Capability::RemoteWrite),
        ]),
    ));
    for (id, class, reason) in [
        (
            "profile:destructive-protected",
            K::Destructive,
            "destructive commands may only target ordinary project files",
        ),
        (
            "profile:permission-protected",
            K::PermissionChange,
            "permission changes may only target ordinary project files",
        ),
    ] {
        rules.push(rule(
            id,
            s.protected_destruction,
            reason,
            command(class, &[Condition::OrdinaryResource(false)]),
        ));
    }
    let mut security_config = kind(ResourceKind::SecurityConfiguration);
    security_config.conditions = vec![Condition::Capability(Capability::Write)];
    rules.push(rule(
        "profile:security-configuration",
        Ra,
        "changing security configuration",
        security_config,
    ));
    for operation in [
        "branch", "checkout", "switch", "merge", "rebase", "reset", "stash", "tag", "clean",
    ] {
        rules.push(Rule::new(
            RuleId::new(format!("profile:git-{operation}"))
                .unwrap_or_else(|_| RuleId::builtin("profile:git-branching")),
            s.git_branching,
            "changing branches or history",
            op(C::Git, operation),
        ));
    }
    for operation in ["push", "pull", "fetch", "clone"] {
        rules.push(Rule::new(
            RuleId::new(format!("profile:git-{operation}"))
                .unwrap_or_else(|_| RuleId::builtin("profile:git-remote")),
            s.git_remote,
            "talking to a Git remote",
            op(C::Git, operation),
        ));
    }
    for operation in ["install", "uninstall", "update"] {
        rules.push(Rule::new(
            RuleId::new(format!("profile:package-{operation}"))
                .unwrap_or_else(|_| RuleId::builtin("profile:packages")),
            s.dependency_changes,
            "changing dependencies",
            op(C::PackageManager, operation),
        ));
    }
    let mut global = category(C::PackageManager);
    global.conditions = vec![Condition::Global(true)];
    rules.push(rule(
        "profile:global-packages",
        Ra,
        "machine-wide package changes",
        global,
    ));
    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::validate_rules;

    #[test]
    fn built_in_rule_sets_are_valid() {
        assert!(validate_rules(&mandatory_rules()).is_ok());
        let profile = SecurityProfile::new(ProfileSettings::default()).unwrap();
        assert!(validate_rules(profile.rules()).is_ok());
        assert!(mandatory_rules()
            .iter()
            .all(|r| r.decision != Decision::Allow));
    }

    #[test]
    fn settings_reject_allowing_uncertain_or_secrets() {
        let s = ProfileSettings {
            uncertain: Decision::Allow,
            ..ProfileSettings::default()
        };
        assert!(SecurityProfile::new(s).is_err());
        let s = ProfileSettings {
            secret_files: Decision::Allow,
            ..ProfileSettings::default()
        };
        assert!(SecurityProfile::new(s).is_err());
        for s in [
            ProfileSettings {
                git_force_push: Decision::Allow,
                ..ProfileSettings::default()
            },
            ProfileSettings {
                protected_destruction: Decision::Allow,
                ..ProfileSettings::default()
            },
        ] {
            assert!(SecurityProfile::new(s).is_err());
        }
        let s: ProfileSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(s, ProfileSettings::default());
        assert!(serde_json::from_str::<ProfileSettings>("{\"bogus\":1}").is_err());
    }
}
