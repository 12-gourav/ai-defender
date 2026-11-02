//! Resource classification: what an action touches, and how sensitive it is.
//!
//! Paths arrive already resolved by the path resolver (symlinks followed, `..` removed), so
//! classification works on the object the path names at decision time, not on the string the
//! agent typed. File-name rules match case-insensitively, so `.ENV` or `ID_RSA` on a
//! case-insensitive filesystem is still recognised.
//!
//! Classification describes; it does not authorise. Policy rules decide what each kind of
//! resource may be used for.

use std::path::Component;

use agentguard_core::action::ConfigScope;
use agentguard_core::{Action, NormalizedPath, ProjectIdentity, RiskLevel};
use serde::{Deserialize, Serialize};

use crate::guard::PROJECT_PROTECTED_PATHS;

/// The kind of resource an action touches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceKind {
    /// Ordinary project files.
    SourceCode,
    /// AgentGuard trusted state, agent hook settings, CI pipelines, security tooling config.
    SecurityConfiguration,
    /// `.env` files.
    EnvironmentFile,
    /// Credential stores and tokens on disk (`.netrc`, `.npmrc`, cloud credentials, keystores).
    CredentialFile,
    /// Private keys (`id_*`, `*.pem`, `*.key`, `~/.ssh`, `~/.gnupg`).
    PrivateKey,
    /// Database files or database servers.
    Database,
    /// Infrastructure definitions, state, and cloud resources.
    Infrastructure,
    /// A Git repository's internals (`.git/`) or its remote.
    GitRepository,
    /// A network service, registry or API outside this machine.
    ExternalService,
    /// A secret store entry.
    SecretStore,
    /// Not classified, or nothing classifiable.
    Unknown,
}

impl ResourceKind {
    /// Inherent sensitivity, independent of the operation.
    #[must_use]
    pub const fn sensitivity(self) -> RiskLevel {
        match self {
            ResourceKind::SourceCode | ResourceKind::Unknown => RiskLevel::Low,
            ResourceKind::Database
            | ResourceKind::Infrastructure
            | ResourceKind::GitRepository
            | ResourceKind::ExternalService => RiskLevel::Medium,
            ResourceKind::SecurityConfiguration
            | ResourceKind::EnvironmentFile
            | ResourceKind::CredentialFile
            | ResourceKind::PrivateKey
            | ResourceKind::SecretStore => RiskLevel::High,
        }
    }

    /// Whether the resource holds secret material.
    #[must_use]
    pub const fn is_secret(self) -> bool {
        matches!(
            self,
            ResourceKind::EnvironmentFile
                | ResourceKind::CredentialFile
                | ResourceKind::PrivateKey
                | ResourceKind::SecretStore
        )
    }
}

/// Where the resource is relative to the project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceLocation {
    /// No local path is involved.
    NotApplicable,
    /// Inside the verified project.
    InsideProject,
    /// On this machine, outside the project.
    OutsideProject,
    /// AgentGuard's trusted state.
    TrustedState,
    /// On another system.
    Remote,
}

/// The classification of one action's target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResourceClassification {
    /// The most sensitive kind among the paths or targets involved.
    pub kind: ResourceKind,
    /// The most exposed location among them.
    pub location: ResourceLocation,
    /// Identifier for audit: project-relative path, absolute path, or the action's target
    /// description. May contain agent-supplied text; redact before storing.
    pub identifier: String,
    /// The individual targets rules match against (one per path, or the target name).
    pub targets: Vec<String>,
    /// Whether the classifier could not inspect everything it needed to (for example an
    /// unresolvable path or an unmodelled action).
    pub uncertain: bool,
    /// Finer-grained sensitivity (set by [`crate::sensitive::categorize`] and content
    /// inspection during evaluation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<crate::sensitive::SensitiveCategory>,
}

impl ResourceClassification {
    /// Whether this is an ordinary resource: source code inside the project, or no local
    /// resource at all.
    #[must_use]
    pub fn is_ordinary(&self) -> bool {
        match self.location {
            ResourceLocation::InsideProject => self.kind == ResourceKind::SourceCode,
            ResourceLocation::NotApplicable => {
                matches!(self.kind, ResourceKind::SourceCode | ResourceKind::Unknown)
            }
            _ => false,
        }
    }
}

const PRIVATE_KEY_NAMES: &[&str] = &[
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_ecdsa_sk",
    "id_ed25519_sk",
];
const PRIVATE_KEY_SUFFIXES: &[&str] = &[".pem", ".key", ".ppk"];
const PRIVATE_KEY_DIRS: &[&str] = &[".ssh", ".gnupg"];
const CREDENTIAL_NAMES: &[&str] = &[
    "credentials",
    "credentials.json",
    "credentials.yml",
    "credentials.yaml",
    ".netrc",
    "_netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    ".htpasswd",
    ".pgpass",
    ".my.cnf",
    "service-account.json",
];
const CREDENTIAL_SUFFIXES: &[&str] = &[".p12", ".pfx", ".keystore", ".jks", ".kdbx"];
const CREDENTIAL_DIRS: &[&str] = &[".aws", ".kube", ".docker", ".azure", "gcloud"];
const ENV_TEMPLATES: &[&str] = &[".env.example", ".env.sample", ".env.template", ".env.dist"];
const SECURITY_CONFIG_NAMES: &[&str] = &[
    ".gitlab-ci.yml",
    "jenkinsfile",
    "azure-pipelines.yml",
    ".pre-commit-config.yaml",
    "codeowners",
    ".gitleaks.toml",
    ".gitleaksignore",
    ".trivyignore",
    "bitbucket-pipelines.yml",
];
const SECURITY_CONFIG_DIRS: &[&str] = &[".circleci", ".husky"];
const INFRA_SUFFIXES: &[&str] = &[".tf", ".tfvars", ".tfstate", ".tfstate.backup", ".hcl"];
const DATABASE_SUFFIXES: &[&str] = &[".sqlite", ".sqlite3", ".db", ".dump"];

/// Classify a file by its path components (lowercased), lexically.
// Components are lowercased by every caller, so suffix comparisons are case-insensitive.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn kind_of_components(components: &[String]) -> ResourceKind {
    let Some(name) = components.last() else {
        return ResourceKind::Unknown;
    };
    let dirs = components
        .get(..components.len().saturating_sub(1))
        .unwrap_or(&[]);
    let in_dir = |list: &[&str]| dirs.iter().any(|d| list.contains(&d.as_str()));
    let ends = |list: &[&str]| list.iter().any(|s| name.ends_with(s));

    if dirs.iter().any(|d| d == ".git") || name == ".git" {
        return ResourceKind::GitRepository;
    }
    let is_public = name.ends_with(".pub") || name == "known_hosts" || name == "authorized_keys";
    if !is_public
        && (PRIVATE_KEY_NAMES.contains(&name.as_str())
            || ends(PRIVATE_KEY_SUFFIXES)
            || in_dir(PRIVATE_KEY_DIRS))
    {
        return ResourceKind::PrivateKey;
    }
    if CREDENTIAL_NAMES.contains(&name.as_str())
        || ends(CREDENTIAL_SUFFIXES)
        || in_dir(CREDENTIAL_DIRS)
        || name == "secrets"
        || name.starts_with("secrets.")
        || name.starts_with("secret.")
    {
        return ResourceKind::CredentialFile;
    }
    if !ENV_TEMPLATES.contains(&name.as_str())
        && (name == ".env" || name.starts_with(".env.") || name.ends_with(".env"))
    {
        return ResourceKind::EnvironmentFile;
    }
    let github_workflow = components
        .windows(2)
        .any(|w| matches!(w, [a, b] if a == ".github" && b == "workflows"));
    if github_workflow
        || SECURITY_CONFIG_NAMES.contains(&name.as_str())
        || in_dir(SECURITY_CONFIG_DIRS)
    {
        return ResourceKind::SecurityConfiguration;
    }
    if ends(INFRA_SUFFIXES) || name.starts_with("terraform.tfstate") {
        return ResourceKind::Infrastructure;
    }
    if ends(DATABASE_SUFFIXES) {
        return ResourceKind::Database;
    }
    ResourceKind::SourceCode
}

fn lower_components(path: &NormalizedPath) -> Vec<String> {
    path.as_path()
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect()
}

/// Classify a path given only its text, without the filesystem (used for `~/...` arguments
/// of terminal commands). The location is supplied by the caller.
#[must_use]
pub fn kind_of_relative_text(text: &str) -> ResourceKind {
    let components: Vec<String> = text
        .split('/')
        .filter(|s| !s.is_empty() && *s != "." && *s != "~")
        .map(str::to_ascii_lowercase)
        .collect();
    kind_of_components(&components)
}

/// Classifies resources. Implementations must be deterministic and must not perform I/O
/// beyond inspecting already-resolved paths.
pub trait ResourceClassifier: Send + Sync {
    /// Classify one resolved path for `project`.
    fn classify_path(
        &self,
        path: &NormalizedPath,
        project: &ProjectIdentity,
    ) -> (ResourceKind, ResourceLocation);
}

/// The built-in classifier.
#[derive(Debug, Clone, Default)]
pub struct DefaultResourceClassifier {
    protected_roots: Vec<NormalizedPath>,
}

impl DefaultResourceClassifier {
    /// A classifier that treats `protected_roots` (AgentGuard's trust and state directories)
    /// as trusted state, in addition to the per-project protected paths.
    #[must_use]
    pub const fn new(protected_roots: Vec<NormalizedPath>) -> Self {
        Self { protected_roots }
    }

    fn is_trusted_state(&self, path: &NormalizedPath, project: &ProjectIdentity) -> bool {
        self.protected_roots.iter().any(|r| path.is_within(r))
            || PROJECT_PROTECTED_PATHS
                .iter()
                .filter_map(|rel| project.root().join(rel).ok())
                .any(|p| path.is_within(&p))
    }
}

impl ResourceClassifier for DefaultResourceClassifier {
    fn classify_path(
        &self,
        path: &NormalizedPath,
        project: &ProjectIdentity,
    ) -> (ResourceKind, ResourceLocation) {
        if self.is_trusted_state(path, project) {
            return (
                ResourceKind::SecurityConfiguration,
                ResourceLocation::TrustedState,
            );
        }
        let location = if project.contains(path) {
            ResourceLocation::InsideProject
        } else {
            ResourceLocation::OutsideProject
        };
        let kind = match kind_of_components(&lower_components(path)) {
            ResourceKind::SourceCode if location == ResourceLocation::OutsideProject => {
                ResourceKind::Unknown
            }
            other => other,
        };
        (kind, location)
    }
}

/// Combine several classified paths: the most sensitive kind and the most exposed location
/// win. Equal sensitivity keeps the first kind seen.
pub(crate) fn combine(
    items: impl IntoIterator<Item = (ResourceKind, ResourceLocation)>,
) -> Option<(ResourceKind, ResourceLocation)> {
    items.into_iter().reduce(|(k1, l1), (k2, l2)| {
        let kind = if k2.sensitivity() > k1.sensitivity()
            || (k1 == ResourceKind::Unknown && k2 != ResourceKind::Unknown)
        {
            k2
        } else {
            k1
        };
        (kind, l1.max(l2))
    })
}

/// Identifier of a path for matching: project-relative inside the project, absolute outside,
/// with `/` separators on every platform (`C:/Users/u/.ssh/id_rsa` on Windows).
#[must_use]
pub fn path_identifier(path: &NormalizedPath, project: &ProjectIdentity) -> String {
    path.relative_to(project.root())
        .filter(|rel| !rel.is_empty())
        .unwrap_or_else(|| path.pattern_text())
}

/// Classify the target of a typed, non-terminal action. Terminal actions are classified from
/// their analysed path arguments by the normaliser.
#[must_use]
pub fn classify_action(
    action: &Action,
    project: &ProjectIdentity,
    classifier: &dyn ResourceClassifier,
) -> ResourceClassification {
    use ResourceKind as K;
    use ResourceLocation as L;
    let paths = action.paths();
    if let Some((kind, location)) =
        combine(paths.iter().map(|p| classifier.classify_path(p, project)))
    {
        let targets: Vec<String> = paths.iter().map(|p| path_identifier(p, project)).collect();
        return ResourceClassification {
            kind,
            location,
            identifier: targets.join(" -> "),
            targets,
            uncertain: false,
            sensitive: None,
        };
    }
    let (kind, location, uncertain) = match action {
        Action::Git(g) => {
            use agentguard_core::action::GitOp;
            let remote = matches!(
                g.op,
                GitOp::Push | GitOp::Pull | GitOp::Fetch | GitOp::Clone
            );
            (
                K::GitRepository,
                if remote { L::Remote } else { L::InsideProject },
                false,
            )
        }
        Action::GitHub(_)
        | Action::Network(_)
        | Action::ExternalTransfer(_)
        | Action::PackageManager(_) => (K::ExternalService, L::Remote, false),
        Action::Secrets(_) => (K::SecretStore, L::NotApplicable, false),
        Action::Database(_) => (K::Database, L::Remote, false),
        Action::Terraform(_) | Action::Cloud(_) => (K::Infrastructure, L::Remote, false),
        Action::Configuration(c) => match c.scope {
            ConfigScope::Agentguard | ConfigScope::AgentSettings => {
                (K::SecurityConfiguration, L::TrustedState, false)
            }
            ConfigScope::Security | ConfigScope::Ci => {
                (K::SecurityConfiguration, L::NotApplicable, false)
            }
            ConfigScope::Build | ConfigScope::Editor => (K::SourceCode, L::NotApplicable, false),
            ConfigScope::Other => (K::Unknown, L::NotApplicable, true),
        },
        Action::CustomTool(_) | Action::Unknown(_) => (K::Unknown, L::NotApplicable, true),
        Action::Filesystem(_) | Action::Terminal(_) => (K::Unknown, L::NotApplicable, false),
    };
    let identifier = action.resource();
    ResourceClassification {
        kind,
        location,
        targets: vec![identifier.clone()],
        identifier,
        uncertain,
        sensitive: None,
    }
}

// Unix paths throughout; the Windows path rules are tested in agentguard-core.
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn np(s: &str) -> NormalizedPath {
        NormalizedPath::new(s).unwrap()
    }

    fn classify(path: &str) -> (ResourceKind, ResourceLocation) {
        let project = ProjectIdentity::new(np("/p"), None);
        DefaultResourceClassifier::new(vec![np("/home/u/.config/agentguard")])
            .classify_path(&np(path), &project)
    }

    #[test]
    fn kinds() {
        use ResourceKind as K;
        use ResourceLocation as L;
        assert_eq!(
            classify("/p/src/main.rs"),
            (K::SourceCode, L::InsideProject)
        );
        assert_eq!(classify("/p/.env"), (K::EnvironmentFile, L::InsideProject));
        assert_eq!(
            classify("/p/.ENV.local"),
            (K::EnvironmentFile, L::InsideProject)
        );
        assert_eq!(
            classify("/p/.env.example"),
            (K::SourceCode, L::InsideProject)
        );
        assert_eq!(
            classify("/p/config/prod.env"),
            (K::EnvironmentFile, L::InsideProject)
        );
        assert_eq!(
            classify("/home/u/.ssh/id_ed25519"),
            (K::PrivateKey, L::OutsideProject)
        );
        assert_eq!(
            classify("/home/u/.ssh/ID_RSA"),
            (K::PrivateKey, L::OutsideProject)
        );
        assert_eq!(
            classify("/home/u/.ssh/id_ed25519.pub"),
            (K::Unknown, L::OutsideProject)
        );
        assert_eq!(
            classify("/p/certs/server.pem"),
            (K::PrivateKey, L::InsideProject)
        );
        assert_eq!(
            classify("/home/u/.aws/credentials"),
            (K::CredentialFile, L::OutsideProject)
        );
        assert_eq!(classify("/p/.npmrc"), (K::CredentialFile, L::InsideProject));
        assert_eq!(
            classify("/p/config/secrets.yml"),
            (K::CredentialFile, L::InsideProject)
        );
        assert_eq!(
            classify("/p/src/secret_santa.rs"),
            (K::SourceCode, L::InsideProject)
        );
        assert_eq!(
            classify("/p/.github/workflows/ci.yml"),
            (K::SecurityConfiguration, L::InsideProject)
        );
        assert_eq!(
            classify("/p/infra/main.tf"),
            (K::Infrastructure, L::InsideProject)
        );
        assert_eq!(
            classify("/p/.git/hooks/pre-commit"),
            (K::GitRepository, L::InsideProject)
        );
        assert_eq!(
            classify("/p/data/app.sqlite"),
            (K::Database, L::InsideProject)
        );
        assert_eq!(classify("/etc/hosts"), (K::Unknown, L::OutsideProject));
        assert_eq!(
            classify("/p/.agent-security.yml"),
            (K::SecurityConfiguration, L::TrustedState)
        );
        assert_eq!(
            classify("/home/u/.config/agentguard/keys/root.json"),
            (K::SecurityConfiguration, L::TrustedState)
        );
    }

    #[test]
    fn combine_prefers_sensitive_and_exposed() {
        use ResourceKind as K;
        use ResourceLocation as L;
        let c = combine([
            (K::SourceCode, L::InsideProject),
            (K::PrivateKey, L::OutsideProject),
        ]);
        assert_eq!(c, Some((K::PrivateKey, L::OutsideProject)));
        assert_eq!(combine(Vec::new()), None);
    }

    #[test]
    fn relative_text() {
        assert_eq!(
            kind_of_relative_text("~/.ssh/id_rsa"),
            ResourceKind::PrivateKey
        );
        assert_eq!(
            kind_of_relative_text("~/.aws/credentials"),
            ResourceKind::CredentialFile
        );
        assert_eq!(kind_of_relative_text("notes.txt"), ResourceKind::SourceCode);
    }
}
