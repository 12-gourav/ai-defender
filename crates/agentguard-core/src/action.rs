//! Typed classification of the actions an agent asks to perform.
//!
//! Every request names exactly one [`Action`]. Each category has its own typed payload and its
//! own operation vocabulary. An operation name this build does not recognise is kept as
//! `Unknown(name)` rather than rejected, so it can be audited; the engine denies every unknown
//! operation before policy runs.

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::error::SecurityError;
use crate::ids::RepositoryId;
use crate::path::NormalizedPath;
use crate::text::BoundedText;

/// The top-level kind of an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActionCategory {
    /// Reading or changing files.
    Filesystem,
    /// Running a shell command.
    Terminal,
    /// Local or remote Git operations.
    Git,
    /// GitHub API operations (issues, pull requests, releases, settings).
    #[serde(rename = "github")]
    GitHub,
    /// Access to a named secret.
    Secrets,
    /// Database statements.
    Database,
    /// Terraform operations.
    Terraform,
    /// Outbound network access.
    Network,
    /// Sending data to an external destination.
    ExternalTransfer,
    /// A tool this build has no typed model for (for example an MCP tool).
    CustomTool,
    /// Installing, removing or publishing packages.
    PackageManager,
    /// Cloud provider control-plane operations.
    Cloud,
    /// Reading or changing tool, agent, CI or security configuration.
    Configuration,
    /// An action the integration could not classify. Evaluated with explicit uncertainty.
    Unknown,
}

impl ActionCategory {
    /// All categories.
    pub const ALL: [ActionCategory; 14] = [
        ActionCategory::Filesystem,
        ActionCategory::Terminal,
        ActionCategory::Git,
        ActionCategory::GitHub,
        ActionCategory::Secrets,
        ActionCategory::Database,
        ActionCategory::Terraform,
        ActionCategory::Network,
        ActionCategory::ExternalTransfer,
        ActionCategory::CustomTool,
        ActionCategory::PackageManager,
        ActionCategory::Cloud,
        ActionCategory::Configuration,
        ActionCategory::Unknown,
    ];

    /// Wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ActionCategory::Filesystem => "filesystem",
            ActionCategory::Terminal => "terminal",
            ActionCategory::Git => "git",
            ActionCategory::GitHub => "github",
            ActionCategory::Secrets => "secrets",
            ActionCategory::Database => "database",
            ActionCategory::Terraform => "terraform",
            ActionCategory::Network => "network",
            ActionCategory::ExternalTransfer => "external-transfer",
            ActionCategory::CustomTool => "custom-tool",
            ActionCategory::PackageManager => "package-manager",
            ActionCategory::Cloud => "cloud",
            ActionCategory::Configuration => "configuration",
            ActionCategory::Unknown => "unknown",
        }
    }
}

impl fmt::Display for ActionCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A short identifier: 1 to 128 ASCII characters from letters, digits and `. _ - / @ : +`.
/// Used for operation names, tool names, Git remotes and refs, secret names and database
/// targets.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Name(String);

impl Name {
    /// Maximum length in characters.
    pub const MAX_LEN: usize = 128;

    /// Validate and wrap.
    pub fn new(value: impl Into<String>) -> Result<Self, SecurityError> {
        let value = value.into();
        let field = "Name";
        if value.is_empty() {
            return Err(SecurityError::Empty { field });
        }
        if value.len() > Self::MAX_LEN {
            return Err(SecurityError::TextTooLong {
                field,
                max: Self::MAX_LEN,
            });
        }
        if !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-/@:+".contains(c))
        {
            return Err(SecurityError::InvalidIdentifier {
                field,
                rule: "only letters, digits and . _ - / @ : + are permitted",
            });
        }
        Ok(Self(value))
    }

    /// Borrow the name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Name {
    type Error = SecurityError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Name> for String {
    fn from(value: Name) -> Self {
        value.0
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A network host: a lowercase DNS name (ASCII only; internationalised names must arrive in
/// punycode) or an IP address literal.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Host(String);

impl Host {
    /// Maximum length of a DNS name.
    pub const MAX_LEN: usize = 253;

    /// Validate and normalise: lowercase, one trailing dot removed, IPv6 brackets removed.
    pub fn new(value: impl Into<String>) -> Result<Self, SecurityError> {
        let raw = value.into();
        let field = "Host";
        let trimmed = raw.strip_suffix('.').unwrap_or(&raw);
        let unbracketed = trimmed
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(trimmed);
        if let Ok(ip) = unbracketed.parse::<IpAddr>() {
            return Ok(Self(ip.to_string()));
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.is_empty() {
            return Err(SecurityError::Empty { field });
        }
        if lower.len() > Self::MAX_LEN {
            return Err(SecurityError::TextTooLong {
                field,
                max: Self::MAX_LEN,
            });
        }
        let label_ok = |l: &str| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        };
        if !lower.split('.').all(label_ok) {
            return Err(SecurityError::InvalidIdentifier {
                field,
                rule: "must be an IP address or a DNS name of letters, digits and '-'",
            });
        }
        // Resolvers accept octal, hex and integer IPv4 spellings (`0177.0.0.1`, `0x7f.1`,
        // `2130706433`) that `IpAddr` rejects; letting them through as names would hide a
        // loopback or metadata address from `is_local_or_private`. No real TLD is numeric.
        let last = lower.rsplit('.').next().unwrap_or(&lower);
        if last.chars().all(|c| c.is_ascii_digit()) || last.starts_with("0x") {
            return Err(SecurityError::InvalidIdentifier {
                field,
                rule: "numeric host names must be canonical IP addresses",
            });
        }
        Ok(Self(lower))
    }

    /// Borrow the normalised host.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the host names this machine, a private or link-local network, or a cloud
    /// metadata endpoint. Decided on the literal only; a public name that resolves to a
    /// private address is not detected here (that needs resolution, a later phase).
    #[must_use]
    pub fn is_local_or_private(&self) -> bool {
        match self.0.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => is_private_v4(v4),
            Ok(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
                Some(v4) => is_private_v4(v4),
                None => {
                    v6.is_loopback()
                        || v6.is_unspecified()
                        || v6.is_unique_local()
                        || v6.is_unicast_link_local()
                }
            },
            // Names are stored lowercase, so an exact top-level-label match suffices.
            Err(_) => matches!(
                self.0.rsplit('.').next(),
                Some("localhost" | "internal" | "local")
            ),
        }
    }
}

fn is_private_v4(v4: std::net::Ipv4Addr) -> bool {
    let [first, second, ..] = v4.octets();
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        // 100.64.0.0/10 carrier-grade NAT, commonly used for internal service meshes.
        || (first == 100 && (second & 0xc0) == 64)
}

impl TryFrom<String> for Host {
    type Error = SecurityError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Host> for String {
    fn from(value: Host) -> Self {
        value.0
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Deployment environment of a database or infrastructure target. `Unknown` is treated as
/// production by risk classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Environment {
    /// Local or development.
    Development,
    /// Shared pre-production.
    Staging,
    /// Production.
    Production,
    /// Not stated.
    #[default]
    Unknown,
}

impl Environment {
    /// Parse a wire name.
    pub fn parse(value: &str) -> Result<Self, SecurityError> {
        match value {
            "development" => Ok(Self::Development),
            "staging" => Ok(Self::Staging),
            "production" => Ok(Self::Production),
            "unknown" => Ok(Self::Unknown),
            _ => Err(SecurityError::UnknownVariant {
                kind: "environment",
                expected: "development, staging, production, unknown",
            }),
        }
    }

    /// Whether risk classification must treat this as production.
    #[must_use]
    pub const fn is_production_like(self) -> bool {
        matches!(self, Self::Production | Self::Unknown)
    }
}

macro_rules! operation_enum {
    ($(#[$meta:meta])* $name:ident { $($(#[$vmeta:meta])* $variant:ident => $text:literal,)+ }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub enum $name {
            $($(#[$vmeta])* #[serde(rename = $text)] $variant,)+
            /// An operation name this build does not recognise. Always denied.
            #[serde(rename = "unknown")]
            Unknown(Name),
        }

        impl $name {
            /// Parse a wire name. A well-formed but unrecognised name becomes `Unknown`.
            pub fn parse(value: &str) -> Result<Self, SecurityError> {
                match value {
                    $($text => Ok(Self::$variant),)+
                    other => Name::new(other).map(Self::Unknown),
                }
            }

            /// Wire name.
            #[must_use]
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $text,)+
                    Self::Unknown(name) => name.as_str(),
                }
            }

            /// Whether this is an unrecognised operation.
            #[must_use]
            pub const fn is_unknown(&self) -> bool {
                matches!(self, Self::Unknown(_))
            }
        }
    };
}

operation_enum! {
    /// Filesystem operations.
    FileOp {
        /// Read a file.
        Read => "read",
        /// List or search a directory.
        List => "list",
        /// Create or modify a file.
        Write => "write",
        /// Delete a file or directory.
        Delete => "delete",
        /// Move or rename; the destination is in `FilesystemAction::destination`.
        Rename => "rename",
        /// Change mode or ownership.
        ChangePermissions => "change-permissions",
        /// Append to a file.
        Append => "append",
        /// Copy; the destination is in `FilesystemAction::destination`.
        Copy => "copy",
        /// Send a file to a remote destination (`FilesystemAction::remote`).
        Upload => "upload",
        /// Fetch a remote resource (`FilesystemAction::remote`) into a file.
        Download => "download",
        /// Pack files into an archive at `FilesystemAction::destination`.
        Archive => "archive",
        /// Recursively list or search a directory tree.
        Traverse => "traverse",
    }
}

operation_enum! {
    /// Git operations.
    GitOp {
        /// `git status`.
        Status => "status",
        /// `git diff`.
        Diff => "diff",
        /// `git log`.
        Log => "log",
        /// `git show`.
        Show => "show",
        /// Fetch from a remote.
        Fetch => "fetch",
        /// Pull from a remote.
        Pull => "pull",
        /// Clone a repository.
        Clone => "clone",
        /// Switch branches or restore files.
        Checkout => "checkout",
        /// Switch branches (`git switch`).
        Switch => "switch",
        /// List branches without changing them.
        BranchList => "branch-list",
        /// Create, rename or delete a branch.
        Branch => "branch",
        /// Stage changes in the index (local, reversible).
        Add => "add",
        /// Stash or apply stashed changes.
        Stash => "stash",
        /// Remove untracked files (`git clean`, irreversible).
        Clean => "clean",
        /// Record a commit.
        Commit => "commit",
        /// Merge.
        Merge => "merge",
        /// Rebase.
        Rebase => "rebase",
        /// Reset.
        Reset => "reset",
        /// Push to a remote.
        Push => "push",
        /// Create or delete a tag.
        Tag => "tag",
        /// Change repository configuration (hooks path, remotes, credentials helpers).
        Config => "config",
    }
}

operation_enum! {
    /// GitHub API operations.
    GitHubOp {
        /// Read issues, pull requests, code or metadata.
        Read => "read",
        /// Comment on an issue or pull request.
        Comment => "comment",
        /// Open an issue.
        CreateIssue => "create-issue",
        /// Open a pull request.
        CreatePullRequest => "create-pull-request",
        /// Merge a pull request.
        MergePullRequest => "merge-pull-request",
        /// Publish a release.
        CreateRelease => "create-release",
        /// Trigger a workflow run.
        TriggerWorkflow => "trigger-workflow",
        /// Change repository settings, permissions or branch protection.
        ModifySettings => "modify-settings",
        /// Delete a repository.
        DeleteRepository => "delete-repository",
    }
}

operation_enum! {
    /// Secret store operations. Only names ever cross the protocol; values never do.
    SecretOp {
        /// List secret names.
        List => "list",
        /// Read a secret value.
        Read => "read",
        /// Create or change a secret.
        Write => "write",
        /// Delete a secret.
        Delete => "delete",
    }
}

operation_enum! {
    /// Database operations, by effect.
    DatabaseOp {
        /// Read rows.
        Read => "read",
        /// Insert, update or delete rows.
        Write => "write",
        /// Change schema (DDL).
        SchemaChange => "schema-change",
        /// Drop or truncate tables or databases.
        Drop => "drop",
        /// Users, grants, configuration.
        Admin => "admin",
        /// Run schema migrations.
        Migrate => "migrate",
        /// Bulk import or load data.
        BulkLoad => "bulk-load",
    }
}

operation_enum! {
    /// Terraform operations.
    TerraformOp {
        /// `terraform init`.
        Init => "init",
        /// `terraform validate`.
        Validate => "validate",
        /// `terraform plan`.
        Plan => "plan",
        /// `terraform apply`.
        Apply => "apply",
        /// `terraform destroy`.
        Destroy => "destroy",
        /// `terraform import`.
        Import => "import",
        /// `terraform state rm|mv|push` and similar.
        StateModify => "state-modify",
    }
}

operation_enum! {
    /// Network operations.
    NetworkOp {
        /// An HTTP(S) request.
        Request => "request",
        /// A raw TCP connection.
        Connect => "connect",
    }
}

operation_enum! {
    /// Ways data leaves the machine other than ordinary network requests.
    TransferKind {
        /// Upload a file or archive.
        Upload => "upload",
        /// Publish to a paste or sharing service.
        Share => "share",
    }
}

operation_enum! {
    /// Package manager operations.
    PackageOp {
        /// Add or install packages.
        Install => "install",
        /// Remove packages.
        Uninstall => "uninstall",
        /// Update or upgrade packages, or rewrite the lock file.
        Update => "update",
        /// List installed packages.
        List => "list",
        /// Audit dependencies for known vulnerabilities.
        Audit => "audit",
        /// Publish a package to a registry.
        Publish => "publish",
    }
}

operation_enum! {
    /// Cloud control-plane operations, by effect.
    CloudOp {
        /// Describe or get a resource.
        Read => "read",
        /// List resources.
        List => "list",
        /// Create a resource.
        Create => "create",
        /// Change a resource.
        Modify => "modify",
        /// Delete a resource.
        Delete => "delete",
        /// Change identity and access management (users, roles, policies, keys).
        ModifyIam => "modify-iam",
    }
}

operation_enum! {
    /// Configuration operations.
    ConfigOp {
        /// Read configuration.
        Read => "read",
        /// Change configuration.
        Modify => "modify",
        /// Delete configuration.
        Delete => "delete",
    }
}

/// Which configuration a [`ConfigurationAction`] concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigScope {
    /// AgentGuard's own configuration and trusted state.
    Agentguard,
    /// The AI agent's settings (hooks, permissions, sandbox), which wire AgentGuard in.
    AgentSettings,
    /// Other security tooling (scanners, signing, branch protection files).
    Security,
    /// Continuous integration pipelines.
    Ci,
    /// Build configuration.
    Build,
    /// Editor or IDE settings.
    Editor,
    /// Anything else.
    Other,
}

impl ConfigScope {
    /// Parse a wire name.
    pub fn parse(value: &str) -> Result<Self, SecurityError> {
        match value {
            "agentguard" => Ok(Self::Agentguard),
            "agent-settings" => Ok(Self::AgentSettings),
            "security" => Ok(Self::Security),
            "ci" => Ok(Self::Ci),
            "build" => Ok(Self::Build),
            "editor" => Ok(Self::Editor),
            "other" => Ok(Self::Other),
            _ => Err(SecurityError::UnknownVariant {
                kind: "configuration scope",
                expected: "agentguard, agent-settings, security, ci, build, editor, other",
            }),
        }
    }

    /// Whether this scope is AgentGuard's trusted state (changes are denied by the guards).
    #[must_use]
    pub const fn is_trusted_state(self) -> bool {
        matches!(self, Self::Agentguard | Self::AgentSettings)
    }
}

/// Upper bound on packages named in one package action.
pub const MAX_PACKAGES: usize = 64;

/// Largest inline content accepted with a write (the request itself is at most 64 KiB).
pub const MAX_INLINE_CONTENT: usize = 48 * 1024;

/// Content an integration supplies with a write or append, so the engine can inspect it for
/// secrets. Never displayed, logged or stored: `Debug` shows only the size, and the
/// serialized form (used for the approval digest) is the size and a SHA-256.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct InlineContent(String);

impl InlineContent {
    /// Wrap content of at most [`MAX_INLINE_CONTENT`] bytes.
    pub fn new(text: String) -> Result<Self, SecurityError> {
        if text.len() > MAX_INLINE_CONTENT {
            return Err(SecurityError::InvalidIdentifier {
                field: "content",
                rule: "inline content is at most 48 KiB",
            });
        }
        Ok(Self(text))
    }

    /// The content, for inspection only.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for InlineContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InlineContent({} bytes)", self.0.len())
    }
}

impl Serialize for InlineContent {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        use sha2::Digest;
        let mut st = s.serialize_struct("InlineContent", 2)?;
        st.serialize_field("bytes", &self.0.len())?;
        st.serialize_field(
            "sha256",
            &hex::encode(sha2::Sha256::digest(self.0.as_bytes())),
        )?;
        st.end()
    }
}

impl<'de> Deserialize<'de> for InlineContent {
    fn deserialize<D: serde::Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
        Err(serde::de::Error::custom(
            "inline content arrives only through the authorization protocol",
        ))
    }
}

/// A filesystem action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FilesystemAction {
    /// What to do.
    pub op: FileOp,
    /// The target.
    pub path: NormalizedPath,
    /// Destination of a rename, copy or archive.
    pub destination: Option<NormalizedPath>,
    /// Remote side of an upload or download.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<Host>,
    /// Content written or appended, when the integration supplies it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<InlineContent>,
}

/// A shell command, kept as the text the agent supplied. Structured parsing is a later phase;
/// classification of this text is best effort and never the sole basis for an allow.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TerminalAction {
    /// The command line.
    pub command: BoundedText<8192>,
}

impl TerminalAction {
    /// The first word of the command with any directory prefix removed, if any.
    #[must_use]
    pub fn program(&self) -> Option<&str> {
        let first = self.command.as_str().split_whitespace().next()?;
        Some(first.rsplit('/').next().unwrap_or(first))
    }
}

/// A Git action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GitAction {
    /// What to do.
    pub op: GitOp,
    /// Remote name, for remote operations.
    pub remote: Option<Name>,
    /// Target ref (branch or tag), when relevant.
    pub target_ref: Option<Name>,
    /// Whether history is rewritten or overwritten (`--force`, `reset --hard`).
    pub force: bool,
}

/// A GitHub API action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GitHubAction {
    /// What to do.
    pub op: GitHubOp,
    /// Target repository, when stated.
    pub repository: Option<RepositoryId>,
}

/// A secret store action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretAction {
    /// What to do.
    pub op: SecretOp,
    /// The secret's name (never its value).
    pub name: Name,
}

/// A database action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DatabaseAction {
    /// What to do.
    pub op: DatabaseOp,
    /// Logical database or connection name.
    pub target: Name,
    /// Environment of the target.
    pub environment: Environment,
}

/// A Terraform action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TerraformAction {
    /// What to do.
    pub op: TerraformOp,
    /// Terraform workspace, when stated.
    pub workspace: Option<Name>,
    /// Environment of the target.
    pub environment: Environment,
}

/// A network action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkAction {
    /// What to do.
    pub op: NetworkOp,
    /// Destination host.
    pub host: Host,
    /// Destination port, when stated.
    pub port: Option<u16>,
}

/// An external transfer.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransferAction {
    /// How the data leaves.
    pub kind: TransferKind,
    /// Where it goes.
    pub destination: Host,
}

/// A tool with no typed model.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CustomToolAction {
    /// Tool name.
    pub tool: Name,
    /// Providing server (for example an MCP server name), when known.
    pub server: Option<Name>,
}

/// A package manager action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PackageAction {
    /// What to do.
    pub op: PackageOp,
    /// The package manager (for example `npm`, `cargo`, `pip`).
    pub manager: Name,
    /// Packages named, at most [`MAX_PACKAGES`]. Empty means "as the manifest says".
    pub packages: Vec<Name>,
    /// Whether the change is machine-wide rather than project-local.
    pub global: bool,
}

/// A cloud control-plane action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CloudAction {
    /// What to do.
    pub op: CloudOp,
    /// Provider (for example `aws`, `gcp`, `azure`).
    pub provider: Name,
    /// Service (for example `s3`, `iam`, `compute`).
    pub service: Name,
    /// Resource identifier, when stated.
    pub resource: Option<Name>,
    /// Environment of the target.
    pub environment: Environment,
}

/// A configuration action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConfigurationAction {
    /// What to do.
    pub op: ConfigOp,
    /// Which configuration.
    pub scope: ConfigScope,
    /// Setting name, when stated.
    pub key: Option<Name>,
    /// File holding the configuration, when stated.
    pub path: Option<NormalizedPath>,
}

/// An action the integration could not map to a typed category.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UnknownAction {
    /// The integration's own name for the kind of action.
    pub kind: Name,
    /// The integration's own name for the operation.
    pub operation: Name,
    /// What it targets, as free text.
    pub target: Option<BoundedText<256>>,
}

/// One requested action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "category", rename_all = "kebab-case")]
pub enum Action {
    /// See [`FilesystemAction`].
    Filesystem(FilesystemAction),
    /// See [`TerminalAction`].
    Terminal(TerminalAction),
    /// See [`GitAction`].
    Git(GitAction),
    /// See [`GitHubAction`].
    #[serde(rename = "github")]
    GitHub(GitHubAction),
    /// See [`SecretAction`].
    Secrets(SecretAction),
    /// See [`DatabaseAction`].
    Database(DatabaseAction),
    /// See [`TerraformAction`].
    Terraform(TerraformAction),
    /// See [`NetworkAction`].
    Network(NetworkAction),
    /// See [`TransferAction`].
    ExternalTransfer(TransferAction),
    /// See [`CustomToolAction`].
    CustomTool(CustomToolAction),
    /// See [`PackageAction`].
    PackageManager(PackageAction),
    /// See [`CloudAction`].
    Cloud(CloudAction),
    /// See [`ConfigurationAction`].
    Configuration(ConfigurationAction),
    /// See [`UnknownAction`].
    Unknown(UnknownAction),
}

impl Action {
    /// The category.
    #[must_use]
    pub const fn category(&self) -> ActionCategory {
        match self {
            Action::Filesystem(_) => ActionCategory::Filesystem,
            Action::Terminal(_) => ActionCategory::Terminal,
            Action::Git(_) => ActionCategory::Git,
            Action::GitHub(_) => ActionCategory::GitHub,
            Action::Secrets(_) => ActionCategory::Secrets,
            Action::Database(_) => ActionCategory::Database,
            Action::Terraform(_) => ActionCategory::Terraform,
            Action::Network(_) => ActionCategory::Network,
            Action::ExternalTransfer(_) => ActionCategory::ExternalTransfer,
            Action::CustomTool(_) => ActionCategory::CustomTool,
            Action::PackageManager(_) => ActionCategory::PackageManager,
            Action::Cloud(_) => ActionCategory::Cloud,
            Action::Configuration(_) => ActionCategory::Configuration,
            Action::Unknown(_) => ActionCategory::Unknown,
        }
    }

    /// The operation name within the category. Terminal commands are `execute` and custom
    /// tools are `invoke`.
    #[must_use]
    pub fn operation(&self) -> &str {
        match self {
            Action::Filesystem(a) => a.op.as_str(),
            Action::Terminal(_) => "execute",
            Action::Git(a) => a.op.as_str(),
            Action::GitHub(a) => a.op.as_str(),
            Action::Secrets(a) => a.op.as_str(),
            Action::Database(a) => a.op.as_str(),
            Action::Terraform(a) => a.op.as_str(),
            Action::Network(a) => a.op.as_str(),
            Action::ExternalTransfer(a) => a.kind.as_str(),
            Action::CustomTool(_) => "invoke",
            Action::PackageManager(a) => a.op.as_str(),
            Action::Cloud(a) => a.op.as_str(),
            Action::Configuration(a) => a.op.as_str(),
            Action::Unknown(a) => a.operation.as_str(),
        }
    }

    /// Whether the operation name was not recognised within a typed category. The `Unknown`
    /// category is different: it is declared unknown and evaluated with explicit uncertainty
    /// instead of being denied as an anomaly.
    #[must_use]
    pub const fn is_unknown_operation(&self) -> bool {
        match self {
            Action::Filesystem(a) => a.op.is_unknown(),
            Action::Git(a) => a.op.is_unknown(),
            Action::GitHub(a) => a.op.is_unknown(),
            Action::Secrets(a) => a.op.is_unknown(),
            Action::Database(a) => a.op.is_unknown(),
            Action::Terraform(a) => a.op.is_unknown(),
            Action::Network(a) => a.op.is_unknown(),
            Action::ExternalTransfer(a) => a.kind.is_unknown(),
            Action::PackageManager(a) => a.op.is_unknown(),
            Action::Cloud(a) => a.op.is_unknown(),
            Action::Configuration(a) => a.op.is_unknown(),
            Action::Terminal(_) | Action::CustomTool(_) | Action::Unknown(_) => false,
        }
    }

    /// Whether the action, as classified, has no side effect beyond reading. Read-only is not
    /// the same as low risk: reading a secret is read-only and high risk. Terminal commands and
    /// custom tools are never read-only because their effect is not modelled.
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        match self {
            Action::Filesystem(a) => matches!(a.op, FileOp::Read | FileOp::List | FileOp::Traverse),
            Action::Git(a) => matches!(
                a.op,
                GitOp::Status | GitOp::Diff | GitOp::Log | GitOp::Show | GitOp::BranchList
            ),
            Action::GitHub(a) => matches!(a.op, GitHubOp::Read),
            Action::Secrets(a) => matches!(a.op, SecretOp::List | SecretOp::Read),
            Action::Database(a) => matches!(a.op, DatabaseOp::Read),
            Action::Terraform(a) => matches!(a.op, TerraformOp::Validate | TerraformOp::Plan),
            Action::PackageManager(a) => matches!(a.op, PackageOp::List | PackageOp::Audit),
            Action::Cloud(a) => matches!(a.op, CloudOp::Read | CloudOp::List),
            Action::Configuration(a) => matches!(a.op, ConfigOp::Read),
            Action::Terminal(_)
            | Action::Network(_)
            | Action::ExternalTransfer(_)
            | Action::CustomTool(_)
            | Action::Unknown(_) => false,
        }
    }

    /// Every filesystem path the action names.
    #[must_use]
    pub fn paths(&self) -> Vec<&NormalizedPath> {
        match self {
            Action::Filesystem(a) => std::iter::once(&a.path)
                .chain(a.destination.as_ref())
                .collect(),
            Action::Configuration(a) => a.path.iter().collect(),
            _ => Vec::new(),
        }
    }

    /// One-line description of the target, for audit records and prompts. May contain
    /// agent-supplied text; callers redact and sanitise before display or storage.
    #[must_use]
    pub fn resource(&self) -> String {
        match self {
            Action::Filesystem(a) => match (&a.destination, &a.remote) {
                (Some(dest), _) => format!("{} -> {dest}", a.path),
                (None, Some(remote)) if a.op == FileOp::Download => {
                    format!("{remote} -> {}", a.path)
                }
                (None, Some(remote)) => format!("{} -> {remote}", a.path),
                (None, None) => a.path.to_string(),
            },
            Action::Terminal(a) => a.command.to_string(),
            Action::Git(a) => {
                let mut out = String::new();
                for part in [&a.remote, &a.target_ref].into_iter().flatten() {
                    if !out.is_empty() {
                        out.push(' ');
                    }
                    out.push_str(part.as_str());
                }
                if a.force {
                    out.push_str(" (force)");
                }
                out
            }
            Action::GitHub(a) => a
                .repository
                .as_ref()
                .map_or_else(String::new, ToString::to_string),
            Action::Secrets(a) => a.name.to_string(),
            Action::Database(a) => format!("{} ({:?})", a.target, a.environment),
            Action::Terraform(a) => format!(
                "{} ({:?})",
                a.workspace.as_ref().map_or("default", Name::as_str),
                a.environment
            ),
            Action::Network(a) => match a.port {
                Some(port) => format!("{}:{port}", a.host),
                None => a.host.to_string(),
            },
            Action::ExternalTransfer(a) => a.destination.to_string(),
            Action::CustomTool(a) => match &a.server {
                Some(server) => format!("{server}/{}", a.tool),
                None => a.tool.to_string(),
            },
            Action::PackageManager(a) => {
                let names: Vec<&str> = a.packages.iter().map(Name::as_str).collect();
                format!(
                    "{} {}{}",
                    a.manager,
                    names.join(" "),
                    if a.global { " (global)" } else { "" }
                )
            }
            Action::Cloud(a) => format!(
                "{}/{}/{} ({:?})",
                a.provider,
                a.service,
                a.resource.as_ref().map_or("*", Name::as_str),
                a.environment
            ),
            Action::Configuration(a) => match (&a.path, &a.key) {
                (Some(path), _) => path.to_string(),
                (None, Some(key)) => format!("{:?}:{key}", a.scope),
                (None, None) => format!("{:?}", a.scope),
            },
            Action::Unknown(a) => format!(
                "{} {}",
                a.kind,
                a.target.as_ref().map_or("", BoundedText::as_str)
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_names_match_serde() {
        for c in ActionCategory::ALL {
            assert_eq!(
                serde_json::to_string(&c).unwrap(),
                format!("\"{}\"", c.as_str())
            );
        }
    }

    #[test]
    fn op_parse_known_unknown_and_invalid() {
        assert_eq!(FileOp::parse("read").unwrap(), FileOp::Read);
        assert_eq!(GitOp::parse("push").unwrap(), GitOp::Push);
        let unknown = GitOp::parse("filter-branch").unwrap();
        assert!(unknown.is_unknown());
        assert_eq!(unknown.as_str(), "filter-branch");
        // Case-sensitive: a variant spelled differently is unknown, never silently mapped.
        assert!(FileOp::parse("READ").unwrap().is_unknown());
        assert!(FileOp::parse("").is_err());
        assert!(FileOp::parse("rm -rf").is_err());
    }

    #[test]
    fn name_rules() {
        assert!(Name::new("feature/AH-1").is_ok());
        assert!(Name::new("mcp__server__tool").is_ok());
        assert!(Name::new("a b").is_err());
        assert!(Name::new("x".repeat(129)).is_err());
        assert!(Name::new("ok;rm").is_err());
    }

    #[test]
    fn host_normalisation_and_locality() {
        assert_eq!(Host::new("Example.COM.").unwrap().as_str(), "example.com");
        assert_eq!(Host::new("[::1]").unwrap().as_str(), "::1");
        assert!(Host::new("exa mple.com").is_err());
        assert!(Host::new("-bad.com").is_err());
        assert!(Host::new("").is_err());
        assert!(Host::new("bücher.de").is_err());
        for spelled in ["0177.0.0.1", "2130706433", "0x7f.1", "010.1.2.3"] {
            assert!(Host::new(spelled).is_err(), "{spelled}");
        }
        for local in [
            "localhost",
            "127.0.0.1",
            "10.1.2.3",
            "169.254.169.254",
            "::1",
            "::ffff:169.254.169.254",
            "fd00::1",
            "metadata.google.internal",
            "100.64.0.1",
        ] {
            assert!(Host::new(local).unwrap().is_local_or_private(), "{local}");
        }
        for public in ["example.com", "8.8.8.8", "2001:4860:4860::8888"] {
            assert!(
                !Host::new(public).unwrap().is_local_or_private(),
                "{public}"
            );
        }
    }

    #[test]
    fn read_only_and_unknown_classification() {
        let path = NormalizedPath::new("/p/a").unwrap();
        let read = Action::Filesystem(FilesystemAction {
            op: FileOp::Read,
            path: path.clone(),
            destination: None,
            remote: None,
            content: None,
        });
        assert!(read.is_read_only());
        assert!(!read.is_unknown_operation());
        let unknown = Action::Filesystem(FilesystemAction {
            op: FileOp::parse("truncate").unwrap(),
            path,
            destination: None,
            remote: None,
            content: None,
        });
        assert!(!unknown.is_read_only());
        assert!(unknown.is_unknown_operation());
        let term = Action::Terminal(TerminalAction {
            command: BoundedText::new("/usr/bin/ls -la").unwrap(),
        });
        assert!(!term.is_read_only());
        assert_eq!(term.operation(), "execute");
        if let Action::Terminal(t) = &term {
            assert_eq!(t.program(), Some("ls"));
        }
    }

    #[test]
    fn serde_round_trip_is_tagged() {
        let a = Action::Git(GitAction {
            op: GitOp::Push,
            remote: Some(Name::new("origin").unwrap()),
            target_ref: Some(Name::new("main").unwrap()),
            force: true,
        });
        let json = serde_json::to_string(&a).unwrap();
        assert!(json.contains("\"category\":\"git\""));
        assert_eq!(serde_json::from_str::<Action>(&json).unwrap(), a);
        assert_eq!(a.resource(), "origin main (force)");
    }
}
