//! Typed identifiers. Each constructor validates its input; a value of one of these types is
//! proof that the validation ran.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::SecurityError;

macro_rules! uuid_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Generate a new random (version 4) identifier from the operating system's CSPRNG.
            #[must_use]
            pub fn generate() -> Self {
                Self(Uuid::new_v4())
            }

            /// Wrap an existing UUID.
            #[must_use]
            pub const fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            /// The underlying UUID.
            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0.hyphenated())
            }
        }

        impl FromStr for $name {
            type Err = SecurityError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(s)
                    .map(Self)
                    .map_err(|_| SecurityError::InvalidIdentifier {
                        field: stringify!($name),
                        rule: "must be a UUID",
                    })
            }
        }
    };
}

uuid_id! {
    /// Identifies one agent session (one `agentguard run` invocation).
    SessionId
}

uuid_id! {
    /// Identifies one authorization request. Echoed in the response as its correlation ID.
    RequestId
}

uuid_id! {
    /// Identifies one approval request and its decision. A public reference: shown to humans
    /// and agents, it authorizes nothing by itself.
    ApprovalId
}

uuid_id! {
    /// Identifies one authorization grant issued when a human approves a request. A public
    /// reference: consuming a grant also needs the requester's claim token.
    GrantId
}

/// Characters permitted in task identifiers, repository segments and agent versions.
fn is_ident_char(c: char, extra: &[char]) -> bool {
    c.is_ascii_alphanumeric() || extra.contains(&c)
}

/// A task identifier such as `AH-5064` or a short slug.
///
/// Rules: 1 to 64 characters, ASCII letters, digits, `.`, `_`, `-`; must start with a letter or
/// digit; must not contain `..`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TaskId(String);

impl TaskId {
    /// Maximum length in characters.
    pub const MAX_LEN: usize = 64;

    /// Validate and wrap.
    pub fn new(value: impl Into<String>) -> Result<Self, SecurityError> {
        let value = value.into();
        let field = "TaskId";
        if value.is_empty() {
            return Err(SecurityError::Empty { field });
        }
        if value.chars().count() > Self::MAX_LEN {
            return Err(SecurityError::TextTooLong {
                field,
                max: Self::MAX_LEN,
            });
        }
        if !value
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        {
            return Err(SecurityError::InvalidIdentifier {
                field,
                rule: "must start with a letter or digit",
            });
        }
        if !value.chars().all(|c| is_ident_char(c, &['.', '_', '-'])) {
            return Err(SecurityError::InvalidIdentifier {
                field,
                rule: "only letters, digits, '.', '_' and '-' are permitted",
            });
        }
        if value.contains("..") {
            return Err(SecurityError::InvalidIdentifier {
                field,
                rule: "must not contain '..'",
            });
        }
        Ok(Self(value))
    }

    /// Borrow the identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TaskId {
    type Error = SecurityError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<TaskId> for String {
    fn from(value: TaskId) -> Self {
        value.0
    }
}

impl FromStr for TaskId {
    type Err = SecurityError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl fmt::Display for TaskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The kind of AI agent an adapter integrates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum AgentKind {
    /// Anthropic Claude Code CLI.
    ClaudeCode,
    /// OpenAI Codex CLI.
    Codex,
    /// Google Gemini CLI.
    GeminiCli,
    /// Google Antigravity CLI.
    AntigravityCli,
    /// Cursor agent CLI.
    CursorAgent,
    /// Any other command run under the generic adapter.
    Generic,
}

impl AgentKind {
    /// All known kinds, in display order.
    pub const ALL: [AgentKind; 6] = [
        AgentKind::ClaudeCode,
        AgentKind::Codex,
        AgentKind::GeminiCli,
        AgentKind::AntigravityCli,
        AgentKind::CursorAgent,
        AgentKind::Generic,
    ];

    /// Canonical short name used on the command line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            AgentKind::ClaudeCode => "claude",
            AgentKind::Codex => "codex",
            AgentKind::GeminiCli => "gemini",
            AgentKind::AntigravityCli => "antigravity",
            AgentKind::CursorAgent => "cursor",
            AgentKind::Generic => "generic",
        }
    }
}

impl fmt::Display for AgentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AgentKind {
    type Err = SecurityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|k| k.as_str() == s)
            .ok_or(SecurityError::UnknownVariant {
                kind: "agent kind",
                expected: "claude, codex, gemini, antigravity, cursor, generic",
            })
    }
}

/// A version string reported by an agent binary. 1 to 64 characters of letters, digits,
/// `.`, `+`, `-`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AgentVersion(String);

impl AgentVersion {
    /// Maximum length in characters.
    pub const MAX_LEN: usize = 64;

    /// Validate and wrap.
    pub fn new(value: impl Into<String>) -> Result<Self, SecurityError> {
        let value = value.into();
        let field = "AgentVersion";
        if value.is_empty() {
            return Err(SecurityError::Empty { field });
        }
        if value.chars().count() > Self::MAX_LEN {
            return Err(SecurityError::TextTooLong {
                field,
                max: Self::MAX_LEN,
            });
        }
        if !value.chars().all(|c| is_ident_char(c, &['.', '+', '-'])) {
            return Err(SecurityError::InvalidIdentifier {
                field,
                rule: "only letters, digits, '.', '+' and '-' are permitted",
            });
        }
        Ok(Self(value))
    }

    /// Borrow the version string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for AgentVersion {
    type Error = SecurityError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<AgentVersion> for String {
    fn from(value: AgentVersion) -> Self {
        value.0
    }
}

impl fmt::Display for AgentVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which agent is running, and which version of it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// The agent kind.
    pub kind: AgentKind,
    /// The detected version, when known.
    pub version: Option<AgentVersion>,
}

impl AgentIdentity {
    /// An identity with no known version.
    #[must_use]
    pub const fn new(kind: AgentKind) -> Self {
        Self {
            kind,
            version: None,
        }
    }

    /// An identity with a known version.
    #[must_use]
    pub const fn with_version(kind: AgentKind, version: AgentVersion) -> Self {
        Self {
            kind,
            version: Some(version),
        }
    }
}

impl fmt::Display for AgentIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.version {
            Some(v) => write!(f, "{}@{v}", self.kind),
            None => write!(f, "{}", self.kind),
        }
    }
}

/// A Git hosting provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum GitProvider {
    /// github.com or GitHub Enterprise.
    GitHub,
    /// gitlab.com or self-managed GitLab.
    GitLab,
    /// Bitbucket.
    Bitbucket,
    /// Any other remote.
    Generic,
}

impl GitProvider {
    /// Canonical short name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            GitProvider::GitHub => "github",
            GitProvider::GitLab => "gitlab",
            GitProvider::Bitbucket => "bitbucket",
            GitProvider::Generic => "generic",
        }
    }
}

impl fmt::Display for GitProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for GitProvider {
    type Err = SecurityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "github" => Ok(GitProvider::GitHub),
            "gitlab" => Ok(GitProvider::GitLab),
            "bitbucket" => Ok(GitProvider::Bitbucket),
            "generic" => Ok(GitProvider::Generic),
            _ => Err(SecurityError::UnknownVariant {
                kind: "git provider",
                expected: "github, gitlab, bitbucket, generic",
            }),
        }
    }
}

/// One path segment of a repository identity (owner or name). 1 to 100 characters of
/// letters, digits, `.`, `_`, `-`; not `.` or `..`; no `/`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RepoSegment(String);

impl RepoSegment {
    /// Maximum length in characters.
    pub const MAX_LEN: usize = 100;

    /// Validate and wrap.
    pub fn new(value: impl Into<String>) -> Result<Self, SecurityError> {
        let value = value.into();
        let field = "RepoSegment";
        if value.is_empty() {
            return Err(SecurityError::Empty { field });
        }
        if value.chars().count() > Self::MAX_LEN {
            return Err(SecurityError::TextTooLong {
                field,
                max: Self::MAX_LEN,
            });
        }
        if value == "." || value == ".." {
            return Err(SecurityError::InvalidIdentifier {
                field,
                rule: "must not be '.' or '..'",
            });
        }
        if !value.chars().all(|c| is_ident_char(c, &['.', '_', '-'])) {
            return Err(SecurityError::InvalidIdentifier {
                field,
                rule: "only letters, digits, '.', '_' and '-' are permitted",
            });
        }
        Ok(Self(value))
    }

    /// Borrow the segment.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RepoSegment {
    type Error = SecurityError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<RepoSegment> for String {
    fn from(value: RepoSegment) -> Self {
        value.0
    }
}

impl fmt::Display for RepoSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Canonical identity of a repository: provider, owner (or group path segment) and name.
///
/// The canonical remote URL is deliberately *not* part of this type in Phase 1; URL
/// canonicalisation belongs to the Git guard and will be added with it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RepositoryId {
    /// Hosting provider.
    pub provider: GitProvider,
    /// Owner, organisation or group.
    pub owner: RepoSegment,
    /// Repository name without a `.git` suffix.
    pub name: RepoSegment,
}

impl RepositoryId {
    /// Build an identity from validated parts.
    #[must_use]
    pub const fn new(provider: GitProvider, owner: RepoSegment, name: RepoSegment) -> Self {
        Self {
            provider,
            owner,
            name,
        }
    }

    /// Parse `provider:owner/name`.
    pub fn parse(value: &str) -> Result<Self, SecurityError> {
        let (provider, rest) = value
            .split_once(':')
            .ok_or(SecurityError::InvalidIdentifier {
                field: "RepositoryId",
                rule: "expected provider:owner/name",
            })?;
        let (owner, name) = rest
            .split_once('/')
            .ok_or(SecurityError::InvalidIdentifier {
                field: "RepositoryId",
                rule: "expected provider:owner/name",
            })?;
        Ok(Self {
            provider: provider.parse()?,
            owner: RepoSegment::new(owner)?,
            name: RepoSegment::new(name)?,
        })
    }
}

impl fmt::Display for RepositoryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}/{}", self.provider, self.owner, self.name)
    }
}

impl FromStr for RepositoryId {
    type Err = SecurityError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// SHA-256 digest of a canonical effective policy. Every decision, approval and audit record
/// is stamped with the version it was made under.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PolicyVersion([u8; 32]);

impl PolicyVersion {
    /// Compute the version of a canonical byte representation.
    #[must_use]
    pub fn compute(canonical: &[u8]) -> Self {
        let digest = Sha256::digest(canonical);
        Self(digest.into())
    }

    /// Wrap raw digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parse 64 lowercase or uppercase hexadecimal characters.
    pub fn from_hex(value: &str) -> Result<Self, SecurityError> {
        if value.len() != 64 {
            return Err(SecurityError::InvalidPolicyVersion);
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(value, &mut bytes).map_err(|_| SecurityError::InvalidPolicyVersion)?;
        Ok(Self(bytes))
    }

    /// The raw digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Full lowercase hexadecimal form.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// First 12 hexadecimal characters, for display.
    #[must_use]
    pub fn short(&self) -> String {
        self.to_hex().chars().take(12).collect()
    }
}

impl TryFrom<String> for PolicyVersion {
    type Error = SecurityError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_hex(&value)
    }
}

impl From<PolicyVersion> for String {
    fn from(value: PolicyVersion) -> Self {
        value.to_hex()
    }
}

impl FromStr for PolicyVersion {
    type Err = SecurityError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl fmt::Debug for PolicyVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PolicyVersion({})", self.short())
    }
}

impl fmt::Display for PolicyVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_ids_are_unique_and_round_trip() {
        let a = SessionId::generate();
        let b = SessionId::generate();
        assert_ne!(a, b);
        let parsed: SessionId = a.to_string().parse().unwrap();
        assert_eq!(parsed, a);
        assert!("not-a-uuid".parse::<SessionId>().is_err());
    }

    #[test]
    fn task_id_rules() {
        assert!(TaskId::new("AH-5064").is_ok());
        assert!(TaskId::new("feature_x.1").is_ok());
        assert!(TaskId::new("").is_err());
        assert!(TaskId::new("-leading").is_err());
        assert!(TaskId::new("a..b").is_err());
        assert!(TaskId::new("a/b").is_err());
        assert!(TaskId::new("a b").is_err());
        assert!(TaskId::new("x".repeat(65)).is_err());
        assert!(TaskId::new("x".repeat(64)).is_ok());
    }

    #[test]
    fn task_id_serde_validates() {
        let ok: TaskId = serde_json::from_str("\"AH-1\"").unwrap();
        assert_eq!(ok.as_str(), "AH-1");
        let bad: Result<TaskId, _> = serde_json::from_str("\"../etc\"");
        assert!(bad.is_err());
    }

    #[test]
    fn agent_kind_names_round_trip() {
        for kind in AgentKind::ALL {
            assert_eq!(kind.as_str().parse::<AgentKind>().unwrap(), kind);
        }
        assert!("copilot".parse::<AgentKind>().is_err());
        assert_eq!(
            serde_json::to_string(&AgentKind::ClaudeCode).unwrap(),
            "\"claude-code\""
        );
    }

    #[test]
    fn agent_identity_display() {
        let id =
            AgentIdentity::with_version(AgentKind::Codex, AgentVersion::new("0.124.0").unwrap());
        assert_eq!(id.to_string(), "codex@0.124.0");
        assert_eq!(
            AgentIdentity::new(AgentKind::Generic).to_string(),
            "generic"
        );
        assert!(AgentVersion::new("1.0 beta").is_err());
    }

    #[test]
    fn repository_id_parse_and_display() {
        let repo = RepositoryId::parse("github:acme/app").unwrap();
        assert_eq!(repo.provider, GitProvider::GitHub);
        assert_eq!(repo.to_string(), "github:acme/app");
        assert!(RepositoryId::parse("github:acme").is_err());
        assert!(RepositoryId::parse("github:../x").is_err());
        assert!(RepositoryId::parse("svn:a/b").is_err());
        assert!(RepositoryId::parse("github:a/b/c").is_err());
    }

    #[test]
    fn policy_version_is_deterministic_and_parses() {
        let v1 = PolicyVersion::compute(b"policy");
        let v2 = PolicyVersion::compute(b"policy");
        assert_eq!(v1, v2);
        assert_ne!(v1, PolicyVersion::compute(b"policy2"));
        let hex = v1.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(PolicyVersion::from_hex(&hex).unwrap(), v1);
        assert!(PolicyVersion::from_hex("abc").is_err());
        assert!(PolicyVersion::from_hex(&"zz".repeat(32)).is_err());
        assert_eq!(v1.short().len(), 12);
        assert_eq!(format!("{v1:?}"), format!("PolicyVersion({})", v1.short()));
    }
}
