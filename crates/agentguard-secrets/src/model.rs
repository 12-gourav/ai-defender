//! Detection vocabulary: what was found, how bad it is, and how sure the detector is.

use std::fmt;

use serde::{Deserialize, Serialize};

/// How damaging disclosure of the matched value would be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    /// Possibly a secret (high-entropy string without other evidence).
    Low,
    /// Credential-shaped value (assignment to a secret-named key, a JWT, a generic token).
    Medium,
    /// A provider credential, a password in a connection string or URL, a bearer token.
    High,
    /// Private keys and cloud or payment credentials that grant broad access.
    Critical,
}

impl Severity {
    /// Kebab-case name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Parse a kebab-case name.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What kind of secret a detector recognises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretCategory {
    /// Private keys (PEM, OpenSSH, PGP).
    PrivateKey,
    /// Cloud provider credentials (AWS, GCP service accounts, Azure storage keys).
    CloudCredential,
    /// Source-control and package-registry tokens (GitHub, GitLab, npm, PyPI).
    AccessToken,
    /// SaaS API keys (payments, messaging, AI providers).
    ApiKey,
    /// Passwords inside connection strings or URLs.
    ConnectionString,
    /// JSON Web Tokens and bearer tokens.
    BearerToken,
    /// A value assigned to a secret-named key (`password = ...`).
    CredentialAssignment,
    /// A high-entropy string without other evidence.
    HighEntropy,
    /// Matched by a pattern from trusted configuration.
    Custom,
}

impl SecretCategory {
    /// Kebab-case name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            SecretCategory::PrivateKey => "private-key",
            SecretCategory::CloudCredential => "cloud-credential",
            SecretCategory::AccessToken => "access-token",
            SecretCategory::ApiKey => "api-key",
            SecretCategory::ConnectionString => "connection-string",
            SecretCategory::BearerToken => "bearer-token",
            SecretCategory::CredentialAssignment => "credential-assignment",
            SecretCategory::HighEntropy => "high-entropy",
            SecretCategory::Custom => "custom",
        }
    }

    /// Parse a kebab-case name.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        [
            SecretCategory::PrivateKey,
            SecretCategory::CloudCredential,
            SecretCategory::AccessToken,
            SecretCategory::ApiKey,
            SecretCategory::ConnectionString,
            SecretCategory::BearerToken,
            SecretCategory::CredentialAssignment,
            SecretCategory::HighEntropy,
            SecretCategory::Custom,
        ]
        .into_iter()
        .find(|c| c.as_str() == text)
    }
}

impl fmt::Display for SecretCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One match inside one line. Holds byte offsets, never the matched text: callers that need
/// the text slice the line they already have and must not keep it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// Detector identifier (`aws-access-key-id`, `custom:acme`).
    pub detector: String,
    /// What kind of secret.
    pub category: SecretCategory,
    /// How bad.
    pub severity: Severity,
    /// Start of the secret value (byte offset in the line).
    pub start: usize,
    /// End of the secret value (exclusive).
    pub end: usize,
    /// How many leading bytes of the value are a public, provider-defined prefix (`ghp_`,
    /// `sk_live_`) that may be shown. Zero for everything else.
    pub public_prefix: usize,
}

/// Aggregate evidence about one piece of content, without any value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Evidence {
    /// Number of matches.
    pub count: usize,
    /// Highest severity among them.
    pub max_severity: Option<Severity>,
    /// Whether a private key block is present.
    pub private_key: bool,
}

impl Evidence {
    /// Add one match.
    pub fn add(&mut self, m: &Match) {
        self.count += 1;
        self.max_severity = self.max_severity.max(Some(m.severity));
        self.private_key |= m.category == SecretCategory::PrivateKey;
    }

    /// Merge another evidence summary.
    pub fn merge(&mut self, other: &Evidence) {
        self.count += other.count;
        self.max_severity = self.max_severity.max(other.max_severity);
        self.private_key |= other.private_key;
    }

    /// Whether anything at or above `min` was found.
    #[must_use]
    pub fn at_least(&self, min: Severity) -> bool {
        self.max_severity.is_some_and(|s| s >= min)
    }
}
