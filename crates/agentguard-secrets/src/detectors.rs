//! Detectors.
//!
//! A [`Detector`] finds secret values in one line of text and reports byte ranges. Built-in
//! detectors cover provider formats, structural markers (private keys, connection strings,
//! JWTs, bearer tokens), credential assignments and high-entropy strings; [`CustomDetector`]
//! adds patterns from trusted configuration. New providers implement the trait or add a
//! [`ProviderSpec`] row; the scanning code does not change.
//!
//! All patterns use the `regex` crate, which matches in linear time (no backtracking), so a
//! configured pattern cannot cause catastrophic matching; compiled size is capped.
//!
//! Detection is heuristic. It finds common credential shapes; it cannot find every secret and
//! reports some values that are not secrets (see docs/SECRETS.md).

use std::sync::LazyLock;

use regex::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};

use crate::model::{Match, SecretCategory, Severity};

/// Finds secrets in one line.
pub trait Detector: Send + Sync {
    /// Stable identifier.
    fn id(&self) -> &str;
    /// Human description (what it matches), for status and explanations.
    fn description(&self) -> &str;
    /// Category of what it finds.
    fn category(&self) -> SecretCategory;
    /// Append every match in `line`.
    fn detect(&self, line: &str, out: &mut Vec<Match>);
    /// A pattern that matches every line [`Detector::detect`] could report on (a superset).
    /// Lines it does not match skip the detector. `None` runs the detector on every line.
    fn prefilter(&self) -> Option<&str> {
        None
    }
}

/// A provider or structural pattern.
#[derive(Debug, Clone, Copy)]
pub struct ProviderSpec {
    /// Identifier.
    pub id: &'static str,
    /// Description.
    pub description: &'static str,
    /// Category.
    pub category: SecretCategory,
    /// Severity.
    pub severity: Severity,
    /// The pattern. Capture group 1, when present, is the secret value; otherwise the whole
    /// match is.
    pub pattern: &'static str,
    /// Public, provider-defined prefixes of the value that may be displayed.
    pub prefixes: &'static [&'static str],
    /// Reject values that look like placeholders or references.
    pub filter_placeholders: bool,
}

use SecretCategory as C;
use Severity as S;

/// Built-in provider and structural patterns. Examples, not an exhaustive list.
pub const PROVIDERS: &[ProviderSpec] = &[
    ProviderSpec {
        id: "private-key",
        description: "PEM, OpenSSH or PGP private key block",
        category: C::PrivateKey,
        severity: S::Critical,
        pattern: r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----",
        prefixes: &[],
        filter_placeholders: false,
    },
    ProviderSpec {
        id: "aws-access-key-id",
        description: "AWS access key ID (AKIA/ASIA followed by 16 characters)",
        category: C::CloudCredential,
        severity: S::Critical,
        pattern: r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b",
        prefixes: &["AKIA", "ASIA", "ABIA", "ACCA"],
        filter_placeholders: false,
    },
    ProviderSpec {
        id: "aws-secret-access-key",
        description: "AWS secret access key assigned to an AWS-named key",
        category: C::CloudCredential,
        severity: S::Critical,
        pattern: r#"(?i)aws[a-z0-9_.\-]{0,20}(?:secret|sk)[a-z0-9_.\-]{0,20}["']?\s*(?:=|:|=>)\s*["']?([A-Za-z0-9/+=]{40})(?:[^A-Za-z0-9/+=]|$)"#,
        prefixes: &[],
        filter_placeholders: true,
    },
    ProviderSpec {
        id: "gcp-service-account",
        description: "Google Cloud service account key file (type service_account)",
        category: C::CloudCredential,
        severity: S::Critical,
        pattern: r#""type"\s*:\s*"(service_account)""#,
        prefixes: &[],
        filter_placeholders: false,
    },
    ProviderSpec {
        id: "azure-storage-key",
        description: "Azure storage account key in a connection string (AccountKey=)",
        category: C::CloudCredential,
        severity: S::Critical,
        pattern: r"(?i)AccountKey=([A-Za-z0-9+/]{40,}={0,2})",
        prefixes: &[],
        filter_placeholders: true,
    },
    ProviderSpec {
        id: "github-token",
        description: "GitHub personal, OAuth, app or refresh token",
        category: C::AccessToken,
        severity: S::High,
        pattern: r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b",
        prefixes: &["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"],
        filter_placeholders: false,
    },
    ProviderSpec {
        id: "gitlab-token",
        description: "GitLab personal, pipeline or deploy token",
        category: C::AccessToken,
        severity: S::High,
        pattern: r"\b((?:glpat|glptt|gldt|glrt)-[A-Za-z0-9_\-]{20,64})\b",
        prefixes: &["glpat-", "glptt-", "gldt-", "glrt-"],
        filter_placeholders: false,
    },
    ProviderSpec {
        id: "npm-token",
        description: "npm access token",
        category: C::AccessToken,
        severity: S::High,
        pattern: r"\b(npm_[A-Za-z0-9]{36})\b",
        prefixes: &["npm_"],
        filter_placeholders: false,
    },
    ProviderSpec {
        id: "pypi-token",
        description: "PyPI API token",
        category: C::AccessToken,
        severity: S::High,
        pattern: r"\b(pypi-[A-Za-z0-9_\-]{50,})",
        prefixes: &["pypi-"],
        filter_placeholders: false,
    },
    ProviderSpec {
        id: "slack-token",
        description: "Slack bot, user or app token",
        category: C::ApiKey,
        severity: S::High,
        pattern: r"\b(xox[abposr]-[A-Za-z0-9\-]{10,250})\b",
        prefixes: &["xoxa-", "xoxb-", "xoxp-", "xoxo-", "xoxs-", "xoxr-"],
        filter_placeholders: false,
    },
    ProviderSpec {
        id: "stripe-key",
        description: "Stripe secret or restricted key",
        category: C::ApiKey,
        severity: S::Critical,
        pattern: r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,247})\b",
        prefixes: &["sk_live_", "sk_test_", "rk_live_", "rk_test_"],
        filter_placeholders: false,
    },
    ProviderSpec {
        id: "anthropic-key",
        description: "Anthropic API key",
        category: C::ApiKey,
        severity: S::High,
        pattern: r"\b(sk-ant-[A-Za-z0-9_\-]{20,200})",
        prefixes: &["sk-ant-"],
        filter_placeholders: false,
    },
    ProviderSpec {
        id: "openai-key",
        description: "OpenAI-style API key (sk-, sk-proj-)",
        category: C::ApiKey,
        severity: S::High,
        pattern: r"\b(sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,200})",
        prefixes: &["sk-proj-", "sk-svcacct-", "sk-"],
        filter_placeholders: false,
    },
    ProviderSpec {
        id: "google-api-key",
        description: "Google API key (AIza)",
        category: C::ApiKey,
        severity: S::High,
        pattern: r"\b(AIza[0-9A-Za-z_\-]{35})",
        prefixes: &["AIza"],
        filter_placeholders: false,
    },
    ProviderSpec {
        id: "sendgrid-key",
        description: "SendGrid API key",
        category: C::ApiKey,
        severity: S::High,
        pattern: r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b",
        prefixes: &["SG."],
        filter_placeholders: false,
    },
    ProviderSpec {
        id: "huggingface-token",
        description: "Hugging Face access token",
        category: C::ApiKey,
        severity: S::High,
        pattern: r"\b(hf_[A-Za-z0-9]{30,40})\b",
        prefixes: &["hf_"],
        filter_placeholders: false,
    },
    ProviderSpec {
        id: "docker-pat",
        description: "Docker Hub personal access token",
        category: C::AccessToken,
        severity: S::High,
        pattern: r"\b(dckr_pat_[A-Za-z0-9_\-]{20,100})",
        prefixes: &["dckr_pat_"],
        filter_placeholders: false,
    },
    ProviderSpec {
        id: "connection-string-password",
        description: "password inside a database or message-broker connection string",
        category: C::ConnectionString,
        severity: S::High,
        pattern: r#"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|clickhouse|jdbc:[a-z]+)://[^\s:/@'"]+:([^\s@/'"]+)@"#,
        prefixes: &[],
        filter_placeholders: true,
    },
    ProviderSpec {
        id: "url-credentials",
        description: "password embedded in an HTTP(S) or FTP URL",
        category: C::ConnectionString,
        severity: S::High,
        pattern: r#"(?i)\b(?:https?|ftps?)://[^\s:/@'"]+:([^\s@/'"]+)@"#,
        prefixes: &[],
        filter_placeholders: true,
    },
    ProviderSpec {
        id: "bearer-token",
        description: "bearer token after `Bearer` (for example in an Authorization header)",
        category: C::BearerToken,
        severity: S::High,
        pattern: r"(?i)\bbearer\s+([A-Za-z0-9\-._~+/]{20,}=*)",
        prefixes: &[],
        filter_placeholders: true,
    },
    ProviderSpec {
        id: "jwt",
        description: "JSON Web Token (three base64url segments, JSON header)",
        category: C::BearerToken,
        severity: S::Medium,
        pattern: r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})",
        prefixes: &[],
        filter_placeholders: false,
    },
];

/// Substrings marking a value as a reference, template or documentation.
const PLACEHOLDER_MARKERS: &[&str] = &[
    "${",
    "$(",
    "{{",
    "%(",
    "<",
    "process.env",
    "os.environ",
    "getenv",
    "env(",
    "env[",
    "environ[",
    "secrets.",
    "vault:",
    "example",
    "changeme",
    "change_me",
    "placeholder",
    "your_",
    "your-",
    "yourpassword",
    "redacted",
    "xxxx",
    "****",
    "dummy",
    "sample",
    "password",
    "secret",
    "token",
    "none",
    "null",
    "undefined",
    "todo",
    "fixme",
];

/// Values that are references or documentation, not secrets.
#[must_use]
pub fn is_placeholder(value: &str) -> bool {
    let v = value.trim_matches(|c| matches!(c, '"' | '\'' | '`'));
    let lower = v.to_ascii_lowercase();
    if v.starts_with('$') || v.starts_with('%') || v.starts_with('@') {
        return true;
    }
    if PLACEHOLDER_MARKERS.iter().any(|m| lower.contains(m)) {
        return true;
    }
    let mut chars = v.chars();
    let first = chars.next();
    first.is_some_and(|f| v.chars().all(|c| c == f))
}

/// A compiled [`ProviderSpec`].
pub struct ProviderDetector {
    spec: ProviderSpec,
    regex: Regex,
}

impl ProviderDetector {
    fn new(spec: ProviderSpec) -> Option<Self> {
        Regex::new(spec.pattern)
            .ok()
            .map(|regex| Self { spec, regex })
    }
}

impl Detector for ProviderDetector {
    fn id(&self) -> &str {
        self.spec.id
    }
    fn prefilter(&self) -> Option<&str> {
        Some(self.spec.pattern)
    }
    fn description(&self) -> &str {
        self.spec.description
    }
    fn category(&self) -> SecretCategory {
        self.spec.category
    }
    fn detect(&self, line: &str, out: &mut Vec<Match>) {
        for caps in self.regex.captures_iter(line) {
            let Some(m) = caps.get(1).or_else(|| caps.get(0)) else {
                continue;
            };
            if self.spec.filter_placeholders && is_placeholder(m.as_str()) {
                continue;
            }
            // The PEM marker is the start of a block; the whole marker stands for the key.
            let public_prefix = self
                .spec
                .prefixes
                .iter()
                .filter(|p| m.as_str().starts_with(**p))
                .map(|p| p.len())
                .max()
                .unwrap_or(0);
            out.push(Match {
                detector: self.spec.id.to_owned(),
                category: self.spec.category,
                severity: self.spec.severity,
                start: m.start(),
                end: m.end(),
                public_prefix,
            });
        }
    }
}

static ASSIGNMENT_QUOTED: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b([a-z0-9_.\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|private[_\-]?key|client[_\-]?secret|auth[_\-]?key|credentials?|signing[_\-]?key|encryption[_\-]?key|session[_\-]?key)[a-z0-9_.\-]*)["']?\s*(?:=|:=|=>|:)\s*["']([^"'\r\n]{8,200})["']"#,
    )
    .ok()
});

static ASSIGNMENT_BARE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^\s*(?:export\s+)?([a-z0-9_.\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|private[_\-]?key|client[_\-]?secret|auth[_\-]?key|credentials?|signing[_\-]?key|encryption[_\-]?key|session[_\-]?key)[a-z0-9_.\-]*)\s*[=:]\s*([^\s'\x22#;,]{8,200})\s*(?:#.*)?$",
    )
    .ok()
});

/// Whether a value looks like a credential rather than a word or a reference.
fn credential_like(value: &str) -> bool {
    if is_placeholder(value) {
        return false;
    }
    let has_alpha = value.chars().any(|c| c.is_ascii_alphabetic());
    let has_digit = value.chars().any(|c| c.is_ascii_digit());
    let has_symbol = value.chars().any(|c| !c.is_ascii_alphanumeric());
    let long = value.len() >= 16;
    // Function calls, paths and dotted identifiers are code, not values.
    let code_like = value.contains('(') || value.starts_with('/') || value.starts_with("./");
    has_alpha && (has_digit || has_symbol || long) && !code_like
}

/// A value assigned to a secret-named key: `password = "..."`, `API_KEY=...`, `"token": "..."`.
pub struct AssignmentDetector;

impl Detector for AssignmentDetector {
    fn id(&self) -> &'static str {
        "credential-assignment"
    }
    fn description(&self) -> &'static str {
        "a credential-like value assigned to a key named password, secret, token, api key and similar"
    }
    fn category(&self) -> SecretCategory {
        C::CredentialAssignment
    }
    fn prefilter(&self) -> Option<&str> {
        Some(
            r"(?i)(?:password|passwd|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|private[_\-]?key|client[_\-]?secret|auth[_\-]?key|credential|signing[_\-]?key|encryption[_\-]?key|session[_\-]?key)",
        )
    }
    fn detect(&self, line: &str, out: &mut Vec<Match>) {
        for regex in [&*ASSIGNMENT_QUOTED, &*ASSIGNMENT_BARE]
            .into_iter()
            .flatten()
        {
            for caps in regex.captures_iter(line) {
                let Some(value) = caps.get(2) else { continue };
                if !credential_like(value.as_str()) {
                    continue;
                }
                out.push(Match {
                    detector: self.id().to_owned(),
                    category: C::CredentialAssignment,
                    severity: S::Medium,
                    start: value.start(),
                    end: value.end(),
                    public_prefix: 0,
                });
            }
        }
    }
}

static ENTROPY_CANDIDATE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r#"(?:[=:]\s*|["'`])([A-Za-z0-9+/_\-]{32,200}={0,2})(?:["'`]|\s|$|[,;])"#).ok()
});

/// Shannon entropy in bits per character.
#[must_use]
pub fn shannon_entropy(text: &str) -> f64 {
    let mut counts = [0usize; 256];
    let bytes = text.as_bytes();
    for b in bytes {
        if let Some(slot) = counts.get_mut(usize::from(*b)) {
            *slot += 1;
        }
    }
    #[allow(clippy::cast_precision_loss)]
    let len = bytes.len() as f64;
    if bytes.is_empty() {
        return 0.0;
    }
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            #[allow(clippy::cast_precision_loss)]
            let p = *c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// A long, high-entropy quoted or assigned string. Hex digests (40 or 64 hex characters),
/// UUIDs and lock-file integrity hashes are skipped; everything else is reported at low
/// severity, because many random-looking strings are not secrets.
pub struct EntropyDetector;

impl Detector for EntropyDetector {
    fn id(&self) -> &'static str {
        "high-entropy"
    }
    fn description(&self) -> &'static str {
        "a long random-looking string in a quoted or assigned position"
    }
    fn category(&self) -> SecretCategory {
        C::HighEntropy
    }
    fn prefilter(&self) -> Option<&str> {
        Some(r"[A-Za-z0-9+/_\-]{32}")
    }
    fn detect(&self, line: &str, out: &mut Vec<Match>) {
        let lower = line.to_ascii_lowercase();
        if lower.contains("integrity")
            || lower.contains("sha512-")
            || lower.contains("sha256-")
            || lower.contains("sha1-")
        {
            return;
        }
        let Some(regex) = &*ENTROPY_CANDIDATE else {
            return;
        };
        for caps in regex.captures_iter(line) {
            let Some(m) = caps.get(1) else { continue };
            let value = m.as_str();
            let hex_only = value.chars().all(|c| c.is_ascii_hexdigit());
            if hex_only && matches!(value.len(), 32 | 40 | 64 | 128) {
                continue;
            }
            let mixed = value.chars().any(|c| c.is_ascii_uppercase())
                && value.chars().any(|c| c.is_ascii_lowercase())
                && value.chars().any(|c| c.is_ascii_digit());
            let threshold = if hex_only { 3.5 } else { 4.5 };
            if (!mixed && !hex_only) || shannon_entropy(value) < threshold || is_placeholder(value)
            {
                continue;
            }
            out.push(Match {
                detector: self.id().to_owned(),
                category: C::HighEntropy,
                severity: S::Low,
                start: m.start(),
                end: m.end(),
                public_prefix: 0,
            });
        }
    }
}

/// A pattern from trusted configuration.
pub struct CustomDetector {
    id: String,
    description: String,
    category: SecretCategory,
    severity: Severity,
    regex: Regex,
    public_prefix: Option<String>,
}

/// Why a custom pattern was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CustomPatternError {
    /// The identifier is not 1 to 64 of `[a-z0-9-]`.
    #[error("custom detector identifiers must be 1 to 64 of [a-z0-9-]")]
    InvalidId,
    /// The pattern is too long or does not compile within the size limit.
    #[error("custom detector pattern is invalid or too large")]
    InvalidPattern,
}

/// Longest custom pattern accepted.
pub const MAX_CUSTOM_PATTERN: usize = 512;

impl CustomDetector {
    /// Compile a custom pattern. Capture group 1, when present, is the secret value.
    pub fn new(
        id: &str,
        pattern: &str,
        category: SecretCategory,
        severity: Severity,
        public_prefix: Option<String>,
    ) -> Result<Self, CustomPatternError> {
        if id.is_empty()
            || id.len() > 64
            || !id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(CustomPatternError::InvalidId);
        }
        if pattern.is_empty() || pattern.len() > MAX_CUSTOM_PATTERN {
            return Err(CustomPatternError::InvalidPattern);
        }
        let regex = RegexBuilder::new(pattern)
            .size_limit(1 << 20)
            .dfa_size_limit(1 << 20)
            .build()
            .map_err(|_| CustomPatternError::InvalidPattern)?;
        Ok(Self {
            description: format!("custom pattern {id} from trusted configuration"),
            id: format!("custom:{id}"),
            category,
            severity,
            regex,
            public_prefix,
        })
    }
}

impl Detector for CustomDetector {
    fn id(&self) -> &str {
        &self.id
    }
    fn description(&self) -> &str {
        &self.description
    }
    fn category(&self) -> SecretCategory {
        self.category
    }
    fn prefilter(&self) -> Option<&str> {
        Some(self.regex.as_str())
    }
    fn detect(&self, line: &str, out: &mut Vec<Match>) {
        for caps in self.regex.captures_iter(line) {
            let Some(m) = caps.get(1).or_else(|| caps.get(0)) else {
                continue;
            };
            if m.is_empty() {
                continue;
            }
            let public_prefix = self
                .public_prefix
                .as_deref()
                .filter(|p| m.as_str().starts_with(p))
                .map_or(0, str::len);
            out.push(Match {
                detector: self.id.clone(),
                category: self.category,
                severity: self.severity,
                start: m.start(),
                end: m.end(),
                public_prefix,
            });
        }
    }
}

/// An ordered set of detectors, with a combined prefilter so a line that no detector could
/// match costs one pass.
pub struct DetectorSet {
    detectors: Vec<Box<dyn Detector>>,
    /// For each detector, its slot in `prefilter`, if it has one.
    slots: Vec<Option<usize>>,
    prefilter: Option<RegexSet>,
}

impl Default for DetectorSet {
    fn default() -> Self {
        Self::builtin()
    }
}

impl DetectorSet {
    /// Every built-in detector.
    #[must_use]
    pub fn builtin() -> Self {
        let mut detectors: Vec<Box<dyn Detector>> = PROVIDERS
            .iter()
            .filter_map(|s| ProviderDetector::new(*s))
            .map(|d| Box::new(d) as Box<dyn Detector>)
            .collect();
        detectors.push(Box::new(AssignmentDetector));
        detectors.push(Box::new(EntropyDetector));
        let mut set = Self {
            detectors,
            slots: Vec::new(),
            prefilter: None,
        };
        set.rebuild();
        set
    }

    fn rebuild(&mut self) {
        let mut patterns = Vec::new();
        self.slots = self
            .detectors
            .iter()
            .map(|d| {
                d.prefilter().map(|p| {
                    patterns.push(p.to_owned());
                    patterns.len() - 1
                })
            })
            .collect();
        self.prefilter = RegexSetBuilder::new(&patterns)
            .size_limit(32 << 20)
            .dfa_size_limit(32 << 20)
            .build()
            .ok();
        if self.prefilter.is_none() {
            // Without a prefilter every detector runs on every line: slower, never weaker.
            self.slots = vec![None; self.detectors.len()];
        }
    }

    /// Add a detector.
    pub fn push(&mut self, detector: Box<dyn Detector>) {
        self.detectors.push(detector);
        self.rebuild();
    }

    /// The detectors, in order.
    pub fn iter(&self) -> impl Iterator<Item = &dyn Detector> {
        self.detectors.iter().map(AsRef::as_ref)
    }

    /// Every match in `line`, overlaps resolved: where two matches overlap, the more severe
    /// (then the longer) one is kept.
    #[must_use]
    pub fn detect_line(&self, line: &str) -> Vec<Match> {
        let mut all = Vec::new();
        let hits = self.prefilter.as_ref().map(|p| p.matches(line));
        if hits.as_ref().is_some_and(|h| !h.matched_any()) && self.slots.iter().all(Option::is_some)
        {
            return all;
        }
        for (d, slot) in self.detectors.iter().zip(&self.slots) {
            let skip = match (slot, &hits) {
                (Some(i), Some(h)) => !h.matched(*i),
                _ => false,
            };
            if !skip {
                d.detect(line, &mut all);
            }
        }
        all.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then((b.end - b.start).cmp(&(a.end - a.start)))
                .then(a.start.cmp(&b.start))
        });
        let mut kept: Vec<Match> = Vec::new();
        for m in all {
            if kept.iter().all(|k| m.end <= k.start || m.start >= k.end) {
                kept.push(m);
            }
        }
        kept.sort_by_key(|m| m.start);
        kept
    }
}

/// The shared built-in detector set.
pub static BUILTIN: LazyLock<DetectorSet> = LazyLock::new(DetectorSet::builtin);

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(line: &str) -> Vec<String> {
        BUILTIN
            .detect_line(line)
            .into_iter()
            .map(|m| m.detector)
            .collect()
    }

    #[test]
    fn every_builtin_pattern_compiles() {
        for spec in PROVIDERS {
            assert!(Regex::new(spec.pattern).is_ok(), "{}", spec.id);
        }
        assert!(
            ASSIGNMENT_QUOTED.is_some() && ASSIGNMENT_BARE.is_some() && ENTROPY_CANDIDATE.is_some()
        );
    }

    #[test]
    fn provider_formats() {
        let cases = [
            ("key = AKIAZZZZFAKEFAKE0001", "aws-access-key-id"),
            ("aws_secret_access_key = FAKEfakeFAKEfakeFAKEfakeFAKEfake0123/+ab", "aws-secret-access-key"),
            ("token: ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0000", "github-token"),
            ("github_pat_FAKE0000000000000000000000fake", "github-token"),
            (concat!("glpat", "-FAKEfakeFAKEfake0000"), "gitlab-token"),
            ("STRIPE=sk_live_FAKEfakeFAKEfake0000", "stripe-key"),
            ("sk-ant-api03-FAKEfakeFAKEfakeFAKE0000", "anthropic-key"),
            ("xoxb-0000000000-FAKEfakeFAKE", "slack-token"),
            ("url = postgres://app:Sup3rS3cretPw@db.internal:5432/app", "connection-string-password"),
            ("mongodb+srv://admin:Fak3Passw0rd99@cluster0.example.net/db", "connection-string-password"),
            ("Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123", "bearer-token"),
            ("-----BEGIN OPENSSH PRIVATE KEY-----", "private-key"),
            ("-----BEGIN RSA PRIVATE KEY-----", "private-key"),
            ("\"type\": \"service_account\",", "gcp-service-account"),
            ("DefaultEndpointsProtocol=https;AccountKey=FAKEfakeFAKEfakeFAKEfakeFAKEfakeFAKEfake0000==", "azure-storage-key"),
        ];
        for (line, expected) in cases {
            assert!(
                ids(line).contains(&expected.to_owned()),
                "{line}: {:?}",
                ids(line)
            );
        }
    }

    #[test]
    fn assignments_and_placeholders() {
        assert_eq!(ids("DB_PASSWORD=hunter2hunter2"), ["credential-assignment"]);
        assert_eq!(
            ids(r#"api_key = "Zq8vR2xT9mK4pL7w""#),
            ["credential-assignment"]
        );
        for benign in [
            "DB_PASSWORD=${DB_PASSWORD}",
            r#"password = os.environ["DB_PASSWORD"]"#,
            "API_KEY=your_api_key_here",
            "token: changeme",
            "password_field = getPasswordFromVault()",
            "postgres://user:${PASSWORD}@localhost/db",
            "let token_count = 12345678;",
        ] {
            assert_eq!(ids(benign).len(), 0, "{benign}: {:?}", ids(benign));
        }
    }

    #[test]
    fn entropy_skips_digests_and_lockfiles() {
        assert_eq!(
            ids("commit = \"3f786850e387550fdab836ed7e6dc881de23001b\"").len(),
            0
        );
        assert_eq!(
            ids("\"integrity\": \"sha512-Zq8vR2xT9mK4pL7wQ3nB6yH1cF5jD0sA8gE2rU4iO7pZ\"").len(),
            0
        );
        assert_eq!(
            ids("value = \"Zq8vR2xT9mK4pL7wQ3nB6yH1cF5jD0sA8gE2rU4iO\""),
            ["high-entropy"]
        );
    }

    #[test]
    fn overlaps_keep_the_most_severe() {
        let m = BUILTIN.detect_line("GITHUB_TOKEN=ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0000");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].detector, "github-token");
        assert_eq!(m[0].public_prefix, 4);
    }

    #[test]
    fn custom_patterns_are_bounded() {
        let d = CustomDetector::new(
            "acme",
            r"\b(acme_[a-z0-9]{24})\b",
            C::Custom,
            S::High,
            Some("acme_".into()),
        )
        .unwrap();
        let mut out = Vec::new();
        d.detect("k=acme_abcdefghijklmnopqrstuvwx", &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].public_prefix, 5);
        assert!(CustomDetector::new("Bad Id", "x", C::Custom, S::Low, None).is_err());
        assert!(CustomDetector::new(
            "big",
            &"a".repeat(MAX_CUSTOM_PATTERN + 1),
            C::Custom,
            S::Low,
            None
        )
        .is_err());
        assert!(
            CustomDetector::new("huge", r"\w{1000}\w{1000}\w{1000}", C::Custom, S::Low, None)
                .is_err()
        );
        assert!(CustomDetector::new("bad", "(", C::Custom, S::Low, None).is_err());
    }
}
