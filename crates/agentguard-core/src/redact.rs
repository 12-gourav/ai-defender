//! Redaction primitives shared by logging and audit.
//!
//! Two independent checks are applied at every write boundary: a field *name* denylist and a
//! conservative secret-*shape* detector. Either one triggering replaces the value with
//! [`REDACTED`]. The detector is deliberately low on false positives; the policy is that
//! secrets never reach a log call in the first place, and redaction is the backstop.

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

/// Replacement text for redacted values.
pub const REDACTED: &str = "[REDACTED]";

/// Substrings that mark a field name as sensitive (matched case-insensitively against the
/// field name with `-` and `.` normalised to `_`).
pub const SENSITIVE_FIELD_MARKERS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "private_key",
    "cookie",
    "session_key",
    "access_key",
    "client_secret",
    "bearer",
    "passphrase",
];

/// Whether a field name indicates sensitive content.
#[must_use]
pub fn is_sensitive_field(name: &str) -> bool {
    let normalised: String = name
        .chars()
        .map(|c| match c {
            '-' | '.' | ' ' => '_',
            other => other.to_ascii_lowercase(),
        })
        .collect();
    SENSITIVE_FIELD_MARKERS
        .iter()
        .any(|m| normalised.contains(m))
}

/// Credential prefixes and the minimum number of key characters that must follow them.
const SECRET_PREFIXES: &[(&str, usize)] = &[
    ("AKIA", 16), // AWS access key id
    ("ASIA", 16), // AWS temporary access key id
    ("ghp_", 20), // GitHub personal access token
    ("gho_", 20), // GitHub OAuth token
    ("ghu_", 20), // GitHub user-to-server token
    ("ghs_", 20), // GitHub server-to-server token
    ("ghr_", 20), // GitHub refresh token
    ("github_pat_", 20),
    ("glpat-", 16), // GitLab PAT
    ("glptt-", 16), // GitLab pipeline trigger token
    ("xoxb-", 16),  // Slack bot
    ("xoxp-", 16),  // Slack user
    ("xoxa-", 16),
    ("xoxr-", 16),
    ("sk-ant-", 16),   // Anthropic
    ("sk-", 20),       // OpenAI-style
    ("AIza", 20),      // Google API key
    ("npm_", 20),      // npm token
    ("pypi-", 20),     // PyPI token
    ("dckr_pat_", 16), // Docker Hub PAT
    ("hf_", 20),       // Hugging Face
];

fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// Whether a single whitespace-free token looks like, or contains, a credential. Prefixes are
/// matched anywhere inside the token so that a path or URL embedding a key is caught.
#[must_use]
pub fn looks_like_secret(token: &str) -> bool {
    let t = token.trim_matches(|c: char| matches!(c, '"' | '\'' | ',' | ';' | ')' | '(' | '`'));
    if t.len() < 16 {
        return false;
    }
    for (prefix, min_len) in SECRET_PREFIXES {
        let mut search = t;
        while let Some(idx) = search.find(prefix) {
            let after = &search[idx + prefix.len()..];
            let run = after.chars().take_while(|c| is_key_char(*c)).count();
            if run >= *min_len {
                return true;
            }
            search = after;
        }
    }
    // JWT: three base64url segments, first is a JSON header.
    if t.contains("eyJ") && t.matches('.').count() >= 2 {
        return true;
    }
    // PEM private key markers anywhere in the token.
    if t.contains("PRIVATE KEY-----") {
        return true;
    }
    false
}

/// Whether a block of text contains a PEM private key.
#[must_use]
pub fn contains_private_key_block(text: &str) -> bool {
    text.contains("-----BEGIN") && text.contains("PRIVATE KEY-----")
}

/// Redact credential-looking content inside `text`. If the text contains a private-key block
/// the entire value is replaced. After the token pass below, every span the secret detectors
/// (`agentguard_secrets`) recognise is replaced too (connection-string passwords, provider
/// keys, bearer tokens), keeping at most a public provider prefix. Otherwise, per whitespace-separated token (whitespace is kept
/// as is):
///
/// - a token shaped like a known credential is replaced;
/// - `key=value` or `key:value` where `key` is a sensitive name keeps the key and replaces the
///   value (`DB_PASSWORD=[REDACTED]`, `--token=[REDACTED]`, `"secret":[REDACTED]`);
/// - the token after `Bearer`/`Basic`, after a sensitive header (`Authorization:`), or after a
///   sensitive flag (`--password`) is replaced.
#[must_use]
pub fn redact_text(text: &str) -> String {
    if contains_private_key_block(text) {
        return REDACTED.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    let mut redact_next = false;
    let mut token = String::new();
    let flush = |token: &mut String, out: &mut String, redact_next: &mut bool| {
        if token.is_empty() {
            return;
        }
        let forced = std::mem::take(redact_next);
        *redact_next = marks_next_token(token);
        if forced || looks_like_secret(token) {
            out.push_str(REDACTED);
        } else if let Some(key_len) = sensitive_assignment(token) {
            out.push_str(token.get(..key_len).unwrap_or_default());
            out.push_str(REDACTED);
        } else {
            out.push_str(token);
        }
        token.clear();
    };
    for c in text.chars() {
        if c.is_whitespace() {
            flush(&mut token, &mut out, &mut redact_next);
            out.push(c);
        } else {
            token.push(c);
        }
    }
    flush(&mut token, &mut out, &mut redact_next);
    agentguard_secrets::redact(&out)
}

/// Trim quoting and flag dashes from a key.
fn bare_key(key: &str) -> &str {
    key.trim_matches(|c: char| matches!(c, '"' | '\'' | '{' | ','))
        .trim_start_matches('-')
}

/// For `key=value` / `key:value` with a sensitive key and a non-empty value, the byte length
/// of `key` plus its separator.
fn sensitive_assignment(token: &str) -> Option<usize> {
    let idx = token.find(['=', ':'])?;
    let (key, rest) = token.split_at(idx);
    let value = rest.get(1..).unwrap_or_default();
    // `https://...` and similar: a scheme is never a credential key.
    if value.starts_with("//") || value.is_empty() {
        return None;
    }
    is_sensitive_field(bare_key(key)).then_some(idx + 1)
}

/// Whether the token announces that the next token is a credential.
fn marks_next_token(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    if lower == "bearer" || lower == "basic" {
        return true;
    }
    let header = token.strip_suffix(':').map(bare_key);
    let flag = (token.starts_with('-') && !token.contains('=')).then(|| bare_key(token));
    header.or(flag).is_some_and(is_sensitive_field)
}

/// Redact a field value given its name: name-based denylist first, then shape detection.
#[must_use]
pub fn redact_field(name: &str, value: &str) -> String {
    if is_sensitive_field(name) {
        REDACTED.to_owned()
    } else {
        redact_text(value)
    }
}

/// A value that must never be printed. `Debug` and `Display` print [`REDACTED`]; the inner
/// value is zeroised on drop. Access is explicit through [`Sensitive::expose`].
#[derive(Clone)]
pub struct Sensitive<T: Zeroize>(Zeroizing<T>);

impl<T: Zeroize> Sensitive<T> {
    /// Wrap a value.
    pub fn new(value: T) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Borrow the protected value. Every call site is a place a secret becomes visible;
    /// keep them few and never pass the result to a logging macro.
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<T: Zeroize> fmt::Display for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_field_names() {
        for name in [
            "password",
            "DB_PASSWORD",
            "api-key",
            "Authorization",
            "github.token",
            "x_secret_y",
        ] {
            assert!(is_sensitive_field(name), "{name}");
        }
        for name in ["branch", "repository", "path", "user", "level"] {
            assert!(!is_sensitive_field(name), "{name}");
        }
    }

    #[test]
    fn secret_shapes() {
        assert!(looks_like_secret("AKIAIOSFODNN7EXAMPLE"));
        assert!(looks_like_secret(
            "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
        ));
        assert!(looks_like_secret("glpat-abcdefghijklmnopqrst"));
        assert!(looks_like_secret("sk-ant-api03-abcdefghijklmnop"));
        assert!(looks_like_secret(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk"
        ));
        assert!(looks_like_secret(
            "/tmp/token-ghp_0123456789abcdefghijklmnopqrstuvwxyz.yml"
        ));
        assert!(looks_like_secret(
            "https://x.example/?key=AKIAIOSFODNN7EXAMPLE"
        ));
        assert!(!looks_like_secret("feature/AH-5064"));
        assert!(!looks_like_secret("sk-short"));
        assert!(!looks_like_secret("README.md"));
        assert!(!looks_like_secret("tasks-ghp_abc"));
    }

    #[test]
    fn redact_text_replaces_only_secret_tokens() {
        let out = redact_text("pushing with ghp_0123456789abcdefghijklmnopqrstuvwxyz to origin");
        assert_eq!(out, "pushing with [REDACTED] to origin");
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----";
        assert_eq!(redact_text(pem), REDACTED);
        assert_eq!(redact_text("nothing here"), "nothing here");
    }

    #[test]
    fn redact_text_assignments_headers_and_flags() {
        assert_eq!(
            redact_text("DB_PASSWORD=hunter2 make"),
            "DB_PASSWORD=[REDACTED] make"
        );
        assert_eq!(
            redact_text("cli --token=abc123 run"),
            "cli --token=[REDACTED] run"
        );
        assert_eq!(
            redact_text("cli --password abc123 run"),
            "cli --password [REDACTED] run"
        );
        assert_eq!(
            redact_text("curl -H 'Authorization: Bearer abc.def' x"),
            "curl -H 'Authorization: [REDACTED] [REDACTED] x"
        );
        assert_eq!(redact_text("{\"secret\":\"v\"}"), "{\"secret\":[REDACTED]");
        // Whitespace other than spaces separates tokens and is preserved.
        assert_eq!(
            redact_text("a\tghp_0123456789abcdefghijklmnopqrstuvwxyz\nb"),
            "a\t[REDACTED]\nb"
        );
        // Ordinary prose and URLs are untouched.
        for keep in [
            "secrets read requires approval",
            "https://example.com/path",
            "token budget exceeded",
            "branch: main",
        ] {
            assert_eq!(redact_text(keep), keep);
        }
    }

    /// Property: a credential embedded anywhere in random text, separated by any whitespace
    /// or attached as a sensitive assignment, never survives redaction.
    #[test]
    fn property_embedded_secrets_never_survive() {
        let mut rng = fastrand::Rng::with_seed(0x00da_c7ed);
        let words = [
            "push",
            "to",
            "origin",
            "main",
            "--verbose",
            "cargo",
            "x=1",
            "https://e.x",
        ];
        let ws = [" ", "\t", "\n", "  "];
        let key_chars: Vec<char> = ('a'..='z').chain('0'..='9').collect();
        for _ in 0..3000 {
            let body: String = (0..rng.usize(24..40))
                .map(|_| key_chars[rng.usize(..key_chars.len())])
                .collect();
            let (prefix, _) = SECRET_PREFIXES[rng.usize(..SECRET_PREFIXES.len())];
            let secret = match rng.u8(0..3) {
                0 => format!("{prefix}{body}"),
                1 => format!("API_TOKEN={body}"),
                _ => format!("--password={body}"),
            };
            let mut parts: Vec<String> = (0..rng.usize(0..8))
                .map(|_| words[rng.usize(..words.len())].to_owned())
                .collect();
            parts.insert(rng.usize(..=parts.len()), secret);
            let mut text = String::new();
            for p in &parts {
                text.push_str(p);
                text.push_str(ws[rng.usize(..ws.len())]);
            }
            let out = redact_text(&text);
            assert!(!out.contains(&body), "leaked from {text:?}: {out:?}");
        }
    }

    #[test]
    fn redact_field_uses_name_first() {
        assert_eq!(redact_field("password", "hunter2"), REDACTED);
        assert_eq!(redact_field("branch", "main"), "main");
        assert_eq!(
            redact_field("note", "token AKIAIOSFODNN7EXAMPLE here"),
            "token [REDACTED] here"
        );
    }

    #[test]
    fn sensitive_never_prints() {
        let s = Sensitive::new(String::from("ghp_0123456789abcdefghijklmnopqrstuvwxyz"));
        assert_eq!(format!("{s:?}"), REDACTED);
        assert_eq!(format!("{s}"), REDACTED);
        assert!(s.expose().starts_with("ghp_"));
    }
}
