//! Bounded glob patterns for rule matching.
//!
//! Syntax: `*` matches any run of characters except `/`; `**` matches any run including `/`;
//! `**/` also matches nothing (so `src/**/x` matches `src/x`); `?` matches one character
//! except `/`. Everything else is literal. There are no character classes, alternations,
//! escapes or regular expressions.
//!
//! Matching is a dynamic program over pattern tokens and text bytes, so its cost is bounded by
//! `pattern length × text length` (at most 256 × 4096) with no backtracking blow-up.

use std::fmt;

use serde::{Deserialize, Serialize};

use agentguard_core::SecurityError;

/// Maximum pattern length in bytes.
pub const MAX_PATTERN_LEN: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token {
    Byte(u8),
    Any,
    Star,
    DoubleStar,
    DoubleStarSlash,
}

/// A validated glob pattern.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Pattern(String);

impl Pattern {
    /// Validate: 1 to [`MAX_PATTERN_LEN`] bytes, no control characters, no `..` segment.
    pub fn new(value: impl Into<String>) -> Result<Self, SecurityError> {
        let value = value.into();
        let field = "Pattern";
        if value.is_empty() {
            return Err(SecurityError::Empty { field });
        }
        if value.len() > MAX_PATTERN_LEN {
            return Err(SecurityError::TextTooLong {
                field,
                max: MAX_PATTERN_LEN,
            });
        }
        if value.chars().any(char::is_control) {
            return Err(SecurityError::ControlCharacters { field });
        }
        if value.split('/').any(|segment| segment == "..") {
            return Err(SecurityError::InvalidIdentifier {
                field,
                rule: "must not contain a '..' segment",
            });
        }
        Ok(Self(value))
    }

    /// The pattern text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the pattern has no wildcards.
    #[must_use]
    pub fn is_literal(&self) -> bool {
        !self.0.contains(['*', '?'])
    }

    /// Whether the pattern is absolute: starts with `/`, or on Windows with a drive (`C:/`).
    #[must_use]
    pub fn is_absolute(&self) -> bool {
        self.0.starts_with('/') || (cfg!(windows) && has_drive(&self.0))
    }

    /// Whether `text` matches. With `case_insensitive`, ASCII letters compare without case.
    #[must_use]
    pub fn matches(&self, text: &str, case_insensitive: bool) -> bool {
        glob_matches(&self.0, text, case_insensitive)
    }
}

/// Whether `text` starts with a drive letter and a separator (`C:/`, `c:\\`).
#[must_use]
pub fn has_drive(text: &str) -> bool {
    let b = text.as_bytes();
    matches!(b, [d, b':', b'/' | b'\\', ..] if d.is_ascii_alphabetic())
}

fn tokens(pattern: &str) -> Vec<Token> {
    let bytes = pattern.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'*' if bytes.get(i + 1) == Some(&b'*') => {
                if bytes.get(i + 2) == Some(&b'/') {
                    out.push(Token::DoubleStarSlash);
                    i += 3;
                } else {
                    out.push(Token::DoubleStar);
                    i += 2;
                }
            }
            b'*' => {
                out.push(Token::Star);
                i += 1;
            }
            b'?' => {
                out.push(Token::Any);
                i += 1;
            }
            other => {
                out.push(Token::Byte(other));
                i += 1;
            }
        }
    }
    out
}

/// Match `text` against an already-validated pattern string without allocating a [`Pattern`].
/// Callers must have validated `pattern` with [`Pattern::new`].
#[must_use]
pub fn glob_matches(pattern: &str, text: &str, case_insensitive: bool) -> bool {
    let eq = |a: u8, b: u8| {
        if case_insensitive {
            a.eq_ignore_ascii_case(&b)
        } else {
            a == b
        }
    };
    if !pattern.contains(['*', '?']) {
        return pattern.len() == text.len()
            && pattern.bytes().zip(text.bytes()).all(|(a, b)| eq(a, b));
    }
    let text = text.as_bytes();
    let mut prev = vec![false; text.len() + 1];
    let mut cur = vec![false; text.len() + 1];
    if let Some(first) = prev.first_mut() {
        *first = true;
    }
    for token in tokens(pattern) {
        let mut any_before = false;
        for j in 0..=text.len() {
            let prev_j = prev.get(j).copied().unwrap_or(false);
            let value = if j == 0 {
                prev_j
                    && matches!(
                        token,
                        Token::Star | Token::DoubleStar | Token::DoubleStarSlash
                    )
            } else {
                let c = text.get(j - 1).copied().unwrap_or(0);
                let diag = prev.get(j - 1).copied().unwrap_or(false);
                let left = cur.get(j - 1).copied().unwrap_or(false);
                any_before |= diag;
                match token {
                    Token::Byte(b) => diag && eq(b, c),
                    Token::Any => diag && c != b'/',
                    Token::Star => prev_j || (left && c != b'/'),
                    Token::DoubleStar => prev_j || left,
                    Token::DoubleStarSlash => prev_j || (any_before && c == b'/'),
                }
            };
            if let Some(slot) = cur.get_mut(j) {
                *slot = value;
            }
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev.last().copied().unwrap_or(false)
}

impl TryFrom<String> for Pattern {
    type Error = SecurityError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Pattern> for String {
    fn from(value: Pattern) -> Self {
        value.0
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(p: &str, t: &str) -> bool {
        Pattern::new(p).unwrap().matches(t, false)
    }

    #[test]
    fn literals_and_wildcards() {
        assert!(m("push", "push"));
        assert!(!m("push", "pushx"));
        assert!(m("src/*.rs", "src/main.rs"));
        assert!(!m("src/*.rs", "src/a/main.rs"));
        assert!(m("src/**", "src/a/b/c.rs"));
        assert!(m("src/**/*.rs", "src/main.rs"));
        assert!(m("src/**/*.rs", "src/a/b/main.rs"));
        assert!(!m("src/**/*.rs", "lib/main.rs"));
        assert!(m("**/.env", ".env"));
        assert!(m("**/.env", "a/b/.env"));
        assert!(m("?ar", "car"));
        assert!(!m("?ar", "/ar"));
        assert!(m("*", "anything"));
        assert!(!m("*", "a/b"));
    }

    #[test]
    fn case_handling() {
        let p = Pattern::new("secrets/**").unwrap();
        assert!(!p.matches("SECRETS/x", false));
        assert!(p.matches("SECRETS/x", true));
    }

    #[test]
    fn validation() {
        assert!(Pattern::new("").is_err());
        assert!(Pattern::new("../x").is_err());
        assert!(Pattern::new("a/../b").is_err());
        assert!(Pattern::new("a\nb").is_err());
        assert!(Pattern::new("x".repeat(257)).is_err());
        assert!(Pattern::new("..x/y").is_ok());
    }

    #[test]
    fn worst_case_is_bounded() {
        let p = Pattern::new("*a*a*a*a*a*a*a*a*a*a*a*a*b".repeat(9)).unwrap();
        let text = "a".repeat(4096);
        assert!(!p.matches(&text, false));
    }
}
