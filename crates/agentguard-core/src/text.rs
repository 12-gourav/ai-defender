//! Length-bounded, control-character-free text.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::SecurityError;

/// Text of at most `MAX` characters containing no control characters other than newline
/// and tab. Used for every free-text value that enters the system from an untrusted source
/// (agent-supplied reasons, commit messages, resource descriptions).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct BoundedText<const MAX: usize>(String);

impl<const MAX: usize> BoundedText<MAX> {
    /// Maximum length in characters.
    pub const MAX_LEN: usize = MAX;

    /// Validate and wrap `value`.
    pub fn new(value: impl Into<String>) -> Result<Self, SecurityError> {
        let value = value.into();
        if value.chars().count() > MAX {
            return Err(SecurityError::TextTooLong {
                field: "text",
                max: MAX,
            });
        }
        if value
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
        {
            return Err(SecurityError::ControlCharacters { field: "text" });
        }
        Ok(Self(value))
    }

    /// Validate, additionally requiring a non-empty value.
    pub fn new_non_empty(value: impl Into<String>) -> Result<Self, SecurityError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(SecurityError::Empty { field: "text" });
        }
        Self::new(value)
    }

    /// Truncate to the limit and strip control characters instead of failing. For values
    /// that must be stored even when malformed (for example an agent's stated reason), so
    /// that an oversized or hostile string cannot suppress an audit record.
    pub fn lossy(value: &str) -> Self {
        let cleaned: String = value
            .chars()
            .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
            .take(MAX)
            .collect();
        Self(cleaned)
    }

    /// Borrow the text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Length in characters.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.chars().count()
    }

    /// Whether the text is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<const MAX: usize> TryFrom<String> for BoundedText<MAX> {
    type Error = SecurityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<const MAX: usize> From<BoundedText<MAX>> for String {
    fn from(value: BoundedText<MAX>) -> Self {
        value.0
    }
}

impl<const MAX: usize> fmt::Debug for BoundedText<MAX> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BoundedText<{MAX}>({:?})", self.0)
    }
}

impl<const MAX: usize> fmt::Display for BoundedText<MAX> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_within_limit() {
        let t = BoundedText::<5>::new("hello").unwrap();
        assert_eq!(t.as_str(), "hello");
        assert_eq!(t.len(), 5);
    }

    #[test]
    fn rejects_over_limit_by_chars_not_bytes() {
        assert!(BoundedText::<5>::new("héllo!").is_err());
        assert!(BoundedText::<5>::new("héllo").is_ok());
    }

    #[test]
    fn rejects_control_characters_but_allows_newline_and_tab() {
        assert!(BoundedText::<16>::new("a\u{1b}[31mred").is_err());
        assert!(BoundedText::<16>::new("line\nnext\tcol").is_ok());
    }

    #[test]
    fn non_empty_rejects_whitespace_only() {
        assert!(BoundedText::<16>::new_non_empty("   ").is_err());
        assert!(BoundedText::<16>::new_non_empty("x").is_ok());
    }

    #[test]
    fn lossy_strips_and_truncates() {
        let t = BoundedText::<4>::lossy("ab\u{7}cdef");
        assert_eq!(t.as_str(), "abcd");
    }

    #[test]
    fn serde_round_trip_and_rejects_invalid() {
        let t = BoundedText::<8>::new("ok").unwrap();
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"ok\"");
        let back: BoundedText<8> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
        let too_long: Result<BoundedText<2>, _> = serde_json::from_str("\"abc\"");
        assert!(too_long.is_err());
    }
}
