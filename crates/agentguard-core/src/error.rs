//! Typed errors for domain validation.
//!
//! Errors describe *which rule* a value broke, never the value itself, so an error message can
//! be shown to a user, written to a log, or stored in an audit record without leaking input.

use crate::approval::ApprovalScope;
use crate::operation::OperationType;

/// A domain validation failure. Carries field names and rules, never offending values.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SecurityError {
    /// Text exceeded the maximum length for its field.
    #[error("{field}: exceeds the maximum length of {max} characters")]
    TextTooLong {
        /// Field or type name.
        field: &'static str,
        /// Maximum permitted length in characters.
        max: usize,
    },

    /// Text was empty where a value is required.
    #[error("{field}: must not be empty")]
    Empty {
        /// Field or type name.
        field: &'static str,
    },

    /// Text contained control characters other than newline or tab.
    #[error("{field}: contains control characters")]
    ControlCharacters {
        /// Field or type name.
        field: &'static str,
    },

    /// An identifier did not match its format rule.
    #[error("{field}: invalid format ({rule})")]
    InvalidIdentifier {
        /// Field or type name.
        field: &'static str,
        /// Human-readable statement of the rule that was broken.
        rule: &'static str,
    },

    /// A policy version string was not 64 lowercase hexadecimal characters.
    #[error("policy version must be 64 hexadecimal characters")]
    InvalidPolicyVersion,

    /// A string did not name a known enum variant.
    #[error("unknown {kind}; expected one of: {expected}")]
    UnknownVariant {
        /// What was being parsed, for example "permission level".
        kind: &'static str,
        /// Comma-separated accepted names.
        expected: &'static str,
    },

    /// Approval timing values were outside the permitted range.
    #[error("approval timing out of range: {detail}")]
    ApprovalTimingOutOfRange {
        /// Which bound was violated.
        detail: &'static str,
    },

    /// A path that must lie inside the project does not.
    #[error("{field}: must be inside the project")]
    OutsideProject {
        /// Field or type name.
        field: &'static str,
    },

    /// A reusable approval scope was requested for an operation that only permits
    /// single-operation approvals.
    #[error("approval scope {scope} is not permitted for operation {operation}")]
    ScopeNotPermitted {
        /// The requested scope.
        scope: ApprovalScope,
        /// The operation it was requested for.
        operation: OperationType,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_never_contain_values() {
        // The error type has no field capable of holding user input; this test documents
        // the invariant by exercising every variant's Display output.
        let errors = [
            SecurityError::TextTooLong { field: "f", max: 3 },
            SecurityError::Empty { field: "f" },
            SecurityError::ControlCharacters { field: "f" },
            SecurityError::InvalidIdentifier {
                field: "f",
                rule: "r",
            },
            SecurityError::InvalidPolicyVersion,
            SecurityError::UnknownVariant {
                kind: "k",
                expected: "a, b",
            },
            SecurityError::ApprovalTimingOutOfRange { detail: "d" },
            SecurityError::OutsideProject { field: "f" },
            SecurityError::ScopeNotPermitted {
                scope: ApprovalScope::CurrentTask,
                operation: OperationType::GitPush,
            },
        ];
        for e in errors {
            let text = e.to_string();
            assert_ne!(text, "");
            assert!(!text.contains("secret-value"));
        }
    }
}
