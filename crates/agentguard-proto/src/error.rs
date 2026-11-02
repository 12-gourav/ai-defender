//! Protocol errors.
//!
//! Requests come from an agent integration and are hostile until validated. Messages name the
//! field and the rule that failed; they never include a submitted value, and JSON syntax errors
//! report only their position, because serde's own messages quote input.

use agentguard_core::{RequestId, SecurityError};

/// Why a request was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProtocolError {
    /// The request exceeded the size limit.
    #[error("request exceeds the maximum size of {max} bytes")]
    TooLarge {
        /// The limit.
        max: usize,
    },

    /// The request is not well-formed JSON for the protocol schema: a syntax error, a missing
    /// or unknown field, a duplicate field, or a wrong type.
    #[error(
        "request does not match the protocol schema ({category} at line {line}, column {column})"
    )]
    Malformed {
        /// `syntax`, `data` (schema mismatch) or `eof`.
        category: &'static str,
        /// 1-based line.
        line: usize,
        /// 1-based column.
        column: usize,
    },

    /// The `protocol` field names a version this build does not speak.
    #[error("unsupported protocol version; expected {expected}")]
    UnsupportedProtocol {
        /// The supported version.
        expected: &'static str,
    },

    /// A field parsed but failed validation.
    #[error("field `{field}`: {source}")]
    Invalid {
        /// The request field.
        field: &'static str,
        /// The rule it broke.
        #[source]
        source: SecurityError,
    },
}

impl ProtocolError {
    pub(crate) fn invalid(field: &'static str) -> impl FnOnce(SecurityError) -> Self {
        move |source| Self::Invalid { field, source }
    }

    pub(crate) fn from_json(e: &serde_json::Error) -> Self {
        let category = match e.classify() {
            serde_json::error::Category::Syntax => "syntax",
            serde_json::error::Category::Eof => "eof",
            serde_json::error::Category::Data | serde_json::error::Category::Io => "data",
        };
        Self::Malformed {
            category,
            line: e.line(),
            column: e.column(),
        }
    }
}

/// A rejected request, with its correlation ID when one could be recovered so the denial can
/// still be matched to the request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{error}")]
pub struct Rejection {
    /// Recovered correlation ID, if the request carried a valid one.
    pub request_id: Option<RequestId>,
    /// Why.
    #[source]
    pub error: ProtocolError,
}
