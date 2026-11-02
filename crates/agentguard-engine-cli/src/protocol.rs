//! The engine protocol `agentguard.engine.v1`: one JSON request on standard input, one JSON
//! response on standard output, per process.
//!
//! - Requests are at most [`MAX_REQUEST_BYTES`]; unknown fields are rejected.
//! - Responses are at most [`MAX_RESPONSE_BYTES`] and always carry `success`, `data` and
//!   `error`, exactly one of `data`/`error` being non-null.
//! - Management, diagnostics and the approval workflow. The approval commands that act for an
//!   agent (`approval.request`, `authorization.validate`, `authorization.consume`) need the
//!   engine to be launched by an agent integration (`--agent`); the npm CLI never calls them
//!   and never interprets a decision.
//! - Secrets sent in a request (a passphrase) are never echoed in a response.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Engine protocol version.
pub const ENGINE_PROTOCOL_VERSION: u32 = 1;
/// Largest request read from standard input.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// Largest response written to standard output.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// A request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Must equal [`ENGINE_PROTOCOL_VERSION`].
    pub protocol_version: u32,
    /// Echoed in the response: 1 to 64 of `[A-Za-z0-9_-]`.
    pub request_id: String,
    /// The command name.
    pub command: String,
    /// Command arguments (an object; validated per command).
    #[serde(default)]
    pub arguments: Option<Value>,
}

/// Error categories. Stable; the CLI maps them to exit codes and messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCode {
    /// The request is malformed.
    InvalidRequest,
    /// The protocol version is not supported.
    UnsupportedProtocol,
    /// The command does not exist.
    UnknownCommand,
    /// No trust store exists yet.
    TrustNotInitialized,
    /// Trusted state failed verification.
    IntegrityFailure,
    /// The directory is not inside a registered, trusted project.
    NotRegistered,
    /// The project's trust was revoked.
    ProjectRevoked,
    /// The operation needs an explicit human confirmation that was not given.
    ConfirmationRequired,
    /// The operation needs the signing key passphrase, which was not supplied.
    AuthorizationRequired,
    /// The passphrase or key was rejected.
    AuthorizationFailed,
    /// The project configuration is invalid.
    InvalidConfiguration,
    /// The directory cannot be a project root.
    UnsupportedProjectRoot,
    /// A file could not be read or written.
    IoError,
    /// The command acts for an agent, and the engine was not launched by an integration.
    IdentityUnavailable,
    /// No approval request matches the ID.
    ApprovalNotFound,
    /// The approval request is not in a state that allows the operation.
    ApprovalConflict,
    /// The operation is not authorized (no valid grant, mismatch, replay, or denied by policy).
    AuthorizationDenied,
    /// A required audit record could not be written; nothing was authorized.
    AuditUnavailable,
    /// The execution request was submitted before; it is never run twice.
    ExecutionDuplicate,
    /// A managed command ran but its outcome could not be recorded; not a success.
    OutcomeUnrecorded,
    /// An internal failure.
    InternalError,
}

impl ErrorCode {
    /// Process exit code for this error.
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self {
            ErrorCode::InvalidRequest
            | ErrorCode::UnsupportedProtocol
            | ErrorCode::UnknownCommand => 2,
            _ => 1,
        }
    }
}

/// A structured error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorBody {
    /// Category.
    pub code: ErrorCode,
    /// What went wrong (no secrets, no key material).
    pub message: String,
    /// What a human can do about it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<String>,
}

/// A response.
#[derive(Debug, Serialize)]
pub struct Response {
    /// Always [`ENGINE_PROTOCOL_VERSION`].
    pub protocol_version: u32,
    /// The request's ID, when it could be read.
    pub request_id: Option<String>,
    /// Whether the command succeeded.
    pub success: bool,
    /// The result, on success.
    pub data: Option<Value>,
    /// The error, on failure.
    pub error: Option<ErrorBody>,
}

/// An error raised while handling a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineError(pub ErrorBody);

impl EngineError {
    /// An error with no recovery hint.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self(ErrorBody {
            code,
            message: message.into(),
            recovery: None,
        })
    }

    /// Attach a recovery hint.
    #[must_use]
    pub fn recovery(mut self, hint: impl Into<String>) -> Self {
        self.0.recovery = Some(hint.into());
        self
    }
}

/// Whether `id` is an acceptable request ID.
#[must_use]
pub fn valid_request_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

impl Response {
    /// A success.
    #[must_use]
    pub const fn ok(request_id: String, data: Value) -> Self {
        Self {
            protocol_version: ENGINE_PROTOCOL_VERSION,
            request_id: Some(request_id),
            success: true,
            data: Some(data),
            error: None,
        }
    }

    /// A failure.
    #[must_use]
    pub const fn failed(request_id: Option<String>, error: ErrorBody) -> Self {
        Self {
            protocol_version: ENGINE_PROTOCOL_VERSION,
            request_id,
            success: false,
            data: None,
            error: Some(error),
        }
    }

    /// The process exit code for this response.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        self.error.as_ref().map_or(0, |e| e.code.exit_code())
    }
}
