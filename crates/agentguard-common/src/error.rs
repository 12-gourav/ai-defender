//! Top-level error type, user-facing rendering and exit codes.
//!
//! Every error has two faces: `Display` is the user-facing message, deliberately free of
//! internal detail and of any value that could be sensitive; the `source` chain carries
//! internal context for debug logs.

use std::path::PathBuf;

use agentguard_core::SecurityError;

use crate::config::ConfigError;
use crate::paths::PathsError;

/// Process exit codes. Stable across releases; scripts may depend on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitCode {
    /// Completed.
    Success = 0,
    /// A runtime failure not covered by a more specific code.
    Failure = 1,
    /// Invalid command-line usage (clap's convention).
    Usage = 2,
    /// The command exists but its functionality is scheduled for a later phase.
    NotImplemented = 3,
    /// Configuration or input failed validation.
    ValidationFailed = 4,
    /// A preflight or environment check failed.
    PreflightFailed = 5,
}

impl ExitCode {
    /// Numeric value.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

impl From<ExitCode> for std::process::ExitCode {
    fn from(value: ExitCode) -> Self {
        std::process::ExitCode::from(value.code())
    }
}

/// The error type returned by every AgentGuard command.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AgentGuardError {
    /// Configuration discovery, parsing or validation failed.
    #[error("configuration: {0}")]
    Config(#[from] ConfigError),

    /// A domain value failed validation.
    #[error("invalid value: {0}")]
    Security(#[from] SecurityError),

    /// A controller-owned path failed a safety check.
    #[error("state directory: {0}")]
    Paths(#[from] PathsError),

    /// An I/O operation failed. `context` names the operation and path; the OS error is in
    /// the source chain.
    #[error("{context}")]
    Io {
        /// What was being attempted, for example "writing .agent-security.yml".
        context: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// The target already exists and the command refuses to overwrite it.
    #[error("refusing to overwrite existing file {}", path.display())]
    AlreadyExists {
        /// The existing path.
        path: PathBuf,
    },

    /// The command is registered but its behaviour belongs to a later phase.
    #[error("`ai-defender {command}` is not implemented yet (planned for {phase})")]
    NotImplemented {
        /// Command name.
        command: &'static str,
        /// Phase in which it is scheduled.
        phase: &'static str,
    },

    /// A preflight check reported a blocking problem.
    #[error("{0}")]
    Preflight(String),

    /// Logging could not be initialised.
    #[error("logging: {0}")]
    Logging(#[from] crate::logging::LoggingError),
}

impl AgentGuardError {
    /// Build an I/O error with context.
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    /// The exit code this error maps to.
    #[must_use]
    pub const fn exit_code(&self) -> ExitCode {
        match self {
            AgentGuardError::Config(_) | AgentGuardError::Security(_) => ExitCode::ValidationFailed,
            AgentGuardError::NotImplemented { .. } => ExitCode::NotImplemented,
            AgentGuardError::Paths(_) | AgentGuardError::Preflight(_) => ExitCode::PreflightFailed,
            AgentGuardError::Io { .. }
            | AgentGuardError::AlreadyExists { .. }
            | AgentGuardError::Logging(_) => ExitCode::Failure,
        }
    }

    /// The message shown to the user: the top-level description plus the chain of causes,
    /// one per line. Causes are rendered through their own `Display`, which by construction
    /// never includes secret values.
    #[must_use]
    pub fn user_message(&self) -> String {
        let mut out = self.to_string();
        let mut source = std::error::Error::source(self);
        while let Some(cause) = source {
            let text = cause.to_string();
            // Variants built with `#[from]` already embed their cause in `Display`; only add
            // causes that contribute new information.
            if !out.contains(&text) {
                out.push_str("\n  caused by: ");
                out.push_str(&text);
            }
            source = cause.source();
        }
        out
    }
}

/// A convenience alias.
pub type Result<T> = std::result::Result<T, AgentGuardError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_stable() {
        assert_eq!(ExitCode::Success.code(), 0);
        assert_eq!(ExitCode::Failure.code(), 1);
        assert_eq!(ExitCode::Usage.code(), 2);
        assert_eq!(ExitCode::NotImplemented.code(), 3);
        assert_eq!(ExitCode::ValidationFailed.code(), 4);
        assert_eq!(ExitCode::PreflightFailed.code(), 5);
    }

    #[test]
    fn mapping_and_user_message_chain() {
        let e = AgentGuardError::io(
            "reading policy",
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
        );
        assert_eq!(e.exit_code(), ExitCode::Failure);
        let msg = e.user_message();
        assert!(msg.starts_with("reading policy"));
        assert!(msg.contains("caused by: denied"));

        let ni = AgentGuardError::NotImplemented {
            command: "run",
            phase: "Phase 4",
        };
        assert_eq!(ni.exit_code(), ExitCode::NotImplemented);
        assert!(ni.user_message().contains("Phase 4"));

        let sec = AgentGuardError::from(SecurityError::InvalidPolicyVersion);
        assert_eq!(sec.exit_code(), ExitCode::ValidationFailed);
        // An embedded cause is not repeated, but a deeper OS error still appears once.
        assert!(!sec.user_message().contains("caused by"));
        let cfg = AgentGuardError::from(ConfigError::Io {
            path: PathBuf::from("/p"),
            source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
        });
        let msg = cfg.user_message();
        assert_eq!(msg.matches("cannot read /p").count(), 1);
        assert_eq!(msg.matches("denied").count(), 1);
    }
}
