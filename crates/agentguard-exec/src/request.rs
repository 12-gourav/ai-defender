//! Execution requests as they arrive over the engine protocol, and their validation.
//!
//! A request names a command either as an argument vector (managed mode, preferred) or as a
//! shell script with an explicit interpreter (shell mode). It never names an agent, a project
//! or an operation digest: those come from how the engine was launched, the trusted project
//! registry, and the engine's own computation.

use serde::Deserialize;

use crate::error::ExecutionError;

/// Most arguments in one argument vector.
pub const MAX_ARGS: usize = 256;
/// Longest single argument, in bytes.
pub const MAX_ARG_BYTES: usize = 4096;
/// Longest shell script, in bytes.
pub const MAX_SCRIPT_BYTES: usize = 4096;

/// A raw request (`execution.run` arguments).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRequest {
    /// Where to run, inside a registered project.
    pub working_directory: String,
    /// Managed mode: the program and its arguments, executed without a shell.
    #[serde(default)]
    pub argv: Option<Vec<String>>,
    /// Shell mode: an interpreter and a script in the supported shell subset.
    #[serde(default)]
    pub shell: Option<ShellRequest>,
    /// Time limit in seconds (default from policy, at most 3600).
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    /// Environment profile: `minimal` or `development`.
    #[serde(default)]
    pub environment_profile: Option<String>,
    /// An approved grant to redeem for exactly this operation.
    #[serde(default)]
    pub approval: Option<ApprovalClaim>,
    /// A unique key per attempt. A key is accepted once; a retry with the same key is refused
    /// rather than executed twice.
    pub idempotency_key: String,
}

/// Shell mode.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellRequest {
    /// `sh` or `bash`.
    pub interpreter: String,
    /// The script.
    pub script: String,
}

/// A grant to redeem.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalClaim {
    /// The approval.
    pub approval_id: String,
    /// The requester's claim token.
    pub claim_token: String,
}

/// A supported shell interpreter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellKind {
    /// POSIX `sh`.
    Sh,
    /// `bash`, started with `--noprofile --norc`.
    Bash,
}

impl ShellKind {
    /// Program name.
    #[must_use]
    pub const fn program(self) -> &'static str {
        match self {
            ShellKind::Sh => "sh",
            ShellKind::Bash => "bash",
        }
    }
}

/// What to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandSpec {
    /// Managed mode.
    Argv(Vec<String>),
    /// Shell mode.
    Shell {
        /// Interpreter.
        interpreter: ShellKind,
        /// Script as submitted (parsed and re-rendered before use).
        script: String,
    },
}

/// A validated request.
#[derive(Debug)]
pub struct ValidRequest {
    /// Raw working directory (resolved by the executor).
    pub working_directory: String,
    /// What to run.
    pub command: CommandSpec,
    /// Requested time limit.
    pub timeout_seconds: Option<u64>,
    /// Requested environment profile.
    pub environment_profile: Option<String>,
    /// Grant to redeem.
    pub approval: Option<ApprovalClaim>,
    /// Idempotency key.
    pub idempotency_key: String,
}

fn invalid(message: &'static str) -> ExecutionError {
    ExecutionError::InvalidRequest(message)
}

impl ExecutionRequest {
    /// Check sizes, shapes and characters. Nothing is resolved or executed here.
    pub fn validate(self) -> Result<ValidRequest, ExecutionError> {
        let key_ok = (16..=64).contains(&self.idempotency_key.len())
            && self
                .idempotency_key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !key_ok {
            return Err(invalid("idempotency_key must be 16 to 64 of [A-Za-z0-9_-]"));
        }
        if let Some(t) = self.timeout_seconds {
            if t == 0 || t > agentguard_trust::manifest::MAX_EXECUTION_TIMEOUT_SECONDS {
                return Err(invalid("timeout_seconds must be between 1 and 3600"));
            }
        }
        if let Some(p) = &self.environment_profile {
            if !matches!(p.as_str(), "minimal" | "development") {
                return Err(invalid(
                    "environment_profile must be minimal or development",
                ));
            }
        }
        let command = match (self.argv, self.shell) {
            (Some(argv), None) => {
                if argv.is_empty() || argv.len() > MAX_ARGS {
                    return Err(invalid("argv must have 1 to 256 elements"));
                }
                if argv
                    .iter()
                    .any(|a| a.len() > MAX_ARG_BYTES || a.contains('\0'))
                {
                    return Err(invalid(
                        "arguments must be at most 4096 bytes and contain no NUL",
                    ));
                }
                if argv.first().is_some_and(String::is_empty) {
                    return Err(invalid("the program name is empty"));
                }
                CommandSpec::Argv(argv)
            }
            (None, Some(shell)) => {
                let interpreter = match shell.interpreter.as_str() {
                    "sh" => ShellKind::Sh,
                    "bash" => ShellKind::Bash,
                    _ => return Err(invalid("shell.interpreter must be sh or bash")),
                };
                if shell.script.trim().is_empty()
                    || shell.script.len() > MAX_SCRIPT_BYTES
                    || shell.script.contains('\0')
                {
                    return Err(invalid(
                        "shell.script must be 1 to 4096 bytes and contain no NUL",
                    ));
                }
                CommandSpec::Shell {
                    interpreter,
                    script: shell.script,
                }
            }
            _ => return Err(invalid("give exactly one of argv or shell")),
        };
        Ok(ValidRequest {
            working_directory: self.working_directory,
            command,
            timeout_seconds: self.timeout_seconds,
            environment_profile: self.environment_profile,
            approval: self.approval,
            idempotency_key: self.idempotency_key,
        })
    }
}

// Unix paths throughout; the Windows path rules are tested in agentguard-core.
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn req(json: &str) -> Result<ValidRequest, String> {
        serde_json::from_str::<ExecutionRequest>(json)
            .map_err(|e| e.to_string())?
            .validate()
            .map_err(|e| e.to_string())
    }

    #[test]
    fn shapes() {
        let key = "k".repeat(20);
        assert!(req(&format!(
            r#"{{"working_directory":"/p","argv":["git","status"],"idempotency_key":"{key}"}}"#
        ))
        .is_ok());
        assert!(req(&format!(r#"{{"working_directory":"/p","shell":{{"interpreter":"bash","script":"cargo fmt && cargo test"}},"idempotency_key":"{key}"}}"#)).is_ok());
        for bad in [
            format!(r#"{{"working_directory":"/p","argv":[],"idempotency_key":"{key}"}}"#),
            format!(r#"{{"working_directory":"/p","argv":[""],"idempotency_key":"{key}"}}"#),
            format!(
                r#"{{"working_directory":"/p","argv":["a\u0000b"],"idempotency_key":"{key}"}}"#
            ),
            format!(
                r#"{{"working_directory":"/p","argv":["ls"],"shell":{{"interpreter":"sh","script":"ls"}},"idempotency_key":"{key}"}}"#
            ),
            format!(
                r#"{{"working_directory":"/p","shell":{{"interpreter":"zsh","script":"ls"}},"idempotency_key":"{key}"}}"#
            ),
            format!(
                r#"{{"working_directory":"/p","argv":["ls"],"timeout_seconds":0,"idempotency_key":"{key}"}}"#
            ),
            format!(
                r#"{{"working_directory":"/p","argv":["ls"],"timeout_seconds":3601,"idempotency_key":"{key}"}}"#
            ),
            format!(
                r#"{{"working_directory":"/p","argv":["ls"],"environment_profile":"full","idempotency_key":"{key}"}}"#
            ),
            r#"{"working_directory":"/p","argv":["ls"],"idempotency_key":"short"}"#.to_owned(),
            format!(
                r#"{{"working_directory":"/p","argv":["ls"],"agent":{{"kind":"claude"}},"idempotency_key":"{key}"}}"#
            ),
            format!(
                r#"{{"working_directory":"/p","argv":["ls"],"project":{{"root":"/p"}},"idempotency_key":"{key}"}}"#
            ),
            format!(
                r#"{{"working_directory":"/p","argv":["ls"],"operation_digest":"00","idempotency_key":"{key}"}}"#
            ),
        ] {
            assert!(req(&bad).is_err(), "{bad}");
        }
    }
}
