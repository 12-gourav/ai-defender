//! The AgentGuard security engine process.
//!
//! `agentguard-engine` reads one request in the [`protocol`] from standard input, handles it
//! against the trust store and the policy engine, and writes one response. It is the only
//! component that reads or writes trusted state; the npm CLI is a user interface over it.
//!
//! Commands:
//!
//! | command | effect |
//! |---|---|
//! | `version` | engine and protocol versions |
//! | `status`, `check` | read-only diagnostics |
//! | `policy.show` | the effective policy, as evaluated |
//! | `project.list`, `project.inspect`, `config.validate` | read-only |
//! | `project.init` | create project configuration, set up trust on first use, register, approve restrictions |
//! | `project.trust` | re-trust a revoked project, approve restrictions |
//! | `project.revoke` | revoke a project's trust |
//! | `approval.list`, `approval.show` | read-only approval views (no secrets) |
//! | `approval.approve` | a human approves one exact operation (confirmation + passphrase) |
//! | `approval.reject`, `approval.cancel`, `authorization.revoke` | withdraw authority |
//! | `approval.request`, `authorization.validate`, `authorization.consume` | act for an agent; need `--agent` |
//! | `secrets.scan`, `secrets.status`, `secrets.explain` | local, read-only secret scanning; redacted results |
//! | `execution.run` | run one command through policy, approval and the controlled executor |
//! | `execution.history`, `execution.inspect` | redacted execution records |
//! | `git.status`, `git.inspect` | read-only repository state (credentials removed from remote URLs) |
//! | `integrations.list`, `.status`, `.coverage`, `.verify` | agent hook integrations (read-only; verify records a health check) |
//! | `integrations.install`, `integrations.uninstall` | add or remove AI Defender's hook entries (confirmation; uninstall also the passphrase) |
//! | `integrations.repair` | re-point degraded or outdated hooks at a verified engine copy (confirmation) |
//! | `history.list` | recent audit events, filterable (read-only) |
//! | `prerequisites` | Git and agent CLI versions (read-only) |
//!
//! `agentguard-engine hook <provider> <event>` is the hook entry point the providers run
//! ([`integrations::run_hook`]); it speaks the provider's protocol, not this one.
//!
//! Every command that changes trusted state requires `confirm: true` and the policy-signing key
//! passphrase; neither has a default. Approving also needs the passphrase; the commands that
//! only withdraw authority need confirmation (or, for cancel, the requester's claim token).

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod activity;
pub mod approvals;
pub mod execution;
pub mod inspect;
pub mod integrations;
pub mod manage;
pub mod protocol;
pub mod secrets;
pub mod support;

use std::sync::Arc;

use agentguard_common::paths::AppPaths;
use agentguard_engine::{Clock, SystemClock, TrustedInvocation};
use agentguard_trust::keyfile::KdfCost;
use agentguard_trust::{AnchorConfig, TrustStore};
use serde_json::Value;

use crate::protocol::{
    valid_request_id, EngineError, ErrorCode, Request, Response, ENGINE_PROTOCOL_VERSION,
    MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
};

/// Where the engine keeps state, how expensive key derivation is, who launched it and what
/// time it is.
pub struct Environment {
    /// The trust store.
    pub store: TrustStore,
    /// Argon2id cost for newly created signing keys.
    pub kdf: KdfCost,
    /// Set when an agent integration launched the engine (`--agent <kind>`): commands then act
    /// for that agent, and human-only commands (approve) are refused.
    pub invocation: Option<TrustedInvocation>,
    /// Time source (injectable for expiry tests).
    pub clock: Arc<dyn Clock>,
    /// The caller's environment variables. Managed execution filters them through an
    /// environment profile; they are never passed through wholesale.
    pub process_env: Vec<(String, String)>,
    /// Termination signals received through a descriptor (the engine binary sets this, so an
    /// interrupted engine terminates the managed process group instead of orphaning it).
    pub signals: Option<agentguard_exec::Signals>,
    /// The engine binary's own path (written into hook configuration; protected like trusted
    /// state while hooks run).
    pub engine_path: Option<std::path::PathBuf>,
}

fn own_path() -> Option<std::path::PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::canonicalize(p).ok())
}

fn caller_environment() -> Vec<(String, String)> {
    std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        .collect()
}

impl Environment {
    /// The user's environment: XDG directories and the default system anchor.
    pub fn from_process(invocation: Option<TrustedInvocation>) -> Result<Self, EngineError> {
        let paths = AppPaths::from_env().map_err(|e| {
            EngineError::new(
                ErrorCode::IoError,
                format!("cannot locate configuration directories: {e}"),
            )
        })?;
        Ok(Self {
            store: TrustStore::for_paths(&paths),
            kdf: KdfCost::DEFAULT,
            invocation,
            clock: Arc::new(SystemClock),
            process_env: caller_environment(),
            signals: None,
            engine_path: own_path(),
        })
    }

    /// An isolated environment (tests): a trust store at `root` without a system anchor.
    #[must_use]
    pub fn isolated(root: std::path::PathBuf, kdf: KdfCost) -> Self {
        Self {
            store: TrustStore::new(
                root,
                AnchorConfig {
                    system_anchor: None,
                    required_owner: 0,
                },
            ),
            kdf,
            invocation: None,
            clock: Arc::new(SystemClock),
            process_env: caller_environment(),
            signals: None,
            engine_path: own_path(),
        }
    }
}

fn salvage_request_id(input: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(input).ok()?;
    let id = value.get("request_id")?.as_str()?;
    valid_request_id(id).then(|| id.to_owned())
}

fn dispatch(env: &Environment, command: &str, arguments: Value) -> Result<Value, EngineError> {
    match command {
        "version" => inspect::version(&arguments),
        "status" => inspect::status(env, arguments),
        "check" => inspect::check(env, arguments),
        "policy.show" => inspect::policy_show(env, arguments),
        "project.list" => inspect::project_list(env, &arguments),
        "project.inspect" => inspect::project_inspect(env, arguments),
        "config.validate" => inspect::config_validate(arguments),
        "project.init" => manage::init(env, arguments),
        "project.trust" => manage::trust(env, arguments),
        "project.revoke" => manage::revoke(env, arguments),
        "approval.request" => approvals::request(env, arguments),
        "approval.list" => approvals::list(env, arguments),
        "approval.show" => approvals::show(env, arguments),
        "approval.approve" => approvals::approve(env, arguments),
        "approval.reject" => approvals::reject(env, arguments),
        "approval.cancel" => approvals::cancel(env, arguments),
        "authorization.validate" => approvals::redeem(env, arguments, false),
        "authorization.consume" => approvals::redeem(env, arguments, true),
        "authorization.revoke" => approvals::revoke(env, arguments),
        "secrets.scan" => secrets::scan_command(env, arguments),
        "secrets.status" => secrets::status(env, arguments),
        "secrets.explain" => secrets::explain(env, arguments),
        "secrets.preview" => secrets::preview(env, arguments),
        "execution.run" => execution::run(env, arguments),
        "execution.history" => execution::history(env, arguments),
        "execution.inspect" => execution::inspect(env, arguments),
        "git.status" => execution::git_status(env, arguments),
        "git.inspect" => execution::git_inspect(env, arguments),
        "integrations.list" => integrations::list(env, arguments),
        "integrations.status" => integrations::status(env, arguments),
        "integrations.coverage" => integrations::coverage(env, arguments),
        "integrations.verify" => integrations::verify(env, arguments),
        "integrations.install" => integrations::install_command(env, arguments),
        "integrations.uninstall" => integrations::uninstall_command(env, arguments),
        "integrations.repair" => integrations::repair_command(env, arguments),
        "history.list" => activity::list(env, arguments),
        "prerequisites" => activity::prerequisites(env, arguments),
        _ => Err(EngineError::new(
            ErrorCode::UnknownCommand,
            "unknown command",
        )),
    }
}

/// Handle one raw request.
#[must_use]
pub fn handle(input: &[u8], env: &Environment) -> Response {
    if input.len() > MAX_REQUEST_BYTES {
        return Response::failed(
            None,
            EngineError::new(
                ErrorCode::InvalidRequest,
                format!("request exceeds {MAX_REQUEST_BYTES} bytes"),
            )
            .0,
        );
    }
    let request: Request = match serde_json::from_slice(input) {
        Ok(r) => r,
        Err(e) => {
            let message = format!(
                "request does not match the protocol schema ({:?} at line {}, column {})",
                e.classify(),
                e.line(),
                e.column()
            );
            return Response::failed(
                salvage_request_id(input),
                EngineError::new(ErrorCode::InvalidRequest, message).0,
            );
        }
    };
    if !valid_request_id(&request.request_id) {
        return Response::failed(
            None,
            EngineError::new(
                ErrorCode::InvalidRequest,
                "request_id must be 1 to 64 of [A-Za-z0-9_-]",
            )
            .0,
        );
    }
    let id = request.request_id;
    if request.protocol_version != ENGINE_PROTOCOL_VERSION {
        return Response::failed(
            Some(id),
            EngineError::new(
                ErrorCode::UnsupportedProtocol,
                format!("engine protocol {} is not supported; this engine speaks {ENGINE_PROTOCOL_VERSION}", request.protocol_version),
            )
            .recovery("install matching versions of the agentguard CLI and engine")
            .0,
        );
    }
    let arguments = request
        .arguments
        .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
    let response = match dispatch(env, &request.command, arguments) {
        Ok(data) => Response::ok(id.clone(), data),
        Err(e) => Response::failed(Some(id.clone()), e.0),
    };
    let size = serde_json::to_vec(&response).map_or(usize::MAX, |b| b.len());
    if size > MAX_RESPONSE_BYTES {
        return Response::failed(
            Some(id),
            EngineError::new(ErrorCode::InternalError, "response too large").0,
        );
    }
    response
}
