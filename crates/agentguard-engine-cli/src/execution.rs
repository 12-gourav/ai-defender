//! Managed execution and Git inspection commands.
//!
//! | command | effect |
//! |---|---|
//! | `execution.run` | run one command through `agentguard_exec::execute` (policy, approval, controlled execution, audit) |
//! | `execution.history` | recent execution records (redacted) |
//! | `execution.inspect` | one execution record (redacted) |
//! | `git.status`, `git.inspect` | read-only repository state through hardened Git plumbing |
//!
//! There is no command that runs a process without the full authorization pipeline.

use std::path::Path;

use agentguard_exec::environment::trusted_path;
use agentguard_exec::git::{GitContext, Plumbing};
use agentguard_exec::validation::resolve;
use agentguard_exec::{execute, ApprovalFailure, ExecEnv, ExecutionError, ExecutionRequest};
use agentguard_trust::executions::{ExecutionStore, ExecutionStoreError};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::protocol::{EngineError, ErrorCode};
use crate::support::{args, verified, working_directory};
use crate::Environment;

fn execution_error(e: &ExecutionError) -> EngineError {
    let code = match e {
        ExecutionError::InvalidRequest(_) | ExecutionError::WorkingDirectory(_) => {
            ErrorCode::InvalidRequest
        }
        ExecutionError::Trust(_) => ErrorCode::IntegrityFailure,
        ExecutionError::Identity { rule, .. } if *rule == "identity.project-unregistered" => {
            ErrorCode::NotRegistered
        }
        ExecutionError::Identity { .. } => ErrorCode::AuthorizationDenied,
        ExecutionError::AuditUnavailable => ErrorCode::AuditUnavailable,
        ExecutionError::RecordUnavailable => ErrorCode::IoError,
        ExecutionError::Duplicate(_) => ErrorCode::ExecutionDuplicate,
        ExecutionError::Approval { class, .. } => match class {
            ApprovalFailure::NotFound => ErrorCode::ApprovalNotFound,
            ApprovalFailure::Conflict => ErrorCode::ApprovalConflict,
            ApprovalFailure::Denied => ErrorCode::AuthorizationDenied,
            ApprovalFailure::Integrity => ErrorCode::IntegrityFailure,
            ApprovalFailure::Audit => ErrorCode::AuditUnavailable,
            ApprovalFailure::Io => ErrorCode::IoError,
        },
        ExecutionError::OutcomeUnrecorded { .. } => ErrorCode::OutcomeUnrecorded,
        ExecutionError::Internal(_) => ErrorCode::InternalError,
    };
    let error = EngineError::new(code, e.to_string());
    match e {
        ExecutionError::Duplicate(id) => error.recovery(format!(
            "see `ai-defender execution inspect {id}`; submit a new request to run it again"
        )),
        ExecutionError::OutcomeUnrecorded { .. } => error.recovery(
            "check the working tree and `ai-defender execution history` before doing anything else",
        ),
        ExecutionError::AuditUnavailable => {
            error.recovery("run `ai-defender check` and fix the audit log; nothing was executed")
        }
        _ => error,
    }
}

/// `execution.run`.
pub fn run(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let request: ExecutionRequest = args(arguments)?;
    verified(&env.store)?;
    let exec_env = ExecEnv {
        store: &env.store,
        invocation: env.invocation.as_ref(),
        clock: &*env.clock,
        caller_env: &env.process_env,
        signals: env.signals.as_ref(),
    };
    execute(&exec_env, request).map_err(|e| execution_error(&e))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryArgs {
    #[serde(default)]
    limit: Option<usize>,
}

fn store_error(e: &ExecutionStoreError) -> EngineError {
    match e {
        ExecutionStoreError::InvalidId => EngineError::new(
            ErrorCode::InvalidRequest,
            "execution_id must be an execution ID (ex_ and 24 hexadecimal characters) or a unique prefix of at least 7 characters",
        ),
        other => EngineError::new(ErrorCode::IoError, other.to_string()),
    }
}

/// A record as displayed: a run left in `started` whose time limit has long passed is shown
/// as indeterminate (the engine stopped before recording an outcome).
fn present(mut record: Value, now: time::OffsetDateTime) -> Value {
    let stale = record.get("state").and_then(Value::as_str) == Some("started")
        && record
            .get("started_at")
            .and_then(Value::as_str)
            .and_then(|s| {
                time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
            })
            .zip(record.get("timeout_seconds").and_then(Value::as_i64))
            .is_some_and(|(started, timeout)| {
                now > started + time::Duration::seconds(timeout.saturating_add(120))
            });
    if stale {
        if let Some(map) = record.as_object_mut() {
            map.insert("state".into(), json!("indeterminate"));
            map.insert(
                "state_note".into(),
                json!("the run started but no outcome was recorded; its effects are unknown and it was not retried"),
            );
        }
    }
    record
}

/// `execution.history`.
pub fn history(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let a: HistoryArgs = args(arguments)?;
    verified(&env.store)?;
    let limit = a.limit.unwrap_or(20).clamp(1, 200);
    let (records, unreadable) = ExecutionStore::new(&env.store)
        .list(limit)
        .map_err(|e| store_error(&e))?;
    let now = env.clock.now();
    Ok(json!({
        "executions": records.into_iter().map(|r| present(r, now)).collect::<Vec<_>>(),
        "unreadable": unreadable,
        "enforcement": agentguard_exec::enforcement(),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectArgs {
    execution_id: String,
}

/// `execution.inspect`.
pub fn inspect(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let a: InspectArgs = args(arguments)?;
    verified(&env.store)?;
    let record = ExecutionStore::new(&env.store)
        .find(&a.execution_id)
        .map_err(|e| store_error(&e))?
        .ok_or_else(|| {
            EngineError::new(
                ErrorCode::InvalidRequest,
                "no execution record matches that ID (or the prefix is ambiguous)",
            )
        })?;
    Ok(json!({ "execution": present(record, env.clock.now()) }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GitArgs {
    working_directory: String,
}

fn git_context(
    env: &Environment,
    arguments: Value,
    with_status: bool,
) -> Result<(GitContext, bool), EngineError> {
    let a: GitArgs = args(arguments)?;
    let cwd = working_directory(&a.working_directory)?;
    let project_root = registered_root(env, &cwd);
    let registered = project_root.is_some();
    let anchor = project_root.unwrap_or_else(|| cwd.as_path().to_path_buf());
    let caller_path = agentguard_exec::environment::lookup(&env.process_env, "PATH");
    let path = trusted_path(caller_path, &anchor);
    let git = resolve("git", cwd.as_path(), &path).map_err(|_| {
        EngineError::new(
            ErrorCode::IoError,
            "git was not found in the trusted search path",
        )
    })?;
    let home = agentguard_exec::environment::home(&env.process_env);
    let plumbing = Plumbing::new(&git.path, cwd.as_path(), &path, home);
    // Unregistered: every repository counts as inside, as below `/` (or the drive root).
    let root_for_check = if registered {
        anchor.as_path()
    } else {
        cwd.as_path().ancestors().last().unwrap_or(Path::new("/"))
    };
    let ctx = GitContext::inspect(&plumbing, root_for_check, with_status).ok_or_else(|| {
        EngineError::new(
            ErrorCode::InvalidRequest,
            "the working directory is not inside a Git working tree",
        )
    })?;
    Ok((ctx, registered))
}

/// The registered project root containing `cwd`, when trusted state verifies.
fn registered_root(
    env: &Environment,
    cwd: &agentguard_core::NormalizedPath,
) -> Option<std::path::PathBuf> {
    let quiet: std::sync::Arc<dyn agentguard_audit::AuditSink> =
        std::sync::Arc::new(agentguard_audit::MemorySink::new());
    let runtime = agentguard_trust::load_runtime(&env.store, cwd, &quiet);
    if !matches!(runtime.state, agentguard_trust::TrustState::Verified(_)) {
        return None;
    }
    runtime
        .registry
        .resolve(cwd)
        .map(|p| p.root().as_path().to_path_buf())
}

fn redacted(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::String(agentguard_core::redact::redact_text(s)),
        Value::Array(a) => Value::Array(a.iter().map(redacted).collect()),
        Value::Object(o) => {
            Value::Object(o.iter().map(|(k, v)| (k.clone(), redacted(v))).collect())
        }
        other => other.clone(),
    }
}

/// `git.status`: branch, HEAD and working-tree status.
pub fn git_status(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let (ctx, registered) = git_context(env, arguments, true)?;
    Ok(redacted(&json!({
        "root": ctx.root,
        "branch": ctx.branch,
        "head": ctx.head,
        "staged": ctx.staged,
        "staged_total": ctx.staged_total,
        "status": ctx.status,
        "status_skipped": ctx.status_skipped,
        "registered_project": registered,
    })))
}

/// `git.inspect`: repository identity, branch, HEAD, status and remotes (credentials removed).
pub fn git_inspect(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let (ctx, registered) = git_context(env, arguments, true)?;
    Ok(redacted(&json!({
        "repository": ctx,
        "registered_project": registered,
        "enforcement": agentguard_exec::enforcement(),
    })))
}
