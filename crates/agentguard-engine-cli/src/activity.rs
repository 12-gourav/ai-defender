//! Security history and machine prerequisites.
//!
//! | command | effect |
//! |---|---|
//! | `history.list` | recent audit events (already redacted when recorded), newest first; filters for blocked operations and approval activity |
//! | `prerequisites` | Git and agent CLI versions, platform; read-only probes |
//!
//! History is read from the hash-chained audit log (`<trust root>/audit/trust.jsonl`). Only
//! the last 8 MiB are read, so the view is bounded on long-lived machines; the log itself is
//! never modified here.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::protocol::{EngineError, ErrorCode};
use crate::support::args;
use crate::Environment;

/// Most bytes read from the end of the audit log.
const TAIL_BYTES: u64 = 8 * 1024 * 1024;

const APPROVAL_PREFIXES: &[&str] = &[
    "approval-",
    "authorization-grant",
    "authorization-validation",
    "authorization-consumed",
    "authorization-replay",
];

const BLOCKING_KINDS: &[&str] = &[
    "authorization-denied",
    "sensitive-access-denied",
    "disclosure-blocked",
    "tamper-detected",
    "unsupported-operation-detected",
    "execution-context-changed",
    "hook-payload-rejected",
    "hook-failed",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryArgs {
    #[serde(default)]
    limit: Option<usize>,
    /// `all` (default), `blocked` or `approvals`.
    #[serde(default)]
    filter: Option<String>,
}

fn matches(event: &Value, filter: &str) -> bool {
    let kind = event.get("kind").and_then(Value::as_str).unwrap_or("");
    match filter {
        "blocked" => {
            event.get("decision").and_then(Value::as_str) == Some("deny")
                || BLOCKING_KINDS.contains(&kind)
        }
        "approvals" => APPROVAL_PREFIXES.iter().any(|p| kind.starts_with(p)),
        _ => true,
    }
}

fn summarize(event: &Value) -> Value {
    let pick = |k: &str| event.get(k).cloned().unwrap_or(Value::Null);
    json!({
        "timestamp": pick("timestamp"),
        "kind": pick("kind"),
        "decision": pick("decision"),
        "resource": pick("resource"),
        "reason": pick("reason"),
        "rule": pick("rule"),
        "reason_code": pick("reason_code"),
        "project_id": pick("project_id"),
        "agent": event.pointer("/agent/kind").cloned().unwrap_or(Value::Null),
        "approval_id": pick("approval_id"),
        "execution_id": pick("execution_id"),
    })
}

/// `history.list`.
pub fn list(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let a: HistoryArgs = args(arguments)?;
    let filter = a.filter.unwrap_or_else(|| "all".to_owned());
    if !matches!(filter.as_str(), "all" | "blocked" | "approvals") {
        return Err(EngineError::new(
            ErrorCode::InvalidRequest,
            "filter must be all, blocked or approvals",
        ));
    }
    let limit = a.limit.unwrap_or(50).clamp(1, 500);
    let path = env.store.root().join("audit").join("trust.jsonl");
    let Ok(mut file) = File::open(&path) else {
        return Ok(
            json!({ "events": [], "available": false, "detail": "no audit log exists yet (AI Defender is not initialised on this machine)" }),
        );
    };
    let size = file.metadata().map_or(0, |m| m.len());
    let start = size.saturating_sub(TAIL_BYTES);
    let mut text = String::new();
    file.seek(SeekFrom::Start(start))
        .and_then(|_| file.take(TAIL_BYTES).read_to_string(&mut text))
        .map_err(|_| EngineError::new(ErrorCode::IoError, "the audit log could not be read"))?;
    let mut lines: Vec<&str> = text.lines().collect();
    if start > 0 && !lines.is_empty() {
        lines.remove(0); // a partial first line
    }
    let mut unreadable = 0usize;
    let events: Vec<Value> = lines
        .iter()
        .rev()
        .filter_map(|line| {
            if let Ok(v) = serde_json::from_str::<Value>(line) {
                v.get("event").cloned()
            } else {
                unreadable += 1;
                None
            }
        })
        .filter(|e| matches(e, &filter))
        .take(limit)
        .map(|e| summarize(&e))
        .collect();
    Ok(json!({
        "events": events,
        "available": true,
        "filter": filter,
        "truncated_to_recent_bytes": start > 0,
        "unreadable_lines": unreadable,
    }))
}

/// `prerequisites`.
pub fn prerequisites(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let _: serde::de::IgnoredAny = args(if arguments.is_null() {
        json!({})
    } else {
        arguments
    })?;
    let probe = |name: &str| agentguard_exec::probe::version(name, &env.process_env);
    Ok(json!({
        "platform": { "os": std::env::consts::OS, "arch": std::env::consts::ARCH },
        "engine_version": env!("CARGO_PKG_VERSION"),
        "git": probe("git"),
        "agents": { "claude": probe("claude"), "codex": probe("codex") },
    }))
}
