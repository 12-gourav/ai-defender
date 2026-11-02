//! Secret scanning commands: `secrets.scan`, `secrets.status`, `secrets.explain`.
//!
//! Scans are local and read-only: nothing is uploaded, no file is modified, no credential is
//! rotated. Results carry locations, detectors, severities and redacted previews; matched
//! values are never returned, stored or logged. Excluded and skipped files are always listed
//! as such, never as clean.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use agentguard_audit::{AuditSink, ScanEventKind, ScanRecord, SecurityEvent};
use agentguard_core::{Name, RuleId};
use agentguard_engine::{PolicyEvaluator, Sensitivity};
use agentguard_secrets::git_index::{staged, IndexError};
use agentguard_secrets::scan::DEFAULT_EXCLUDED_DIRS;
use agentguard_secrets::{is_finding_id, scan, scan_files, Finding, ScanOptions, ScanReport};
use agentguard_trust::scans::{load_scan_record, save_scan_record};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::inspect::{effective, snapshot, Snapshot};
use crate::protocol::{EngineError, ErrorCode};
use crate::support::{args, TrustView};
use crate::Environment;

/// A nested JSON value by pointer, or null.
fn at(value: &Value, pointer: &str) -> Value {
    value.pointer(pointer).cloned().unwrap_or(Value::Null)
}

/// Most per-finding audit records written for one scan (the rest are counted).
const MAX_FINDING_EVENTS: usize = 100;

/// The effective sensitivity (configured detectors, exclusions) for the snapshot's project, or
/// the built-in configuration when trust is not set up or the project is not registered.
fn sensitivity(snap: &Snapshot) -> (Sensitivity, &'static str) {
    match &snap.trust {
        TrustView::Verified(trust) => match effective(trust, snap.registration.as_ref()) {
            Ok(policy) => (
                policy.sensitivity().cloned().unwrap_or_default(),
                "verified",
            ),
            Err(_) => (Sensitivity::default(), "integrity-failure"),
        },
        TrustView::Uninitialized => (Sensitivity::default(), "uninitialized"),
        TrustView::Failed(_) => (Sensitivity::default(), "integrity-failure"),
    }
}

fn audit(env: &Environment) -> Option<Arc<dyn AuditSink>> {
    env.store
        .open_audit_log()
        .ok()
        .map(|s| Arc::new(s) as Arc<dyn AuditSink>)
}

fn project_id(snap: &Snapshot) -> Option<agentguard_core::ProjectId> {
    snap.registration.as_ref().map(|r| r.id)
}

fn record(sink: Option<&Arc<dyn AuditSink>>, ok: &mut bool, event: ScanRecord) {
    if let Some(sink) = sink {
        *ok &= sink
            .record(SecurityEvent::Scan(Box::new(event)).into_audit_event())
            .is_ok();
    }
}

fn scan_event(
    snap: &Snapshot,
    kind: ScanEventKind,
    code: &'static str,
    resource: String,
    detail: String,
) -> ScanRecord {
    ScanRecord {
        kind,
        project: project_id(snap),
        finding_id: None,
        reason_code: RuleId::builtin(code),
        resource,
        detail,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanArgs {
    working_directory: String,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    staged: bool,
    #[serde(default)]
    exclude: Vec<String>,
    #[serde(default)]
    no_default_exclusions: bool,
}

/// A user path (relative to the working directory) as a root-relative path.
fn root_relative(snap: &Snapshot, raw: &str) -> Result<String, EngineError> {
    let outside = || {
        EngineError::new(
            ErrorCode::InvalidRequest,
            format!("{raw} is outside the project being scanned (paths may not contain `..`)"),
        )
    };
    let raw_path = Path::new(raw);
    if raw_path.is_absolute() {
        return raw_path
            .strip_prefix(snap.root.as_path())
            .map(|p| p.to_string_lossy().into_owned())
            .map_err(|_| outside());
    }
    let prefix = snap
        .cwd
        .as_path()
        .strip_prefix(snap.root.as_path())
        .map_err(|_| outside())?;
    let joined: PathBuf = prefix.join(raw_path);
    let text = joined.to_string_lossy().into_owned();
    Ok(if text.is_empty() {
        ".".to_owned()
    } else {
        text
    })
}

fn report_json(report: &ScanReport) -> Value {
    json!({
        "findings": report.findings,
        "findings_truncated": report.findings_truncated,
        "files_scanned": report.files_scanned,
        "bytes_scanned": report.bytes_scanned,
        "excluded": report.excluded,
        "excluded_total": report.excluded_total,
        "skipped": report.skipped,
        "skipped_total": report.skipped_total,
        "complete": report.complete,
    })
}

fn now_text(env: &Environment) -> Option<String> {
    env.clock
        .now()
        .format(&time::format_description::well_known::Rfc3339)
        .ok()
}

/// Run the scan the arguments ask for.
fn run_scan(
    snap: &Snapshot,
    a: &ScanArgs,
    options: &ScanOptions,
    sensitivity: &Sensitivity,
) -> Result<ScanReport, (String, ErrorCode)> {
    let root = snap.root.as_path();
    let detectors = sensitivity.detectors();
    if a.staged {
        return match staged(root) {
            Ok(s) => scan_files(root, &s.verified, &s.unverified, options, detectors)
                .map_err(|e| (e.to_string(), ErrorCode::InvalidRequest)),
            Err(e @ (IndexError::NoRepository | IndexError::Unsupported)) => Err((
                format!("cannot scan staged changes: {e}"),
                ErrorCode::InvalidRequest,
            )),
            Err(e) => Err((
                format!("cannot scan staged changes: {e}"),
                ErrorCode::IoError,
            )),
        };
    }
    let rel = a
        .paths
        .iter()
        .map(|p| root_relative(snap, p).map_err(|e| (e.0.message, ErrorCode::InvalidRequest)))
        .collect::<Result<Vec<_>, _>>()?;
    let whole = rel.is_empty() || rel.iter().any(|r| r == ".");
    let paths = (!whole).then_some(rel.as_slice());
    scan(root, paths, options, detectors).map_err(|e| (e.to_string(), ErrorCode::InvalidRequest))
}

/// Record findings (capped), exclusions and the outcome.
fn audit_results(
    sink: Option<&Arc<dyn AuditSink>>,
    audited: &mut bool,
    snap: &Snapshot,
    scope: &str,
    report: &ScanReport,
) {
    for f in report.findings.iter().take(MAX_FINDING_EVENTS) {
        record(
            sink,
            audited,
            ScanRecord {
                kind: ScanEventKind::SecretCandidateDetected,
                project: project_id(snap),
                finding_id: Name::new(f.id.clone()).ok(),
                reason_code: RuleId::new(f.detector.clone())
                    .unwrap_or_else(|_| RuleId::builtin("scan.finding")),
                resource: f.path.clone(),
                detail: format!(
                    "detector={} category={} severity={} line={}",
                    f.detector, f.category, f.severity, f.line
                ),
            },
        );
    }
    if report.excluded_total > 0 {
        let detail = format!(
            "excluded={} (not scanned; not reported as clean)",
            report.excluded_total
        );
        record(
            sink,
            audited,
            scan_event(
                snap,
                ScanEventKind::ExcludedFileEncountered,
                "scan.excluded",
                scope.to_owned(),
                detail,
            ),
        );
    }
    let (kind, code) = if report.complete {
        (ScanEventKind::Completed, "scan.completed")
    } else {
        (ScanEventKind::Partial, "scan.partial")
    };
    let detail = format!(
        "files={} findings={} skipped={} excluded={}",
        report.files_scanned,
        report.findings.len(),
        report.skipped_total,
        report.excluded_total
    );
    record(
        sink,
        audited,
        scan_event(snap, kind, code, scope.to_owned(), detail),
    );
}

/// `secrets.scan`.
pub fn scan_command(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let a: ScanArgs = args(arguments)?;
    let snap = snapshot(env, &a.working_directory)?;
    let (sensitivity, policy_state) = sensitivity(&snap);
    let mut options = ScanOptions {
        default_exclusions: !a.no_default_exclusions,
        ..ScanOptions::default()
    };
    options
        .exclude
        .extend(sensitivity.config().scan_exclusions.iter().cloned());
    options.exclude.extend(a.exclude.iter().cloned());
    let sink = audit(env);
    let mut audited = sink.is_some();
    let scope = if a.staged {
        "staged changes".to_owned()
    } else if a.paths.is_empty() {
        ".".to_owned()
    } else {
        a.paths.join(" ")
    };
    let started = format!("exclusions={}", options.exclude.len());
    record(
        sink.as_ref(),
        &mut audited,
        scan_event(
            &snap,
            ScanEventKind::Started,
            "scan.started",
            scope.clone(),
            started,
        ),
    );
    let report = match run_scan(&snap, &a, &options, &sensitivity) {
        Ok(r) => r,
        Err((message, code)) => {
            record(
                sink.as_ref(),
                &mut audited,
                scan_event(
                    &snap,
                    ScanEventKind::Error,
                    "scan.error",
                    scope,
                    message.clone(),
                ),
            );
            return Err(EngineError::new(code, message));
        }
    };
    audit_results(sink.as_ref(), &mut audited, &snap, &scope, &report);
    let body = report_json(&report);
    let stored = json!({
        "schema": "agentguard.scan-record.v1",
        "root": snap.root,
        "scope": scope,
        "staged": a.staged,
        "scanned_at": now_text(env),
        "exclusions": options.exclude,
        "report": body,
    });
    let recorded = matches!(snap.trust, TrustView::Verified(_))
        && save_scan_record(&env.store, snap.root.as_path(), &stored).is_ok();
    let default_dirs = if options.default_exclusions {
        DEFAULT_EXCLUDED_DIRS.to_vec()
    } else {
        Vec::new()
    };
    Ok(json!({
        "root": snap.root,
        "scope": scope,
        "staged": a.staged,
        "policy": policy_state,
        "exclusions": { "default_dirs": default_dirs, "patterns": options.exclude },
        "report": body,
        "recorded": recorded,
        "audit_recorded": audited,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusArgs {
    working_directory: String,
}

/// `secrets.status`.
pub fn status(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let a: StatusArgs = args(arguments)?;
    let snap = snapshot(env, &a.working_directory)?;
    let (sensitivity, policy_state) = sensitivity(&snap);
    let detectors: Vec<Value> = sensitivity
        .detectors()
        .iter()
        .map(|d| json!({ "id": d.id(), "category": d.category(), "description": d.description() }))
        .collect();
    let mut categories: Vec<String> = sensitivity
        .detectors()
        .iter()
        .map(|d| d.category().to_string())
        .collect();
    categories.sort();
    categories.dedup();
    let settings = match &snap.trust {
        TrustView::Verified(trust) => effective(trust, snap.registration.as_ref())
            .ok()
            .map(|p| p.layered().profile().settings().clone()),
        _ => None,
    }
    .unwrap_or_default();
    let last = match &snap.trust {
        TrustView::Verified(_) => load_scan_record(&env.store, snap.root.as_path())
            .ok()
            .flatten(),
        _ => None,
    };
    let last_summary = last.map(|r| {
        json!({
            "scanned_at": at(&r, "/scanned_at"),
            "scope": at(&r, "/scope"),
            "staged": at(&r, "/staged"),
            "complete": at(&r, "/report/complete"),
            "findings": at(&r, "/report/findings").as_array().map_or(0, Vec::len),
            "files_scanned": at(&r, "/report/files_scanned"),
            "skipped_total": at(&r, "/report/skipped_total"),
            "excluded_total": at(&r, "/report/excluded_total"),
        })
    });
    Ok(json!({
        "engine": { "state": "available", "detectors": detectors, "categories": categories },
        "root": snap.root,
        "exclusions": { "default_dirs": DEFAULT_EXCLUDED_DIRS, "configured": sensitivity.config().scan_exclusions },
        "protected_patterns": sensitivity.config().protected_patterns,
        "policy": {
            "state": policy_state,
            "sensitive_read": settings.sensitive_read,
            "sensitive_write": settings.sensitive_write,
            "sensitive_delete": settings.sensitive_delete,
            "source_with_secrets": settings.source_with_secrets,
            "secret_files": settings.secret_files,
            "block_severity": sensitivity.block_severity(),
            "mandatory": ["mandatory:environment-file", "mandatory:credential-file", "mandatory:private-key", "mandatory:secret-disclosure", "mandatory:secret-commit", "mandatory:secret-into-ordinary-file"],
        },
        "last_scan": last_summary,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewArgs {
    working_directory: String,
    path: String,
}

/// `secrets.preview`: the keys of a `.env`-format file inside the project and whether each is
/// set, empty or a reference. Never a value. Safe to show to an agent: it lets the agent work
/// with configuration by name instead of reading the file.
pub fn preview(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    use agentguard_secrets::access::{DotenvFile, SecretSource};
    let a: PreviewArgs = args(arguments)?;
    let snap = snapshot(env, &a.working_directory)?;
    let rel = root_relative(&snap, &a.path)?;
    let clean = agentguard_secrets::scan::resolve_within(snap.root.as_path(), &rel)
        .map_err(|e| EngineError::new(ErrorCode::InvalidRequest, e.to_string()))?;
    let keys = DotenvFile::new(&snap.root.as_path().join(&clean))
        .describe()
        .map_err(|e| EngineError::new(ErrorCode::InvalidRequest, e.to_string()))?;
    Ok(json!({
        "path": clean,
        "keys": keys,
        "values": "never returned; refer to settings by name",
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplainArgs {
    working_directory: String,
    finding_id: String,
}

fn guidance(category: &str) -> &'static str {
    match category {
        "private-key" => "Private keys should never live in a repository. Move the key to a secret store or the user's key directory, rotate it if it was ever committed or shared, and reference it by path or environment variable.",
        "cloud-credential" => "Cloud credentials grant broad access. Revoke and rotate the key in the provider console if it was committed or shared, then load credentials from the provider's credential chain or a secret manager.",
        "access-token" | "api-key" => "Revoke the token with its provider and issue a new one if it was committed or shared. Read tokens from the environment or a secret store instead of source files.",
        "connection-string" => "Move the password out of the connection string into an environment variable or secret store, and change the database password if it was committed or shared.",
        "bearer-token" => "Bearer tokens and JWTs authorize requests directly. Invalidate the token if it is live, and avoid committing tokens even in tests (use clearly fake fixtures).",
        "credential-assignment" => "A credential-like value is assigned to a secret-named key. If it is real, move it to the environment or a secret store; if it is a placeholder, use an obvious placeholder such as ${VAR}.",
        "high-entropy" => "A long random-looking string. This is often a hash or an identifier rather than a secret; review it in your editor.",
        _ => "Review the value in your editor. If it is a real credential, move it out of the file and rotate it.",
    }
}

/// `secrets.explain`: describe a finding from the last scan without revealing its value.
pub fn explain(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let a: ExplainArgs = args(arguments)?;
    if !is_finding_id(&a.finding_id) {
        return Err(EngineError::new(
            ErrorCode::InvalidRequest,
            "finding IDs look like f_0123456789abcdef",
        ));
    }
    let snap = snapshot(env, &a.working_directory)?;
    if !matches!(snap.trust, TrustView::Verified(_)) {
        return Err(EngineError::new(
            ErrorCode::TrustNotInitialized,
            "scan results are recorded only once AI Defender is initialised",
        )
        .recovery("run `ai-defender init`, then `ai-defender secrets scan`"));
    }
    let record = load_scan_record(&env.store, snap.root.as_path())
        .map_err(|e| crate::support::trust_error(&e))?
        .ok_or_else(|| {
            EngineError::new(
                ErrorCode::NotRegistered,
                "no scan has been recorded for this project",
            )
            .recovery("run `ai-defender secrets scan` first")
        })?;
    let findings: Vec<Finding> =
        serde_json::from_value(at(&record, "/report/findings")).unwrap_or_default();
    let finding = findings
        .into_iter()
        .find(|f| f.id == a.finding_id)
        .ok_or_else(|| {
            EngineError::new(
                ErrorCode::InvalidRequest,
                "no finding with this ID in the last scan",
            )
            .recovery("re-run `ai-defender secrets scan` and use an ID from its output")
        })?;
    let (sensitivity, _) = sensitivity(&snap);
    let description = sensitivity
        .detectors()
        .iter()
        .find(|d| d.id() == finding.detector)
        .map_or_else(
            || "a detector that is no longer configured".to_owned(),
            |d| d.description().to_owned(),
        );
    let category = finding.category.to_string();
    Ok(json!({
        "finding": finding,
        "detector_description": description,
        "scanned_at": at(&record, "/scanned_at"),
        "guidance": guidance(&category),
        "false_positive": "If this is not a secret (a test fixture, a hash, an example), you can exclude the path from scans with --exclude or `sensitive.scan_exclusions`. Excluding a file hides it from scans; it does not make its contents safe, and excluded files are always listed as excluded.",
        "value_policy": "AI Defender never stores, prints or hashes the matched value. Open the file at the reported line to review it.",
    }))
}
