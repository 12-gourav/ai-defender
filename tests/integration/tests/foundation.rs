//! Cross-crate behaviour: configuration → domain types → audit → logging.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;

use agentguard_audit::{
    AuditDecision, AuditEvent, AuditEventKind, AuditSink, JsonlSink, MemorySink,
};
use agentguard_common::config;
use agentguard_common::logging::{LogFormat, MemorySink as LogSink, RedactingLayer};
use agentguard_common::paths::AppPaths;
use agentguard_core::{
    AgentIdentity, AgentKind, Alternative, ApprovalScope, BoundedText, OperationType,
    PermissionLevel, PolicyVersion, RuleId, SecurityDecision, SessionId, TaskId,
};
use tracing_subscriber::layer::SubscriberExt;

fn with_capture(f: impl FnOnce()) -> Vec<String> {
    let sink = LogSink::new();
    let subscriber =
        tracing_subscriber::registry().with(RedactingLayer::new(LogFormat::Json, sink.clone()));
    tracing::subscriber::with_default(subscriber, f);
    sink.lines()
}

#[test]
fn policy_loads_into_typed_mode_and_versions_deterministically() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".agent-security.yml");
    fs::write(
        &path,
        "version: 1\nmode: DEVELOPER_AUTHORIZED\ngit:\n  commit: approval\n",
    )
    .unwrap();
    let (cfg, report) = config::load_validated(&path).unwrap();
    assert_eq!(cfg.mode(), PermissionLevel::DeveloperAuthorized);
    assert_eq!(report.problems, Vec::new());

    let text = fs::read(&path).unwrap();
    let v1 = PolicyVersion::compute(&text);
    let v2 = PolicyVersion::compute(&fs::read(&path).unwrap());
    assert_eq!(v1, v2);
}

#[test]
fn decision_flows_into_audit_with_redaction_and_chain() {
    let session = SessionId::generate();
    let task = TaskId::new("AH-5064").unwrap();
    let policy = PolicyVersion::compute(b"effective");
    let decision = SecurityDecision::deny(
        OperationType::GitPush,
        RuleId::new("git.push.protected_branches").unwrap(),
        BoundedText::new("destination is protected").unwrap(),
        false,
        Alternative::suggest("push to feature/AH-5064").unwrap(),
    );
    assert!(ApprovalScope::CurrentTask
        .check_permitted(decision.operation)
        .is_err());

    let sink = MemorySink::new();
    let event = AuditEvent::new(
        AuditEventKind::PolicyDecision,
        "origin main (token ghp_0123456789abcdefghijklmnopqrstuvwxyz)",
        &decision.explanation(),
    )
    .with_session(session)
    .with_task(task)
    .with_agent(AgentIdentity::new(AgentKind::ClaudeCode))
    .with_policy_version(policy)
    .with_decision(decision.operation, AuditDecision::Deny);
    let rec = sink.record(event).unwrap();
    assert_eq!(rec.seq, 0);
    assert!(rec.event.resource.as_str().contains("[REDACTED]"));
    assert!(!rec.event.resource.as_str().contains("ghp_"));
    assert!(rec.event.reason.as_str().contains("Approval possible: no"));
    assert!(sink.verify().is_ok());
}

#[test]
fn jsonl_audit_lives_in_private_state_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = AppPaths::resolve(Some(tmp.path().to_path_buf()), None, None, None).unwrap();
    let state = paths.ensure_state_dir(None).unwrap();
    let sink = JsonlSink::open(&state.join("audit.jsonl")).unwrap();
    sink.record(AuditEvent::new(AuditEventKind::SessionStarted, "s", ""))
        .unwrap();
    sink.record(AuditEvent::new(AuditEventKind::SessionEnded, "s", ""))
        .unwrap();
    assert!(sink.verify().is_ok());
    assert_eq!(sink.records().unwrap().len(), 2);
}

#[test]
fn logging_never_emits_sensitive_values() {
    let lines = with_capture(|| {
        tracing::info!(
            github_token = "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
            branch = "main",
            "pushing"
        );
    });
    assert_eq!(lines.len(), 1);
    let v: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    let fields = v["fields"].as_array().unwrap();
    assert_eq!(fields[0][1], "[REDACTED]");
    assert_eq!(fields[1][1], "main");
}
