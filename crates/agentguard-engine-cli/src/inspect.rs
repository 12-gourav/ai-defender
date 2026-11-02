//! Read-only commands: version, status, check, policy.show, project.list, project.inspect,
//! config.validate. None of them changes trusted state.

use agentguard_audit::{AuditError, AuditSink};
use agentguard_core::NormalizedPath;
use agentguard_engine::profile::MANDATORY_BASELINE_VERSION;
use agentguard_engine::PolicyEvaluator;
use agentguard_trust::hierarchy::{EffectivePolicy, Provenance};
use agentguard_trust::keyfile::{read_key_file, SigningRole};
use agentguard_trust::project_file::{
    has_drift, load_project_config, ConfigSource, ProjectConfigError,
};
use agentguard_trust::{ProjectRegistration, TrustError, TrustStatus, TrustStore, VerifiedTrust};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::protocol::{EngineError, ErrorCode, ENGINE_PROTOCOL_VERSION};
use crate::support::{
    args, detect_kind, detect_root, directory_matches, load_trust, registered_for, verified,
    working_directory, TrustView,
};
use crate::Environment;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoArgs {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Location {
    working_directory: String,
}

const INTEGRATION: &str = "agent hook integrations for Claude Code and Codex: see `ai-defender integrations status`; hooks enforce only the protected tools listed by `ai-defender integrations coverage`";
const ENFORCEMENT: &str = "AI Defender is not intercepting any agent action on this machine; only commands run through `ai-defender run` are controlled";

/// `version`.
pub fn version(arguments: &Value) -> Result<Value, EngineError> {
    args::<NoArgs>(arguments.clone())?;
    Ok(json!({
        "engine_version": env!("CARGO_PKG_VERSION"),
        "engine_protocol_version": ENGINE_PROTOCOL_VERSION,
        "authorization_protocol": agentguard_proto::PROTOCOL_VERSION,
        "mandatory_baseline": MANDATORY_BASELINE_VERSION,
        "profiles": ["balanced"],
        "platform": { "os": std::env::consts::OS, "arch": std::env::consts::ARCH },
    }))
}

/// The project configuration's state, never failing.
fn config_state(root: &NormalizedPath) -> Value {
    match load_project_config(root) {
        Ok(None) => json!({ "state": "absent" }),
        Ok(Some(loaded)) => {
            let (format, path) = match &loaded.source {
                ConfigSource::ConfigYaml(p) => ("config-yaml", p),
                ConfigSource::Legacy(p) => ("legacy", p),
            };
            json!({
                "state": "valid",
                "format": format,
                "path": path,
                "rules": loaded.config.rules.len(),
                "expected_profile": loaded.config.profile,
                "name": loaded.config.project.name,
            })
        }
        Err(ProjectConfigError::Ambiguous) => {
            json!({ "state": "ambiguous", "error": ProjectConfigError::Ambiguous.to_string() })
        }
        Err(e) => json!({ "state": "invalid", "error": e.to_string() }),
    }
}

fn registration_json(registration: &ProjectRegistration) -> Value {
    json!({
        "id": registration.id,
        "root": registration.root,
        "status": registration.status,
        "approved_policy": registration.approved_policy.map(|v| v.to_string()),
        "registered_at": registration.registered_at.unix_timestamp(),
        "repository": registration.repository,
        "directory_matches": directory_matches(registration),
    })
}

/// The effective policy for a project (or the global layers alone).
pub(crate) fn effective(
    trust: &VerifiedTrust,
    registration: Option<&ProjectRegistration>,
) -> Result<EffectivePolicy, TrustError> {
    let trusted = registration.filter(|r| r.status == TrustStatus::Trusted && directory_matches(r));
    let manifest = trusted.and_then(|r| trust.project_policies.get(&r.id));
    EffectivePolicy::merge(
        &trust.global.policy,
        manifest.map(|m| &m.policy),
        Provenance {
            mandatory: MANDATORY_BASELINE_VERSION,
            global: Some(trust.integrity.global_policy),
            project: trusted.and_then(|r| r.approved_policy),
        },
    )
}

fn audit_state(store: &TrustStore) -> Value {
    let path = store.audit_log_path();
    if !store.root().join("audit").is_dir() {
        return json!({ "state": "unavailable", "path": path });
    }
    // Opening verifies the hash chain.
    match agentguard_audit::JsonlSink::open(&path).and_then(|sink| sink.records()) {
        Ok(records) => {
            json!({ "state": "available", "path": path, "records": records.len(), "format": "json-lines" })
        }
        Err(AuditError::ChainBroken { index }) => {
            json!({ "state": "chain-broken", "path": path, "detail": format!("chain broken at record {index}") })
        }
        Err(_) => json!({ "state": "unavailable", "path": path }),
    }
}

fn signing_key_state(store: &TrustStore) -> &'static str {
    match read_key_file(&store.signing_key_path(SigningRole::Policy)) {
        Ok(_) => "present",
        Err(agentguard_trust::keyfile::KeyFileError::Missing) => "missing",
        Err(_) => "invalid",
    }
}

pub(crate) struct Snapshot {
    pub(crate) cwd: NormalizedPath,
    pub(crate) root: NormalizedPath,
    pub(crate) trust: TrustView,
    pub(crate) registration: Option<ProjectRegistration>,
}

pub(crate) fn snapshot(env: &Environment, raw_cwd: &str) -> Result<Snapshot, EngineError> {
    let cwd = working_directory(raw_cwd)?;
    let trust = load_trust(&env.store);
    let registration = match &trust {
        TrustView::Verified(t) => registered_for(&cwd, &t.registry).cloned(),
        _ => None,
    };
    let root = registration
        .as_ref()
        .map_or_else(|| detect_root(&cwd), |r| r.root.clone());
    Ok(Snapshot {
        cwd,
        root,
        trust,
        registration,
    })
}

fn registration_state(snap: &Snapshot) -> &'static str {
    match (&snap.trust, &snap.registration) {
        (TrustView::Verified(_), Some(r)) if r.status == TrustStatus::Revoked => "revoked",
        (TrustView::Verified(_), Some(r)) if !directory_matches(r) => "identity-mismatch",
        (TrustView::Verified(_), Some(_)) => "registered",
        (TrustView::Verified(_), None) => "unregistered",
        _ => "unknown",
    }
}

fn trust_store_json(env: &Environment, snap: &Snapshot) -> Value {
    let path = env.store.root();
    match &snap.trust {
        TrustView::Verified(t) => json!({
            "path": path,
            "state": "verified",
            "integrity_version": t.integrity.sequence,
            "root_key": t.root.public_key.key_id().to_string(),
            "signing_key": signing_key_state(&env.store),
            "registered_projects": t.registry.projects.len(),
        }),
        TrustView::Uninitialized => json!({ "path": path, "state": "uninitialized" }),
        TrustView::Failed(e) => {
            json!({ "path": path, "state": "integrity-failure", "detail": e.to_string() })
        }
    }
}

fn policy_json(snap: &Snapshot, expected: Option<&Value>) -> Value {
    let TrustView::Verified(trust) = &snap.trust else {
        let state = if matches!(snap.trust, TrustView::Failed(_)) {
            "integrity-failure"
        } else {
            "unavailable"
        };
        return json!({ "state": state });
    };
    match effective(trust, snap.registration.as_ref()) {
        Ok(policy) => {
            let profile = policy.layered().profile().settings().name;
            let expected = expected.filter(|v| !v.is_null());
            json!({
                "state": "verified",
                "integrity": "verified",
                "version": policy.version().to_hex(),
                "profile": profile,
                "expected_profile": expected,
                "profile_matches": expected.is_none_or(|e| e == &json!(profile)),
            })
        }
        Err(e) => json!({ "state": "integrity-failure", "detail": e.to_string() }),
    }
}

/// `status`.
pub fn status(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let a: Location = args(arguments)?;
    let snap = snapshot(env, &a.working_directory)?;
    let config = config_state(&snap.root);
    let drift = match (&snap.trust, &snap.registration) {
        (TrustView::Verified(t), Some(r)) => Some(has_drift(
            &r.root,
            t.project_policies.get(&r.id).map(|m| &m.policy_hash),
        )),
        _ => None,
    };
    let integration = crate::integrations::summary(env);
    Ok(json!({
        "engine": { "version": env!("CARGO_PKG_VERSION"), "protocol_version": ENGINE_PROTOCOL_VERSION },
        "trust_store": trust_store_json(env, &snap),
        "project": {
            "working_directory": snap.cwd,
            "root": snap.root,
            "kind": detect_kind(&snap.root),
            "config": config,
            "registration": {
                "state": registration_state(&snap),
                "details": snap.registration.as_ref().map(registration_json),
            },
            "policy_drift": drift,
        },
        "policy": policy_json(&snap, config.get("expected_profile")),
        "audit": audit_state(&env.store),
        "integration": {
            "state": integration.get("state").cloned(),
            "providers": integration.get("providers").cloned(),
            "detail": INTEGRATION,
        },
        "enforcement": {
            "state": "inactive",
            "detail": ENFORCEMENT,
            "global_enforcement": false,
            "managed_execution": "available: `ai-defender run` evaluates, gates and records the commands routed through it",
            "direct_terminal": "not intercepted: commands an agent runs through its own terminal tool bypass AI Defender",
            "direct_git": "not intercepted: Git commands run outside `ai-defender run` bypass AI Defender",
        },
    }))
}

fn item(
    id: &str,
    title: &str,
    status: &str,
    detail: impl Into<String>,
    recovery: Option<&str>,
) -> Value {
    json!({ "id": id, "title": title, "status": status, "detail": detail.into(), "recovery": recovery })
}

fn text<'a>(status: &'a Value, pointer: &str) -> &'a str {
    status
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// Trust store, integrity and signing-key checks.
fn trust_checks(status: &Value, checks: &mut Vec<Value>) {
    let get = |pointer: &str| text(status, pointer);
    let trust = get("/trust_store/state");
    checks.push(match trust {
        "uninitialized" => item(
            "trust-store",
            "Trusted state available",
            "fail",
            "no trust store exists",
            Some("run `ai-defender init` in a project"),
        ),
        _ => item(
            "trust-store",
            "Trusted state available",
            "pass",
            get("/trust_store/path"),
            None,
        ),
    });
    checks.push(match trust {
        "verified" => item(
            "trust-integrity",
            "Trusted policy integrity",
            "pass",
            "signatures, pins and versions verified",
            None,
        ),
        "integrity-failure" => item(
            "trust-integrity",
            "Trusted policy integrity",
            "fail",
            get("/trust_store/detail"),
            Some("see docs/TRUST_MODEL.md section 6 (recovery)"),
        ),
        _ => item(
            "trust-integrity",
            "Trusted policy integrity",
            "skip",
            "no trust store",
            None,
        ),
    });
    if trust == "verified" {
        checks.push(match get("/trust_store/signing_key") {
            "present" => item(
                "signing-key",
                "Policy-signing key available",
                "pass",
                "encrypted key file present",
                None,
            ),
            other => item(
                "signing-key",
                "Policy-signing key available",
                "warn",
                format!("key file {other}; trusted state cannot be changed"),
                Some("restore the signing key from your backup"),
            ),
        });
    }
}

/// Project, configuration, policy and audit checks.
fn project_checks(status: &Value, checks: &mut Vec<Value>) {
    let get = |pointer: &str| text(status, pointer);
    let trust = get("/trust_store/state");
    checks.push(match get("/project/registration/state") {
        "registered" => item(
            "project-registered",
            "Project registered and trusted",
            "pass",
            get("/project/root"),
            None,
        ),
        "unknown" => item(
            "project-registered",
            "Project registered and trusted",
            "skip",
            "trusted state unavailable",
            None,
        ),
        "unregistered" => item(
            "project-registered",
            "Project registered and trusted",
            "fail",
            "this directory is not inside a registered project",
            Some("run `ai-defender init`"),
        ),
        other => item(
            "project-registered",
            "Project registered and trusted",
            "fail",
            other.to_owned(),
            Some("see `ai-defender project inspect`"),
        ),
    });
    checks.push(match get("/project/config/state") {
        "valid" => item(
            "project-config",
            "Project configuration valid",
            "pass",
            get("/project/config/path"),
            None,
        ),
        "absent" => item(
            "project-config",
            "Project configuration valid",
            "warn",
            "no project configuration",
            Some("run `ai-defender init`"),
        ),
        _ => item(
            "project-config",
            "Project configuration valid",
            "fail",
            get("/project/config/error"),
            Some("fix the configuration; `ai-defender project inspect` shows details"),
        ),
    });
    if status.pointer("/project/policy_drift") == Some(&json!(true)) {
        checks.push(item("policy-drift", "Project configuration matches approved policy", "warn", "the configuration differs from the approved restrictions; the approved ones remain in force", Some("review and run `ai-defender project trust` to approve")));
    }
    checks.push(match get("/policy/state") {
        "verified" => item(
            "effective-policy",
            "Effective policy available",
            "pass",
            format!("version {}", get("/policy/version")),
            None,
        ),
        "unavailable" => item(
            "effective-policy",
            "Effective policy available",
            "skip",
            "trusted state unavailable",
            None,
        ),
        _ => item(
            "effective-policy",
            "Effective policy available",
            "fail",
            get("/policy/detail"),
            None,
        ),
    });
    if status.pointer("/policy/profile_matches") == Some(&json!(false)) {
        checks.push(item(
            "profile",
            "Expected security profile",
            "warn",
            "the project expects a different profile than the global policy selects",
            None,
        ));
    }
    checks.push(match (get("/audit/state"), trust) {
        ("available", _) => item(
            "audit",
            "Audit storage available",
            "pass",
            get("/audit/path"),
            None,
        ),
        (_, "uninitialized") => item(
            "audit",
            "Audit storage available",
            "skip",
            "no trust store",
            None,
        ),
        (state, _) => item(
            "audit",
            "Audit storage available",
            "fail",
            state.to_owned(),
            None,
        ),
    });
}

/// `check`.
pub fn check(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let status = status(env, arguments)?;
    let mut checks = vec![
        item(
            "engine",
            "Rust engine responds",
            "pass",
            format!("version {}", env!("CARGO_PKG_VERSION")),
            None,
        ),
        item(
            "protocol",
            "Engine protocol compatible",
            "pass",
            format!("version {ENGINE_PROTOCOL_VERSION}"),
            None,
        ),
    ];
    trust_checks(&status, &mut checks);
    project_checks(&status, &mut checks);
    let integration = crate::integrations::summary(env);
    let configured = integration.get("state").and_then(Value::as_str) == Some("configured");
    checks.push(item(
        "integration",
        "Agent integration configured",
        if configured { "pass" } else { "warn" },
        if configured {
            INTEGRATION.to_owned()
        } else {
            "no agent hooks are installed, so no agent action is intercepted".to_owned()
        },
        (!configured).then_some("run `ai-defender integrations install claude` (or codex)"),
    ));
    let count = |s: &str| {
        checks
            .iter()
            .filter(|c| c.get("status").and_then(Value::as_str) == Some(s))
            .count()
    };
    let summary = json!({ "pass": count("pass"), "warn": count("warn"), "fail": count("fail"), "skip": count("skip") });
    let ok = count("fail") == 0;
    Ok(json!({ "ok": ok, "summary": summary, "checks": checks }))
}

const DEFAULTS: &[&str] = &[
    "read-only, low-risk, confidently classified actions: ALLOW",
    "critical-risk actions: DENY",
    "uncertain classification: the profile's `uncertain` setting (REQUIRE_APPROVAL unless DENY)",
    "everything else: REQUIRE_APPROVAL",
];
const PRECEDENCE: &[&str] = &[
    "guards (unknown operations, trusted state, self-approval) always deny",
    "global policy decides first; else profile rules; else defaults",
    "mandatory and project rules are floors: they can raise a decision, never lower it",
    "within a layer a DENY wins; otherwise the highest priority decides, the more restrictive winning",
    "critical risk is never plainly allowed",
];

/// `policy.show`.
pub fn policy_show(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let a: Location = args(arguments)?;
    let cwd = working_directory(&a.working_directory)?;
    let trust = verified(&env.store)?;
    let registration = registered_for(&cwd, &trust.registry).cloned();
    let policy =
        effective(&trust, registration.as_ref()).map_err(|e| crate::support::trust_error(&e))?;
    let layered = policy.layered();
    let layers = layered.layers();
    Ok(json!({
        "version": policy.version().to_hex(),
        "integrity": "verified",
        "provenance": {
            "mandatory": policy.provenance().mandatory,
            "global": policy.provenance().global.map(|v| v.to_string()),
            "project": policy.provenance().project.map(|v| v.to_string()),
        },
        "profile": {
            "name": layers.settings.name,
            "version": layers.settings.name.version(),
            "settings": layers.settings,
        },
        "project": registration.as_ref().map(registration_json),
        "layers": {
            "mandatory": layers.mandatory,
            "global": layers.global,
            "project": layers.project,
            "profile": layers.profile,
        },
        "defaults": DEFAULTS,
        "precedence": PRECEDENCE,
    }))
}

/// `project.list`.
pub fn project_list(env: &Environment, arguments: &Value) -> Result<Value, EngineError> {
    args::<NoArgs>(arguments.clone())?;
    let trust = verified(&env.store)?;
    let projects: Vec<Value> = trust
        .registry
        .projects
        .iter()
        .map(registration_json)
        .collect();
    Ok(json!({ "projects": projects }))
}

/// `project.inspect`.
pub fn project_inspect(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let a: Location = args(arguments)?;
    let cwd = working_directory(&a.working_directory)?;
    let trust = verified(&env.store)?;
    let Some(registration) = registered_for(&cwd, &trust.registry) else {
        return Err(EngineError::new(
            ErrorCode::NotRegistered,
            "this directory is not inside a registered project",
        )
        .recovery("run `ai-defender init` in the project"));
    };
    let manifest = trust.project_policies.get(&registration.id);
    Ok(json!({
        "registration": registration_json(registration),
        "approved_rules": manifest.map(|m| &m.policy.rules),
        "approved_by": manifest.map(|m| m.authorized_by.to_string()),
        "config": config_state(&registration.root),
        "policy_drift": has_drift(&registration.root, manifest.map(|m| &m.policy_hash)),
    }))
}

/// `config.validate`.
pub fn config_validate(arguments: Value) -> Result<Value, EngineError> {
    let a: Location = args(arguments)?;
    let cwd = working_directory(&a.working_directory)?;
    let root = detect_root(&cwd);
    let state = config_state(&root);
    let valid = state.get("state").and_then(Value::as_str) == Some("valid");
    Ok(json!({ "root": root, "config": state, "valid": valid }))
}
