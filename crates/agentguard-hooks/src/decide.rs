//! Decisions for hooked tool calls.
//!
//! ```text
//! payload ─ validate ─ normalize into protocol actions ─ resolve cwd ─ verify trusted state
//!   ─ project from the registry (outside every registered project: only the trusted-state
//!     guard applies, otherwise the call is not governed)
//!   ─ per operation: identity (installed agent + registry) ─ content and Git inspection
//!     ─ evaluate (the existing policy engine) ─ digest (operation + tool input + Git facts)
//!   ─ combine: any DENY → deny; any REQUIRE_APPROVAL → redeem an approved grant for the
//!     exact digest, or create a pending request and block
//! ```
//!
//! Neither provider can pause a tool call while a human approves in another terminal (Claude
//! Code's `defer` works only in non-interactive mode). So `REQUIRE_APPROVAL` blocks the call
//! and keeps a pending request. The human approves with `agentguard approve`, and the agent
//! retries the identical call, which then redeems the one-time grant. A retry that differs in
//! any bound field computes a different digest and is not authorized.
//!
//! `ALLOW` adds no decision: the provider's own permission checks still apply. AgentGuard only
//! ever restricts what the provider would do.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agentguard_audit::{AuditSink, HookEventKind, HookRecord, SecurityEvent};
use agentguard_core::redact::redact_text;
use agentguard_core::{
    ActionCategory, AgentIdentity, ApprovalId, ApprovalStatus, BoundedText, Decision, Name,
    NormalizedPath, OperationFingerprint, PathResolver, PolicyVersion, ProjectId, ProjectIdentity,
    RequestId, RuleId, SecurityContext,
};
use agentguard_engine::{
    evaluate, operation_digest_with, Clock, EvaluationContext, ExecutionBinding, FsPathResolver,
    HostInspection, TrustedInvocation, TrustedStateGuard,
};
use agentguard_exec::environment::{build, Profile};
use agentguard_exec::request::CommandSpec;
use agentguard_proto::{parse_request, AuthorizationRequest};
use agentguard_secrets::{inspect_text, DetectorSet, Evidence};
use agentguard_trust::approvals::{
    ApprovalStore, ClaimToken, NewRequest, OperationSummary, Redemption,
};
use agentguard_trust::{load_runtime, TrustState, TrustStore, TrustedRuntime};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::input::{normalize, tool_input_digest, HookInput, Operation};

/// Everything a decision needs from its host.
pub struct HookEnv<'a> {
    /// The trust store.
    pub store: &'a TrustStore,
    /// Time source.
    pub clock: &'a dyn Clock,
    /// The hook process's environment (for `HOME` and the trusted search path).
    pub caller_env: &'a [(String, String)],
    /// The engine binary the hooks run (protected from changes like trusted state).
    pub engine_path: Option<&'a Path>,
}

/// A decision for one hooked tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Policy allows; AgentGuard adds no decision.
    Allow,
    /// Approved one-time grants for this exact call were consumed.
    Authorized {
        /// The approvals consumed.
        approvals: Vec<ApprovalId>,
    },
    /// Blocked.
    Deny {
        /// Rule or reason code.
        rule: String,
        /// Why.
        reason: String,
    },
    /// Blocked until a human approves; the agent must then retry the identical call.
    ApprovalRequired {
        /// Pending requests to approve.
        approvals: Vec<ApprovalId>,
        /// Rule.
        rule: String,
        /// Why.
        reason: String,
    },
    /// Outside every registered project and not touching trusted state: not governed.
    NotGoverned,
}

/// Paths outside any project that hold the agents' own hook configuration. A change to them
/// could remove AgentGuard's hooks, so they are guarded like AgentGuard's trusted state.
#[must_use]
pub fn agent_config_paths(home: Option<&str>) -> Vec<PathBuf> {
    let Some(home) = home.filter(|h| Path::new(h).is_absolute()) else {
        return Vec::new();
    };
    let home = Path::new(home);
    vec![
        home.join(".claude/settings.json"),
        home.join(".claude/settings.local.json"),
        home.join(".codex/hooks.json"),
        home.join(".codex/config.toml"),
    ]
}

fn var<'a>(env: &'a [(String, String)], name: &str) -> Option<&'a str> {
    env.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

fn guard_for(env: &HookEnv<'_>, runtime: &TrustedRuntime) -> TrustedStateGuard {
    let mut roots = runtime.protected_roots.clone();
    let extra = agent_config_paths(var(env.caller_env, "HOME"))
        .into_iter()
        .chain(env.engine_path.map(Path::to_path_buf));
    roots.extend(extra.filter_map(|p| NormalizedPath::new(p.to_string_lossy().as_ref()).ok()));
    let guard = TrustedStateGuard::new(roots);
    match var(env.caller_env, "HOME").and_then(|h| NormalizedPath::new(h).ok()) {
        Some(home) => guard.with_home(home),
        None => guard,
    }
}

fn session_hash(input: &HookInput) -> Option<String> {
    input.session_id.as_ref().map(|s| {
        hex::encode(Sha256::digest(s.as_bytes()))
            .get(..16)
            .unwrap_or_default()
            .to_owned()
    })
}

/// Records hook events for one invocation.
pub struct Recorder<'a> {
    audit: Arc<dyn AuditSink>,
    input: &'a HookInput,
    project: Option<ProjectId>,
    policy_version: Option<PolicyVersion>,
}

impl<'a> Recorder<'a> {
    /// A recorder for `input`.
    #[must_use]
    pub fn new(audit: Arc<dyn AuditSink>, input: &'a HookInput) -> Self {
        Self {
            audit,
            input,
            project: None,
            policy_version: None,
        }
    }

    /// Record one event. A failure is returned; for enforcement hooks the caller blocks.
    pub fn record(
        &self,
        kind: HookEventKind,
        code: &str,
        detail: &str,
        decision: Option<Decision>,
        request_id: Option<RequestId>,
        approval_id: Option<ApprovalId>,
    ) -> Result<(), HookError> {
        let enforcement = match self.input.event.capability {
            crate::provider::Capability::PreExecutionEnforcement => "enforced-before-execution",
            crate::provider::Capability::PostExecutionAudit => "observed-after-execution",
            crate::provider::Capability::Informational => "informational",
        };
        let event = SecurityEvent::Hook(Box::new(HookRecord {
            kind,
            provider: self.input.provider.as_str(),
            event: self.input.event.name,
            tool: self.input.tool_name.clone(),
            session: session_hash(self.input),
            request_id,
            project: self.project,
            agent: Some(AgentIdentity::new(self.input.provider.agent())),
            policy_version: self.policy_version,
            decision,
            approval_id,
            enforcement,
            reason_code: RuleId::new(code).unwrap_or_else(|_| RuleId::builtin("hook.event")),
            detail: detail.to_owned(),
        }));
        self.audit
            .record(event.into_audit_event())
            .map(|_| ())
            .map_err(|_| {
                HookError::new(
                    "hook.audit-unavailable",
                    "the audit log could not be written",
                )
            })
    }
}

/// An internal failure. For enforcement hooks it always becomes a block.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message} ({code})")]
pub struct HookError {
    /// Stable reason code.
    pub code: &'static str,
    /// Why.
    pub message: String,
}

impl HookError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

fn deny(rule: impl Into<String>, reason: impl Into<String>) -> Verdict {
    Verdict::Deny {
        rule: rule.into(),
        reason: reason.into(),
    }
}

/// The protocol request for one operation.
fn request_for(
    input: &HookInput,
    op: &Operation,
    project_root: &str,
    cwd: &str,
    policy: PolicyVersion,
) -> Result<AuthorizationRequest, String> {
    let mut body = json!({
        "protocol": agentguard_proto::PROTOCOL_VERSION,
        "request_id": RequestId::generate().to_string(),
        "agent": { "kind": input.provider.agent().as_str() },
        "project": { "root": project_root },
        "action": op.action,
        "working_directory": cwd,
        "policy_version": policy.to_string(),
    });
    if let Some(tool) = input.tool_name.as_deref().filter(|t| Name::new(*t).is_ok()) {
        crate::input::set_field(&mut body, "context", json!({ "tool": tool }));
    }
    if let Some(s) = input
        .session_id
        .as_deref()
        .filter(|s| s.parse::<agentguard_core::SessionId>().is_ok())
    {
        crate::input::set_field(&mut body, "session_id", json!(s));
    }
    let bytes = serde_json::to_vec(&body).map_err(|_| "request encoding failed".to_owned())?;
    parse_request(&bytes, &FsPathResolver).map_err(|r| r.error.to_string())
}

/// A single simple `git` command in `command`, as an argument vector.
fn simple_git(command: &str) -> Option<Vec<String>> {
    let script = agentguard_exec::shell::parse(command).ok()?;
    match script.commands.as_slice() {
        [only]
            if only.redirects.is_empty()
                && only
                    .argv
                    .first()
                    .is_some_and(|p| p == "git" || p.ends_with("/git")) =>
        {
            Some(only.argv.clone())
        }
        _ => None,
    }
}

/// Binding and inspection for one operation: the tool input digest always; for a single Git
/// command, the repository facts and pre-execution scans the managed executor uses.
fn bind(
    env: &HookEnv<'_>,
    input: &HookInput,
    op: &Operation,
    cwd: &Path,
    project_root: &Path,
    detectors: &DetectorSet,
) -> (ExecutionBinding, Option<HostInspection>) {
    let mut binding = ExecutionBinding::new();
    let _ = binding.insert("hook.provider", input.provider.as_str());
    let _ = binding.insert("hook.tool-input", tool_input_digest(input));
    let mut evidence = Evidence::default();
    let mut incomplete = false;
    if let Some(content) = &op.content {
        evidence.merge(&inspect_text(content, detectors).evidence);
    }
    if let Some(argv) = op
        .action
        .get("command")
        .and_then(Value::as_str)
        .and_then(simple_git)
    {
        let built = build(env.caller_env, Profile::Development, &[], project_root);
        if let Ok(plan) = agentguard_exec::plan::plan(
            &CommandSpec::Argv(argv),
            cwd,
            project_root,
            &built,
            detectors,
        ) {
            if let Some(g) = &plan.git {
                for (k, v) in agentguard_exec::plan::git_facts(g, project_root) {
                    let _ = binding.insert(&k, v);
                }
                if let Some((e, inc)) = agentguard_exec::plan::scan_evidence(&plan) {
                    evidence.merge(&e);
                    incomplete |= inc;
                }
            }
        }
    }
    let host = (evidence.count > 0 || incomplete).then_some(HostInspection {
        evidence,
        incomplete,
    });
    (binding, host)
}

fn summary(
    input: &HookInput,
    request: &AuthorizationRequest,
    reason: &BoundedText<512>,
) -> Result<OperationSummary, HookError> {
    let action = &request.action;
    let target = redact_text(&agentguard_engine::normalize::audit_resource(action));
    let impact = match action.category() {
        ActionCategory::Terminal => {
            "The agent wants to run this shell command with your permissions."
        }
        ActionCategory::Filesystem => "The agent wants to change or read this file.",
        ActionCategory::Network => "The agent wants to send a request to this host.",
        _ => "The agent wants to use this tool.",
    };
    Ok(OperationSummary {
        category: action.category(),
        operation: Name::new(action.operation())
            .map_err(|_| HookError::new("hook.internal", "unnamed operation"))?,
        label: BoundedText::lossy(&format!(
            "{} {}",
            input.provider.display(),
            input.tool_name.as_deref().unwrap_or("tool")
        )),
        target_truncated: target.chars().count() > 2048,
        target: BoundedText::lossy(&target),
        impact: BoundedText::lossy(impact),
        reason: reason.clone(),
        tool: input.tool_name.as_deref().and_then(|t| Name::new(t).ok()),
    })
}

// ---------------------------------------------------------------------------------------------
// Claim tokens kept by the hook between the blocked call and the retry
// ---------------------------------------------------------------------------------------------

fn claims_dir(store: &TrustStore) -> PathBuf {
    store.root().join("hooks").join("claims")
}

fn save_claim(store: &TrustStore, id: ApprovalId, token: &str) -> Result<(), HookError> {
    let dir = claims_dir(store);
    let fail = || {
        HookError::new(
            "hook.claims-unavailable",
            "the hook claim store could not be written",
        )
    };
    for d in [store.root().join("hooks"), dir.clone()] {
        match DirBuilder::new().mode(0o700).create(&d) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(fail()),
        }
        let meta = fs::symlink_metadata(&d).map_err(|_| fail())?;
        if !meta.is_dir() {
            return Err(fail());
        }
    }
    let path = dir.join(id.to_string());
    let tmp = dir.join(format!(".{id}.{}", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(&tmp)
        .map_err(|_| fail())?;
    f.write_all(token.as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|_| fail())?;
    fs::rename(&tmp, &path).map_err(|_| fail())
}

fn load_claim(store: &TrustStore, id: ApprovalId) -> Option<ClaimToken> {
    let mut text = String::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(claims_dir(store).join(id.to_string()))
        .ok()?
        .take(256)
        .read_to_string(&mut text)
        .ok()?;
    ClaimToken::parse(text.trim()).ok()
}

// ---------------------------------------------------------------------------------------------
// The decision
// ---------------------------------------------------------------------------------------------

struct Evaluated {
    request: AuthorizationRequest,
    security: SecurityContext,
    decision: Decision,
    rule: String,
    reason: BoundedText<512>,
    risk: agentguard_core::RiskLevel,
    digest: OperationFingerprint,
}

fn verified_runtime(
    env: &HookEnv<'_>,
    cwd: &NormalizedPath,
    audit: &Arc<dyn AuditSink>,
) -> Result<TrustedRuntime, Verdict> {
    let runtime = load_runtime(env.store, cwd, audit);
    match &runtime.state {
        TrustState::Verified(_) => Ok(runtime),
        TrustState::Lockdown(e) => Err(deny(
            "policy.integrity",
            format!("AI Defender's trusted state did not verify ({e}); protected operations are blocked until `ai-defender check` passes"),
        )),
    }
}

/// Decide a pre-execution tool call.
// One fail-closed sequence; each step's early return is a block.
#[allow(clippy::too_many_lines)]
pub fn decide(
    env: &HookEnv<'_>,
    input: &HookInput,
    rec: &mut Recorder<'_>,
) -> Result<Verdict, HookError> {
    let ops = match normalize(input) {
        Ok(ops) if !ops.is_empty() => ops,
        Ok(_) => {
            return Ok(deny(
                "hook.no-operation",
                "the tool call could not be normalized",
            ))
        }
        Err(e) => {
            rec.record(
                HookEventKind::PayloadRejected,
                e.code,
                &e.message,
                Some(Decision::Deny),
                None,
                None,
            )?;
            return Ok(deny(e.code, e.message));
        }
    };
    rec.record(
        HookEventKind::Normalized,
        "hook.normalized",
        &format!("{} operation(s)", ops.len()),
        None,
        None,
        None,
    )?;
    let Ok(cwd) = FsPathResolver.resolve(None, &input.cwd) else {
        return Ok(deny(
            "hook.cwd-invalid",
            "the session's working directory cannot be resolved",
        ));
    };
    let audit = Arc::clone(&rec.audit);
    let runtime = match verified_runtime(env, &cwd, &audit) {
        Ok(r) => r,
        Err(v) => return Ok(v),
    };
    rec.policy_version = Some(runtime.policy.version());
    let guard = guard_for(env, &runtime);
    let invocation = TrustedInvocation {
        agent: input.provider.agent(),
    };
    let project = runtime.registry.resolve(&cwd).or_else(|| {
        ops.iter()
            .filter_map(|o| o.action.get("path").and_then(Value::as_str))
            .filter_map(|p| NormalizedPath::new(p).ok())
            .find_map(|p| runtime.registry.resolve(&p))
    });
    let Some(project) = project else {
        return Ok(not_governed(input, &ops, &cwd, &guard, &runtime));
    };
    rec.project = Some(*project.id());
    // A session outside the project acting on a file inside it is evaluated from the project.
    let eval_cwd = if project.contains(&cwd) {
        cwd.clone()
    } else {
        project.root().clone()
    };
    let detectors: &DetectorSet = match runtime.policy.sensitivity() {
        Some(s) => s.detectors(),
        None => &agentguard_secrets::BUILTIN,
    };
    let mut evaluated = Vec::new();
    for op in &ops {
        let request = match request_for(
            input,
            op,
            project.root().as_str(),
            eval_cwd.as_str(),
            runtime.policy.version(),
        ) {
            Ok(r) => r,
            Err(e) => {
                return Ok(deny(
                    "hook.operation-invalid",
                    format!("the operation is not a valid request: {e}"),
                ))
            }
        };
        let mut context = match EvaluationContext::establish(
            &request,
            &invocation,
            &*runtime.registry,
            &guard,
            &FsPathResolver,
            runtime.policy.version(),
        ) {
            Ok(c) => c,
            Err(e) => return Ok(deny(e.rule().as_str().to_owned(), e.to_string())),
        };
        let (binding, host) = bind(
            env,
            input,
            op,
            eval_cwd.as_path(),
            project.root().as_path(),
            detectors,
        );
        if let Some(h) = host {
            context = context.with_inspection(h);
        }
        let e = match evaluate(&request, &context, &*runtime.policy) {
            Ok(e) => e,
            Err(e) => return Ok(deny(e.rule().as_str().to_owned(), e.to_string())),
        };
        let digest = operation_digest_with(context.security(), &request, Some(&binding))
            .map_err(|_| HookError::new("hook.internal", "operation digest failed"))?;
        rec.record(
            HookEventKind::Decision,
            e.rule.as_str(),
            e.reason.as_str(),
            Some(e.decision),
            Some(request.request_id),
            None,
        )?;
        evaluated.push(Evaluated {
            security: context.security().clone(),
            request,
            decision: e.decision,
            rule: e.rule.to_string(),
            reason: e.reason.clone(),
            risk: e.risk.level,
            digest,
        });
    }
    if let Some(d) = evaluated.iter().find(|e| e.decision == Decision::Deny) {
        return Ok(deny(d.rule.clone(), d.reason.as_str()));
    }
    let needing: Vec<&Evaluated> = evaluated
        .iter()
        .filter(|e| e.decision == Decision::RequireApproval)
        .collect();
    if needing.is_empty() {
        return Ok(Verdict::Allow);
    }
    approvals(env, input, &runtime, &needing, rec)
}

fn not_governed(
    input: &HookInput,
    ops: &[Operation],
    cwd: &NormalizedPath,
    guard: &TrustedStateGuard,
    runtime: &TrustedRuntime,
) -> Verdict {
    // Trusted state is protected everywhere, governed project or not.
    let Ok(ctx) = SecurityContext::new(
        AgentIdentity::new(input.provider.agent()),
        ProjectIdentity::new(cwd.clone(), None),
        None,
        runtime.policy.version(),
        cwd.clone(),
    ) else {
        return deny("hook.internal", "context");
    };
    for op in ops {
        let request = match request_for(
            input,
            op,
            cwd.as_str(),
            cwd.as_str(),
            runtime.policy.version(),
        ) {
            Ok(r) => r,
            Err(e) => return deny("hook.operation-invalid", e),
        };
        if let Some(v) = guard.check(&ctx, &request.action) {
            return deny(v.rule(), v.reason());
        }
    }
    Verdict::NotGoverned
}

fn approvals(
    env: &HookEnv<'_>,
    input: &HookInput,
    runtime: &TrustedRuntime,
    needing: &[&Evaluated],
    rec: &Recorder<'_>,
) -> Result<Verdict, HookError> {
    let store = ApprovalStore::new(env.store);
    let now = env.clock.now();
    let unavailable = |e: agentguard_trust::approvals::ApprovalError| {
        HookError::new(
            "hook.approvals-unavailable",
            format!("the approval store could not be used: {e}"),
        )
    };
    let listing = store.list(now, &*rec.audit).map_err(unavailable)?;
    let approved = |e: &Evaluated| {
        listing.records.iter().find(|r| {
            r.status == ApprovalStatus::Approved
                && r.request.operation_digest == e.digest
                && r.request.agent.kind == input.provider.agent()
                && r.request.project == *e.security.project().id()
        })
    };
    let ready: Vec<Option<(ApprovalId, ClaimToken)>> = needing
        .iter()
        .map(|e| {
            approved(e).and_then(|r| {
                load_claim(env.store, r.request.approval_id).map(|t| (r.request.approval_id, t))
            })
        })
        .collect();
    if ready.iter().all(Option::is_some) {
        let trust = env
            .store
            .load()
            .map_err(|e| HookError::new("hook.trust-unavailable", e.to_string()))?;
        let mut consumed = Vec::new();
        for (e, grant) in needing.iter().zip(ready.into_iter().flatten()) {
            let (id, token) = grant;
            let redeemed = store.consume(
                &Redemption {
                    approval_id: id,
                    token: &token,
                    request_id: e.request.request_id,
                    operation_digest: e.digest,
                    project: *e.security.project().id(),
                    agent: e.security.agent().clone(),
                    policy_version: runtime.policy.version(),
                    trusted_signers: &trust.signers,
                },
                now,
                &*rec.audit,
            );
            match redeemed {
                Ok(_) => consumed.push(id),
                Err(err) => {
                    return Ok(deny(
                        err.reason_code(),
                        format!("the approved grant could not be redeemed: {err}"),
                    ))
                }
            }
        }
        return Ok(Verdict::Authorized {
            approvals: consumed,
        });
    }
    let timing = env
        .store
        .load()
        .map_err(|e| HookError::new("hook.trust-unavailable", e.to_string()))?
        .global
        .policy
        .approval_timing()
        .map_err(|r| HookError::new("hook.trust-unavailable", r))?;
    let mut ids = Vec::new();
    for e in needing {
        if let Some(r) = approved(e) {
            if load_claim(env.store, r.request.approval_id).is_some() {
                continue;
            }
        }
        // A retry before the human decides reuses the pending request this hook already holds
        // a claim for, instead of adding claims to it.
        let pending = listing.records.iter().find(|r| {
            r.status == ApprovalStatus::Pending
                && r.request.operation_digest == e.digest
                && r.request.agent.kind == input.provider.agent()
                && r.request.project == *e.security.project().id()
                && load_claim(env.store, r.request.approval_id).is_some()
        });
        if let Some(r) = pending {
            ids.push(r.request.approval_id);
            continue;
        }
        let created = store
            .create(
                NewRequest {
                    request_id: e.request.request_id,
                    operation_digest: e.digest,
                    agent: e.security.agent().clone(),
                    project: *e.security.project().id(),
                    project_root: e.security.project().root().clone(),
                    session: e.security.session().copied(),
                    summary: summary(input, &e.request, &e.reason)?,
                    risk: e.risk,
                    rule: RuleId::new(e.rule.clone())
                        .unwrap_or_else(|_| RuleId::builtin("hook.approval")),
                    policy_version: runtime.policy.version(),
                },
                timing,
                now,
                &*rec.audit,
            )
            .map_err(unavailable)?;
        let id = created.record.request.approval_id;
        save_claim(env.store, id, created.token.reveal().as_str())?;
        ids.push(id);
    }
    let first = needing
        .first()
        .map_or(("", ""), |e| (e.rule.as_str(), e.reason.as_str()));
    Ok(Verdict::ApprovalRequired {
        approvals: ids,
        rule: first.0.to_owned(),
        reason: first.1.to_owned(),
    })
}

/// A short approval reference for messages (the CLI accepts unique prefixes).
#[must_use]
pub fn short(id: &ApprovalId) -> String {
    id.to_string().chars().take(8).collect()
}

/// The JSON a status or health check reports for a verdict.
#[must_use]
pub fn verdict_json(v: &Verdict) -> Value {
    match v {
        Verdict::Allow => json!({"decision": "ALLOW"}),
        Verdict::Authorized { approvals } => {
            json!({"decision": "ALLOW", "authorized_by": approvals})
        }
        Verdict::Deny { rule, reason } => {
            json!({"decision": "DENY", "rule": rule, "reason": reason})
        }
        Verdict::ApprovalRequired {
            approvals,
            rule,
            reason,
        } => {
            json!({"decision": "REQUIRE_APPROVAL", "approvals": approvals, "rule": rule, "reason": reason})
        }
        Verdict::NotGoverned => json!({"decision": "NOT_GOVERNED"}),
    }
}
