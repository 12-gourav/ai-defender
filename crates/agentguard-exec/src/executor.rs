//! The controlled executor: `execute(request, environment) -> Result<outcome, ExecutionError>`.
//!
//! ```text
//! validate ─ resolve working directory ─ verify trusted state ─ resolve project (registry)
//!   ─ audit(request) ─ plan (resolve executable, parse Git or shell, inspect repository,
//!     scan what a commit or push would publish) ─ audit(classified, context, scan)
//!   ─ evaluate (identity: trusted invocation + registry; policy) ─ digest(operation + binding)
//!   ─ audit(decision)
//!   ─ DENY → refused                     REQUIRE_APPROVAL → create request, or redeem grant
//!   ─ reserve idempotency key ─ [consume grant] ─ Permit
//!   ─ revalidate (executables unchanged, repository facts unchanged)
//!   ─ record(started) + audit(started) ─ spawn ─ wait ─ verify ─ record + audit(outcome)
//! ```
//!
//! Classification ([`crate::plan`]), authorization (this module, through the policy engine and
//! the approval store) and execution (the private `process` module) are separate. The process runner is
//! private to this crate and takes a [`Permit`], which only this module can construct, and only
//! after an `ALLOW` decision or a consumed grant for the exact operation digest.
//!
//! ```compile_fail
//! // A permit cannot be built outside the executor.
//! let p = agentguard_exec::executor::Permit { };
//! ```
//!
//! Failures before the process starts mean it never starts: a failed audit write, a failed
//! record write, a changed repository or executable. After it starts, a failure to record the
//! outcome is reported as [`ExecutionError::OutcomeUnrecorded`], never as success. Nothing is
//! retried.

use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use agentguard_audit::{AuditSink, ExecutionEventKind, ExecutionRecord, SecurityEvent};
use agentguard_core::redact::redact_text;
use agentguard_core::{
    AgentKind, ApprovalId, BoundedText, Decision, GrantId, Name, NormalizedPath,
    OperationFingerprint, PathResolver, RequestId, RuleId,
};
use agentguard_engine::{
    evaluate, operation_digest_with, Clock, Evaluation, EvaluationContext, ExecutionBinding,
    FsPathResolver, HostInspection, TrustedInvocation, TrustedStateGuard,
};
use agentguard_proto::{parse_request, AuthorizationRequest};
use agentguard_trust::approvals::{
    ApprovalError, ApprovalStore, ClaimToken, NewRequest, OperationSummary, Redemption,
};
use agentguard_trust::executions::{new_execution_id, ExecutionStore, ExecutionStoreError};
use agentguard_trust::manifest::DEFAULT_EXECUTION_TIMEOUT_SECONDS;
use agentguard_trust::{load_runtime, TrustState, TrustStore, TrustedRuntime};
use serde_json::{json, Map, Value};

use crate::environment::{build, BuiltEnvironment, Profile};
use crate::error::{ApprovalFailure, ExecutionError};
use crate::git::{self, GitKind, Verification};
use crate::plan::{binding, git_facts, plan, scan_evidence, view, Plan, Refusal};
use crate::process::{self, Signals, Spawn, Termination};
use crate::request::{ExecutionRequest, ValidRequest};

/// Bytes of each output stream kept in memory and returned (redacted).
pub const CAPTURE_LIMIT: usize = 128 * 1024;
/// Bytes of each output stream kept in the execution record.
pub const RECORD_OUTPUT: usize = 16 * 1024;

/// The tool name policy sees for managed executions.
pub const TOOL: &str = "agentguard-run";

/// What managed execution does and does not cover, attached to every outcome.
pub const ENFORCEMENT_NOTE: &str = "AI Defender controlled this command because it was run through `ai-defender run`. Commands an agent runs through its own terminal or tools are not intercepted: managed execution is not global enforcement, and no agent hook is installed yet.";

/// The enforcement coverage statement.
#[must_use]
pub fn enforcement() -> Value {
    json!({
        "mode": "managed",
        "scope": "this command only",
        "global_enforcement": false,
        "direct_execution_protected": false,
        "agent_hooks": "not-installed",
        "note": ENFORCEMENT_NOTE,
    })
}

/// Everything the executor needs from its host. All of it is trusted host configuration;
/// nothing comes from the request.
pub struct ExecEnv<'a> {
    /// The trust store (policy, registry, approvals, records, audit).
    pub store: &'a TrustStore,
    /// Set when an agent integration launched the engine. Without it the caller is an
    /// unverified command-line user and is evaluated as the generic agent: AgentGuard cannot
    /// tell a human at a terminal from an agent typing into one.
    pub invocation: Option<&'a TrustedInvocation>,
    /// Time source.
    pub clock: &'a dyn Clock,
    /// The caller's environment variables (filtered before anything runs).
    pub caller_env: &'a [(String, String)],
    /// Termination signals to forward to the process group (the engine binary only).
    pub signals: Option<&'a Signals>,
}

/// Authorization for exactly one plan. Only this module constructs it.
pub struct Permit {
    plan: Plan,
    digest: OperationFingerprint,
    binding: ExecutionBinding,
    approval: Option<(ApprovalId, GrantId)>,
    _sealed: Sealed,
}

struct Sealed;

fn now_text(clock: &dyn Clock) -> Value {
    clock
        .now()
        .format(&time::format_description::well_known::Rfc3339)
        .map_or(Value::Null, Value::String)
}

/// Redact captured output: values of withheld credential variables, detector matches, and
/// sensitive assignments; control characters other than newline and tab become U+FFFD.
#[must_use]
pub fn redact_output(bytes: &[u8], secrets: &[String]) -> String {
    let mut text: String = String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                '\u{fffd}'
            } else {
                c
            }
        })
        .collect();
    for s in secrets {
        if text.contains(s.as_str()) {
            text = text.replace(s.as_str(), "[REDACTED]");
        }
    }
    let detected = agentguard_secrets::redact(&text);
    let mut out = String::with_capacity(detected.len());
    for (i, line) in detected.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&redact_text(line));
    }
    out
}

fn excerpt(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or_default().to_owned()
}

struct Run<'a> {
    env: &'a ExecEnv<'a>,
    audit: Arc<dyn AuditSink>,
    records: ExecutionStore,
    execution_id: String,
    name: Name,
    record: Map<String, Value>,
    agent: agentguard_core::AgentIdentity,
    project: Option<agentguard_core::ProjectId>,
    project_root: NormalizedPath,
    request_id: Option<RequestId>,
    policy_version: Option<agentguard_core::PolicyVersion>,
    summary: String,
}

impl Run<'_> {
    fn event(
        &self,
        kind: ExecutionEventKind,
        code: &str,
        detail: &str,
        decision: Option<Decision>,
        digest: Option<OperationFingerprint>,
        approval: Option<(ApprovalId, GrantId)>,
    ) -> Result<(), ExecutionError> {
        let event = SecurityEvent::Execution(Box::new(ExecutionRecord {
            kind,
            execution_id: self.name.clone(),
            request_id: self.request_id,
            project: self.project,
            agent: Some(self.agent.clone()),
            policy_version: self.policy_version,
            decision,
            digest,
            approval_id: approval.map(|a| a.0),
            grant_id: approval.map(|a| a.1),
            reason_code: RuleId::new(code).unwrap_or_else(|_| RuleId::builtin("execution.event")),
            resource: self.summary.clone(),
            detail: detail.to_owned(),
        }));
        self.audit
            .record(event.into_audit_event())
            .map(|_| ())
            .map_err(|_| ExecutionError::AuditUnavailable)
    }

    fn set(&mut self, key: &str, value: Value) {
        self.record.insert(key.to_owned(), value);
    }

    fn save(&mut self, state: &str) -> Result<(), ExecutionError> {
        self.set("state", json!(state));
        self.set("updated_at", now_text(self.env.clock));
        self.records
            .save(&self.execution_id, &Value::Object(self.record.clone()))
            .map_err(|_| ExecutionError::RecordUnavailable)
    }

    fn outcome(&self, outcome: &str, extra: Value) -> Value {
        let mut v = json!({
            "outcome": outcome,
            "executed": outcome == "executed",
            "execution_id": self.execution_id,
            "enforcement": enforcement(),
        });
        if let (Some(map), Value::Object(more)) = (v.as_object_mut(), extra) {
            map.extend(more);
        }
        v
    }

    /// Refuse before policy: record, audit, report. Nothing runs.
    fn refuse(&mut self, refusal: &Refusal) -> Result<Value, ExecutionError> {
        self.event(
            ExecutionEventKind::Unsupported,
            refusal.code,
            &refusal.reason,
            Some(Decision::Deny),
            None,
            None,
        )?;
        self.set(
            "refusal",
            json!({"code": refusal.code, "reason": refusal.reason}),
        );
        let _ = self.save("refused");
        Ok(self.outcome(
            "refused",
            json!({"refusal": {"code": refusal.code, "reason": refusal.reason}}),
        ))
    }
}

fn trust_failure(e: &agentguard_trust::TrustError) -> ExecutionError {
    ExecutionError::Trust(e.to_string())
}

fn approval_failure(e: &ApprovalError) -> ExecutionError {
    let class = match e {
        ApprovalError::NotFound => ApprovalFailure::NotFound,
        ApprovalError::Ambiguous
        | ApprovalError::NotPending(_)
        | ApprovalError::Expired
        | ApprovalError::ReviewMismatch
        | ApprovalError::PolicyChanged
        | ApprovalError::ProjectNotTrusted
        | ApprovalError::TooManyOpen
        | ApprovalError::TooManyClaims => ApprovalFailure::Conflict,
        ApprovalError::Corrupt | ApprovalError::SchemaUnsupported => ApprovalFailure::Integrity,
        ApprovalError::AuditFailed => ApprovalFailure::Audit,
        ApprovalError::NotApproved(_)
        | ApprovalError::Replay
        | ApprovalError::TokenMismatch
        | ApprovalError::OperationMismatch
        | ApprovalError::ProjectMismatch
        | ApprovalError::AgentMismatch
        | ApprovalError::GrantInvalid
        | ApprovalError::UntrustedApprover
        | ApprovalError::SelfApproval => ApprovalFailure::Denied,
        _ => ApprovalFailure::Io,
    };
    ExecutionError::Approval {
        class,
        message: format!("{e} ({})", e.reason_code()),
    }
}

fn working_directory(raw: &str) -> Result<NormalizedPath, ExecutionError> {
    let path = FsPathResolver
        .resolve(None, raw)
        .map_err(|_| ExecutionError::WorkingDirectory("must be an absolute, resolvable path"))?;
    if !path.as_path().is_dir() {
        return Err(ExecutionError::WorkingDirectory("is not a directory"));
    }
    Ok(path)
}

fn verified_runtime(
    store: &TrustStore,
    cwd: &NormalizedPath,
    audit: &Arc<dyn AuditSink>,
) -> Result<TrustedRuntime, ExecutionError> {
    let runtime = load_runtime(store, cwd, audit);
    match &runtime.state {
        TrustState::Verified(_) => Ok(runtime),
        TrustState::Lockdown(e) => Err(trust_failure(e)),
    }
}

fn authorization_request(
    plan: &Plan,
    agent: AgentKind,
    project_root: &NormalizedPath,
    cwd: &NormalizedPath,
    policy_version: &agentguard_core::PolicyVersion,
) -> Result<AuthorizationRequest, ExecutionError> {
    let body = json!({
        "protocol": agentguard_proto::PROTOCOL_VERSION,
        "request_id": RequestId::generate().to_string(),
        "agent": { "kind": agent.as_str() },
        "project": { "root": project_root.as_str() },
        "action": { "category": "terminal", "command": plan.policy_text },
        "working_directory": cwd.as_str(),
        "policy_version": policy_version.to_string(),
        "context": { "tool": TOOL },
    });
    let bytes =
        serde_json::to_vec(&body).map_err(|_| ExecutionError::Internal("request encoding"))?;
    parse_request(&bytes, &FsPathResolver).map_err(|_| {
        ExecutionError::InvalidRequest(
            "the command could not be expressed as an authorization request",
        )
    })
}

fn decision_view(e: &Evaluation) -> Value {
    json!({
        "decision": e.decision,
        "rule": e.rule,
        "reason": e.reason,
        "risk": e.risk.level,
        "policy_version": e.policy_version,
    })
}

fn impact(plan: &Plan) -> &'static str {
    use crate::command::TerminalCategory as T;
    match (plan.git.as_ref().map(|g| g.command.kind), plan.category) {
        (Some(GitKind::Push), _) => "This sends local commits to a remote repository.",
        (Some(GitKind::Commit), _) => "This records the staged changes as a commit.",
        (Some(GitKind::Change), _) => {
            "This changes the Git repository (branches, history, index or remotes)."
        }
        (_, T::Destructive) => "This deletes or overwrites data.",
        (_, T::PackageManagement) => "This installs, removes or publishes software packages.",
        (_, T::Network) => "This talks to another system over the network.",
        (_, T::SystemConfiguration | T::PrivilegeEscalation) => {
            "This changes system configuration."
        }
        (_, T::SecurityConfiguration) => "This touches credentials or security settings.",
        (_, T::FilesystemModification) => "This changes files in the project.",
        _ => "This runs a program with your permissions.",
    }
}

fn context_line(plan: &Plan) -> String {
    let Some(g) = &plan.git else {
        return String::new();
    };
    let Some(c) = &g.context else {
        return String::new();
    };
    let short = |s: &Option<String>| {
        s.as_deref()
            .map_or("-".to_owned(), |h| h.chars().take(12).collect())
    };
    let mut line = format!(
        " [repository {} on {} at {}",
        c.repository_id,
        c.branch.as_deref().unwrap_or("(detached)"),
        short(&c.head)
    );
    if g.command.kind == GitKind::Commit {
        let _ = write!(
            line,
            "; {} staged change(s), tree {}",
            c.staged_total,
            short(&c.staged_tree)
        );
    }
    if let (Some(spec), Some(p)) = (&g.command.push, &g.push) {
        let url = c
            .remote(&spec.remote)
            .map(|r| r.url.clone())
            .unwrap_or_default();
        let _ = write!(
            line,
            "; push {} -> {} {} ({}), {} commit(s){}",
            spec.src.as_deref().unwrap_or("(delete)"),
            spec.remote,
            spec.dst,
            url,
            p.commits.len(),
            if spec.forced { ", FORCED" } else { "" }
        );
    }
    if !c.hooks.is_empty() {
        let _ = write!(line, "; hooks that will run: {}", c.hooks.join(", "));
    }
    line.push(']');
    line
}

fn summary(plan: &Plan, e: &Evaluation) -> Result<OperationSummary, ExecutionError> {
    let label = match plan.mode {
        crate::plan::Mode::Managed => "Run command",
        crate::plan::Mode::Shell(_) => "Run shell script",
    };
    let target = redact_text(&format!("{}{}", plan.policy_text, context_line(plan)));
    Ok(OperationSummary {
        category: agentguard_core::ActionCategory::Terminal,
        operation: Name::new("execute").map_err(|_| ExecutionError::Internal("operation name"))?,
        label: BoundedText::lossy(label),
        target_truncated: target.chars().count() > 2048,
        target: BoundedText::lossy(&target),
        impact: BoundedText::lossy(impact(plan)),
        reason: e.reason.clone(),
        tool: Name::new(TOOL).ok(),
    })
}

/// Run one execution request end to end.
pub fn execute(env: &ExecEnv<'_>, request: ExecutionRequest) -> Result<Value, ExecutionError> {
    let valid = request.validate()?;
    let audit: Arc<dyn AuditSink> = Arc::new(
        env.store
            .open_audit_log()
            .map_err(|_| ExecutionError::AuditUnavailable)?,
    );
    let cwd = working_directory(&valid.working_directory)?;
    let runtime = verified_runtime(env.store, &cwd, &audit)?;
    let invocation = env.invocation.cloned().unwrap_or(TrustedInvocation {
        agent: AgentKind::Generic,
    });
    let project = runtime
        .registry
        .resolve(&cwd)
        .ok_or(ExecutionError::Identity {
            rule: "identity.project-unregistered",
            message: "the working directory is not inside a registered project".to_owned(),
        })?;
    let execution_id = new_execution_id().map_err(|e| trust_failure(&e))?;
    let name = Name::new(&execution_id).map_err(|_| ExecutionError::Internal("execution ID"))?;
    let mut run = Run {
        env,
        audit,
        records: ExecutionStore::new(env.store),
        execution_id,
        name,
        record: Map::new(),
        agent: agentguard_core::AgentIdentity::new(invocation.agent),
        project: Some(*project.id()),
        project_root: project.root().clone(),
        request_id: None,
        policy_version: Some(runtime.policy.version()),
        summary: String::new(),
    };
    run.set("execution_id", json!(run.execution_id));
    run.set("created_at", now_text(env.clock));
    run.set(
        "project",
        json!({"id": project.id(), "root": project.root().as_str()}),
    );
    run.set("working_directory", json!(cwd.as_str()));
    run.set("agent", json!(run.agent));
    run.set(
        "invocation",
        json!(if env.invocation.is_some() {
            "agent-integration"
        } else {
            "command-line (unverified: may be a human or an agent)"
        }),
    );
    run.set("enforcement", enforcement());
    run.event(
        ExecutionEventKind::RequestReceived,
        "execution.request",
        "",
        None,
        None,
        None,
    )?;
    let trust = env.store.load().map_err(|e| trust_failure(&e))?;
    let settings = trust.global.policy.execution.clone().unwrap_or_default();
    let profile = valid
        .environment_profile
        .as_deref()
        .or(settings.default_profile.as_deref())
        .and_then(Profile::parse)
        .unwrap_or(Profile::Development);
    let timeout = valid
        .timeout_seconds
        .or(settings.default_timeout_seconds)
        .unwrap_or(DEFAULT_EXECUTION_TIMEOUT_SECONDS);
    let built = build(
        env.caller_env,
        profile,
        &settings.environment,
        project.root().as_path(),
    );
    let detectors: &agentguard_secrets::DetectorSet = match runtime.policy.sensitivity() {
        Some(s) => s.detectors(),
        None => &agentguard_secrets::detectors::BUILTIN,
    };
    let plan = match plan(
        &valid.command,
        cwd.as_path(),
        project.root().as_path(),
        &built,
        detectors,
    ) {
        Ok(p) => p,
        Err(refusal) => {
            run.summary = redact_text(&display_of(&valid));
            run.set("command", json!(run.summary));
            return run.refuse(&refusal);
        }
    };
    run.summary = redact_text(&plan.policy_text).chars().take(512).collect();
    run.set("command", json!(run.summary));
    run.set(
        "plan",
        sanitize(&view(&plan, &built, project.root().as_path())),
    );
    run.set("timeout_seconds", json!(timeout));
    authorize_and_run(
        &mut run,
        &runtime,
        &invocation,
        &cwd,
        plan,
        &built,
        timeout,
        &valid,
        &trust,
    )
}

fn display_of(valid: &ValidRequest) -> String {
    match &valid.command {
        crate::request::CommandSpec::Argv(argv) => agentguard_engine::normalize::quote_argv(argv),
        crate::request::CommandSpec::Shell { script, .. } => script.clone(),
    }
}

/// Redact every string in a JSON value.
fn sanitize(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::String(redact_text(s)),
        Value::Array(a) => Value::Array(a.iter().map(sanitize).collect()),
        Value::Object(o) => {
            Value::Object(o.iter().map(|(k, v)| (k.clone(), sanitize(v))).collect())
        }
        other => other.clone(),
    }
}

// The decision branches share a lot of state; splitting further would obscure their order.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn authorize_and_run(
    run: &mut Run<'_>,
    runtime: &TrustedRuntime,
    invocation: &TrustedInvocation,
    cwd: &NormalizedPath,
    plan: Plan,
    built: &BuiltEnvironment,
    timeout: u64,
    valid: &ValidRequest,
    trust: &agentguard_trust::VerifiedTrust,
) -> Result<Value, ExecutionError> {
    let project_root = run.project_root.clone();
    run.event(
        ExecutionEventKind::CommandClassified,
        "execution.classified",
        &format!(
            "mode {}, category {:?}, class {}, confidence {:?}, program {}",
            plan.mode.as_str(),
            plan.category,
            plan.analysis.class,
            plan.analysis.confidence,
            plan.program.path.display()
        ),
        None,
        None,
        None,
    )?;
    let facts = match &plan.git {
        Some(g) => {
            let facts = git_facts(g, project_root.as_path());
            if g.command.kind != GitKind::ReadOnly {
                run.event(
                    ExecutionEventKind::GitContextInspected,
                    "execution.git-context",
                    &format!(
                        "git {} with {} bound fact(s)",
                        g.command.subcommand,
                        facts.len()
                    ),
                    None,
                    None,
                    None,
                )?;
            }
            if let Some(scan) = &g.scan {
                run.event(
                    ExecutionEventKind::SecretScanCompleted,
                    "execution.secret-scan",
                    &format!(
                        "{} added line(s) scanned, {} detection(s){}",
                        scan.lines,
                        scan.detections,
                        if scan.incomplete { ", incomplete" } else { "" }
                    ),
                    None,
                    None,
                    None,
                )?;
            }
            facts
        }
        None => Vec::new(),
    };
    let binding = binding(&plan, built, timeout, &facts)
        .map_err(|_| ExecutionError::Internal("execution binding"))?;
    let request = authorization_request(
        &plan,
        invocation.agent,
        &project_root,
        cwd,
        &runtime.policy.version(),
    )?;
    run.request_id = Some(request.request_id);
    let guard = TrustedStateGuard::new(runtime.protected_roots.clone());
    let mut context = EvaluationContext::establish(
        &request,
        invocation,
        &*runtime.registry,
        &guard,
        &FsPathResolver,
        runtime.policy.version(),
    )
    .map_err(|e| ExecutionError::Identity {
        rule: match e.rule().as_str() {
            "identity.agent-mismatch" => "identity.agent-mismatch",
            "identity.project-mismatch" => "identity.project-mismatch",
            _ => "identity.project-unregistered",
        },
        message: e.to_string(),
    })?;
    if let Some((evidence, incomplete)) = scan_evidence(&plan) {
        context = context.with_inspection(HostInspection {
            evidence,
            incomplete,
        });
    }
    let evaluation =
        evaluate(&request, &context, &*runtime.policy).map_err(|e| ExecutionError::Identity {
            rule: "evaluation.failed",
            message: e.to_string(),
        })?;
    let digest = operation_digest_with(context.security(), &request, Some(&binding))
        .map_err(|_| ExecutionError::Internal("operation digest"))?;
    run.set("decision", decision_view(&evaluation));
    run.set("operation_digest", json!(digest.to_string()));
    run.event(
        ExecutionEventKind::PolicyDecision,
        evaluation.rule.as_str(),
        evaluation.reason.as_str(),
        Some(evaluation.decision),
        Some(digest),
        None,
    )?;
    let plan_view = sanitize(&view(&plan, built, project_root.as_path()));
    match evaluation.decision {
        Decision::Deny => {
            let _ = run.save("denied");
            return Ok(run.outcome(
                "denied",
                json!({"decision": decision_view(&evaluation), "plan": plan_view, "operation_digest": digest.to_string()}),
            ));
        }
        Decision::RequireApproval if valid.approval.is_none() => {
            let timing = trust
                .global
                .policy
                .approval_timing()
                .map_err(|_| ExecutionError::Trust("approval timing is invalid".to_owned()))?;
            let security = context.security();
            let created = ApprovalStore::new(run.env.store)
                .create(
                    NewRequest {
                        request_id: request.request_id,
                        operation_digest: digest,
                        agent: security.agent().clone(),
                        project: *security.project().id(),
                        project_root: security.project().root().clone(),
                        session: security.session().copied(),
                        summary: summary(&plan, &evaluation)?,
                        risk: evaluation.risk.level,
                        rule: evaluation.rule.clone(),
                        policy_version: evaluation.policy_version,
                    },
                    timing,
                    run.env.clock.now(),
                    &*run.audit,
                )
                .map_err(|e| approval_failure(&e))?;
            let mut approval = created.record.view(false);
            if let Some(map) = approval.as_object_mut() {
                map.insert("duplicate".into(), json!(created.duplicate));
                map.insert("claim_token".into(), json!(created.token.reveal().as_str()));
            }
            run.set("approval_id", json!(created.record.request.approval_id));
            let _ = run.save("awaiting-approval");
            return Ok(run.outcome(
                "approval-required",
                json!({
                    "decision": decision_view(&evaluation),
                    "plan": plan_view,
                    "operation_digest": digest.to_string(),
                    "approval": approval,
                }),
            ));
        }
        _ => {}
    }
    // ALLOW, or REQUIRE_APPROVAL with a grant to redeem.
    match run
        .records
        .reserve(&valid.idempotency_key, &run.execution_id)
    {
        Ok(()) => {}
        Err(ExecutionStoreError::Duplicate(existing)) => {
            return Err(ExecutionError::Duplicate(existing))
        }
        Err(_) => return Err(ExecutionError::RecordUnavailable),
    }
    let approval = match (evaluation.decision, &valid.approval) {
        (Decision::RequireApproval, Some(claim)) => {
            let id: ApprovalId = claim.approval_id.parse().map_err(|_| {
                ExecutionError::InvalidRequest("approval.approval_id must be a full approval ID")
            })?;
            let token =
                ClaimToken::parse(&claim.claim_token).map_err(|_| ExecutionError::Approval {
                    class: ApprovalFailure::Denied,
                    message: "the claim token is malformed (approval.token-mismatch)".to_owned(),
                })?;
            let security = context.security();
            let redeemed = ApprovalStore::new(run.env.store)
                .consume(
                    &Redemption {
                        approval_id: id,
                        token: &token,
                        request_id: request.request_id,
                        operation_digest: digest,
                        project: *security.project().id(),
                        agent: security.agent().clone(),
                        policy_version: runtime.policy.version(),
                        trusted_signers: &trust.signers,
                    },
                    run.env.clock.now(),
                    &*run.audit,
                )
                .map_err(|e| {
                    run.set(
                        "refusal",
                        json!({"code": e.reason_code(), "reason": e.to_string()}),
                    );
                    let _ = run.save("refused");
                    approval_failure(&e)
                })?;
            run.set("approval_id", json!(id));
            run.set("grant_id", json!(redeemed.grant_id));
            Some((id, redeemed.grant_id))
        }
        _ => None,
    };
    let permit = Permit {
        plan,
        digest,
        binding,
        approval,
        _sealed: Sealed,
    };
    execute_permitted(run, permit, built, timeout)
}

/// Revalidate, record, spawn, verify, record. Takes the permit by value: one permit, one run.
// One linear sequence of fail-closed steps.
#[allow(clippy::too_many_lines)]
fn execute_permitted(
    run: &mut Run<'_>,
    permit: Permit,
    built: &BuiltEnvironment,
    timeout: u64,
) -> Result<Value, ExecutionError> {
    let Permit {
        plan,
        digest,
        binding: bound,
        approval,
        _sealed,
    } = permit;
    let project_root = run.project_root.clone();
    // Revalidate: the executables and the repository are still what was evaluated and bound.
    let mut changed: Vec<String> = Vec::new();
    if !plan.program.unchanged() {
        changed.push("exec.program.identity".to_owned());
    }
    for (i, p) in plan.script_programs.iter().enumerate() {
        if !p.unchanged() {
            changed.push(format!("shell.{i}.identity"));
        }
    }
    if let Some(g) = &plan.git {
        for (k, v) in git_facts(g, project_root.as_path()) {
            if bound.get(&k) != Some(v.as_str()) {
                changed.push(k);
            }
        }
    }
    if !changed.is_empty() {
        let detail = format!("changed since authorization: {}", changed.join(", "));
        run.event(
            ExecutionEventKind::ContextChanged,
            "execution.context-changed",
            &detail,
            Some(Decision::Deny),
            Some(digest),
            approval,
        )?;
        run.set("changed", json!(changed));
        let _ = run.save("context-changed");
        return Ok(run.outcome(
            "context-changed",
            json!({"changed": changed, "reason": "the repository or an executable changed after authorization; nothing was run. Request a new approval."}),
        ));
    }
    run.set("started_at", now_text(run.env.clock));
    run.save("started")?;
    if let Err(e) = run.event(
        ExecutionEventKind::Started,
        "execution.started",
        &format!("pid pending; timeout {timeout}s"),
        Some(Decision::Allow),
        Some(digest),
        approval,
    ) {
        let _ = run.save("not-started");
        return Err(e);
    }
    let old_head = plan
        .git
        .as_ref()
        .and_then(|g| g.context.as_ref())
        .and_then(|c| c.head.clone());
    let result = process::run(&Spawn {
        program: &plan.program.path,
        arg0: &plan.arg0,
        args: &plan.args,
        cwd: Path::new(
            run.record
                .get("working_directory")
                .and_then(Value::as_str)
                .unwrap_or("/"),
        ),
        env: &built.vars,
        timeout: Duration::from_secs(timeout),
        capture_limit: CAPTURE_LIMIT,
        signals: run.env.signals,
    });
    let verification = match &plan.git {
        Some(g) if !matches!(result.termination, Termination::Exited { code: 0 }) => {
            let _ = g;
            Verification::NotApplicable
        }
        Some(g) => match (g.command.kind, &g.command.push, &g.push) {
            (GitKind::Commit, _, _) => git::verify_commit(
                &g.plumbing,
                bound.get("git.staged-tree").filter(|t| *t != "unmerged"),
                old_head.as_deref(),
            ),
            (GitKind::Push, Some(spec), Some(ctx)) => git::verify_push(&g.plumbing, spec, ctx),
            _ => Verification::NotApplicable,
        },
        None => Verification::NotApplicable,
    };
    let stdout = redact_output(&result.stdout.bytes, built.secret_values());
    let stderr = redact_output(&result.stderr.bytes, built.secret_values());
    let (state, kind, code) = match result.termination {
        Termination::Exited { code: 0 } => (
            "completed",
            ExecutionEventKind::Completed,
            "execution.completed",
        ),
        Termination::Exited { .. } | Termination::Signaled { .. } | Termination::SpawnFailed => {
            ("failed", ExecutionEventKind::Failed, "execution.failed")
        }
        Termination::TimedOut => (
            "timed-out",
            ExecutionEventKind::TimedOut,
            "execution.timed-out",
        ),
        Termination::Interrupted => (
            "interrupted",
            ExecutionEventKind::Indeterminate,
            "execution.interrupted",
        ),
        Termination::Indeterminate => (
            "indeterminate",
            ExecutionEventKind::Indeterminate,
            "execution.indeterminate",
        ),
    };
    let outcome_text = match result.termination {
        Termination::Exited { code } => format!("exit {code}"),
        Termination::Signaled { signal } => format!("killed by signal {signal}"),
        Termination::TimedOut => format!("timed out after {timeout}s and was terminated"),
        Termination::Interrupted => "interrupted and terminated".to_owned(),
        Termination::SpawnFailed => "could not be started".to_owned(),
        Termination::Indeterminate => "outcome unknown".to_owned(),
    };
    let result_json = json!({
        "termination": result.termination,
        "exit_code": match result.termination { Termination::Exited { code } => Some(code), _ => None },
        "duration_ms": u64::try_from(result.duration.as_millis()).unwrap_or(u64::MAX),
        "stdout_bytes": result.stdout.total,
        "stderr_bytes": result.stderr.total,
        "stdout_truncated": result.stdout.truncated(),
        "stderr_truncated": result.stderr.truncated(),
    });
    run.set("finished_at", now_text(run.env.clock));
    run.set("result", result_json.clone());
    run.set("verification", json!(verification));
    run.set(
        "output",
        json!({"stdout": excerpt(&stdout, RECORD_OUTPUT), "stderr": excerpt(&stderr, RECORD_OUTPUT)}),
    );
    let recorded = run.save(state);
    let audited = run.event(
        kind,
        code,
        &outcome_text,
        Some(Decision::Allow),
        Some(digest),
        approval,
    );
    if let Verification::Mismatch(why) = &verification {
        let _ = run.event(
            ExecutionEventKind::VerificationFailed,
            "execution.verification-failed",
            why,
            None,
            Some(digest),
            approval,
        );
    }
    if recorded.is_err() || audited.is_err() {
        return Err(ExecutionError::OutcomeUnrecorded {
            outcome: outcome_text,
        });
    }
    Ok(run.outcome(
        "executed",
        json!({
            "state": state,
            "operation_digest": digest.to_string(),
            "decision": run.record.get("decision").cloned().unwrap_or(Value::Null),
            "approval_id": approval.map(|a| a.0),
            "grant_id": approval.map(|a| a.1),
            "plan": run.record.get("plan").cloned().unwrap_or(Value::Null),
            "result": result_json,
            "verification": verification,
            "stdout": stdout,
            "stderr": stderr,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_redaction() {
        let secrets = vec!["s3cr3t-value-123".to_owned()];
        let out = redact_output(
            b"token ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0000\nPASSWORD=hunter22\nleak s3cr3t-value-123\n\x1b[31mred\x00",
            &secrets,
        );
        assert!(!out.contains("FAKEfake"), "{out}");
        assert!(!out.contains("hunter22"), "{out}");
        assert!(!out.contains("s3cr3t-value-123"), "{out}");
        assert!(!out.contains('\u{1b}') && !out.contains('\0'));
        assert!(out.contains("red"));
    }
}
