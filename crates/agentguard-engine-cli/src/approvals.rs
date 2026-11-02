//! Approval commands: the bridge between the protocol, the policy engine and the approval
//! store (`agentguard_trust::approvals`).
//!
//! | command | who calls it | authority needed |
//! |---|---|---|
//! | `approval.request` | an integration, for an agent | engine launched with `--agent` |
//! | `approval.list`, `approval.show` | the CLI | none (no secrets in the output) |
//! | `approval.approve` | the CLI, interactively | confirmation + policy-key passphrase; refused when launched with `--agent` |
//! | `approval.reject`, `approval.cancel`, `authorization.revoke` | the CLI (cancel also the requester) | confirmation, or the requester's claim token; these only remove authority |
//! | `authorization.validate`, `authorization.consume` | an integration, for an agent | `--agent`, the claim token, and a live grant for the exact operation |
//!
//! Every redemption re-runs identity verification and policy evaluation and recomputes the
//! operation digest; an approval never turns `DENY` into anything else.

use std::sync::Arc;

use agentguard_audit::AuditSink;
use agentguard_core::redact::redact_text;
use agentguard_core::{
    Action, ApprovalId, BoundedText, Decision, Name, OperationFingerprint, SecurityContext,
};
use agentguard_engine::{
    binding_gap, evaluate, operation_digest, Evaluation, EvaluationContext, FsPathResolver,
    TrustedInvocation, TrustedStateGuard,
};
use agentguard_proto::{parse_request, AuthorizationRequest};
use agentguard_trust::approvals::{
    Approval, ApprovalError, ApprovalStore, ClaimToken, NewRequest, OperationSummary, Redemption,
    Withdrawer,
};
use agentguard_trust::keyfile::SigningRole;
use agentguard_trust::{load_runtime, TrustState, TrustedRuntime};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::protocol::{EngineError, ErrorCode};
use crate::support::{args, passphrase, require_confirmation, trust_error, unlock, verified};
use crate::Environment;

/// Map an approval failure to a protocol error. The reason code is appended so callers can
/// tell refusals apart without parsing prose.
fn approval_error(e: &ApprovalError) -> EngineError {
    let code = match e {
        ApprovalError::NotFound => ErrorCode::ApprovalNotFound,
        ApprovalError::Ambiguous => ErrorCode::InvalidRequest,
        ApprovalError::NotPending(_)
        | ApprovalError::Expired
        | ApprovalError::ReviewMismatch
        | ApprovalError::PolicyChanged
        | ApprovalError::ProjectNotTrusted
        | ApprovalError::TooManyOpen
        | ApprovalError::TooManyClaims => ErrorCode::ApprovalConflict,
        ApprovalError::NotApproved(_)
        | ApprovalError::Replay
        | ApprovalError::TokenMismatch
        | ApprovalError::OperationMismatch
        | ApprovalError::ProjectMismatch
        | ApprovalError::AgentMismatch
        | ApprovalError::GrantInvalid => ErrorCode::AuthorizationDenied,
        ApprovalError::UntrustedApprover | ApprovalError::SelfApproval => {
            ErrorCode::AuthorizationFailed
        }
        ApprovalError::Corrupt | ApprovalError::SchemaUnsupported => ErrorCode::IntegrityFailure,
        ApprovalError::AuditFailed => ErrorCode::AuditUnavailable,
        _ => ErrorCode::IoError,
    };
    EngineError::new(code, format!("{e} ({})", e.reason_code()))
}

fn denied(rule: &str, reason: &str) -> EngineError {
    EngineError::new(ErrorCode::AuthorizationDenied, format!("{reason} ({rule})"))
}

fn audit_log(env: &Environment) -> Result<Arc<dyn AuditSink>, EngineError> {
    env.store
        .open_audit_log()
        .map(|sink| Arc::new(sink) as Arc<dyn AuditSink>)
        .map_err(|e| trust_error(&e))
}

fn agent_invocation(env: &Environment) -> Result<&TrustedInvocation, EngineError> {
    env.invocation.as_ref().ok_or_else(|| {
        EngineError::new(
            ErrorCode::IdentityUnavailable,
            "this command acts for an agent and needs the engine to be launched by an agent integration (--agent)",
        )
    })
}

fn approval_id(raw: &str) -> Result<ApprovalId, EngineError> {
    raw.parse().map_err(|_| {
        EngineError::new(
            ErrorCode::InvalidRequest,
            "approval_id must be a full approval ID",
        )
    })
}

fn account(raw: &str) -> Result<Name, EngineError> {
    Name::new(raw).map_err(|_| {
        EngineError::new(
            ErrorCode::InvalidRequest,
            "requested_by must be a simple account name",
        )
    })
}

fn claim_token(raw: &str) -> Result<ClaimToken, EngineError> {
    ClaimToken::parse(raw)
        .map_err(|_| denied("approval.token-mismatch", "the claim token is malformed"))
}

fn now(env: &Environment) -> time::OffsetDateTime {
    env.clock.now()
}

/// The verified runtime for a working directory, or an integrity error. Never a lockdown
/// policy: approvals are refused outright when trusted state does not verify.
fn runtime(
    env: &Environment,
    directory: &agentguard_core::NormalizedPath,
    audit: &Arc<dyn AuditSink>,
) -> Result<TrustedRuntime, EngineError> {
    let runtime = load_runtime(&env.store, directory, audit);
    match &runtime.state {
        TrustState::Verified(_) => Ok(runtime),
        TrustState::Lockdown(e) => Err(trust_error(e)),
    }
}

/// An agent's request, parsed, verified and evaluated now.
struct Evaluated {
    request: AuthorizationRequest,
    security: SecurityContext,
    evaluation: Evaluation,
    runtime: TrustedRuntime,
}

fn evaluate_now(
    env: &Environment,
    raw: &Value,
    audit: &Arc<dyn AuditSink>,
) -> Result<Evaluated, EngineError> {
    let invocation = agent_invocation(env)?;
    let bytes = serde_json::to_vec(raw)
        .map_err(|_| EngineError::new(ErrorCode::InvalidRequest, "request is not JSON"))?;
    let request = parse_request(&bytes, &FsPathResolver).map_err(|r| {
        EngineError::new(
            ErrorCode::InvalidRequest,
            format!("invalid authorization request: {}", r.error),
        )
    })?;
    let runtime = runtime(env, &request.working_directory, audit)?;
    let guard = TrustedStateGuard::new(runtime.protected_roots.clone());
    let context = EvaluationContext::establish(
        &request,
        invocation,
        &*runtime.registry,
        &guard,
        &FsPathResolver,
        runtime.policy.version(),
    )
    .map_err(|e| denied(e.rule().as_str(), &e.to_string()))?;
    let evaluation = evaluate(&request, &context, &*runtime.policy)
        .map_err(|e| denied(e.rule().as_str(), &e.to_string()))?;
    let security = context.security().clone();
    Ok(Evaluated {
        request,
        security,
        evaluation,
        runtime,
    })
}

fn title(category: &str) -> String {
    let mut chars = category.chars();
    chars.next().map_or_else(String::new, |c| {
        c.to_uppercase()
            .chain(chars)
            .collect::<String>()
            .replace('-', " ")
    })
}

/// One plain sentence on what the operation does.
fn impact(action: &Action) -> &'static str {
    use agentguard_core::action::{FileOp, GitOp};
    match action {
        Action::Git(a) if a.op == GitOp::Push => {
            "This operation sends local commits to a remote repository."
        }
        Action::Git(a) if matches!(a.op, GitOp::Reset | GitOp::Rebase | GitOp::Clean) => {
            "This operation can rewrite or discard local Git history or files."
        }
        Action::Git(_) => "This operation changes the Git repository.",
        Action::Filesystem(a) if a.op == FileOp::Delete => {
            "This operation deletes a file or directory."
        }
        Action::Filesystem(_) => "This operation changes files in the project.",
        Action::Terminal(_) => "This operation runs a shell command with your permissions.",
        Action::Database(_) => "This operation changes a database.",
        Action::Terraform(_) => "This operation changes infrastructure.",
        Action::Cloud(_) => "This operation changes cloud resources.",
        Action::Secrets(_) => "This operation reads or changes a secret.",
        Action::Network(_) | Action::ExternalTransfer(_) => {
            "This operation sends data outside this machine."
        }
        Action::PackageManager(_) => "This operation installs or changes software packages.",
        Action::GitHub(_) => "This operation acts on GitHub with your credentials.",
        Action::Configuration(_) => "This operation changes configuration.",
        Action::CustomTool(_) | Action::Unknown(_) => "This operation runs an external tool.",
    }
}

const MAX_TARGET: usize = 2048;

fn summary(
    request: &AuthorizationRequest,
    evaluation: &Evaluation,
) -> Result<OperationSummary, EngineError> {
    let action = &request.action;
    let operation = Name::new(action.operation())
        .map_err(|_| EngineError::new(ErrorCode::InvalidRequest, "unnamed operation"))?;
    let target = redact_text(&action.resource());
    let target_truncated = target.chars().count() > MAX_TARGET;
    Ok(OperationSummary {
        category: action.category(),
        operation,
        label: BoundedText::lossy(&format!(
            "{} {}",
            title(action.category().as_str()),
            action.operation().replace('-', " ")
        )),
        target: BoundedText::lossy(&target),
        target_truncated,
        impact: BoundedText::lossy(impact(action)),
        reason: evaluation.reason.clone(),
        tool: request.context.tool.clone(),
    })
}

fn decision_json(evaluation: &Evaluation) -> Value {
    json!({
        "decision": evaluation.decision,
        "rule": evaluation.rule,
        "reason": evaluation.reason,
        "risk": evaluation.risk.level,
        "policy_version": evaluation.policy_version,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestArgs {
    request: Value,
}

/// `approval.request`: evaluate an agent's operation now; when it requires approval, create
/// (or join) a pending request and hand the requester its claim token.
pub fn request(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let a: RequestArgs = args(arguments)?;
    let audit = audit_log(env)?;
    let e = evaluate_now(env, &a.request, &audit)?;
    let mut out = decision_json(&e.evaluation);
    if e.evaluation.decision != Decision::RequireApproval {
        return Ok(json!({ "evaluation": out, "approval": null }));
    }
    if let Some(gap) = binding_gap(&e.request.action) {
        if let Some(map) = out.as_object_mut() {
            map.insert("decision".into(), json!(Decision::Deny));
            map.insert("rule".into(), json!(gap.rule()));
            map.insert("reason".into(), json!(gap.reason()));
        }
        return Ok(json!({ "evaluation": out, "approval": null }));
    }
    let digest = operation_digest(&e.security, &e.request)
        .map_err(|_| EngineError::new(ErrorCode::InternalError, "operation digest failed"))?;
    let trust = verified(&env.store)?;
    let timing = trust
        .global
        .policy
        .approval_timing()
        .map_err(|rule| EngineError::new(ErrorCode::IntegrityFailure, rule))?;
    let project = e.security.project();
    let created = ApprovalStore::new(&env.store)
        .create(
            NewRequest {
                request_id: e.request.request_id,
                operation_digest: digest,
                agent: e.security.agent().clone(),
                project: *project.id(),
                project_root: project.root().clone(),
                session: e.security.session().copied(),
                summary: summary(&e.request, &e.evaluation)?,
                risk: e.evaluation.risk.level,
                rule: e.evaluation.rule.clone(),
                policy_version: e.evaluation.policy_version,
            },
            timing,
            now(env),
            &*audit,
        )
        .map_err(|e| approval_error(&e))?;
    let mut approval = created.record.view(false);
    if let Some(map) = approval.as_object_mut() {
        map.insert("duplicate".into(), json!(created.duplicate));
        map.insert("claim_token".into(), json!(created.token.reveal().as_str()));
    }
    Ok(json!({ "evaluation": out, "approval": approval }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListArgs {
    #[serde(default)]
    include_closed: Option<bool>,
}

/// `approval.list`.
pub fn list(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let a: ListArgs = args(arguments)?;
    verified(&env.store)?;
    let audit = audit_log(env)?;
    let listing = ApprovalStore::new(&env.store)
        .list(now(env), &*audit)
        .map_err(|e| approval_error(&e))?;
    let include_closed = a.include_closed.unwrap_or(true);
    let approvals: Vec<Value> = listing
        .records
        .iter()
        .filter(|r| include_closed || !r.status.is_terminal())
        .map(|r| r.view(false))
        .collect();
    Ok(json!({
        "approvals": approvals,
        "unreadable": listing.unreadable,
        "now": now(env).format(&time::format_description::well_known::Rfc3339).ok(),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShowArgs {
    approval_id: String,
}

/// `approval.show`: full details by ID or unique prefix.
pub fn show(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let a: ShowArgs = args(arguments)?;
    verified(&env.store)?;
    let audit = audit_log(env)?;
    let record = ApprovalStore::new(&env.store)
        .show(&a.approval_id, now(env), &*audit)
        .map_err(|e| approval_error(&e))?;
    Ok(json!({
        "approval": record.view(true),
        "now": now(env).format(&time::format_description::well_known::Rfc3339).ok(),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveArgs {
    approval_id: String,
    operation_digest: String,
    requested_by: String,
    confirm: bool,
    #[serde(default)]
    passphrase: Option<String>,
}

/// The policy version in force for the request's project now, if it is still a trusted,
/// registered project.
fn current_policy(
    env: &Environment,
    record: &agentguard_trust::approvals::ApprovalRecord,
    audit: &Arc<dyn AuditSink>,
) -> Result<agentguard_core::PolicyVersion, EngineError> {
    let runtime = runtime(env, &record.request.project_root, audit)?;
    let still_trusted = runtime
        .registry
        .resolve(&record.request.project_root)
        .is_some_and(|p| *p.id() == record.request.project);
    if !still_trusted {
        return Err(approval_error(&ApprovalError::ProjectNotTrusted));
    }
    Ok(runtime.policy.version())
}

/// `approval.approve`: a human approves one exact pending operation. Needs explicit
/// confirmation and the policy-signing key passphrase (inline; a passphrase file is not
/// accepted for approvals). Refused outright when the engine was launched for an agent.
pub fn approve(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    if env.invocation.is_some() {
        return Err(approval_error(&ApprovalError::SelfApproval));
    }
    let a: ApproveArgs = args(arguments)?;
    let id = approval_id(&a.approval_id)?;
    let reviewed = OperationFingerprint::from_hex(&a.operation_digest).map_err(|_| {
        EngineError::new(
            ErrorCode::InvalidRequest,
            "operation_digest must be 64 hexadecimal characters",
        )
    })?;
    let who = account(&a.requested_by)?;
    require_confirmation(a.confirm, "approving an operation")?;
    let phrase = passphrase(a.passphrase, None)?;
    let trust = verified(&env.store)?;
    let signer = unlock(&env.store, SigningRole::Policy, &phrase, env.clock.now())?;
    let audit = audit_log(env)?;
    let store = ApprovalStore::new(&env.store);
    let record = store.peek(id).map_err(|e| approval_error(&e))?;
    let current = current_policy(env, &record, &audit)?;
    let timing = trust
        .global
        .policy
        .approval_timing()
        .map_err(|rule| EngineError::new(ErrorCode::IntegrityFailure, rule))?;
    let record = store
        .approve(
            &Approval {
                approval_id: id,
                reviewed_digest: reviewed,
                account: who,
                signer: &signer,
                trusted_signers: &trust.signers,
                current_policy: current,
            },
            timing,
            now(env),
            &*audit,
        )
        .map_err(|e| approval_error(&e))?;
    Ok(json!({ "approval": record.view(true) }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectArgs {
    approval_id: String,
    requested_by: String,
    confirm: bool,
    #[serde(default)]
    reason: Option<String>,
}

/// `approval.reject`.
pub fn reject(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let a: RejectArgs = args(arguments)?;
    let id = approval_id(&a.approval_id)?;
    let who = account(&a.requested_by)?;
    require_confirmation(a.confirm, "rejecting an approval request")?;
    verified(&env.store)?;
    let audit = audit_log(env)?;
    let record = ApprovalStore::new(&env.store)
        .reject(id, who, a.reason.as_deref(), now(env), &*audit)
        .map_err(|e| approval_error(&e))?;
    Ok(json!({ "approval": record.view(true) }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelArgs {
    approval_id: String,
    #[serde(default)]
    requested_by: Option<String>,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    claim_token: Option<String>,
}

/// `approval.cancel`: by a confirmed human, or by the requester with its claim token.
pub fn cancel(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let a: CancelArgs = args(arguments)?;
    let id = approval_id(&a.approval_id)?;
    verified(&env.store)?;
    let audit = audit_log(env)?;
    let store = ApprovalStore::new(&env.store);
    let record = match (a.claim_token, a.requested_by) {
        (Some(token), None) => {
            let token = claim_token(&token)?;
            store.cancel(id, &Withdrawer::Requester(&token), now(env), &*audit)
        }
        (None, Some(who)) => {
            require_confirmation(a.confirm, "cancelling an approval request")?;
            store.cancel(id, &Withdrawer::Human(account(&who)?), now(env), &*audit)
        }
        _ => {
            return Err(EngineError::new(
                ErrorCode::InvalidRequest,
                "give either claim_token (requester) or requested_by with confirm (human)",
            ))
        }
    }
    .map_err(|e| approval_error(&e))?;
    Ok(json!({ "approval": record.view(true) }))
}

/// `authorization.revoke`: revoke an approved, unused grant.
pub fn revoke(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let a: RejectArgs = args(arguments)?;
    let id = approval_id(&a.approval_id)?;
    let who = account(&a.requested_by)?;
    require_confirmation(a.confirm, "revoking an authorization")?;
    verified(&env.store)?;
    let audit = audit_log(env)?;
    let record = ApprovalStore::new(&env.store)
        .revoke(id, &who, now(env), &*audit)
        .map_err(|e| approval_error(&e))?;
    Ok(json!({ "approval": record.view(true) }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedeemArgs {
    request: Value,
    approval_id: String,
    claim_token: String,
}

/// `authorization.validate` (`consume == false`) and `authorization.consume`.
///
/// The order is fixed: identity and policy are re-evaluated first, so a now-denied operation
/// is denied whatever the approval says; then the store checks token, state, signature,
/// expiry, project, agent, policy version and digest, and (for consume) transitions the grant
/// in the same locked transaction.
pub fn redeem(env: &Environment, arguments: Value, consume: bool) -> Result<Value, EngineError> {
    let a: RedeemArgs = args(arguments)?;
    let id = approval_id(&a.approval_id)?;
    let token = claim_token(&a.claim_token)?;
    let audit = audit_log(env)?;
    let e = evaluate_now(env, &a.request, &audit)?;
    let store = ApprovalStore::new(&env.store);
    match e.evaluation.decision {
        Decision::Deny => {
            store
                .void_denied(id, &token, now(env), &*audit)
                .map_err(|e| approval_error(&e))?;
            return Err(denied(
                e.evaluation.rule.as_str(),
                e.evaluation.reason.as_str(),
            ));
        }
        Decision::Allow => {
            return Ok(json!({
                "authorized": true,
                "evaluation": decision_json(&e.evaluation),
                "grant": null,
                "consumed": false,
            }));
        }
        Decision::RequireApproval => {}
    }
    if let Some(gap) = binding_gap(&e.request.action) {
        return Err(denied(gap.rule(), gap.reason()));
    }
    let digest = operation_digest(&e.security, &e.request)
        .map_err(|_| EngineError::new(ErrorCode::InternalError, "operation digest failed"))?;
    let trust = verified(&env.store)?;
    let redemption = Redemption {
        approval_id: id,
        token: &token,
        request_id: e.request.request_id,
        operation_digest: digest,
        project: *e.security.project().id(),
        agent: e.security.agent().clone(),
        policy_version: e.runtime.policy.version(),
        trusted_signers: &trust.signers,
    };
    let redeemed = if consume {
        store.consume(&redemption, now(env), &*audit)
    } else {
        store.validate(&redemption, now(env), &*audit)
    }
    .map_err(|e| approval_error(&e))?;
    Ok(json!({
        "authorized": true,
        "evaluation": decision_json(&e.evaluation),
        "grant": { "approval_id": id, "grant_id": redeemed.grant_id },
        "consumed": consume,
    }))
}
