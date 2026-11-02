//! Running one hook invocation and producing the provider's response.
//!
//! Response formats (provider documentation, 2026-10-31):
//!
//! | provider, event | block | no decision |
//! |---|---|---|
//! | Claude Code `PreToolUse` | exit 0, `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":…}}` | exit 0, no output |
//! | Codex `PreToolUse` | the same shape (Codex documents `allow` and `deny`; `ask` is unsupported) | exit 0, no output |
//! | `PostToolUse` (both), `PostToolUseFailure` (Claude Code) | cannot block; audit only | exit 0, no output |
//! | `SessionStart` (both) | cannot block | exit 0, `hookSpecificOutput.additionalContext` |
//!
//! On a pre-execution event every failure (invalid payload, unverified policy, unavailable
//! audit or approval store, internal error) is an explicit `deny`. If even that cannot be
//! serialized, the hook exits 2 with the reason on standard error, which both providers treat
//! as a block on `PreToolUse`. AgentGuard never answers `allow`.

use std::sync::Arc;

use agentguard_audit::{AuditSink, HookEventKind};
use agentguard_core::redact::redact_text;
use agentguard_core::Decision;
use serde_json::{json, Value};

use crate::decide::{decide, short, HookEnv, Recorder, Verdict};
use crate::input::{parse, HookInput};
use crate::provider::{Capability, Provider};

/// What the hook process writes and how it exits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookResponse {
    /// Standard output (one JSON object), if any.
    pub stdout: Option<String>,
    /// Standard error, if any.
    pub stderr: Option<String>,
    /// Exit status.
    pub exit_code: u8,
    /// The verdict, for diagnostics and tests.
    pub verdict: Option<Verdict>,
}

/// Exit status both providers treat as a block on `PreToolUse`.
pub const BLOCK_EXIT: u8 = 2;

const SESSION_CONTEXT: &str = "AI Defender governs this session's tool calls in projects registered with AI Defender. A call may be blocked by policy, or blocked pending human approval. When a call is blocked for approval, tell the user the approval command from the message (`ai-defender approve <id>`); the user must run it in their own terminal, never through you. After it is approved, retry exactly the same call: any change needs a new approval. Do not try to work around a block.";

fn deny_json(provider: Provider, reason: &str) -> Value {
    // Same documented shape for both providers.
    let _ = provider;
    json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    })
}

fn block(provider: Provider, reason: &str, verdict: Option<Verdict>) -> HookResponse {
    let reason = redact_text(reason);
    match serde_json::to_string(&deny_json(provider, &reason)) {
        Ok(s) => HookResponse {
            stdout: Some(s),
            stderr: None,
            exit_code: 0,
            verdict,
        },
        Err(_) => HookResponse {
            stdout: None,
            stderr: Some(reason),
            exit_code: BLOCK_EXIT,
            verdict,
        },
    }
}

fn nothing(verdict: Option<Verdict>) -> HookResponse {
    HookResponse {
        stdout: None,
        stderr: None,
        exit_code: 0,
        verdict,
    }
}

/// The message an agent receives for a verdict.
#[must_use]
pub fn message(verdict: &Verdict) -> Option<String> {
    match verdict {
        Verdict::Deny { rule, reason } => Some(format!(
            "AI Defender blocked this operation: {reason} ({rule})."
        )),
        Verdict::ApprovalRequired {
            approvals,
            rule,
            reason,
        } => {
            let commands: Vec<String> = approvals
                .iter()
                .map(|id| format!("`ai-defender approve {}`", short(id)))
                .collect();
            Some(format!(
                "AI Defender requires human approval for this exact operation ({reason}; {rule}). Ask the user to run {} in their own terminal; do not run it yourself. After approval, retry exactly the same call; any change needs a new approval.",
                if commands.is_empty() { "`ai-defender approvals`".to_owned() } else { commands.join(" and ") }
            ))
        }
        _ => None,
    }
}

/// Handle one invocation of `agentguard-engine hook <provider> <event>`.
pub fn run(
    env: &HookEnv<'_>,
    provider: &str,
    event: &str,
    payload: &[u8],
    audit: Option<Arc<dyn AuditSink>>,
) -> HookResponse {
    let Some(provider) = Provider::parse(provider) else {
        return HookResponse {
            stdout: None,
            stderr: Some("AI Defender: unknown hook provider; the operation is blocked".to_owned()),
            exit_code: BLOCK_EXIT,
            verdict: None,
        };
    };
    let Some(spec) = provider.event(event) else {
        // An unregistered event: blocking events are blocked, informational ones see a
        // non-blocking error.
        return HookResponse {
            stdout: None,
            stderr: Some(format!(
                "AI Defender does not support the {event} hook event; reinstall the integration"
            )),
            exit_code: BLOCK_EXIT,
            verdict: None,
        };
    };
    let enforcing = spec.capability == Capability::PreExecutionEnforcement;
    let input = match parse(provider, payload, spec) {
        Ok(i) => i,
        Err(e) => {
            if let Some(a) = &audit {
                let placeholder = HookInput {
                    provider,
                    event: spec,
                    session_id: None,
                    cwd: String::new(),
                    tool_name: None,
                    tool_input: None,
                    subagent: false,
                };
                let _ = Recorder::new(Arc::clone(a), &placeholder).record(
                    HookEventKind::PayloadRejected,
                    e.code,
                    &e.message,
                    enforcing.then_some(Decision::Deny),
                    None,
                    None,
                );
            }
            return if enforcing {
                block(provider, &format!("AI Defender could not validate the hook payload: {e}. The operation is blocked."), None)
            } else {
                nothing(None)
            };
        }
    };
    let Some(audit) = audit else {
        return if enforcing {
            block(provider, "AI Defender's audit log is unavailable, so the operation is blocked (hook.audit-unavailable). Run `ai-defender check`.", None)
        } else {
            nothing(None)
        };
    };
    let mut rec = Recorder::new(Arc::clone(&audit), &input);
    let invoked = rec.record(HookEventKind::Invoked, "hook.invoked", "", None, None, None);
    match spec.capability {
        Capability::PreExecutionEnforcement => {
            if invoked.is_err() {
                return block(provider, "AI Defender's audit log could not be written, so the operation is blocked (hook.audit-unavailable).", None);
            }
            let verdict = match decide(env, &input, &mut rec) {
                Ok(v) => v,
                Err(e) => {
                    let _ = rec.record(
                        HookEventKind::Failed,
                        e.code,
                        &e.message,
                        Some(Decision::Deny),
                        None,
                        None,
                    );
                    return block(
                        provider,
                        &format!(
                            "AI Defender could not evaluate this operation ({e}); it is blocked."
                        ),
                        None,
                    );
                }
            };
            let response = match message(&verdict) {
                Some(m) => block(provider, &m, Some(verdict.clone())),
                None => nothing(Some(verdict.clone())),
            };
            let decision = match &verdict {
                Verdict::Deny { .. } => Some(Decision::Deny),
                Verdict::ApprovalRequired { .. } => Some(Decision::RequireApproval),
                Verdict::Allow | Verdict::Authorized { .. } => Some(Decision::Allow),
                Verdict::NotGoverned => None,
            };
            let code = match &verdict {
                Verdict::NotGoverned => "hook.not-governed",
                Verdict::Authorized { .. } => "hook.grant-redeemed",
                _ => "hook.response",
            };
            if rec
                .record(
                    HookEventKind::ResponseGenerated,
                    code,
                    "",
                    decision,
                    None,
                    None,
                )
                .is_err()
                && decision == Some(Decision::Allow)
            {
                return block(provider, "AI Defender's audit log could not be written, so the operation is blocked (hook.audit-unavailable).", None);
            }
            response
        }
        Capability::PostExecutionAudit => {
            let _ = rec.record(
                HookEventKind::Observed,
                "hook.observed",
                input.event.name,
                None,
                None,
                None,
            );
            nothing(None)
        }
        Capability::Informational => {
            let context = json!({
                "hookSpecificOutput": { "hookEventName": spec.name, "additionalContext": SESSION_CONTEXT }
            });
            HookResponse {
                stdout: serde_json::to_string(&context).ok(),
                stderr: None,
                exit_code: 0,
                verdict: None,
            }
        }
    }
}
