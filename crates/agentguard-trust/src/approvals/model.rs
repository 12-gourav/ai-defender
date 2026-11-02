//! Approval models.
//!
//! Every value that leaves the engine (listings, CLI output, audit) is built from these types
//! through [`ApprovalRecord::view`], which never includes claim-token verifiers or signatures.

use agentguard_core::{
    ActionCategory, AgentIdentity, ApprovalId, ApprovalStatus, BoundedText, GrantId, Name,
    NormalizedPath, OperationFingerprint, PolicyVersion, ProjectId, RequestId, RiskLevel, RuleId,
    SessionId,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use time::OffsetDateTime;

use crate::canonical::Signed;
use crate::crypto::KeyId;

use super::token::TokenVerifier;

/// Schema of a stored approval record.
pub const RECORD_SCHEMA: u32 = 1;

/// The engine-derived, redacted description a human reviews. Built from the verified,
/// normalized operation; never free text from the requester.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationSummary {
    /// Action category.
    pub category: ActionCategory,
    /// Operation within the category.
    pub operation: Name,
    /// Short label, for example `Git push`.
    pub label: BoundedText<128>,
    /// The target, redacted, for example `origin feature-a` or the command text.
    pub target: BoundedText<2048>,
    /// Whether `target` had to be shortened to fit (the human must then be told).
    pub target_truncated: bool,
    /// What the operation does, in one sentence.
    pub impact: BoundedText<256>,
    /// Why it needs approval (the deciding rule's reason).
    pub reason: BoundedText<512>,
    /// The integration's tool name, when supplied.
    pub tool: Option<Name>,
}

/// A request for a human decision on one exact operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequest {
    /// Public reference.
    pub approval_id: ApprovalId,
    /// The authorization request that required approval.
    pub request_id: RequestId,
    /// Digest of the canonical operation, computed by the engine.
    pub operation_digest: OperationFingerprint,
    /// Verified agent.
    pub agent: AgentIdentity,
    /// Verified project.
    pub project: ProjectId,
    /// The project's registered root.
    pub project_root: NormalizedPath,
    /// Session, where the integration has one.
    pub session: Option<SessionId>,
    /// What a human reviews.
    pub summary: OperationSummary,
    /// Risk level.
    pub risk: RiskLevel,
    /// The rule that required approval.
    pub rule: RuleId,
    /// Policy version the decision was made under.
    pub policy_version: PolicyVersion,
    /// When the request was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it expires if nobody decides.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

/// How an approver was authenticated. Extensible: stronger methods (a hardware key, a remote
/// approval service) are new variants, and each operation states which methods it accepts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ApproverAuthentication {
    /// Unlocked a trusted policy-signing key with its passphrase. Required to approve.
    SigningKeyPassphrase {
        /// The key that was unlocked and signed the decision.
        key_id: KeyId,
    },
    /// Confirmed at the CLI without a credential. Accepted only for decisions that remove
    /// authority (reject, cancel, revoke), never to approve.
    InteractiveConfirmation,
    /// The requester cancelled its own request with its claim token.
    RequesterClaim,
}

/// Who decided, and how that was established.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproverIdentity {
    /// Account name reported by the trusted channel (attribution; authority comes from
    /// `authentication`).
    pub account: Name,
    /// How the decision was authenticated.
    pub authentication: ApproverAuthentication,
}

/// What a human decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HumanDecision {
    /// Approve the exact operation once.
    Approve,
    /// Reject it.
    Reject,
    /// Withdraw the request before a decision.
    Cancel,
}

/// A human decision on one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalDecision {
    /// The request decided.
    pub approval_id: ApprovalId,
    /// The decision.
    pub decision: HumanDecision,
    /// Who decided.
    pub approver: ApproverIdentity,
    /// When.
    #[serde(with = "time::serde::rfc3339")]
    pub decided_at: OffsetDateTime,
    /// Optional reason given by the human (redacted, bounded).
    pub reason: Option<BoundedText<256>>,
    /// The grant issued, when approved.
    pub grant_id: Option<GrantId>,
}

/// A one-time authorization bound to one exact operation. Signed by the approver's policy key
/// ([`crate::Purpose::ApprovalGrant`]); every field is checked against the operation presented
/// at consumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationGrant {
    /// Public reference.
    pub grant_id: GrantId,
    /// The approved request.
    pub approval_id: ApprovalId,
    /// The authorization request it answers.
    pub request_id: RequestId,
    /// The bound operation.
    pub operation_digest: OperationFingerprint,
    /// The bound project.
    pub project: ProjectId,
    /// The bound agent (execution identity).
    pub agent: AgentIdentity,
    /// The bound session.
    pub session: Option<SessionId>,
    /// The bound policy version.
    pub policy_version: PolicyVersion,
    /// Verifiers of the claim tokens that may redeem this grant, fixed at approval.
    pub claims: Vec<TokenVerifier>,
    /// The human decision that issued it.
    pub decision: ApprovalDecision,
    /// Issue time.
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
    /// Expiry time.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

/// A grant's consumption status. Moves only away from `Active`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum GrantState {
    /// Unused and within its validity window (as of the last transition).
    Active,
    /// Used by exactly one operation.
    Consumed {
        /// When.
        #[serde(with = "time::serde::rfc3339")]
        at: OffsetDateTime,
        /// The authorization request that consumed it.
        request_id: RequestId,
    },
    /// Revoked before use.
    Revoked {
        /// When.
        #[serde(with = "time::serde::rfc3339")]
        at: OffsetDateTime,
        /// Why.
        reason_code: RuleId,
    },
    /// Aged out unused.
    Expired {
        /// When the expiry was recorded.
        #[serde(with = "time::serde::rfc3339")]
        at: OffsetDateTime,
    },
}

impl GrantState {
    /// Kebab-case name.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            GrantState::Active => "active",
            GrantState::Consumed { .. } => "consumed",
            GrantState::Revoked { .. } => "revoked",
            GrantState::Expired { .. } => "expired",
        }
    }
}

/// How a request reached a terminal status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Closure {
    /// When.
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    /// Stable reason code.
    pub reason_code: RuleId,
}

/// A stored approval: the request, its claim verifiers, its status, and the decision and
/// grant once made. One file per request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRecord {
    /// Always [`RECORD_SCHEMA`].
    pub schema: u32,
    /// The request.
    pub request: ApprovalRequest,
    /// Verifiers of the claim tokens handed to requesters.
    pub claims: Vec<TokenVerifier>,
    /// Lifecycle status.
    pub status: ApprovalStatus,
    /// A rejection, or the decision of a cancelled request. An approval lives inside the
    /// signed grant instead.
    pub decision: Option<ApprovalDecision>,
    /// The signed grant, once approved.
    pub grant: Option<Signed<AuthorizationGrant>>,
    /// The grant's consumption status.
    pub grant_state: Option<GrantState>,
    /// How the request closed, once terminal.
    pub closure: Option<Closure>,
    /// Last transition.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

fn rfc3339(t: OffsetDateTime) -> Value {
    t.format(&time::format_description::well_known::Rfc3339)
        .map_or(Value::Null, Value::String)
}

impl ApprovalRecord {
    /// The human decision, wherever it is stored.
    #[must_use]
    pub fn human_decision(&self) -> Option<&ApprovalDecision> {
        self.decision
            .as_ref()
            .or_else(|| self.grant.as_ref().map(|g| &g.body.decision))
    }

    /// A display view: no claim verifiers, no signatures, no token material. Safe for
    /// AI-readable listings, CLI output and JSON mode.
    #[must_use]
    pub fn view(&self, detailed: bool) -> Value {
        let r = &self.request;
        let decision = self.human_decision();
        let mut view = json!({
            "approval_id": r.approval_id,
            "status": self.status,
            "operation": {
                "category": r.summary.category,
                "operation": r.summary.operation,
                "label": r.summary.label,
                "target": r.summary.target,
                "target_truncated": r.summary.target_truncated,
                "impact": r.summary.impact,
            },
            "project": { "id": r.project, "root": r.project_root },
            "agent": { "kind": r.agent.kind.as_str(), "name": agent_name(&r.agent), "version": r.agent.version },
            "risk": r.risk,
            "created_at": rfc3339(r.created_at),
            "expires_at": rfc3339(r.expires_at),
            "grant": self.grant.as_ref().map(|g| json!({
                "grant_id": g.body.grant_id,
                "state": self.grant_state.as_ref().map(GrantState::as_str),
                "issued_at": rfc3339(g.body.issued_at),
                "expires_at": rfc3339(g.body.expires_at),
            })),
            "decided_by": decision.map(|d| d.approver.account.as_str()),
        });
        if detailed {
            if let Some(map) = view.as_object_mut() {
                map.insert("request_id".into(), json!(r.request_id));
                map.insert("operation_digest".into(), json!(r.operation_digest));
                map.insert("reason".into(), json!(r.summary.reason));
                map.insert("tool".into(), json!(r.summary.tool));
                map.insert("rule".into(), json!(r.rule));
                map.insert("policy_version".into(), json!(r.policy_version));
                map.insert("session".into(), json!(r.session));
                map.insert("scope".into(), json!("single-operation"));
                map.insert(
                    "decision".into(),
                    decision.map_or(Value::Null, |d| {
                        json!({
                            "decision": d.decision,
                            "by": d.approver.account,
                            "authentication": d.approver.authentication,
                            "at": rfc3339(d.decided_at),
                            "reason": d.reason,
                        })
                    }),
                );
                map.insert(
                    "closure".into(),
                    self.closure.as_ref().map_or(
                        Value::Null,
                        |c| json!({ "at": rfc3339(c.at), "reason_code": c.reason_code }),
                    ),
                );
            }
        }
        view
    }
}

/// Display name of an agent kind.
#[must_use]
pub const fn agent_name(agent: &AgentIdentity) -> &'static str {
    use agentguard_core::AgentKind;
    match agent.kind {
        AgentKind::ClaudeCode => "Claude Code",
        AgentKind::Codex => "Codex CLI",
        AgentKind::GeminiCli => "Gemini CLI",
        AgentKind::AntigravityCli => "Antigravity CLI",
        AgentKind::CursorAgent => "Cursor Agent",
        AgentKind::Generic => "Generic agent",
        _ => "Agent",
    }
}
