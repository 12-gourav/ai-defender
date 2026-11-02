//! The AgentGuard authorization engine.
//!
//! Given a request in the canonical protocol, the engine decides `ALLOW`, `DENY` or
//! `REQUIRE_APPROVAL`, deterministically and fail-closed:
//!
//! - [`evaluate`](mod@evaluate): the evaluation API, `evaluate(request, context, policy)`, and the verified
//!   [`EvaluationContext`].
//! - [`identity`]: verifies the claimed agent against the trusted invocation and the claimed
//!   project against the trusted project registry.
//! - [`normalize`]: builds the [`SecurityAction`] (operation, executable, capabilities,
//!   resource, confidence), including side-effect-free terminal command analysis.
//! - [`resource`]: classifies what an action touches.
//! - [`rules`], [`pattern`]: rule matching, typed conditions, priority, bounded globs.
//! - [`profile`], [`layered`]: the mandatory baseline, the `balanced` profile and layered
//!   precedence.
//! - [`sensitive`], [`content`], [`disclosure`]: sensitive-resource categories and trusted
//!   configuration, bounded content inspection for secrets, and where data would go.
//! - [`classify`](mod@classify): rates risk (`LOW` to `CRITICAL`) independently of authorization.
//! - [`guard`]: hard rules no policy can override (unknown operations, trusted-state changes,
//!   agent-side approval attempts).
//! - [`policy`]: the [`PolicyEvaluator`] interface and the built-in rule-set policy.
//! - [`binding`]: the canonical operation and its digest, which every approval is bound to,
//!   and the operations the protocol cannot yet bind exactly.
//! - [`approval`]: in-process approval binding for the authorizer; single use, short-lived,
//!   humans only.
//! - [`authorize`]: the pipeline that composes all of the above and records every decision.
//! - [`resolve`]: resolves request paths against the real filesystem.
//!
//! No AI model, network service or background process takes part in a decision.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod approval;
pub mod authorize;
pub mod binding;
pub mod classify;
pub mod clock;
pub mod content;
pub mod disclosure;
pub mod evaluate;
pub mod guard;
pub mod identity;
pub mod layered;
pub mod normalize;
pub mod pattern;
pub mod policy;
pub mod profile;
pub mod resolve;
pub mod resource;
pub mod rules;
pub mod sensitive;

pub use approval::{ApprovalGrant, ApprovalStore, Approver, MemoryApprovalStore};
pub use authorize::{Authorizer, AuthorizerParts};
pub use binding::{
    binding_gap, operation_digest, operation_digest_with, BindingGap, CanonicalOperation,
    ExecutionBinding,
};
pub use classify::{assess, classify, ImpactScope, RiskAssessment, RiskFactor};
pub use clock::{Clock, ManualClock, SystemClock};
pub use disclosure::{Destination, DisclosureAssessment};
pub use evaluate::{evaluate, Evaluation, EvaluationContext, EvaluationError, HostInspection};
pub use guard::TrustedStateGuard;
pub use identity::{ProjectRegistry, StaticProjectRegistry, TrustedInvocation};
pub use layered::{LayeredPolicy, PolicyLayers};
pub use normalize::{
    analyze_command, Capability, CapabilitySet, CommandAnalysis, CommandClass, Confidence,
    SecurityAction,
};
pub use pattern::Pattern;
pub use policy::{
    ActionMatcher, Condition, PolicyEvaluator, PolicyIntegrity, PolicyOutcome, PolicyVerdict, Rule,
    RuleSetPolicy,
};
pub use profile::{mandatory_rules, ProfileName, ProfileSettings, SecurityProfile};
pub use resolve::FsPathResolver;
pub use resource::{ResourceClassification, ResourceKind, ResourceLocation};
pub use rules::{Conflict, ConflictKind, MatchEffect, PolicyLayer, RuleInput, RuleMatch};
pub use sensitive::{CustomDetectorSpec, SensitiveCategory, SensitiveConfig, Sensitivity};
