//! Foundational domain types for AgentGuard.
//!
//! This crate holds the vocabulary every other AgentGuard crate speaks: typed identifiers,
//! permission levels, typed actions and their categories, operation and risk classifications,
//! the shape of a security decision, project identity and the verified security context,
//! approval scopes, timing and operation fingerprints, and redaction primitives. It performs no
//! I/O, makes no authorisation decisions, and depends on nothing that could reach the host.
//!
//! Every type that crosses a trust boundary is a validated newtype. Bare strings never
//! carry security meaning.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod action;
pub mod approval;
pub mod context;
pub mod decision;
pub mod envvars;
pub mod error;
pub mod ids;
pub mod operation;
pub mod path;
pub mod permission;
pub mod project;
pub mod redact;
pub mod risk;
pub mod text;

pub use action::{Action, ActionCategory, ConfigScope, Environment, Host, Name};
pub use approval::{
    ApprovalDecisionKind, ApprovalScope, ApprovalStatus, ApprovalTiming, OperationFingerprint,
};
pub use context::SecurityContext;
pub use decision::{Alternative, Decision, DecisionOutcome, RuleId, SecurityDecision};
pub use error::SecurityError;
pub use ids::{
    AgentIdentity, AgentKind, AgentVersion, ApprovalId, GitProvider, GrantId, PolicyVersion,
    RepoSegment, RepositoryId, RequestId, SessionId, TaskId,
};
pub use operation::OperationType;
pub use path::{NormalizedPath, PathResolver};
pub use permission::PermissionLevel;
pub use project::{ProjectId, ProjectIdentity};
pub use redact::Sensitive;
pub use risk::RiskLevel;
pub use text::BoundedText;
