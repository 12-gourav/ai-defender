//! Human approval of `REQUIRE_APPROVAL` operations.
//!
//! ```text
//! engine evaluates ─ REQUIRE_APPROVAL ─ create ──> pending ── claim token to the requester
//!                                                    │
//!                     human reviews (approval ID) ───┼── reject ─> rejected
//!                                                    ├── cancel ─> cancelled
//!                                                    ├── timeout ─> expired
//!                                                    └── approve (policy-key passphrase)
//!                                                          │ signed one-time grant
//!                                                          v
//! requester presents the operation + claim token ── re-evaluate, recompute digest
//!                                                    └── consume (atomic) ─> consumed
//! ```
//!
//! - [`model`]: requests, decisions, approver identity, grants, stored records.
//! - [`token`]: claim tokens and their verifiers.
//! - [`store`]: the on-disk store and its exclusive transactions.
//! - [`lifecycle`]: every transition, its checks and its audit events.
//!
//! The approval ID is a public reference; it authorizes nothing. Redeeming a grant needs the
//! requester's claim token, a grant signed by a trusted policy key (only a human who knows the
//! passphrase can produce one), an unexpired and unconsumed state, the same project, agent and
//! policy version, and an operation whose recomputed digest equals the approved one.

pub mod error;
pub mod lifecycle;
pub mod model;
pub mod store;
pub mod token;

pub use error::ApprovalError;
pub use lifecycle::{
    Approval, Created, Listing, NewRequest, Redeemed, Redemption, Withdrawer, MAX_CLAIMS,
    MAX_OPEN_REQUESTS, RETENTION,
};
pub use model::{
    agent_name, ApprovalDecision, ApprovalRecord, ApprovalRequest, ApproverAuthentication,
    ApproverIdentity, AuthorizationGrant, GrantState, HumanDecision, OperationSummary,
};
pub use store::{ApprovalStore, Transaction};
pub use token::{ClaimToken, TokenError, TokenVerifier};
