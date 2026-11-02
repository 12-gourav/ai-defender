//! Root of trust for AgentGuard policy.
//!
//! Trusted state lives in a private directory outside every project (see [`store`]). Each piece
//! is signed and pinned:
//!
//! - [`keys`]: the root anchor (optionally administrator-provisioned) and the root-signed set
//!   of policy-signing keys.
//! - [`manifest`]: signed, versioned, hash-chained policy manifests (global and per project).
//! - [`registry`]: the signed project registry, bound to each root's directory identity.
//! - [`integrity`]: one signed state pinning every current object, plus a rollback mark.
//! - [`hierarchy`]: mandatory baseline > global > project > request, merged deterministically;
//!   projects can only add restrictions.
//! - [`update`]: the only way to change trusted state: human-requested, key-authorised,
//!   validated, versioned and audited.
//! - [`runtime`]: verified policy and registry for the engine, or a deny-all lockdown.
//! - [`approvals`]: pending approval requests, signed one-time grants, claim tokens and atomic
//!   consumption.
//! - [`scans`]: the last secret-scan result per root (findings without values).
//! - [`crypto`], [`canonical`]: Ed25519 signatures and canonical serialisation.
//!
//! A local tool cannot protect itself from a process with the same user's full privileges or
//! from an administrator; see `docs/TRUST_MODEL.md`.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod approvals;
pub mod canonical;
pub mod crypto;
pub mod error;
pub mod executions;
pub mod hierarchy;
pub mod integrity;
pub mod keyfile;
pub mod keys;
pub mod manifest;
pub mod project_file;
pub mod registry;
pub mod runtime;
pub mod scans;
pub mod store;
pub mod update;

pub use canonical::{ContentHash, Signed, VersionRef};
pub use crypto::{Ed25519Signer, KeyId, PublicKey, Purpose, Signer};
pub use error::TrustError;
pub use hierarchy::{mandatory_rules, EffectivePolicy, Layer, Provenance};
pub use manifest::{ExecutionSettings, PolicyDocument, PolicyScope};
pub use registry::{ProjectRegistration, TrustStatus, VerifiedRegistry};
pub use runtime::{load_runtime, LockdownPolicy, TrustState, TrustedRuntime};
pub use store::{AnchorConfig, AnchorOwner, TrustStore, VerifiedTrust};
pub use update::{
    initialize, quarantine, register_project, revoke_project, rotate_keyset, update_policy,
    PolicyUpdateRequest, UpdateReceipt,
};
