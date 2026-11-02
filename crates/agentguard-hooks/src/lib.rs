//! AgentGuard integrations with official AI-agent hook systems: Claude Code and OpenAI Codex.
//!
//! The provider runs `agentguard-engine hook <provider> <event>` for each registered event.
//! The engine validates the native payload ([`input`]) and normalizes the tool call into
//! AgentGuard protocol actions. It then decides with the existing policy engine and approval
//! store ([`decide`]) and writes the provider's documented response ([`respond`]). Adapters
//! never decide; they only translate.
//!
//! - [`provider`]: providers, registered events, capabilities, documentation sources.
//! - [`input`]: payload validation and normalization (separate for each provider).
//! - [`apply_patch`]: Codex patch envelopes.
//! - [`decide`]: decisions, approvals and the retry protocol.
//! - [`respond`]: provider responses and failure behaviour.
//! - [`install`]: safe, idempotent installation into the providers' hook configuration.
//! - [`coverage`]: what is enforced, observed, unsupported or bypassable.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod apply_patch;
pub mod coverage;
pub mod decide;
pub mod input;
pub mod install;
pub mod provider;
pub mod respond;

pub use decide::{HookEnv, Verdict};
pub use provider::{Capability, Provider};
pub use respond::{run, HookResponse};
