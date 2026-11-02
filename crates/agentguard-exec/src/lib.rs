//! Managed execution for AgentGuard.
//!
//! [`execute`] runs one command through the full pipeline: validation, verified identity,
//! classification, repository inspection, policy, approval, revalidation, controlled
//! execution, verification and audit. See [`executor`] for the order and its guarantees.
//!
//! - [`request`]: the request shape and its validation.
//! - [`validation`]: executable resolution through a trusted search path, and identity.
//! - [`environment`]: environment profiles; credentials and code-injection variables are
//!   never inherited.
//! - [`shell`]: the supported shell subset and its canonical rendering.
//! - [`git`]: the Git adapter (parsing, inspection, binding facts, scans, verification).
//! - [`command`]: terminal operation categories for display and audit.
//! - [`plan`]: what would run, what policy evaluates, and what an approval binds.
//! - [`executor`]: authorization and the controlled run.
//!
//! Managed execution controls only what is routed through it. It does not intercept commands
//! an agent runs through its own tools; every outcome says so ([`executor::enforcement`]).

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod command;
pub mod environment;
pub mod error;
pub mod executor;
pub mod git;
pub mod plan;
pub mod probe;
mod process;
pub mod request;
pub mod shell;
pub mod validation;

pub use command::TerminalCategory;
pub use error::{ApprovalFailure, ExecutionError};
pub use executor::{enforcement, execute, ExecEnv, Permit};
pub use process::{harden_current_process, Signals};
pub use request::ExecutionRequest;
