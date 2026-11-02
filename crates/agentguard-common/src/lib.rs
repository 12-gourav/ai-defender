//! Shared infrastructure for AgentGuard binaries and services.
//!
//! - [`error`]: the top-level error type, user-facing messages and process exit codes.
//! - [`logging`]: structured `tracing` output with redaction at the write boundary.
//! - [`config`]: discovery, size-limited loading, version dispatch and structural validation
//!   of `.agent-security.yml`.
//! - [`paths`]: XDG-based locations for controller-owned state, with permission checks.
//! - [`environment`]: helpers that describe the process environment without ever exposing values.
//!
//! Nothing in this crate executes a process, opens a network connection, or reads a
//! credential.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod config;
pub mod environment;
pub mod error;
pub mod logging;
pub mod paths;

pub use error::{AgentGuardError, ExitCode};
