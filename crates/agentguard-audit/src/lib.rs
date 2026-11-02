//! Audit foundation for AgentGuard.
//!
//! An [`AuditEvent`] is a typed, redacted record of one security-relevant fact. Events are
//! appended to an [`AuditSink`] which wraps each one in a [`ChainedRecord`] carrying the hash of
//! its predecessor, so later tampering with a stored sequence is detectable with
//! [`chain::verify`]. Two sinks exist in Phase 1: in-memory, and an append-only JSON Lines file
//! created with mode `0600`. The SQLite sink is part of the security controller (Phase 3).
//!
//! Redaction happens when an event is constructed, before it reaches any sink; sinks never see
//! raw values. The engine's typed [`SecurityEvent`]s convert into audit events, so they share
//! the same redaction and chain. Opening a JSON Lines file verifies its chain first.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod chain;
pub mod error;
pub mod event;
pub mod security;
pub mod sink;

pub use chain::ChainedRecord;
pub use error::AuditError;
pub use event::{AuditDecision, AuditEvent, AuditEventKind};
pub use security::{
    ApprovalEventKind, ApprovalRecord, DecisionRecord, ExecutionEventKind, ExecutionOutcome,
    ExecutionRecord, HookEventKind, HookRecord, ScanEventKind, ScanRecord, SecurityEvent, StepKind,
    StepRecord, TamperKind, TrustEventKind, TrustRecord,
};
pub use sink::{AuditSink, JsonlSink, MemorySink};
