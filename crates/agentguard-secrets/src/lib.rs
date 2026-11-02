//! Secret detection for AgentGuard.
//!
//! - [`detectors`]: the [`Detector`] interface, built-in provider and structural patterns,
//!   credential assignments, high-entropy strings and custom patterns from trusted
//!   configuration.
//! - [`redact`](mod@redact): redaction that keeps at most a public provider prefix (`ghp_****REDACTED`).
//! - [`inspect`]: bounded inspection of content for policy decisions (evidence only).
//! - [`scan`](mod@scan): bounded local scanning of a tree or a file list, reporting every exclusion and
//!   skip.
//! - [`finding`]: findings that record where, never what; IDs derived from the location.
//! - [`git_index`]: staged changes read from `.git/index` without running Git.
//! - [`access`]: secret-safe access: describe configuration (keys, set or empty) without values.
//!
//! The crate performs no network access and runs no processes. Pattern detection cannot find
//! every secret: it finds common shapes and reports some false positives. It is one input to
//! the engine's policy decisions, not a guarantee against disclosure.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod access;
pub mod detectors;
pub mod finding;
pub mod git_index;
pub mod inspect;
pub mod model;
pub mod redact;
pub mod scan;

pub use detectors::{CustomDetector, Detector, DetectorSet, BUILTIN, PROVIDERS};
pub use finding::{finding_id, is_finding_id, Finding};
pub use inspect::{inspect_file, inspect_text, Inspection};
pub use model::{Evidence, Match, SecretCategory, Severity};
pub use redact::{redact, redact_with, MASK};
pub use scan::{scan, scan_files, ScanError, ScanOptions, ScanReport, SkipReason};
