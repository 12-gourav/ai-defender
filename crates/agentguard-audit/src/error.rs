//! Audit errors.

use std::path::PathBuf;

/// Failures while recording or verifying audit records.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuditError {
    /// The audit file could not be opened, created or written.
    #[error("audit file {}: {action}", path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// What was attempted.
        action: &'static str,
        /// The OS error.
        #[source]
        source: std::io::Error,
    },

    /// A record could not be serialised or deserialised.
    #[error("audit record serialisation failed")]
    Serialise(#[source] serde_json::Error),

    /// An existing record in the file is malformed.
    #[error("audit file {} has a malformed record at line {line}", path.display())]
    Malformed {
        /// The file.
        path: PathBuf,
        /// 1-based line number.
        line: usize,
    },

    /// The hash chain does not verify.
    #[error("audit chain broken at record {index}")]
    ChainBroken {
        /// 0-based index of the first bad record.
        index: usize,
    },

    /// The audit path exists but is not a regular file (for example a symlink).
    #[error("audit file {} is not a regular file", path.display())]
    NotARegularFile {
        /// The file.
        path: PathBuf,
    },

    /// An internal lock was poisoned by a panic elsewhere.
    #[error("audit sink is unavailable")]
    Unavailable,
}
