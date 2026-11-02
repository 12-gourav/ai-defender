//! Findings: where a detector matched, never what it matched.
//!
//! A finding carries the location, the detector, the category, the severity and a redacted
//! preview. Its identifier is derived from the location and detector only, so neither the ID
//! nor any other field can be used to recover or confirm the secret (no hash of the value is
//! kept: a hash of a low-entropy password could be brute-forced).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::{SecretCategory, Severity};

/// A finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// `f_` and 16 hexadecimal characters.
    pub id: String,
    /// Detector identifier.
    pub detector: String,
    /// Category.
    pub category: SecretCategory,
    /// Severity.
    pub severity: Severity,
    /// Path relative to the scan root.
    pub path: String,
    /// 1-based line.
    pub line: u64,
    /// 1-based column (bytes).
    pub column: u64,
    /// The redacted value (`ghp_****REDACTED`), optionally after the assigned key name.
    pub preview: String,
}

/// The identifier of a finding at a location.
#[must_use]
pub fn finding_id(path: &str, line: u64, column: u64, detector: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"agentguard.finding.v1\0");
    for part in [path, &line.to_string(), &column.to_string(), detector] {
        h.update(part.as_bytes());
        h.update(b"\0");
    }
    let digest = h.finalize();
    format!("f_{}", hex::encode(digest.get(..8).unwrap_or(&[])))
}

/// Whether text is a well-formed finding ID.
#[must_use]
pub fn is_finding_id(text: &str) -> bool {
    text.strip_prefix("f_").is_some_and(|h| {
        h.len() == 16
            && h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    })
}
