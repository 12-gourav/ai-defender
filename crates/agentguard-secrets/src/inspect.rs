//! Bounded content inspection for policy decisions: does this content contain secrets?
//!
//! Used by the engine on files an operation would read or move and on content an operation
//! would write. Returns evidence only (counts and severities), never values.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use nix::fcntl::OFlag;
use serde::Serialize;

use crate::detectors::DetectorSet;
use crate::model::Evidence;

/// Most bytes of a file inspected for a decision.
pub const MAX_INSPECT_BYTES: u64 = 1024 * 1024;

/// The outcome of inspecting some content.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Inspection {
    /// What was found.
    pub evidence: Evidence,
    /// Whether content was actually inspected (false: missing, unreadable, not a file).
    pub inspected: bool,
    /// Whether only a prefix was inspected (the file is larger than the limit).
    pub truncated: bool,
    /// Whether the content looked binary and was not inspected as text.
    pub binary: bool,
}

/// Whether a byte prefix looks binary (contains NUL).
#[must_use]
pub fn looks_binary(prefix: &[u8]) -> bool {
    prefix.iter().take(8192).any(|b| *b == 0)
}

/// Inspect text.
#[must_use]
pub fn inspect_text(text: &str, set: &DetectorSet) -> Inspection {
    let mut evidence = Evidence::default();
    let mut in_key = false;
    for line in text.lines() {
        if in_key {
            in_key = !(line.contains("-----END") && line.contains("PRIVATE KEY"));
            continue;
        }
        for m in set.detect_line(line) {
            if m.category == crate::model::SecretCategory::PrivateKey && !line.contains("-----END")
            {
                in_key = true;
            }
            evidence.add(&m);
        }
    }
    Inspection {
        evidence,
        inspected: true,
        truncated: false,
        binary: false,
    }
}

/// Open a regular file without following a final symlink and without blocking on a FIFO.
pub fn open_regular(path: &Path) -> std::io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
        .open(path)?;
    if file.metadata()?.file_type().is_file() {
        Ok(file)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ))
    }
}

/// Inspect the first [`MAX_INSPECT_BYTES`] of a file. A file that cannot be opened as a regular
/// file is reported as not inspected; callers treat that as uncertainty, not as clean.
#[must_use]
pub fn inspect_file(path: &Path, set: &DetectorSet) -> Inspection {
    let Ok(file) = open_regular(path) else {
        return Inspection::default();
    };
    let len = file.metadata().map_or(0, |m| m.len());
    let mut bytes = Vec::new();
    if file
        .take(MAX_INSPECT_BYTES)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return Inspection::default();
    }
    if looks_binary(&bytes) {
        return Inspection {
            inspected: true,
            binary: true,
            ..Inspection::default()
        };
    }
    let mut inspection = inspect_text(&String::from_utf8_lossy(&bytes), set);
    inspection.truncated = len > MAX_INSPECT_BYTES;
    inspection
}
