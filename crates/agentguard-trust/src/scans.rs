//! The last secret-scan result per scanned root, kept in the trust store (`scans/`, 0700;
//! files 0600) so `agentguard secrets explain` can describe a finding later.
//!
//! Records hold findings as produced by `agentguard_secrets` (location, detector, severity,
//! redacted preview) and scan statistics. They never hold a matched value or any hash of one.

use std::fs::DirBuilder;
use std::io::ErrorKind;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::TrustError;
use crate::store::{atomic_replace, check_dir, read_object, TrustStore};

fn scans_dir(store: &TrustStore) -> PathBuf {
    store.root().join("scans")
}

/// Path of the record for a scanned root.
#[must_use]
pub fn scan_record_path(store: &TrustStore, root: &Path) -> PathBuf {
    let digest = Sha256::digest(root.to_string_lossy().as_bytes());
    scans_dir(store).join(format!(
        "{}.json",
        hex::encode(digest.get(..16).unwrap_or(&[]))
    ))
}

/// Replace the record for `root`. The trust store must exist.
pub fn save_scan_record(store: &TrustStore, root: &Path, record: &Value) -> Result<(), TrustError> {
    check_dir(store.root(), "trust store")?;
    let dir = scans_dir(store);
    match DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        Err(_) => {
            return Err(TrustError::Io {
                object: "scan records",
                action: "created",
            })
        }
    }
    check_dir(&dir, "scan records")?;
    let bytes = serde_json::to_vec_pretty(record).map_err(|_| TrustError::Canonicalisation)?;
    atomic_replace(&scan_record_path(store, root), &bytes, "scan record")
}

/// The record for `root`, if one exists.
pub fn load_scan_record(store: &TrustStore, root: &Path) -> Result<Option<Value>, TrustError> {
    match read_object::<Value>(&scan_record_path(store, root), "scan record") {
        Ok(v) => Ok(Some(v)),
        Err(TrustError::Unavailable { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}
