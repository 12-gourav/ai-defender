//! Managed execution records, kept in the trust store so an execution can be inspected later
//! and never repeated by accident.
//!
//! ```text
//! <trust root>/executions/        0700, inside the trust store, outside every project
//!   lock                          exclusive flock for reservations and pruning
//!   records/<execution-id>.json   one record per execution, 0600, replaced atomically
//!   keys/<sha256(key)>            one file per idempotency key; holds the execution ID
//! ```
//!
//! A request's idempotency key is reserved before anything runs ([`ExecutionStore::reserve`]),
//! with `O_CREAT|O_EXCL`, so a retried request with the same key is refused rather than run a
//! second time. Records are produced by the executor already redacted; this module stores them
//! as given and never interprets their content beyond the fields used for ordering.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;

use nix::fcntl::{Flock, FlockArg, OFlag};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::TrustError;
use crate::store::{atomic_replace, check_dir, read_object, TrustStore};

/// Records kept; older ones are pruned when a new execution is reserved.
pub const MAX_RECORDS: usize = 500;
/// Idempotency keys kept (they outlive their records, so a late retry is still refused).
pub const MAX_KEYS: usize = 5000;

/// Why an execution could not be reserved or recorded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecutionStoreError {
    /// The idempotency key was used before; nothing may run again under it.
    #[error("this execution request was already submitted (execution {0}); it is never run twice")]
    Duplicate(String),
    /// The identifier is malformed.
    #[error("malformed execution ID")]
    InvalidId,
    /// The store could not be used.
    #[error("{0}")]
    Trust(TrustError),
}

impl From<TrustError> for ExecutionStoreError {
    fn from(e: TrustError) -> Self {
        Self::Trust(e)
    }
}

/// Whether `id` is an execution ID: `ex_` and 24 lowercase hexadecimal characters.
#[must_use]
pub fn is_execution_id(id: &str) -> bool {
    id.strip_prefix("ex_").is_some_and(|hex| {
        hex.len() == 24
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// A new random execution ID.
pub fn new_execution_id() -> Result<String, TrustError> {
    let mut bytes = [0u8; 12];
    getrandom::fill(&mut bytes).map_err(|_| TrustError::Io {
        object: "execution ID",
        action: "generated",
    })?;
    Ok(format!("ex_{}", hex::encode(bytes)))
}

/// The execution records of one trust store.
#[derive(Debug, Clone)]
pub struct ExecutionStore {
    trust_root: PathBuf,
    root: PathBuf,
}

fn io(action: &'static str) -> TrustError {
    TrustError::Io {
        object: "execution records",
        action,
    }
}

impl ExecutionStore {
    /// The execution store inside `trust`.
    #[must_use]
    pub fn new(trust: &TrustStore) -> Self {
        Self {
            trust_root: trust.root().to_path_buf(),
            root: trust.root().join("executions"),
        }
    }

    fn records(&self) -> PathBuf {
        self.root.join("records")
    }

    fn keys(&self) -> PathBuf {
        self.root.join("keys")
    }

    fn prepare(&self) -> Result<(), TrustError> {
        check_dir(&self.trust_root, "trust store")?;
        for dir in [self.root.clone(), self.records(), self.keys()] {
            match DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
                Err(_) => return Err(io("created")),
            }
            check_dir(&dir, "execution records")?;
        }
        Ok(())
    }

    fn lock(&self) -> Result<Flock<File>, TrustError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(OFlag::O_NOFOLLOW.bits())
            .open(self.root.join("lock"))
            .map_err(|_| io("locked"))?;
        Flock::lock(file, FlockArg::LockExclusive).map_err(|_| io("locked"))
    }

    /// Reserve `key` for `execution_id`. Fails with [`ExecutionStoreError::Duplicate`] when the
    /// key was reserved before, whatever happened to that execution.
    pub fn reserve(&self, key: &str, execution_id: &str) -> Result<(), ExecutionStoreError> {
        if !is_execution_id(execution_id) {
            return Err(ExecutionStoreError::InvalidId);
        }
        self.prepare()?;
        let _lock = self.lock()?;
        let path = self
            .keys()
            .join(hex::encode(Sha256::digest(key.as_bytes())));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(OFlag::O_NOFOLLOW.bits())
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(execution_id.as_bytes())
                    .and_then(|()| file.sync_all())
                    .map_err(|_| io("written"))?;
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                let mut existing = String::new();
                let _ = OpenOptions::new()
                    .read(true)
                    .custom_flags(OFlag::O_NOFOLLOW.bits())
                    .open(&path)
                    .and_then(|f| f.take(64).read_to_string(&mut existing));
                let existing = existing.trim();
                return Err(ExecutionStoreError::Duplicate(
                    if is_execution_id(existing) {
                        existing.to_owned()
                    } else {
                        "unknown".to_owned()
                    },
                ));
            }
            Err(_) => return Err(io("reserved").into()),
        }
        prune(&self.records(), MAX_RECORDS);
        prune(&self.keys(), MAX_KEYS);
        Ok(())
    }

    /// Replace the record of `execution_id`.
    pub fn save(&self, execution_id: &str, record: &Value) -> Result<(), ExecutionStoreError> {
        if !is_execution_id(execution_id) {
            return Err(ExecutionStoreError::InvalidId);
        }
        self.prepare()?;
        let bytes = serde_json::to_vec_pretty(record).map_err(|_| TrustError::Canonicalisation)?;
        atomic_replace(
            &self.records().join(format!("{execution_id}.json")),
            &bytes,
            "execution record",
        )?;
        Ok(())
    }

    /// The record of `execution_id`, if it exists.
    pub fn load(&self, execution_id: &str) -> Result<Option<Value>, ExecutionStoreError> {
        if !is_execution_id(execution_id) {
            return Err(ExecutionStoreError::InvalidId);
        }
        match read_object::<Value>(
            &self.records().join(format!("{execution_id}.json")),
            "execution record",
        ) {
            Ok(v) => Ok(Some(v)),
            Err(TrustError::Unavailable { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// The record whose ID is `id` or starts with `id` (at least 7 characters including the
    /// `ex_` prefix). Ambiguous prefixes return `None`.
    pub fn find(&self, id: &str) -> Result<Option<Value>, ExecutionStoreError> {
        if is_execution_id(id) {
            return self.load(id);
        }
        let valid_prefix = id.len() >= 7
            && id.len() < 27
            && id.starts_with("ex_")
            && id
                .bytes()
                .skip(3)
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !valid_prefix {
            return Err(ExecutionStoreError::InvalidId);
        }
        let Ok(entries) = fs::read_dir(self.records()) else {
            return Ok(None);
        };
        let matches: Vec<String> = entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                name.strip_suffix(".json")
                    .filter(|stem| stem.starts_with(id) && is_execution_id(stem))
                    .map(str::to_owned)
            })
            .collect();
        match matches.as_slice() {
            [one] => self.load(one),
            _ => Ok(None),
        }
    }

    /// The newest `limit` records, newest first. Unreadable records are counted, not
    /// returned.
    pub fn list(&self, limit: usize) -> Result<(Vec<Value>, usize), ExecutionStoreError> {
        let Ok(entries) = fs::read_dir(self.records()) else {
            return Ok((Vec::new(), 0));
        };
        let mut files: Vec<(std::time::SystemTime, String)> = entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let stem = name.strip_suffix(".json")?.to_owned();
                let modified = e.metadata().ok()?.modified().ok()?;
                is_execution_id(&stem).then_some((modified, stem))
            })
            .collect();
        files.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        let mut unreadable = 0;
        let mut out = Vec::new();
        for (_, id) in files.into_iter().take(limit) {
            match self.load(&id) {
                Ok(Some(v)) => out.push(v),
                _ => unreadable += 1,
            }
        }
        Ok((out, unreadable))
    }
}

/// Remove the oldest regular files in `dir` beyond `keep`. Best effort.
fn prune(dir: &std::path::Path, keep: usize) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = entries
        .flatten()
        .filter_map(|e| {
            let meta = fs::symlink_metadata(e.path()).ok()?;
            (meta.is_file() && !e.file_name().to_string_lossy().starts_with('.'))
                .then(|| Some((meta.modified().ok()?, e.path())))
                .flatten()
        })
        .collect();
    if files.len() <= keep {
        return;
    }
    files.sort();
    let excess = files.len() - keep;
    for (_, path) in files.into_iter().take(excess) {
        let _ = fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AnchorConfig;

    fn store() -> (tempfile::TempDir, ExecutionStore) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("trust");
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        let trust = TrustStore::new(
            root,
            AnchorConfig {
                system_anchor: None,
                required_owner: 0,
            },
        );
        (dir, ExecutionStore::new(&trust))
    }

    #[test]
    fn ids() {
        let id = new_execution_id().unwrap();
        assert!(is_execution_id(&id), "{id}");
        for bad in [
            "",
            "ex_",
            "ex_../../etc/passwd",
            "EX_0123456789abcdef01234567",
            "ex_0123456789ABCDEF01234567",
        ] {
            assert!(!is_execution_id(bad), "{bad}");
        }
    }

    #[test]
    fn a_key_is_reserved_once() {
        let (_d, s) = store();
        let a = new_execution_id().unwrap();
        let b = new_execution_id().unwrap();
        s.reserve("key-1", &a).unwrap();
        assert_eq!(
            s.reserve("key-1", &b),
            Err(ExecutionStoreError::Duplicate(a.clone()))
        );
        s.reserve("key-2", &b).unwrap();
        s.save(
            &a,
            &serde_json::json!({"execution_id": a, "state": "completed"}),
        )
        .unwrap();
        assert_eq!(s.load(&a).unwrap().unwrap()["state"], "completed");
        assert_eq!(
            s.find(&a[..10]).unwrap().unwrap()["execution_id"],
            a.as_str()
        );
        assert!(s.load(&b).unwrap().is_none());
        assert_eq!(s.load("../x"), Err(ExecutionStoreError::InvalidId));
        assert_eq!(s.find("ex_../"), Err(ExecutionStoreError::InvalidId));
        let (records, unreadable) = s.list(10).unwrap();
        assert_eq!((records.len(), unreadable), (1, 0));
    }
}
