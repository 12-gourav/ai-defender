//! The approval store on disk.
//!
//! ```text
//! <trust root>/approvals/             0700, inside the trust store, outside every project
//!   schema.json                       {"schema": 1}; a newer schema is refused, never guessed
//!   lock                              exclusive flock held for exactly one transition
//!   requests/<approval-id>.json       one record per request, 0600, replaced atomically
//! ```
//!
//! Every read-check-write runs inside a [`Transaction`], which holds an exclusive `flock` on
//! `lock`. The lock serialises transitions across processes and threads (each transaction
//! opens its own file description), so validation and consumption of a grant are one atomic
//! step: two consumers cannot both observe an active grant. Transactions are short; no
//! transaction is held while a human is reading or typing.

use agentguard_platform::fs::{OpenNoFollow, UnixMode};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::ErrorKind;
use std::path::PathBuf;

use agentguard_core::ApprovalId;
use serde::{Deserialize, Serialize};

use crate::error::TrustError;
use crate::store::{atomic_replace, check_dir, create_new_object, read_object, TrustStore};

use super::error::ApprovalError;
use super::model::{ApprovalRecord, RECORD_SCHEMA};

/// Schema of the store layout.
pub const STORE_SCHEMA: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaFile {
    schema: u32,
}

/// The approval store of one trust store.
#[derive(Debug, Clone)]
pub struct ApprovalStore {
    trust_root: PathBuf,
    root: PathBuf,
}

fn unavailable(action: &'static str) -> impl Fn(TrustError) -> ApprovalError {
    move |_| ApprovalError::Unavailable(action)
}

impl ApprovalStore {
    /// The approval store inside `trust`.
    #[must_use]
    pub fn new(trust: &TrustStore) -> Self {
        Self {
            trust_root: trust.root().to_path_buf(),
            root: trust.root().join("approvals"),
        }
    }

    /// The store directory.
    #[must_use]
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    fn requests_dir(&self) -> PathBuf {
        self.root.join("requests")
    }

    fn record_path(&self, id: ApprovalId) -> PathBuf {
        self.requests_dir().join(format!("{id}.json"))
    }

    /// Create the layout on first use, then check ownership and permissions, then the
    /// schema (migrating older layouts; refusing newer ones).
    fn prepare(&self) -> Result<(), ApprovalError> {
        check_dir(&self.trust_root, "trust store").map_err(unavailable("opened"))?;
        for dir in [&self.root, &self.requests_dir()] {
            match DirBuilder::new().unix_mode(0o700).create(dir) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
                Err(_) => return Err(ApprovalError::Unavailable("created")),
            }
            check_dir(dir, "approval store").map_err(unavailable("opened"))?;
        }
        let schema_path = self.root.join("schema.json");
        match create_new_object(
            &schema_path,
            &SchemaFile {
                schema: STORE_SCHEMA,
            },
            "approval store schema",
        ) {
            Ok(()) | Err(TrustError::AlreadyInitialized) => {}
            Err(_) => return Err(ApprovalError::Unavailable("created")),
        }
        let found: SchemaFile = read_object(&schema_path, "approval store schema")
            .map_err(|_| ApprovalError::Corrupt)?;
        migrate(found.schema)
    }

    /// Begin a transaction: prepare the store and take its exclusive lock.
    pub fn transaction(&self) -> Result<Transaction<'_>, ApprovalError> {
        self.prepare()?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .unix_mode(0o600)
            .open_no_follow(self.root.join("lock"))
            .map_err(|_| ApprovalError::Unavailable("locked"))?;
        file.lock()
            .map_err(|_| ApprovalError::Unavailable("locked"))?;
        Ok(Transaction {
            store: self,
            _lock: file,
        })
    }
}

/// Bring an older layout to [`STORE_SCHEMA`]. There is one schema so far; a future version
/// adds its migration step here and rewrites `schema.json` last, so an interrupted migration
/// is retried rather than half-applied.
fn migrate(found: u32) -> Result<(), ApprovalError> {
    if found == STORE_SCHEMA {
        Ok(())
    } else {
        Err(ApprovalError::SchemaUnsupported)
    }
}

/// An exclusive transaction over the store. Dropping it releases the lock.
pub struct Transaction<'a> {
    store: &'a ApprovalStore,
    /// Holds the exclusive lock until the transaction is dropped.
    _lock: File,
}

impl Transaction<'_> {
    /// Load one record.
    pub fn load(&self, id: ApprovalId) -> Result<ApprovalRecord, ApprovalError> {
        let path = self.store.record_path(id);
        let record: ApprovalRecord =
            read_object(&path, "approval record").map_err(|e| match e {
                TrustError::Unavailable { .. } => ApprovalError::NotFound,
                TrustError::Malformed { .. } => ApprovalError::Corrupt,
                _ => ApprovalError::Unavailable("read"),
            })?;
        if record.schema != RECORD_SCHEMA || record.request.approval_id != id {
            return Err(ApprovalError::Corrupt);
        }
        Ok(record)
    }

    /// Write one record atomically.
    pub fn save(&self, record: &ApprovalRecord) -> Result<(), ApprovalError> {
        let bytes =
            serde_json::to_vec_pretty(record).map_err(|_| ApprovalError::Unavailable("written"))?;
        atomic_replace(
            &self.store.record_path(record.request.approval_id),
            &bytes,
            "approval record",
        )
        .map_err(unavailable("written"))
    }

    /// Delete one record (retention pruning).
    pub fn remove(&self, id: ApprovalId) -> Result<(), ApprovalError> {
        match fs::remove_file(self.store.record_path(id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(_) => Err(ApprovalError::Unavailable("written")),
        }
    }

    /// Every stored request ID.
    pub fn ids(&self) -> Result<Vec<ApprovalId>, ApprovalError> {
        let entries = fs::read_dir(self.store.requests_dir())
            .map_err(|_| ApprovalError::Unavailable("read"))?;
        let mut ids = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| ApprovalError::Unavailable("read"))?;
            let name = entry.file_name();
            let Some(stem) = name.to_str().and_then(|n| n.strip_suffix(".json")) else {
                continue;
            };
            if let Ok(id) = stem.parse::<ApprovalId>() {
                ids.push(id);
            }
        }
        ids.sort();
        Ok(ids)
    }

    /// Every record that loads; malformed ones are counted, never returned.
    pub fn all(&self) -> Result<(Vec<ApprovalRecord>, usize), ApprovalError> {
        let mut records = Vec::new();
        let mut unreadable = 0;
        for id in self.ids()? {
            match self.load(id) {
                Ok(r) => records.push(r),
                Err(ApprovalError::NotFound) => {}
                Err(_) => unreadable += 1,
            }
        }
        Ok((records, unreadable))
    }

    /// Resolve a full ID or a unique prefix of at least 8 characters.
    pub fn resolve(&self, reference: &str) -> Result<ApprovalId, ApprovalError> {
        if let Ok(id) = reference.parse::<ApprovalId>() {
            return Ok(id);
        }
        let reference = reference.to_ascii_lowercase();
        if reference.len() < 8 || !reference.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
            return Err(ApprovalError::NotFound);
        }
        let mut matches = self
            .ids()?
            .into_iter()
            .filter(|id| id.to_string().starts_with(&reference));
        match (matches.next(), matches.next()) {
            (Some(id), None) => Ok(id),
            (Some(_), Some(_)) => Err(ApprovalError::Ambiguous),
            (None, _) => Err(ApprovalError::NotFound),
        }
    }
}
