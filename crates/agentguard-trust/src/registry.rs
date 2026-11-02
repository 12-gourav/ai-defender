//! The trusted project registry.
//!
//! A registration binds a project identifier to its canonical root, the directory's device and
//! inode at registration time, a trust status and the approved policy version. The registry is
//! signed; an entry an agent adds or edits fails verification.
//!
//! At decision time a registration matches only if the root still is the same directory: not a
//! symlink, still canonical, same device and inode. Deleting a registered project and creating
//! a look-alike at the same path, or swapping the root for a symlink, no longer matches.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;

use agentguard_audit::{AuditSink, SecurityEvent, TrustEventKind, TrustRecord};
use agentguard_core::{NormalizedPath, ProjectId, ProjectIdentity, RepositoryId};
use agentguard_engine::ProjectRegistry;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::canonical::{ContentHash, VersionRef};
use crate::error::TrustError;

/// Schema identifier of the registry.
pub const REGISTRY_SCHEMA: &str = "agentguard.registry.v1";

/// Whether a registered project is trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustStatus {
    /// Requests from the project are evaluated.
    Trusted,
    /// Trust was withdrawn; requests from the project are treated as unregistered.
    Revoked,
}

/// Device and inode of a directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryIdentity {
    /// `st_dev`.
    pub device: u64,
    /// `st_ino`.
    pub inode: u64,
}

impl DirectoryIdentity {
    /// Observe `root` now. It must be a real directory (not a symlink) whose canonical path is
    /// itself.
    pub fn observe(root: &NormalizedPath) -> Result<Self, TrustError> {
        let object = "project root";
        let meta =
            fs::symlink_metadata(root.as_path()).map_err(|_| TrustError::Unavailable { object })?;
        if !meta.file_type().is_dir() {
            return Err(TrustError::Insecure {
                object,
                rule: "must be a directory, not a symlink",
            });
        }
        let canonical = fs::canonicalize(root.as_path()).map_err(|_| TrustError::Io {
            object,
            action: "resolved",
        })?;
        if canonical.as_path() != root.as_path() {
            return Err(TrustError::Insecure {
                object,
                rule: "path is not canonical",
            });
        }
        Ok(Self {
            device: meta.dev(),
            inode: meta.ino(),
        })
    }
}

/// One registered project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectRegistration {
    /// Identifier, derived from `root`.
    pub id: ProjectId,
    /// Canonical root.
    pub root: NormalizedPath,
    /// Trust status.
    pub status: TrustStatus,
    /// The approved project policy, if any.
    pub approved_policy: Option<VersionRef>,
    /// Hosted repository, when known.
    pub repository: Option<RepositoryId>,
    /// The root directory's identity at registration.
    pub directory: DirectoryIdentity,
    /// When it was registered (or last re-trusted).
    #[serde(with = "time::serde::rfc3339")]
    pub registered_at: OffsetDateTime,
}

/// The signed registry body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryBody {
    /// Always [`REGISTRY_SCHEMA`].
    pub schema: String,
    /// Monotonic version, starting at 1.
    pub sequence: u64,
    /// Body hash of the previous version.
    pub previous: Option<ContentHash>,
    /// Registrations, sorted by identifier.
    pub projects: Vec<ProjectRegistration>,
    /// When this version was issued.
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
}

impl RegistryBody {
    /// Structural rules: schema, sequence, identifiers derived from roots, unique, sorted.
    pub fn validate(&self) -> Result<(), TrustError> {
        let object = "project registry";
        if self.schema != REGISTRY_SCHEMA {
            return Err(TrustError::Malformed { object });
        }
        if self.sequence == 0 {
            return Err(TrustError::Inconsistent {
                object,
                rule: "sequence starts at 1",
            });
        }
        if self
            .projects
            .iter()
            .any(|p| p.id != ProjectId::derive(&p.root))
        {
            return Err(TrustError::Inconsistent {
                object,
                rule: "a project identifier does not match its root",
            });
        }
        if self.projects.windows(2).any(|w| match w {
            [a, b] => a.id >= b.id,
            _ => false,
        }) {
            return Err(TrustError::Inconsistent {
                object,
                rule: "registrations must be unique and sorted",
            });
        }
        Ok(())
    }

    /// The registration for `id`.
    #[must_use]
    pub fn get(&self, id: &ProjectId) -> Option<&ProjectRegistration> {
        self.projects.iter().find(|p| &p.id == id)
    }
}

/// Validate and canonicalise a directory proposed for registration.
pub fn canonical_project_root(
    path: &Path,
    trust_root: &Path,
) -> Result<NormalizedPath, TrustError> {
    let reject = |rule| TrustError::ProjectRejected { rule };
    let canonical = fs::canonicalize(path).map_err(|_| reject("directory does not exist"))?;
    if !canonical.is_dir() {
        return Err(reject("not a directory"));
    }
    if canonical.parent().is_none() {
        return Err(reject("the filesystem root cannot be a project"));
    }
    let trust = fs::canonicalize(trust_root).unwrap_or_else(|_| trust_root.to_path_buf());
    if canonical.starts_with(&trust) || trust.starts_with(&canonical) {
        return Err(reject(
            "a project must not contain, or lie inside, the trust store",
        ));
    }
    let text = canonical
        .into_os_string()
        .into_string()
        .map_err(|_| reject("path is not valid UTF-8"))?;
    NormalizedPath::new(text).map_err(|_| reject("path is not a valid normalised path"))
}

/// A verified registry, used by the engine to resolve projects.
pub struct VerifiedRegistry {
    projects: Vec<ProjectRegistration>,
    audit: Option<Arc<dyn AuditSink>>,
}

impl VerifiedRegistry {
    /// Wrap the projects of a verified registry. Mismatches are recorded to `audit`.
    #[must_use]
    pub fn new(registry: &RegistryBody, audit: Option<Arc<dyn AuditSink>>) -> Self {
        Self {
            projects: registry.projects.clone(),
            audit,
        }
    }

    fn mismatch(&self, project: &ProjectRegistration, error: &TrustError) {
        if let Some(audit) = &self.audit {
            let event = SecurityEvent::Trust(Box::new(TrustRecord {
                kind: TrustEventKind::ProjectIdentityMismatch,
                subject: format!("project {}", project.root),
                detail: error.to_string(),
                old_version: None,
                new_version: None,
                actor: None,
                project: Some(project.id),
            }));
            let _ = audit.record(event.into_audit_event());
        }
    }
}

impl ProjectRegistry for VerifiedRegistry {
    /// The deepest registration containing the directory. A revoked or no-longer-matching
    /// registration yields `None` rather than falling back to an enclosing project, so trust
    /// is never inherited from a parent.
    fn resolve(&self, working_directory: &NormalizedPath) -> Option<ProjectIdentity> {
        let project = self
            .projects
            .iter()
            .filter(|p| working_directory.is_within(&p.root))
            .max_by_key(|p| p.root.as_path().components().count())?;
        if project.status != TrustStatus::Trusted {
            return None;
        }
        match DirectoryIdentity::observe(&project.root) {
            Ok(observed) if observed == project.directory => Some(ProjectIdentity::new(
                project.root.clone(),
                project.repository.clone(),
            )),
            Ok(_) => {
                self.mismatch(
                    project,
                    &TrustError::Inconsistent {
                        object: "project root",
                        rule: "directory was replaced since registration",
                    },
                );
                None
            }
            Err(e) => {
                self.mismatch(project, &e);
                None
            }
        }
    }
}
