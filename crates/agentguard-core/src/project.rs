//! Project identity.
//!
//! A project is identified by its canonical root directory. The identifier is derived from the
//! root, so an identity whose identifier and root disagree cannot be constructed or
//! deserialised. Which roots are projects at all is decided by the engine's trusted registry,
//! never by a request.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::SecurityError;
use crate::ids::RepositoryId;
use crate::path::NormalizedPath;

/// Domain-separation prefix for project identifiers.
const PROJECT_ID_DOMAIN: &[u8] = b"agentguard.project-id.v1\0";

/// SHA-256 of a project's canonical root path, domain separated.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProjectId([u8; 32]);

impl ProjectId {
    /// Derive the identifier of the project rooted at `root`.
    #[must_use]
    pub fn derive(root: &NormalizedPath) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(PROJECT_ID_DOMAIN);
        hasher.update(root.as_str().as_bytes());
        Self(hasher.finalize().into())
    }

    /// Parse 64 hexadecimal characters.
    pub fn from_hex(value: &str) -> Result<Self, SecurityError> {
        let mut bytes = [0u8; 32];
        if value.len() != 64 || hex::decode_to_slice(value, &mut bytes).is_err() {
            return Err(SecurityError::InvalidIdentifier {
                field: "ProjectId",
                rule: "must be 64 hexadecimal characters",
            });
        }
        Ok(Self(bytes))
    }

    /// Lowercase hexadecimal form.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl TryFrom<String> for ProjectId {
    type Error = SecurityError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_hex(&value)
    }
}

impl From<ProjectId> for String {
    fn from(value: ProjectId) -> Self {
        value.to_hex()
    }
}

impl FromStr for ProjectId {
    type Err = SecurityError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl fmt::Debug for ProjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.to_hex();
        write!(f, "ProjectId({})", hex.get(..12).unwrap_or(&hex))
    }
}

impl fmt::Display for ProjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// A project: its canonical root, the identifier derived from it, and optionally the
/// repository it hosts.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "ProjectIdentityRepr")]
pub struct ProjectIdentity {
    id: ProjectId,
    root: NormalizedPath,
    repository: Option<RepositoryId>,
}

impl ProjectIdentity {
    /// Build an identity; the identifier is derived from `root`.
    #[must_use]
    pub fn new(root: NormalizedPath, repository: Option<RepositoryId>) -> Self {
        Self {
            id: ProjectId::derive(&root),
            root,
            repository,
        }
    }

    /// The identifier.
    #[must_use]
    pub const fn id(&self) -> &ProjectId {
        &self.id
    }

    /// The canonical root directory.
    #[must_use]
    pub const fn root(&self) -> &NormalizedPath {
        &self.root
    }

    /// The hosted repository, when known.
    #[must_use]
    pub const fn repository(&self) -> Option<&RepositoryId> {
        self.repository.as_ref()
    }

    /// Whether `path` is the root or lies beneath it.
    #[must_use]
    pub fn contains(&self, path: &NormalizedPath) -> bool {
        path.is_within(&self.root)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectIdentityRepr {
    id: ProjectId,
    root: NormalizedPath,
    repository: Option<RepositoryId>,
}

impl TryFrom<ProjectIdentityRepr> for ProjectIdentity {
    type Error = SecurityError;
    fn try_from(repr: ProjectIdentityRepr) -> Result<Self, Self::Error> {
        let identity = Self::new(repr.root, repr.repository);
        if identity.id == repr.id {
            Ok(identity)
        } else {
            Err(SecurityError::InvalidIdentifier {
                field: "ProjectIdentity",
                rule: "identifier does not match the root",
            })
        }
    }
}

// Unix paths throughout; the Windows path rules are tested in agentguard-core.
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn root(s: &str) -> NormalizedPath {
        NormalizedPath::new(s).unwrap()
    }

    #[test]
    fn id_is_deterministic_and_distinct() {
        assert_eq!(
            ProjectId::derive(&root("/p")),
            ProjectId::derive(&root("/p"))
        );
        assert_ne!(
            ProjectId::derive(&root("/p")),
            ProjectId::derive(&root("/q"))
        );
        let id = ProjectId::derive(&root("/p"));
        assert_eq!(ProjectId::from_hex(&id.to_hex()).unwrap(), id);
        assert!(ProjectId::from_hex("abc").is_err());
    }

    #[test]
    fn contains_and_accessors() {
        let p = ProjectIdentity::new(root("/work/app"), None);
        assert!(p.contains(&root("/work/app/src")));
        assert!(!p.contains(&root("/work/application")));
        assert_eq!(p.id(), &ProjectId::derive(&root("/work/app")));
        assert!(p.repository().is_none());
    }

    #[test]
    fn deserialise_rejects_mismatched_id() {
        let p = ProjectIdentity::new(root("/work/app"), None);
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<ProjectIdentity>(&json).unwrap(), p);
        let forged = json.replace("/work/app", "/work/other");
        assert!(serde_json::from_str::<ProjectIdentity>(&forged).is_err());
    }
}
