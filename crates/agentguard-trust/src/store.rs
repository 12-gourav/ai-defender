//! The trust store on disk.
//!
//! ```text
//! <trust root>/                      $XDG_CONFIG_HOME/agentguard (0700), outside every project
//!   keys/root.json                   root anchor (public key only)
//!   keys/keyset/<seq>.json           signed key sets
//!   trusted/global/<seq>.json        signed global policy manifests
//!   trusted/projects/<id>/<seq>.json signed project policy manifests
//!   registry/<seq>.json              signed project registries
//!   integrity/state.json             signed integrity state (the only mutable pointer)
//!   integrity/high-water.json        highest integrity sequence committed
//!   audit/trust.jsonl                hash-chained trust events
//! ```
//!
//! Versioned objects are written before the integrity state that points at them, and the
//! integrity state is replaced atomically, so an interrupted commit leaves the previous
//! consistent state in force. Nothing under a project directory is ever read as trust
//! material.

use std::collections::BTreeMap;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use agentguard_audit::JsonlSink;
use agentguard_common::paths::AppPaths;
use agentguard_core::{NormalizedPath, ProjectId};
use agentguard_platform::access::{self, Owner};
use agentguard_platform::fs::{OpenNoFollow, UnixMode};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::canonical::{Signed, VersionRef};
use crate::crypto::{PublicKey, Purpose};
use crate::error::TrustError;
use crate::integrity::{HighWaterMark, IntegrityBody};
use crate::keys::{verify_keyset, KeySetBody, RootAnchor};
use crate::manifest::{verify_manifest, ManifestBody, PolicyScope};
use crate::registry::RegistryBody;

/// Largest trusted file read.
pub const MAX_OBJECT_BYTES: u64 = 1024 * 1024;

const SUBDIRS: &[&str] = &[
    "keys",
    "keys/keyset",
    "trusted",
    "trusted/global",
    "trusted/projects",
    "registry",
    "integrity",
    "audit",
];

/// Who must own a system trust anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorOwner {
    /// The system: root on Unix; SYSTEM, Administrators or TrustedInstaller on Windows.
    System,
    /// The current user (tests).
    CurrentUser,
}

impl AnchorOwner {
    fn accepts(self, owner: Owner) -> bool {
        match self {
            Self::System => owner == Owner::System,
            Self::CurrentUser => owner == Owner::CurrentUser,
        }
    }
}

/// Where an administrator-provisioned root anchor may live, and who must own it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorConfig {
    /// Path of the system anchor. When the file exists, the user's root key must equal it.
    pub system_anchor: Option<PathBuf>,
    /// Required owner of the system anchor ([`AnchorOwner::System`] in production).
    pub required_owner: AnchorOwner,
}

impl Default for AnchorConfig {
    /// `/etc/agentguard/root.json`; on Windows `%ProgramData%\agentguard\root.json`.
    fn default() -> Self {
        #[cfg(unix)]
        let system_anchor = Some(PathBuf::from("/etc/agentguard/root.json"));
        #[cfg(windows)]
        let system_anchor = std::env::var_os("ProgramData")
            .filter(|p| !p.is_empty())
            .map(|p| PathBuf::from(p).join("agentguard").join("root.json"));
        Self {
            system_anchor,
            required_owner: AnchorOwner::System,
        }
    }
}

/// A trust store rooted at one directory.
#[derive(Debug, Clone)]
pub struct TrustStore {
    root: PathBuf,
    anchor: AnchorConfig,
}

/// Everything in the store, verified.
#[derive(Debug, Clone)]
pub struct VerifiedTrust {
    /// The root anchor.
    pub root: RootAnchor,
    /// The current key set.
    pub keyset: KeySetBody,
    /// Keys allowed to sign manifests, the registry and the integrity state (the key set's
    /// policy signers plus the root key).
    pub signers: Vec<PublicKey>,
    /// The integrity state.
    pub integrity: IntegrityBody,
    /// The global policy manifest.
    pub global: ManifestBody,
    /// The project registry.
    pub registry: RegistryBody,
    /// Approved project policies, by project.
    pub project_policies: BTreeMap<ProjectId, ManifestBody>,
}

/// A serialised object waiting to be committed.
pub(crate) struct PendingObject {
    path: PathBuf,
    bytes: Vec<u8>,
    object: &'static str,
}

impl PendingObject {
    pub(crate) fn new<T: Serialize>(
        path: PathBuf,
        value: &T,
        object: &'static str,
    ) -> Result<Self, TrustError> {
        Ok(Self {
            path,
            bytes: serde_json::to_vec_pretty(value).map_err(|_| TrustError::Canonicalisation)?,
            object,
        })
    }
}

fn seq_file(sequence: u64) -> String {
    format!("{sequence:020}.json")
}

impl TrustStore {
    /// A store rooted at `root`.
    #[must_use]
    pub const fn new(root: PathBuf, anchor: AnchorConfig) -> Self {
        Self { root, anchor }
    }

    /// The user's store: `$XDG_CONFIG_HOME/agentguard` with the default system anchor.
    #[must_use]
    pub fn for_paths(paths: &AppPaths) -> Self {
        Self::new(paths.config_dir.clone(), AnchorConfig::default())
    }

    /// The trust root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The trust root as a normalised path, for the engine's trusted-state guard.
    #[must_use]
    pub fn protected_root(&self) -> Option<NormalizedPath> {
        let path =
            agentguard_platform::fs::canonicalize(&self.root).unwrap_or_else(|_| self.root.clone());
        NormalizedPath::new(path.to_string_lossy().into_owned()).ok()
    }

    pub(crate) fn root_anchor_path(&self) -> PathBuf {
        self.root.join("keys/root.json")
    }

    pub(crate) fn keyset_path(&self, sequence: u64) -> PathBuf {
        self.root.join("keys/keyset").join(seq_file(sequence))
    }

    pub(crate) fn manifest_path(&self, scope: PolicyScope, sequence: u64) -> PathBuf {
        match scope {
            PolicyScope::Global => self.root.join("trusted/global").join(seq_file(sequence)),
            PolicyScope::Project(id) => self
                .root
                .join("trusted/projects")
                .join(id.to_hex())
                .join(seq_file(sequence)),
        }
    }

    pub(crate) fn registry_path(&self, sequence: u64) -> PathBuf {
        self.root.join("registry").join(seq_file(sequence))
    }

    pub(crate) fn integrity_path(&self) -> PathBuf {
        self.root.join("integrity/state.json")
    }

    pub(crate) fn high_water_path(&self) -> PathBuf {
        self.root.join("integrity/high-water.json")
    }

    /// Path of an encrypted signing key file (`signing/<role>.key`).
    #[must_use]
    pub fn signing_key_path(&self, role: crate::keyfile::SigningRole) -> PathBuf {
        self.root.join("signing").join(role.file_name())
    }

    /// Path of the trust audit log.
    #[must_use]
    pub fn audit_log_path(&self) -> PathBuf {
        self.root.join("audit/trust.jsonl")
    }

    /// Open the trust audit log (the store must be initialised).
    pub fn open_audit_log(&self) -> Result<JsonlSink, TrustError> {
        check_dir(&self.root.join("audit"), "trust store directory")?;
        JsonlSink::open(&self.audit_log_path()).map_err(|_| TrustError::Io {
            object: "trust audit log",
            action: "opened",
        })
    }

    /// Whether any trusted state exists (initialisation refuses to run if so).
    #[must_use]
    pub fn has_state(&self) -> bool {
        [self.root_anchor_path(), self.integrity_path()]
            .iter()
            .any(|p| fs::symlink_metadata(p).is_ok())
    }

    pub(crate) fn ensure_layout(&self) -> Result<(), TrustError> {
        let io = |_| TrustError::Io {
            object: "trust store directory",
            action: "created",
        };
        DirBuilder::new()
            .recursive(true)
            .unix_mode(0o700)
            .create(&self.root)
            .map_err(io)?;
        for sub in SUBDIRS {
            DirBuilder::new()
                .recursive(true)
                .unix_mode(0o700)
                .create(self.root.join(sub))
                .map_err(io)?;
        }
        self.check_layout()
    }

    fn check_layout(&self) -> Result<(), TrustError> {
        check_dir(&self.root, "trust store")?;
        for sub in SUBDIRS {
            check_dir(&self.root.join(sub), "trust store directory")?;
        }
        Ok(())
    }

    /// Commit new versioned objects, then the integrity state that points at them, then the
    /// high-water mark.
    pub(crate) fn commit(
        &self,
        objects: &[PendingObject],
        integrity: &Signed<IntegrityBody>,
    ) -> Result<(), TrustError> {
        for object in objects {
            if let Some(parent) = object.path.parent() {
                DirBuilder::new()
                    .recursive(true)
                    .unix_mode(0o700)
                    .create(parent)
                    .map_err(|_| TrustError::Io {
                        object: object.object,
                        action: "created",
                    })?;
            }
            atomic_replace(&object.path, &object.bytes, object.object)?;
        }
        let state = PendingObject::new(self.integrity_path(), integrity, "integrity state")?;
        atomic_replace(&state.path, &state.bytes, state.object)?;
        let mark = PendingObject::new(
            self.high_water_path(),
            &HighWaterMark::for_state(&integrity.body),
            "integrity high-water mark",
        )?;
        atomic_replace(&mark.path, &mark.bytes, mark.object)
    }

    fn check_system_anchor(&self, root: &RootAnchor) -> Result<(), TrustError> {
        let Some(path) = &self.anchor.system_anchor else {
            return Ok(());
        };
        let object = "system trust anchor";
        match fs::symlink_metadata(path) {
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(_) => {
                return Err(TrustError::Io {
                    object,
                    action: "read",
                })
            }
            Ok(_) => {}
        }
        let bytes = read_secure_file(path, object, self.anchor.required_owner)?;
        let system: RootAnchor =
            serde_json::from_slice(&bytes).map_err(|_| TrustError::Malformed { object })?;
        system.validate(object)?;
        if system.public_key != root.public_key {
            return Err(TrustError::KeyChange {
                rule: "the root key does not match the administrator-provisioned anchor",
            });
        }
        Ok(())
    }

    /// Check a root key against the system anchor before it is first provisioned.
    pub(crate) fn check_new_root(&self, root: &RootAnchor) -> Result<(), TrustError> {
        self.check_system_anchor(root)
    }

    /// Load and verify everything. Any failure fails the whole load: there is no partial or
    /// default trust state.
    pub fn load(&self) -> Result<VerifiedTrust, TrustError> {
        self.check_layout()?;
        let root: RootAnchor = read_object(&self.root_anchor_path(), "root anchor")?;
        root.validate("root anchor")?;
        self.check_system_anchor(&root)?;

        let integrity: Signed<IntegrityBody> =
            read_object(&self.integrity_path(), "integrity state")?;
        if integrity.body.root_key != root.public_key.key_id() {
            return Err(TrustError::KeyChange {
                rule: "the root key does not match the one the trust store was created with",
            });
        }
        let pins = integrity.body.clone();

        let keyset_signed: Signed<KeySetBody> =
            read_object(&self.keyset_path(pins.keyset.sequence), "key set")?;
        let mut signers = verify_keyset(&root, &keyset_signed)?;
        pins.keyset.check(
            "key set",
            &found(keyset_signed.body.sequence, &keyset_signed)?,
        )?;
        signers.push(root.public_key);

        let integrity = integrity
            .verify(Purpose::Integrity, &signers, "integrity state")?
            .clone();
        integrity.validate()?;
        let mark: HighWaterMark =
            read_object(&self.high_water_path(), "integrity high-water mark")?;
        mark.check(&integrity)?;

        let global_signed: Signed<ManifestBody> = read_object(
            &self.manifest_path(PolicyScope::Global, pins.global_policy.sequence),
            PolicyScope::Global.object(),
        )?;
        let global = verify_manifest(
            &global_signed,
            &signers,
            PolicyScope::Global,
            &pins.global_policy,
        )?
        .clone();

        let registry_signed: Signed<RegistryBody> = read_object(
            &self.registry_path(pins.registry.sequence),
            "project registry",
        )?;
        let registry = registry_signed
            .verify(Purpose::Registry, &signers, "project registry")?
            .clone();
        registry.validate()?;
        pins.registry.check(
            "project registry",
            &found(registry.sequence, &registry_signed)?,
        )?;

        let mut project_policies = BTreeMap::new();
        for project in &registry.projects {
            if let Some(pin) = &project.approved_policy {
                let scope = PolicyScope::Project(project.id);
                let signed: Signed<ManifestBody> =
                    read_object(&self.manifest_path(scope, pin.sequence), scope.object())?;
                let manifest = verify_manifest(&signed, &signers, scope, pin)?.clone();
                project_policies.insert(project.id, manifest);
            }
        }
        Ok(VerifiedTrust {
            root,
            keyset: keyset_signed.body,
            signers,
            integrity,
            global,
            registry,
            project_policies,
        })
    }
}

/// Read a trusted file: a regular file (never followed through a symlink), owned by the
/// current user, not writable by group or others, at most [`MAX_OBJECT_BYTES`].
pub(crate) fn read_object<T: DeserializeOwned>(
    path: &Path,
    object: &'static str,
) -> Result<T, TrustError> {
    let bytes = read_secure_file(path, object, AnchorOwner::CurrentUser)?;
    serde_json::from_slice(&bytes).map_err(|_| TrustError::Malformed { object })
}

/// Create a file that must not exist yet.
pub(crate) fn create_new_object<T: Serialize>(
    path: &Path,
    value: &T,
    object: &'static str,
) -> Result<(), TrustError> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| TrustError::Canonicalisation)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .unix_mode(0o600)
        .open_no_follow(path)
        .map_err(|e| {
            if e.kind() == ErrorKind::AlreadyExists {
                TrustError::AlreadyInitialized
            } else {
                TrustError::Io {
                    object,
                    action: "created",
                }
            }
        })?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| TrustError::Io {
            object,
            action: "written",
        })?;
    sync_parent(path);
    Ok(())
}

fn found<T: Serialize + DeserializeOwned>(
    sequence: u64,
    signed: &Signed<T>,
) -> Result<VersionRef, TrustError> {
    Ok(VersionRef {
        sequence,
        hash: signed.body_hash()?,
    })
}

/// A directory that is not a symlink, owned by the current user, that no other user can access.
pub(crate) fn check_dir(path: &Path, object: &'static str) -> Result<(), TrustError> {
    let meta = fs::symlink_metadata(path).map_err(|e| match e.kind() {
        ErrorKind::NotFound => TrustError::Unavailable { object },
        _ => TrustError::Io {
            object,
            action: "inspected",
        },
    })?;
    if !meta.file_type().is_dir() {
        return Err(TrustError::Insecure {
            object,
            rule: "must be a directory, not a symlink",
        });
    }
    let observed = access::of(path, &meta).map_err(|_| TrustError::Io {
        object,
        action: "inspected",
    })?;
    if observed.owner != Owner::CurrentUser {
        return Err(TrustError::Insecure {
            object,
            rule: "must be owned by the current user",
        });
    }
    if observed.others_have_access {
        return Err(TrustError::Insecure {
            object,
            rule: "must not be accessible to other users (Unix: chmod 700)",
        });
    }
    Ok(())
}

fn read_secure_file(
    path: &Path,
    object: &'static str,
    owner: AnchorOwner,
) -> Result<Vec<u8>, TrustError> {
    let meta = fs::symlink_metadata(path).map_err(|e| match e.kind() {
        ErrorKind::NotFound => TrustError::Unavailable { object },
        _ => TrustError::Io {
            object,
            action: "inspected",
        },
    })?;
    if !meta.file_type().is_file() {
        return Err(TrustError::Insecure {
            object,
            rule: "must be a regular file, not a symlink",
        });
    }
    let observed = access::of(path, &meta).map_err(|_| TrustError::Io {
        object,
        action: "inspected",
    })?;
    if !owner.accepts(observed.owner) {
        return Err(TrustError::Insecure {
            object,
            rule: "has an unexpected owner",
        });
    }
    if observed.others_can_write {
        return Err(TrustError::Insecure {
            object,
            rule: "must not be writable by other users",
        });
    }
    if meta.len() > MAX_OBJECT_BYTES {
        return Err(TrustError::Malformed { object });
    }
    let file = OpenOptions::new()
        .read(true)
        .open_no_follow(path)
        .map_err(|_| TrustError::Io {
            object,
            action: "read",
        })?;
    let mut bytes = Vec::new();
    file.take(MAX_OBJECT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| TrustError::Io {
            object,
            action: "read",
        })?;
    if bytes.len() as u64 > MAX_OBJECT_BYTES {
        return Err(TrustError::Malformed { object });
    }
    Ok(bytes)
}

pub(crate) fn atomic_replace(
    path: &Path,
    bytes: &[u8],
    object: &'static str,
) -> Result<(), TrustError> {
    let io = |action| TrustError::Io { object, action };
    let name = path
        .file_name()
        .ok_or_else(|| io("named"))?
        .to_string_lossy()
        .into_owned();
    let tmp = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .unix_mode(0o600)
        .open_no_follow(&tmp)
        .map_err(|_| io("created"))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| io("written"))?;
    drop(file);
    fs::rename(&tmp, path).map_err(|_| io("replaced"))?;
    sync_parent(path);
    Ok(())
}

fn sync_parent(path: &Path) {
    // Durability of the rename; a failure here cannot be meaningfully recovered and the data
    // itself is already synced.
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}
