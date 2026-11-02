//! Helpers shared by the command handlers.

use std::fs;
use std::io::{ErrorKind, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use agentguard_core::{Name, NormalizedPath, PathResolver};
use agentguard_engine::approval::Approver;
use agentguard_engine::FsPathResolver;
use agentguard_trust::keyfile::{read_key_file, KeyFileError, Passphrase, SigningRole};
use agentguard_trust::registry::{DirectoryIdentity, RegistryBody};
use agentguard_trust::{Ed25519Signer, ProjectRegistration, TrustError, TrustStore, VerifiedTrust};
use serde::de::DeserializeOwned;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::protocol::{EngineError, ErrorCode};

/// Deserialize command arguments (each argument struct denies unknown fields).
pub fn args<T: DeserializeOwned>(value: Value) -> Result<T, EngineError> {
    serde_json::from_value(value).map_err(|e| {
        EngineError::new(
            ErrorCode::InvalidRequest,
            format!("invalid arguments ({:?})", e.classify()),
        )
    })
}

/// Resolve a working directory: absolute, canonical (symlinks followed), an existing directory.
pub fn working_directory(raw: &str) -> Result<NormalizedPath, EngineError> {
    let path = FsPathResolver.resolve(None, raw).map_err(|_| {
        EngineError::new(
            ErrorCode::InvalidRequest,
            "working_directory must be an absolute, resolvable path",
        )
    })?;
    if !path.as_path().is_dir() {
        return Err(EngineError::new(
            ErrorCode::InvalidRequest,
            "working_directory is not a directory",
        ));
    }
    Ok(path)
}

const ROOT_MARKERS: &[(&str, &str)] = &[
    ("Cargo.toml", "rust"),
    ("package.json", "node"),
    ("pyproject.toml", "python"),
    ("setup.py", "python"),
    ("requirements.txt", "python"),
    ("go.mod", "go"),
    ("pom.xml", "java"),
    ("build.gradle", "java"),
    ("build.gradle.kts", "java"),
    ("Gemfile", "ruby"),
    ("composer.json", "php"),
    ("mix.exs", "elixir"),
    ("Package.swift", "swift"),
    ("deno.json", "deno"),
];

/// The project kind suggested by marker files in `root`, if any.
#[must_use]
pub fn detect_kind(root: &NormalizedPath) -> Option<&'static str> {
    ROOT_MARKERS
        .iter()
        .find(|(file, _)| root.as_path().join(file).is_file())
        .map(|(_, kind)| *kind)
}

fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// The candidate project root for an unregistered directory: the nearest ancestor holding
/// `.git`; otherwise the nearest holding a project marker or `.agentguard`; otherwise the
/// directory itself. Purely a suggestion: registration canonicalises and validates it.
#[must_use]
pub fn detect_root(cwd: &NormalizedPath) -> NormalizedPath {
    let ancestors = || cwd.as_path().ancestors();
    let found = ancestors()
        .find(|dir| exists(&dir.join(".git")))
        .or_else(|| {
            ancestors().find(|dir| {
                exists(&dir.join(".agentguard"))
                    || ROOT_MARKERS
                        .iter()
                        .any(|(file, _)| dir.join(file).is_file())
            })
        });
    found
        .and_then(|p| p.to_str())
        .and_then(|p| NormalizedPath::new(p).ok())
        .unwrap_or_else(|| cwd.clone())
}

/// The deepest registration containing `cwd`.
#[must_use]
pub fn registered_for<'a>(
    cwd: &NormalizedPath,
    registry: &'a RegistryBody,
) -> Option<&'a ProjectRegistration> {
    registry
        .projects
        .iter()
        .filter(|p| cwd.is_within(&p.root))
        .max_by_key(|p| p.root.as_path().components().count())
}

/// Whether a registration's directory is still the registered one.
#[must_use]
pub fn directory_matches(registration: &ProjectRegistration) -> bool {
    DirectoryIdentity::observe(&registration.root).is_ok_and(|d| registration.directory.matches(&d))
}

/// The trust store's state.
pub enum TrustView {
    /// Verified.
    Verified(Box<VerifiedTrust>),
    /// No trusted state exists.
    Uninitialized,
    /// Trusted state exists but failed verification.
    Failed(TrustError),
}

/// Load the trust store.
#[must_use]
pub fn load_trust(store: &TrustStore) -> TrustView {
    if !store.has_state() {
        return TrustView::Uninitialized;
    }
    match store.load() {
        Ok(trust) => TrustView::Verified(Box::new(trust)),
        Err(e) => TrustView::Failed(e),
    }
}

/// Map a trust failure to a protocol error.
#[must_use]
pub fn trust_error(e: &TrustError) -> EngineError {
    let code = match e {
        TrustError::SelfApproval | TrustError::UnauthorizedSigner => ErrorCode::AuthorizationFailed,
        TrustError::PolicyRejected { .. } => ErrorCode::InvalidConfiguration,
        TrustError::ProjectRejected { .. } => ErrorCode::UnsupportedProjectRoot,
        TrustError::AlreadyInitialized => ErrorCode::IoError,
        _ => ErrorCode::IntegrityFailure,
    };
    let err = EngineError::new(code, e.to_string());
    if code == ErrorCode::IntegrityFailure {
        err.recovery("inspect the trust audit log, restore the trust store from a backup, or quarantine it and re-initialise (docs/TRUST_MODEL.md section 6)")
    } else {
        err
    }
}

/// Require a verified trust store.
pub fn verified(store: &TrustStore) -> Result<Box<VerifiedTrust>, EngineError> {
    match load_trust(store) {
        TrustView::Verified(t) => Ok(t),
        TrustView::Uninitialized => Err(EngineError::new(
            ErrorCode::TrustNotInitialized,
            "no AI Defender trust store exists on this machine",
        )
        .recovery("run `ai-defender init` in a project to create it")),
        TrustView::Failed(e) => Err(trust_error(&e)),
    }
}

const MAX_PASSPHRASE_FILE: u64 = 4096;

fn read_passphrase_file(raw: &str) -> Result<Passphrase, EngineError> {
    let denied = |msg: &str| EngineError::new(ErrorCode::AuthorizationFailed, msg.to_owned());
    let path = Path::new(raw);
    if !path.is_absolute() {
        return Err(denied("the passphrase file path must be absolute"));
    }
    let meta = fs::symlink_metadata(path).map_err(|e| match e.kind() {
        ErrorKind::NotFound => denied("the passphrase file does not exist"),
        _ => denied("the passphrase file cannot be inspected"),
    })?;
    if !meta.file_type().is_file() {
        return Err(denied(
            "the passphrase file must be a regular file, not a symlink",
        ));
    }
    if meta.uid() != nix::unistd::Uid::current().as_raw() || meta.permissions().mode() & 0o077 != 0
    {
        return Err(denied(
            "the passphrase file must be owned by you and private (chmod 600)",
        ));
    }
    if meta.len() > MAX_PASSPHRASE_FILE {
        return Err(denied("the passphrase file is too large"));
    }
    let mut text = Zeroizing::new(String::new());
    fs::File::open(path)
        .and_then(|f| f.take(MAX_PASSPHRASE_FILE).read_to_string(&mut text))
        .map_err(|_| denied("the passphrase file cannot be read"))?;
    Passphrase::new(text.trim_end_matches(['\n', '\r']).to_owned())
        .map_err(|e| denied(&e.to_string()))
}

/// The passphrase from exactly one of the two sources.
pub fn passphrase(inline: Option<String>, file: Option<String>) -> Result<Passphrase, EngineError> {
    match (inline, file) {
        (Some(_), Some(_)) => Err(EngineError::new(
            ErrorCode::InvalidRequest,
            "give either passphrase or passphrase_file, not both",
        )),
        (Some(p), None) => Passphrase::new(p)
            .map_err(|e| EngineError::new(ErrorCode::AuthorizationFailed, e.to_string())),
        (None, Some(f)) => read_passphrase_file(&f),
        (None, None) => Err(EngineError::new(
            ErrorCode::AuthorizationRequired,
            "this operation changes trusted state and needs the signing key passphrase",
        )
        .recovery("run the command in an interactive terminal, or pass --passphrase-file with a private file")),
    }
}

/// Unlock a signing key from the store.
pub fn unlock(
    store: &TrustStore,
    role: SigningRole,
    passphrase: &Passphrase,
) -> Result<Ed25519Signer, EngineError> {
    let file = read_key_file(&store.signing_key_path(role)).map_err(|e| match e {
        KeyFileError::Missing => EngineError::new(
            ErrorCode::AuthorizationFailed,
            "the signing key file is missing from the trust store",
        )
        .recovery("restore it from your backup; without it trusted state cannot be changed"),
        other => EngineError::new(ErrorCode::AuthorizationFailed, other.to_string()),
    })?;
    file.open(role, passphrase)
        .map_err(|e| EngineError::new(ErrorCode::AuthorizationFailed, e.to_string()))
}

/// The human requester named by the CLI (attribution; authorisation is the signing key).
pub fn requester(name: &str) -> Result<Approver, EngineError> {
    Name::new(name)
        .map(|name| Approver::Human { name })
        .map_err(|_| {
            EngineError::new(
                ErrorCode::InvalidRequest,
                "requested_by must be a simple account name",
            )
        })
}

/// Require an explicit confirmation.
pub fn require_confirmation(confirm: bool, what: &str) -> Result<(), EngineError> {
    if confirm {
        Ok(())
    } else {
        Err(EngineError::new(
            ErrorCode::ConfirmationRequired,
            format!("{what} requires explicit confirmation"),
        )
        .recovery("confirm interactively, or pass --yes"))
    }
}
