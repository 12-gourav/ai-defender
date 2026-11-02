//! Executable resolution and identity.
//!
//! A program named without a slash is looked up only in the trusted search path
//! ([`crate::environment::trusted_path`]); directories inside the project, relative entries and
//! directories writable by others are never searched, so a `git` planted in
//! `node_modules/.bin` or `./` cannot stand in for the real one. A program named with a slash
//! is resolved against the working directory and classified as a project script.
//!
//! The resolved file's identity (device, inode, size, modification time, mode and SHA-256) is
//! part of the operation an approval is bound to, and is checked again immediately before the
//! process is spawned. Set-user-ID and set-group-ID programs, privilege wrappers and
//! AgentGuard's own binaries are refused.

use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Programs managed execution never runs: privilege escalation, and AgentGuard itself.
pub const REFUSED_PROGRAMS: &[&str] = &[
    "sudo",
    "doas",
    "su",
    "pkexec",
    "runas",
    "run0",
    "ai-defender",
    "agentguard",
    "agentguard-engine",
];

/// Largest executable whose content is hashed; larger files are identified by metadata only.
pub const MAX_HASHED_BYTES: u64 = 256 * 1024 * 1024;

/// Why a program cannot be run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    /// Not found in the trusted search path, or the named file does not exist.
    #[error("the program was not found in the trusted search path")]
    NotFound,
    /// Not a regular executable file.
    #[error("the program is not an executable regular file")]
    NotExecutable,
    /// A privilege wrapper or AgentGuard binary.
    #[error("managed execution never runs privilege escalation or AI Defender's own commands")]
    Refused,
    /// Set-user-ID or set-group-ID.
    #[error("managed execution does not run set-user-ID or set-group-ID programs")]
    SetId,
}

/// The identity of an executable file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileIdentity {
    /// Device.
    pub dev: u64,
    /// Inode.
    pub ino: u64,
    /// Size in bytes.
    pub size: u64,
    /// Modification time, nanoseconds since the epoch.
    pub mtime_ns: i128,
    /// Permission bits.
    pub mode: u32,
    /// SHA-256 of the content, when it was small enough to hash.
    pub sha256: Option<String>,
}

impl FileIdentity {
    fn of(path: &Path) -> Option<Self> {
        let meta = std::fs::metadata(path).ok()?;
        let sha256 = if meta.len() <= MAX_HASHED_BYTES {
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
                .open(path)
                .ok()?;
            let mut hasher = Sha256::new();
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = file.read(&mut buf).ok()?;
                if n == 0 {
                    break;
                }
                hasher.update(buf.get(..n)?);
            }
            Some(hex::encode(hasher.finalize()))
        } else {
            None
        };
        Some(Self {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.len(),
            mtime_ns: i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec()),
            mode: meta.mode(),
            sha256,
        })
    }

    /// A short stable digest for bindings.
    #[must_use]
    pub fn digest(&self) -> String {
        let text = format!(
            "{}:{}:{}:{}:{:o}:{}",
            self.dev,
            self.ino,
            self.size,
            self.mtime_ns,
            self.mode,
            self.sha256.as_deref().unwrap_or("-")
        );
        hex::encode(Sha256::digest(text.as_bytes()))
    }
}

/// A resolved program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedExecutable {
    /// The name as requested.
    pub requested: String,
    /// The canonical path executed.
    pub path: PathBuf,
    /// Whether the request named a path (a project script) rather than a program.
    pub explicit_path: bool,
    /// Identity at resolution.
    pub identity: FileIdentity,
}

impl ResolvedExecutable {
    /// The basename of the executed file.
    #[must_use]
    pub fn basename(&self) -> String {
        self.path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// Whether the file is still the one that was resolved (metadata comparison; the content
    /// hash was bound at resolution).
    #[must_use]
    pub fn unchanged(&self) -> bool {
        std::fs::metadata(&self.path).is_ok_and(|m| {
            m.dev() == self.identity.dev
                && m.ino() == self.identity.ino
                && m.len() == self.identity.size
                && m.mode() == self.identity.mode
                && i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec())
                    == self.identity.mtime_ns
        })
    }
}

fn base(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

fn check(candidate: &Path) -> Result<PathBuf, ResolveError> {
    let canonical = std::fs::canonicalize(candidate).map_err(|_| ResolveError::NotFound)?;
    let meta = std::fs::metadata(&canonical).map_err(|_| ResolveError::NotFound)?;
    if !meta.is_file() || meta.mode() & 0o111 == 0 {
        return Err(ResolveError::NotExecutable);
    }
    if meta.mode() & 0o6000 != 0 {
        return Err(ResolveError::SetId);
    }
    Ok(canonical)
}

/// Resolve `program` for execution in `cwd` using the trusted search path `path`.
pub fn resolve(
    program: &str,
    cwd: &Path,
    path: &[PathBuf],
) -> Result<ResolvedExecutable, ResolveError> {
    if program.is_empty() || program.contains('\0') {
        return Err(ResolveError::NotFound);
    }
    if REFUSED_PROGRAMS.contains(&base(program)) {
        return Err(ResolveError::Refused);
    }
    let explicit_path = program.contains('/');
    let resolved = if explicit_path {
        check(&cwd.join(program))?
    } else {
        let mut found = Err(ResolveError::NotFound);
        for dir in path {
            match check(&dir.join(program)) {
                Ok(p) => {
                    found = Ok(p);
                    break;
                }
                Err(ResolveError::NotFound) => {}
                Err(e) => {
                    found = Err(e);
                    break;
                }
            }
        }
        found?
    };
    let resolved_base = resolved
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if REFUSED_PROGRAMS.contains(&resolved_base.as_str()) {
        return Err(ResolveError::Refused);
    }
    let identity = FileIdentity::of(&resolved).ok_or(ResolveError::NotFound)?;
    Ok(ResolvedExecutable {
        requested: program.to_owned(),
        path: resolved,
        explicit_path,
        identity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn trusted() -> Vec<PathBuf> {
        crate::environment::trusted_path(None, Path::new("/nonexistent-project"))
    }

    #[test]
    fn resolves_system_programs_and_refuses_wrappers() {
        let sh = resolve("sh", Path::new("/"), &trusted()).unwrap();
        assert!(sh.path.is_absolute());
        assert!(sh.identity.sha256.is_some());
        assert!(sh.unchanged());
        for refused in [
            "sudo",
            "/usr/bin/sudo",
            "su",
            "agentguard",
            "./agentguard-engine",
        ] {
            assert_eq!(
                resolve(refused, Path::new("/"), &trusted()),
                Err(ResolveError::Refused),
                "{refused}"
            );
        }
        assert_eq!(
            resolve("definitely-not-a-program-xyz", Path::new("/"), &trusted()),
            Err(ResolveError::NotFound)
        );
    }

    #[test]
    fn project_directories_are_never_searched() {
        let dir = tempfile::tempdir().unwrap();
        let project = std::fs::canonicalize(dir.path()).unwrap();
        let bin = project.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let fake = bin.join("sh");
        std::fs::write(&fake, "#!/bin/true\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = crate::environment::trusted_path(
            Some(&format!("{}:/usr/bin:/bin", bin.display())),
            &project,
        );
        let r = resolve("sh", &project, &path).unwrap();
        assert_ne!(r.path, fake, "a planted program never shadows the real one");
        let explicit = resolve("./bin/sh", &project, &path).unwrap();
        assert_eq!(explicit.path, fake);
        assert!(explicit.explicit_path);
        std::fs::write(&fake, "#!/bin/true\n# changed\n").unwrap();
        assert!(!explicit.unchanged(), "a replaced file is detected");
    }
}
