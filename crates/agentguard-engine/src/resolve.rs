//! Filesystem path resolution.

use std::fs;
use std::io::ErrorKind;
use std::path::{Component, PathBuf};

use agentguard_core::path::join_raw;
use agentguard_core::{NormalizedPath, PathResolver, SecurityError};

/// Resolves paths against the real filesystem: the longest existing ancestor is canonicalised
/// (following every symlink in it) and the remaining, not-yet-existing components are appended.
///
/// Refused, because the eventual write would land somewhere the decision did not see:
/// - a dangling symlink anywhere in the non-existing tail (writing through it creates the
///   link's target, which may be outside the project);
/// - `..` in the non-existing tail.
///
/// The result describes the filesystem at decision time. The agent's tool runs later; a symlink
/// swapped in between is not detected (see the known limitations).
#[derive(Debug, Default, Clone, Copy)]
pub struct FsPathResolver;

impl PathResolver for FsPathResolver {
    fn resolve(
        &self,
        base: Option<&NormalizedPath>,
        raw: &str,
    ) -> Result<NormalizedPath, SecurityError> {
        let joined = join_raw(base, raw)?;
        let mut existing = joined.clone();
        let mut tail: Vec<std::ffi::OsString> = Vec::new();
        let canonical = loop {
            match fs::canonicalize(&existing) {
                Ok(c) => break c,
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    if fs::symlink_metadata(&existing).is_ok() {
                        return Err(SecurityError::InvalidIdentifier {
                            field: "path",
                            rule: "must not pass through a dangling symlink",
                        });
                    }
                    match existing.components().next_back() {
                        Some(Component::Normal(name)) => tail.push(name.to_os_string()),
                        Some(Component::CurDir) => {}
                        _ => {
                            return Err(SecurityError::InvalidIdentifier {
                                field: "path",
                                rule: "must not contain '..' below a directory that does not exist",
                            });
                        }
                    }
                    if !existing.pop() {
                        return Err(SecurityError::InvalidIdentifier {
                            field: "path",
                            rule: "no existing ancestor",
                        });
                    }
                }
                Err(_) => {
                    return Err(SecurityError::InvalidIdentifier {
                        field: "path",
                        rule: "could not be resolved",
                    });
                }
            }
        };
        let full: PathBuf = canonical.join(tail.iter().rev().collect::<PathBuf>());
        let text =
            full.into_os_string()
                .into_string()
                .map_err(|_| SecurityError::InvalidIdentifier {
                    field: "path",
                    rule: "must be valid UTF-8",
                })?;
        NormalizedPath::new(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn np(p: &std::path::Path) -> NormalizedPath {
        NormalizedPath::new(fs::canonicalize(p).unwrap().to_str().unwrap()).unwrap()
    }

    #[test]
    fn resolves_existing_and_new_paths() {
        let dir = tempfile::tempdir().unwrap();
        let root = np(dir.path());
        fs::create_dir(dir.path().join("src")).unwrap();
        let r = FsPathResolver;
        assert_eq!(
            r.resolve(Some(&root), "src/new.rs").unwrap(),
            root.join("src/new.rs").unwrap()
        );
        assert_eq!(
            r.resolve(Some(&root), "src/../x").unwrap(),
            root.join("x").unwrap()
        );
        assert_eq!(
            r.resolve(Some(&root), "a/b/c").unwrap(),
            root.join("a/b/c").unwrap()
        );
        assert!(r.resolve(Some(&root), "missing/../x").is_err());
    }

    #[test]
    fn follows_symlinks_out_of_the_project() {
        let outside = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let root = np(dir.path());
        symlink(outside.path(), dir.path().join("link")).unwrap();
        let resolved = FsPathResolver
            .resolve(Some(&root), "link/secret.txt")
            .unwrap();
        assert!(!resolved.is_within(&root));
        assert!(resolved.is_within(&np(outside.path())));
    }

    #[test]
    fn refuses_dangling_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let root = np(dir.path());
        symlink(
            "/nonexistent-agentguard-target/x",
            dir.path().join("dangling"),
        )
        .unwrap();
        assert!(FsPathResolver.resolve(Some(&root), "dangling").is_err());
        assert!(FsPathResolver
            .resolve(Some(&root), "dangling/child")
            .is_err());
    }
}
