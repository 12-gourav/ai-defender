//! Absolute, normalised filesystem paths and the interface that produces them.
//!
//! Policy never sees a path string supplied by an agent. A [`PathResolver`] turns the raw string
//! into a [`NormalizedPath`] first; whether symlinks were resolved on the way depends on the
//! resolver (the engine's filesystem resolver does; [`LexicalResolver`] does not).

use std::fmt;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::SecurityError;

/// An absolute UTF-8 path with no `.` or `..` components, no control characters, no repeated
/// or trailing separators, and at most [`NormalizedPath::MAX_LEN`] bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct NormalizedPath(String);

impl NormalizedPath {
    /// Maximum length in bytes (Linux `PATH_MAX`).
    pub const MAX_LEN: usize = 4096;

    /// Validate an already-normalised absolute path. Rejects (rather than resolves) `..`.
    pub fn new(value: impl Into<String>) -> Result<Self, SecurityError> {
        let value = value.into();
        let field = "path";
        check_raw(field, &value)?;
        let path = Path::new(&value);
        if !path.is_absolute() {
            return Err(SecurityError::InvalidIdentifier {
                field,
                rule: "must be absolute",
            });
        }
        if path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        {
            return Err(SecurityError::InvalidIdentifier {
                field,
                rule: "must not contain '..' components",
            });
        }
        Ok(Self::from_components(path))
    }

    /// Rebuild from components, which drops `.`, repeated and trailing separators. The caller
    /// guarantees the input is absolute, UTF-8 and contains no `..`.
    fn from_components(path: &Path) -> Self {
        let rebuilt: PathBuf = path.components().collect();
        Self(rebuilt.to_string_lossy().into_owned())
    }

    /// Borrow as a `Path`.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    /// Borrow as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `self` is `ancestor` or lies beneath it, compared component by component (so
    /// `/a/bc` is not inside `/a/b`).
    #[must_use]
    pub fn is_within(&self, ancestor: &NormalizedPath) -> bool {
        self.as_path().starts_with(ancestor.as_path())
    }

    /// Append one relative path made only of normal components.
    pub fn join(&self, relative: &str) -> Result<Self, SecurityError> {
        check_raw("path", relative)?;
        let rel = Path::new(relative);
        if rel.is_absolute()
            || rel
                .components()
                .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
        {
            return Err(SecurityError::InvalidIdentifier {
                field: "path",
                rule: "joined segment must be relative and must not contain '..'",
            });
        }
        Self::new(format!("{}/{relative}", self.0))
    }
}

fn check_raw(field: &'static str, value: &str) -> Result<(), SecurityError> {
    if value.is_empty() {
        return Err(SecurityError::Empty { field });
    }
    if value.len() > NormalizedPath::MAX_LEN {
        return Err(SecurityError::TextTooLong {
            field,
            max: NormalizedPath::MAX_LEN,
        });
    }
    if value.chars().any(char::is_control) {
        return Err(SecurityError::ControlCharacters { field });
    }
    Ok(())
}

impl TryFrom<String> for NormalizedPath {
    type Error = SecurityError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<NormalizedPath> for String {
    fn from(value: NormalizedPath) -> Self {
        value.0
    }
}

impl fmt::Display for NormalizedPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Turns an untrusted path string into a [`NormalizedPath`].
pub trait PathResolver: Send + Sync {
    /// Resolve `raw`. An absolute `raw` ignores `base`; a relative one is resolved against
    /// `base`, and is an error when `base` is `None`.
    fn resolve(
        &self,
        base: Option<&NormalizedPath>,
        raw: &str,
    ) -> Result<NormalizedPath, SecurityError>;
}

/// Resolves `.` and `..` textually and never touches the filesystem, so a symlink inside the
/// path is not followed: `/proj/link/../x` becomes `/proj/x` even if `link` points elsewhere.
/// Suitable only where the caller knows the path is symlink-free, and for tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct LexicalResolver;

impl PathResolver for LexicalResolver {
    fn resolve(
        &self,
        base: Option<&NormalizedPath>,
        raw: &str,
    ) -> Result<NormalizedPath, SecurityError> {
        let joined = join_raw(base, raw)?;
        let mut out = PathBuf::from("/");
        for component in joined.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(part) => out.push(part),
                Component::ParentDir => {
                    if !out.pop() {
                        return Err(SecurityError::InvalidIdentifier {
                            field: "path",
                            rule: "must not traverse above the filesystem root",
                        });
                    }
                }
                Component::Prefix(_) => {
                    return Err(SecurityError::InvalidIdentifier {
                        field: "path",
                        rule: "platform path prefixes are not supported",
                    });
                }
            }
        }
        Ok(NormalizedPath::from_components(&out))
    }
}

/// Validate `raw` and join it to `base` when relative. Shared by every resolver so the input
/// rules (length, control characters, a base for relative paths) cannot drift between them.
pub fn join_raw(base: Option<&NormalizedPath>, raw: &str) -> Result<PathBuf, SecurityError> {
    check_raw("path", raw)?;
    let path = Path::new(raw);
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let base = base.ok_or(SecurityError::InvalidIdentifier {
        field: "path",
        rule: "relative path without a working directory",
    })?;
    let joined = base.as_path().join(path);
    if joined.as_os_str().len() > NormalizedPath::MAX_LEN {
        return Err(SecurityError::TextTooLong {
            field: "path",
            max: NormalizedPath::MAX_LEN,
        });
    }
    Ok(joined)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> NormalizedPath {
        NormalizedPath::new(s).unwrap()
    }

    #[test]
    fn normalises_separators_and_dot() {
        assert_eq!(p("/a//b/./c/").as_str(), "/a/b/c");
        assert_eq!(p("/").as_str(), "/");
    }

    #[test]
    fn rejects_relative_parent_control_and_empty() {
        assert!(NormalizedPath::new("a/b").is_err());
        assert!(NormalizedPath::new("/a/../b").is_err());
        assert!(NormalizedPath::new("/a/\nb").is_err());
        assert!(NormalizedPath::new("/a/\0b").is_err());
        assert!(NormalizedPath::new("").is_err());
        assert!(NormalizedPath::new(format!("/{}", "a".repeat(4096))).is_err());
    }

    #[test]
    fn within_is_component_wise() {
        assert!(p("/a/b/c").is_within(&p("/a/b")));
        assert!(p("/a/b").is_within(&p("/a/b")));
        assert!(!p("/a/bc").is_within(&p("/a/b")));
        assert!(p("/x").is_within(&p("/")));
    }

    #[test]
    fn join_rejects_escape() {
        assert_eq!(p("/a").join("b/c").unwrap().as_str(), "/a/b/c");
        assert!(p("/a").join("../b").is_err());
        assert!(p("/a").join("/etc").is_err());
    }

    #[test]
    fn lexical_resolver() {
        let r = LexicalResolver;
        let base = p("/proj/src");
        assert_eq!(
            r.resolve(Some(&base), "x.rs").unwrap().as_str(),
            "/proj/src/x.rs"
        );
        assert_eq!(r.resolve(Some(&base), "../x").unwrap().as_str(), "/proj/x");
        assert_eq!(
            r.resolve(Some(&base), "/etc/passwd").unwrap().as_str(),
            "/etc/passwd"
        );
        assert_eq!(r.resolve(None, "/a/./b/../c").unwrap().as_str(), "/a/c");
        assert!(r.resolve(None, "relative").is_err());
        assert!(r.resolve(None, "/../../x").is_err());
        assert!(r.resolve(Some(&base), "a\u{1b}b").is_err());
    }

    #[test]
    fn serde_validates() {
        let ok: NormalizedPath = serde_json::from_str("\"/a/b\"").unwrap();
        assert_eq!(ok, p("/a/b"));
        assert!(serde_json::from_str::<NormalizedPath>("\"/a/../b\"").is_err());
        assert!(serde_json::from_str::<NormalizedPath>("\"rel\"").is_err());
    }
}
