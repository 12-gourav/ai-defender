//! Absolute, normalised filesystem paths and the interface that produces them.
//!
//! Policy never sees a path string supplied by an agent. A [`PathResolver`] turns the raw string
//! into a [`NormalizedPath`] first; whether symlinks were resolved on the way depends on the
//! resolver (the engine's filesystem resolver does; [`LexicalResolver`] does not).
//!
//! On Windows a path is `C:\dir\name` or `\\server\share\dir\name`: the `\\?\` prefix is
//! removed, the drive letter upper-cased and `/` read as `\`. Names Windows rewrites or reads
//! as something else are refused rather than interpreted (see [`windows_name_error`]), so the
//! path a decision sees is the file the tool opens. Containment ignores case, as NTFS does.

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
        #[cfg(windows)]
        let value = windows_native(&value);
        let path = Path::new(&value);
        if !path.is_absolute() {
            return Err(SecurityError::InvalidIdentifier {
                field,
                rule: "must be absolute",
            });
        }
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => check_name(field, name)?,
                #[cfg(windows)]
                Component::Prefix(prefix)
                    if matches!(
                        prefix.kind(),
                        std::path::Prefix::Disk(_) | std::path::Prefix::UNC(..)
                    ) => {}
                #[cfg(windows)]
                Component::Prefix(_) => {
                    return Err(SecurityError::InvalidIdentifier {
                        field,
                        rule: "must start with a drive letter or a network share",
                    });
                }
                _ => {
                    return Err(SecurityError::InvalidIdentifier {
                        field,
                        rule: "must not contain '..' components",
                    });
                }
            }
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
    /// `/a/bc` is not inside `/a/b`). Case-insensitive on Windows.
    #[must_use]
    pub fn is_within(&self, ancestor: &NormalizedPath) -> bool {
        self.relative_to(ancestor).is_some()
    }

    /// The part of `self` below `ancestor`, joined with `/` (empty when they are the same
    /// path), or `None` when `self` is not within `ancestor`. Case-insensitive on Windows.
    #[must_use]
    pub fn relative_to(&self, ancestor: &NormalizedPath) -> Option<String> {
        let mut own = self.as_path().components();
        for theirs in ancestor.as_path().components() {
            let mine = own.next()?;
            if !same_component(mine.as_os_str(), theirs.as_os_str()) {
                return None;
            }
        }
        let rest: Vec<String> = own
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        Some(rest.join("/"))
    }

    /// The path with `/` separators, the form glob patterns are written in: `C:/dir/name` on
    /// Windows, the path itself elsewhere.
    #[must_use]
    pub fn pattern_text(&self) -> String {
        if cfg!(windows) {
            self.0.replace('\\', "/")
        } else {
            self.0.clone()
        }
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

/// Refuse a file name Windows would not open as written. Nothing to check elsewhere.
fn check_name(field: &'static str, name: &std::ffi::OsStr) -> Result<(), SecurityError> {
    if cfg!(windows) {
        if let Some(rule) = windows_name_error(&name.to_string_lossy()) {
            return Err(SecurityError::InvalidIdentifier { field, rule });
        }
    }
    Ok(())
}

fn same_component(a: &std::ffi::OsStr, b: &std::ffi::OsStr) -> bool {
    if cfg!(windows) {
        fold_case(&a.to_string_lossy()) == fold_case(&b.to_string_lossy())
    } else {
        a == b
    }
}

/// Upper-case for comparison, as NTFS compares names. NTFS uses its own per-volume table;
/// Unicode upper-casing agrees with it for every name an agent can plausibly write.
#[must_use]
pub fn fold_case(name: &str) -> String {
    name.chars().flat_map(char::to_uppercase).collect()
}

/// Device names Windows opens instead of a file of that name, in any directory and with any
/// extension (`nul.txt` is the null device).
const WINDOWS_DEVICE_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "COM0", "COM1", "COM2", "COM3", "COM4",
    "COM5", "COM6", "COM7", "COM8", "COM9", "COM¹", "COM²", "COM³", "LPT0", "LPT1", "LPT2", "LPT3",
    "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "LPT¹", "LPT²", "LPT³",
];

/// Why Windows would open something other than the file `name` names, if it would. Checked on
/// every platform's build so the rules are tested everywhere; enforced only on Windows.
///
/// - a `:` selects an alternate data stream (`.env:x` is a stream of `.env`);
/// - a trailing dot or space is removed (`.env.` opens `.env`);
/// - `CON`, `NUL`, `COM1` and the other device names, with any extension;
/// - `<>"|?*` are wildcards or invalid in names.
///
/// 8.3 short names (`SECRET~1.ENV`) need no rule here: the filesystem resolver canonicalises
/// existing components to their long names, and a short name that does not exist names a new
/// file of exactly that name.
#[must_use]
pub fn windows_name_error(name: &str) -> Option<&'static str> {
    if name.contains(':') {
        return Some("must not contain ':' (an alternate data stream on Windows)");
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return Some("must not end with a dot or space (Windows removes them)");
    }
    if name.contains(['<', '>', '"', '|', '?', '*']) {
        return Some("must not contain <>\"|?* (wildcards or invalid on Windows)");
    }
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    let stem = fold_case(stem);
    if WINDOWS_DEVICE_NAMES.contains(&stem.as_str()) {
        return Some("must not be a Windows device name (CON, NUL, COM1, ...)");
    }
    None
}

/// The native spelling of a Windows path: `/` as `\`, no `\\?\` prefix, drive letter in upper
/// case. A path that was only valid because of the verbatim prefix (`..`, trailing dots) is
/// then refused by the component checks instead of being taken literally.
#[must_use]
pub fn windows_native(value: &str) -> String {
    let value = value.replace('/', "\\");
    let value = if let Some(rest) = value.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = value.strip_prefix(r"\\?\") {
        rest.to_owned()
    } else {
        value
    };
    let mut chars = value.chars();
    match (chars.next(), chars.next()) {
        (Some(drive), Some(':')) if drive.is_ascii_alphabetic() => {
            format!("{}:{}", drive.to_ascii_uppercase(), chars.as_str())
        }
        _ => value,
    }
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
        let mut root = PathBuf::new();
        let mut parts: Vec<&std::ffi::OsStr> = Vec::new();
        for component in joined.components() {
            match component {
                Component::Prefix(_) | Component::RootDir => root.push(component.as_os_str()),
                Component::CurDir => {}
                Component::Normal(part) => parts.push(part),
                Component::ParentDir => {
                    if parts.pop().is_none() {
                        return Err(SecurityError::InvalidIdentifier {
                            field: "path",
                            rule: "must not traverse above the filesystem root",
                        });
                    }
                }
            }
        }
        root.extend(parts);
        NormalizedPath::new(root.to_string_lossy().into_owned())
    }
}

/// Validate `raw` and join it to `base` when relative. Shared by every resolver so the input
/// rules (length, control characters, Windows names, a base for relative paths) cannot drift
/// between them. Names are checked before anything resolves them: Windows would otherwise
/// strip a trailing dot or open a stream during canonicalisation, and the decision would be
/// about a different spelling than the agent's.
pub fn join_raw(base: Option<&NormalizedPath>, raw: &str) -> Result<PathBuf, SecurityError> {
    check_raw("path", raw)?;
    let path = Path::new(raw);
    for component in path.components() {
        if let Component::Normal(name) = component {
            check_name("path", name)?;
        }
    }
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
mod windows_rules {
    use super::*;

    #[test]
    fn names_windows_rewrites_are_refused() {
        for bad in [
            ".env:stream",
            ".env::$DATA",
            ".env.",
            ".env ",
            "secrets...",
            "nul",
            "NUL.txt",
            "con",
            "Com1.log",
            "lpt9",
            "COM\u{b9}",
            "aux .txt",
            "conin$",
            "a*b",
            "what?",
            "a<b",
            "pipe|x",
            "quote\"",
        ] {
            assert!(windows_name_error(bad).is_some(), "{bad}");
        }
        for good in [
            ".env",
            "file.txt",
            "SECRET~1.ENV",
            "console",
            "nulls",
            "com10",
            "lpt",
            "a.b.c",
            "\u{e9}t\u{e9}",
        ] {
            assert_eq!(windows_name_error(good), None, "{good}");
        }
    }

    #[test]
    fn native_spelling() {
        assert_eq!(windows_native("c:/Users/u"), r"C:\Users\u");
        assert_eq!(windows_native(r"\\?\C:\a"), r"C:\a");
        assert_eq!(windows_native(r"\\?\d:\a"), r"D:\a");
        assert_eq!(windows_native(r"\\?\UNC\srv\share\a"), r"\\srv\share\a");
        assert_eq!(windows_native(r"\\srv\share"), r"\\srv\share");
        assert_eq!(windows_native("/a/b"), r"\a\b");
    }

    #[test]
    fn case_folding() {
        assert_eq!(fold_case(".Env"), fold_case(".ENV"));
        assert_eq!(fold_case("\u{e9}"), fold_case("\u{c9}"));
        assert_ne!(fold_case("a"), fold_case("b"));
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    fn p(s: &str) -> NormalizedPath {
        NormalizedPath::new(s).unwrap()
    }

    #[test]
    fn drive_and_share_paths() {
        assert_eq!(p(r"c:\a\\b\.\c\").as_str(), r"C:\a\b\c");
        assert_eq!(p("C:/a/b").as_str(), r"C:\a\b");
        assert_eq!(p(r"\\?\C:\a").as_str(), r"C:\a");
        assert_eq!(p(r"\\srv\share\a").as_str(), r"\\srv\share\a");
        assert_eq!(p(r"C:\a\b").pattern_text(), "C:/a/b");
        for bad in [
            r"\a\b",
            r"C:a\b",
            "relative",
            r"C:\a\..\b",
            r"\\?\C:\a\..\b",
            r"\\.\PhysicalDrive0",
            r"\\?\GLOBALROOT\Device\x",
            r"C:\proj\.env:x",
            r"C:\proj\.env.",
            r"C:\proj\nul",
        ] {
            assert!(NormalizedPath::new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn within_ignores_case() {
        assert!(p(r"C:\Proj\SRC\x").is_within(&p(r"c:\proj\src")));
        assert!(!p(r"C:\proj2\x").is_within(&p(r"C:\proj")));
        assert!(!p(r"D:\proj\x").is_within(&p(r"C:\proj")));
        assert_eq!(
            p(r"C:\Proj\src\x.rs").relative_to(&p(r"C:\proj")),
            Some("src/x.rs".to_owned())
        );
    }

    #[test]
    fn lexical_resolver_keeps_the_drive() {
        let r = LexicalResolver;
        let base = p(r"C:\proj\src");
        assert_eq!(
            r.resolve(Some(&base), r"..\x").unwrap().as_str(),
            r"C:\proj\x"
        );
        assert_eq!(r.resolve(Some(&base), "/etc").unwrap().as_str(), r"C:\etc");
        assert!(r.resolve(Some(&base), r"..\..\..\x").is_err());
        assert!(r.resolve(Some(&base), ".env:x").is_err());
        assert!(r.resolve(Some(&base), "NUL").is_err());
    }
}

#[cfg(all(test, unix))]
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
