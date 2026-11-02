//! Discovery, loading and structural validation of `.agent-security.yml`.
//!
//! Phase 1 scope: find the file, enforce a size limit, parse YAML, dispatch on `version`, parse
//! the top level into a typed structure that rejects unknown keys, and report structural
//! problems. Semantic policy validation (what the sections mean, precedence, effective policy)
//! is the policy engine's job in Phase 2 and is explicitly *not* performed here.
//!
//! The policy file must never contain secrets; its contents may appear in error messages and
//! `inspect` output.

pub mod discovery;
pub mod v1;

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use serde::Serialize;

pub use discovery::{discover, Discovered};
pub use v1::ProjectConfigV1;

/// Name of the project policy file.
pub const POLICY_FILE_NAME: &str = ".agent-security.yml";

/// Largest policy file the loader will read.
pub const MAX_POLICY_FILE_BYTES: u64 = 1024 * 1024;

/// Policy file format versions this build understands.
pub const SUPPORTED_VERSIONS: &[u32] = &[1];

/// Configuration failures. Messages name paths and rules, not secrets.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// No policy file was found walking up from `searched_from`.
    #[error("no {POLICY_FILE_NAME} found in {} or any parent directory", searched_from.display())]
    NotFound {
        /// Where the search started.
        searched_from: PathBuf,
    },

    /// The file could not be read.
    #[error("cannot read {}", path.display())]
    Io {
        /// The path.
        path: PathBuf,
        /// The OS error.
        #[source]
        source: std::io::Error,
    },

    /// The file exceeds the size limit.
    #[error("{} is larger than the {max} byte limit", path.display())]
    TooLarge {
        /// The path.
        path: PathBuf,
        /// The limit.
        max: u64,
    },

    /// The file is not valid YAML.
    #[error("{} is not valid YAML{}: {detail}", path.display(), location_suffix(*line, *column))]
    Yaml {
        /// The path.
        path: PathBuf,
        /// 1-based line, if known.
        line: Option<usize>,
        /// 1-based column, if known.
        column: Option<usize>,
        /// Parser message.
        detail: String,
    },

    /// The top level is not a mapping.
    #[error("{}: top level must be a mapping", path.display())]
    NotAMapping {
        /// The path.
        path: PathBuf,
    },

    /// `version` is absent or not an integer.
    #[error("{}: missing or non-integer `version` field", path.display())]
    MissingVersion {
        /// The path.
        path: PathBuf,
    },

    /// `version` names a format this build does not support.
    #[error("{}: version {found} is not supported (supported: {})", path.display(), format_versions(supported))]
    UnsupportedVersion {
        /// The path.
        path: PathBuf,
        /// The version found.
        found: u32,
        /// Supported versions.
        supported: &'static [u32],
    },

    /// The document does not match the schema for its version.
    #[error("{}: {detail}", path.display())]
    Schema {
        /// The path.
        path: PathBuf,
        /// Parser message (field names and types, never values of secrets).
        detail: String,
    },

    /// Structural validation found problems.
    #[error("{}: {} validation problem(s):\n{}", path.display(), problems.len(), format_problems(problems))]
    Invalid {
        /// The path.
        path: PathBuf,
        /// The problems.
        problems: Vec<Problem>,
    },
}

fn location_suffix(line: Option<usize>, column: Option<usize>) -> String {
    match (line, column) {
        (Some(l), Some(c)) => format!(" at line {l}, column {c}"),
        (Some(l), None) => format!(" at line {l}"),
        _ => String::new(),
    }
}

fn format_versions(v: &[u32]) -> String {
    v.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_problems(problems: &[Problem]) -> String {
    problems
        .iter()
        .map(|p| format!("  - {p}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Severity of a validation problem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// The configuration cannot be used.
    Error,
    /// The configuration can be used but something is suspicious.
    Warning,
}

/// One validation finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Problem {
    /// Severity.
    pub severity: Severity,
    /// Dotted path into the document, for example `git.push`.
    pub path: String,
    /// What is wrong.
    pub message: String,
}

impl Problem {
    /// An error at `path`.
    pub fn error(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            path: path.into(),
            message: message.into(),
        }
    }

    /// A warning at `path`.
    pub fn warning(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            path: path.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sev = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        write!(f, "{sev} at `{}`: {}", self.path, self.message)
    }
}

/// Result of structural validation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ValidationReport {
    /// All findings.
    pub problems: Vec<Problem>,
}

impl ValidationReport {
    /// Whether any problem has error severity.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.problems.iter().any(|p| p.severity == Severity::Error)
    }

    /// Only the errors.
    #[must_use]
    pub fn errors(&self) -> Vec<&Problem> {
        self.problems
            .iter()
            .filter(|p| p.severity == Severity::Error)
            .collect()
    }

    /// Only the warnings.
    #[must_use]
    pub fn warnings(&self) -> Vec<&Problem> {
        self.problems
            .iter()
            .filter(|p| p.severity == Severity::Warning)
            .collect()
    }
}

/// Structural validation interface implemented by every configuration version.
pub trait Validate {
    /// Check structural rules. Never performs I/O.
    fn validate(&self) -> ValidationReport;
}

/// A loaded, version-dispatched configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProjectConfig {
    /// Format version 1.
    V1(ProjectConfigV1),
}

impl ProjectConfig {
    /// The format version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        match self {
            ProjectConfig::V1(_) => 1,
        }
    }

    /// The permission level declared by the file.
    #[must_use]
    pub const fn mode(&self) -> agentguard_core::PermissionLevel {
        match self {
            ProjectConfig::V1(c) => c.mode,
        }
    }

    /// Names of the sections present in the document.
    #[must_use]
    pub fn present_sections(&self) -> Vec<&'static str> {
        match self {
            ProjectConfig::V1(c) => c.present_sections(),
        }
    }
}

impl Validate for ProjectConfig {
    fn validate(&self) -> ValidationReport {
        match self {
            ProjectConfig::V1(c) => c.validate(),
        }
    }
}

/// Read the file at `path` with the size limit enforced.
pub fn read_limited(path: &Path) -> Result<String, ConfigError> {
    let meta = fs::metadata(path).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if meta.len() > MAX_POLICY_FILE_BYTES {
        return Err(ConfigError::TooLarge {
            path: path.to_path_buf(),
            max: MAX_POLICY_FILE_BYTES,
        });
    }
    let file = fs::File::open(path).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut text = String::new();
    // Guard against the file growing between metadata and read.
    file.take(MAX_POLICY_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if text.len() as u64 > MAX_POLICY_FILE_BYTES {
        return Err(ConfigError::TooLarge {
            path: path.to_path_buf(),
            max: MAX_POLICY_FILE_BYTES,
        });
    }
    Ok(text)
}

/// Parse policy text that came from `path` (used for error messages only).
pub fn parse_str(path: &Path, text: &str) -> Result<ProjectConfig, ConfigError> {
    let value: serde_yaml::Value = serde_yaml::from_str(text).map_err(|e| {
        let loc = e.location();
        ConfigError::Yaml {
            path: path.to_path_buf(),
            line: loc.as_ref().map(serde_yaml::Location::line),
            column: loc.as_ref().map(serde_yaml::Location::column),
            detail: e.to_string(),
        }
    })?;
    let mapping = value.as_mapping().ok_or_else(|| ConfigError::NotAMapping {
        path: path.to_path_buf(),
    })?;
    let version = mapping
        .get("version")
        .and_then(serde_yaml::Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| ConfigError::MissingVersion {
            path: path.to_path_buf(),
        })?;
    if !SUPPORTED_VERSIONS.contains(&version) {
        return Err(ConfigError::UnsupportedVersion {
            path: path.to_path_buf(),
            found: version,
            supported: SUPPORTED_VERSIONS,
        });
    }
    match version {
        1 => {
            let config: ProjectConfigV1 =
                serde_yaml::from_value(value).map_err(|e| ConfigError::Schema {
                    path: path.to_path_buf(),
                    detail: e.to_string(),
                })?;
            Ok(ProjectConfig::V1(config))
        }
        // Unreachable while SUPPORTED_VERSIONS == [1]; kept explicit so adding a version is a
        // compile-visible change here rather than a silent fallthrough.
        other => Err(ConfigError::UnsupportedVersion {
            path: path.to_path_buf(),
            found: other,
            supported: SUPPORTED_VERSIONS,
        }),
    }
}

/// Load and parse the policy at `path`. Does not run validation; call [`Validate::validate`].
pub fn load(path: &Path) -> Result<ProjectConfig, ConfigError> {
    let text = read_limited(path)?;
    let config = parse_str(path, &text)?;
    tracing::debug!(
        path = %path.display(),
        version = config.version(),
        mode = %config.mode(),
        "loaded project policy"
    );
    Ok(config)
}

/// Load, parse and validate, turning validation errors into [`ConfigError::Invalid`].
pub fn load_validated(path: &Path) -> Result<(ProjectConfig, ValidationReport), ConfigError> {
    let config = load(path)?;
    let report = config.validate();
    if report.has_errors() {
        return Err(ConfigError::Invalid {
            path: path.to_path_buf(),
            problems: report.errors().into_iter().cloned().collect(),
        });
    }
    Ok((config, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentguard_core::PermissionLevel;

    const MINIMAL: &str = "version: 1\nmode: DEVELOPMENT\n";
    const P: &str = "/virtual/.agent-security.yml";

    fn path() -> PathBuf {
        PathBuf::from(P)
    }

    #[test]
    fn parses_minimal_v1() {
        let cfg = parse_str(&path(), MINIMAL).unwrap();
        assert_eq!(cfg.version(), 1);
        assert_eq!(cfg.mode(), PermissionLevel::Development);
        assert_eq!(cfg.present_sections(), Vec::<&str>::new());
        assert!(!cfg.validate().has_errors());
    }

    #[test]
    fn rejects_unknown_top_level_keys() {
        let err = parse_str(&path(), "version: 1\nmode: DEVELOPMENT\nbypass: true\n").unwrap_err();
        match err {
            ConfigError::Schema { detail, .. } => assert!(detail.contains("bypass"), "{detail}"),
            other => panic!("unexpected: {other}"),
        }
    }

    #[test]
    fn rejects_missing_and_unsupported_versions() {
        assert!(matches!(
            parse_str(&path(), "mode: DEVELOPMENT\n"),
            Err(ConfigError::MissingVersion { .. })
        ));
        assert!(matches!(
            parse_str(&path(), "version: 2\nmode: DEVELOPMENT\n"),
            Err(ConfigError::UnsupportedVersion { found: 2, .. })
        ));
        assert!(matches!(
            parse_str(&path(), "version: '1'\nmode: DEVELOPMENT\n"),
            Err(ConfigError::MissingVersion { .. })
        ));
    }

    #[test]
    fn rejects_non_mapping_and_invalid_yaml() {
        assert!(matches!(
            parse_str(&path(), "- a\n- b\n"),
            Err(ConfigError::NotAMapping { .. })
        ));
        assert!(matches!(
            parse_str(&path(), "version: [\n"),
            Err(ConfigError::Yaml { .. })
        ));
    }

    #[test]
    fn rejects_bad_mode_value() {
        let err = parse_str(&path(), "version: 1\nmode: development\n").unwrap_err();
        assert!(matches!(err, ConfigError::Schema { .. }));
    }

    #[test]
    fn read_limited_enforces_size() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(POLICY_FILE_NAME);
        let oversized = usize::try_from(MAX_POLICY_FILE_BYTES + 1).unwrap();
        fs::write(&file, "x".repeat(oversized)).unwrap();
        assert!(matches!(
            read_limited(&file),
            Err(ConfigError::TooLarge { .. })
        ));
        fs::write(&file, MINIMAL).unwrap();
        assert_eq!(read_limited(&file).unwrap(), MINIMAL);
        assert!(matches!(
            read_limited(&dir.path().join("missing")),
            Err(ConfigError::Io { .. })
        ));
    }

    #[test]
    fn load_validated_surfaces_structural_errors() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(POLICY_FILE_NAME);
        fs::write(&file, "version: 1\nmode: DEVELOPMENT\ngit: not-a-mapping\n").unwrap();
        let err = load_validated(&file).unwrap_err();
        match err {
            ConfigError::Invalid { problems, .. } => {
                assert_eq!(problems.len(), 1);
                assert_eq!(problems[0].path, "git");
            }
            other => panic!("unexpected: {other}"),
        }
    }

    #[test]
    fn problem_display() {
        let p = Problem::warning("approvals.ttl_seconds", "exceeds organisation maximum");
        assert_eq!(
            p.to_string(),
            "warning at `approvals.ttl_seconds`: exceeds organisation maximum"
        );
    }
}
