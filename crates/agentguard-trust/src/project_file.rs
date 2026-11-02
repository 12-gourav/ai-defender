//! The project's own configuration: untrusted input.
//!
//! Two locations are recognised at the registered, canonical project root (never discovered by
//! walking up from the working directory, which would let a nested file shadow the real one):
//!
//! - `.agentguard/config.yaml`: the project configuration (metadata, expected profile,
//!   restrictions, integration preferences);
//! - `.agent-security.yml`: the earlier format, still read when the new file is absent.
//!
//! If both exist the configuration is ambiguous and refused. Neither is ever trusted because it
//! exists: its `rules` are a *proposal* that takes effect only after an authorised update copies
//! them into a signed project manifest, and a file that differs from the approved policy is
//! reported as drift and otherwise ignored. Only the global policy selects the security profile;
//! a project's `profile` is an expectation that is checked, not applied.

use agentguard_platform::fs::{OpenNoFollow, UnixMode};
use std::collections::BTreeMap;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use agentguard_common::config::{self, ProjectConfig, POLICY_FILE_NAME};
use agentguard_core::{BoundedText, NormalizedPath};
use agentguard_engine::{ProfileName, Rule};
use serde::{Deserialize, Serialize};

use crate::canonical::ContentHash;
use crate::error::TrustError;
use crate::hierarchy::{validate_document, Layer};
use crate::manifest::PolicyDocument;

/// Directory of the project configuration.
pub const CONFIG_DIR: &str = ".agentguard";
/// File name of the project configuration within [`CONFIG_DIR`].
pub const CONFIG_FILE: &str = "config.yaml";
/// Current project configuration format version.
pub const CONFIG_VERSION: u32 = 1;

/// Why a project configuration is unusable. Messages may quote the configuration (which must
/// never contain secrets) but never anything else.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProjectConfigError {
    /// A configuration path is a symlink, or not the expected type.
    #[error("{path} is insecure: {rule}")]
    Insecure {
        /// Project-relative path.
        path: &'static str,
        /// The rule it broke.
        rule: &'static str,
    },
    /// Both configuration files exist.
    #[error("both .agentguard/config.yaml and .agent-security.yml exist; keep one")]
    Ambiguous,
    /// The file could not be read or written.
    #[error("{path} could not be {action}")]
    Io {
        /// Project-relative path.
        path: &'static str,
        /// What was attempted.
        action: &'static str,
    },
    /// YAML or schema error, with location when known.
    #[error("{path}: {message}")]
    Parse {
        /// Project-relative path.
        path: &'static str,
        /// Parser message.
        message: String,
    },
    /// The configuration parsed but is invalid.
    #[error("{path}: {message}")]
    Invalid {
        /// Project-relative path.
        path: &'static str,
        /// What is wrong.
        message: String,
    },
    /// A configuration already exists and will not be overwritten.
    #[error("a project configuration already exists; refusing to overwrite it")]
    Exists,
}

impl From<ProjectConfigError> for TrustError {
    fn from(e: ProjectConfigError) -> Self {
        match e {
            ProjectConfigError::Insecure { rule, .. } => TrustError::Insecure {
                object: "project configuration",
                rule,
            },
            ProjectConfigError::Io { action, .. } => TrustError::Io {
                object: "project configuration",
                action,
            },
            _ => TrustError::Malformed {
                object: "project configuration",
            },
        }
    }
}

/// Descriptive project metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectMetadata {
    /// Display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<BoundedText<100>>,
    /// Project kind (`rust`, `node`, `python`, ...), informational.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<BoundedText<32>>,
}

/// `.agentguard/config.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfigFile {
    /// Format version; must be [`CONFIG_VERSION`].
    pub version: u32,
    /// Metadata.
    #[serde(default)]
    pub project: ProjectMetadata,
    /// The security profile the project expects. Checked against the effective profile; only
    /// the global policy selects it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileName>,
    /// Proposed restrictions (`DENY` or `REQUIRE_APPROVAL` only).
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Proposed sensitive-resource additions (protected patterns, detectors, scan
    /// exclusions). Like `rules`, applied only once a human approves them; they can only add
    /// protection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<agentguard_engine::SensitiveConfig>,
    /// Integration preferences for later phases, kept opaque.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub integrations: BTreeMap<String, serde_yaml::Value>,
}

/// Which file a configuration came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "format", content = "path")]
pub enum ConfigSource {
    /// `.agentguard/config.yaml`.
    ConfigYaml(PathBuf),
    /// `.agent-security.yml`.
    Legacy(PathBuf),
}

/// A loaded and validated configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedConfig {
    /// Where it came from.
    pub source: ConfigSource,
    /// The configuration (legacy files are mapped onto the same shape).
    pub config: ProjectConfigFile,
}

impl LoadedConfig {
    /// The proposed project policy layer.
    #[must_use]
    pub fn policy(&self) -> PolicyDocument {
        PolicyDocument {
            rules: self.config.rules.clone(),
            profile: None,
            approvals: None,
            sensitive: self.config.sensitive.clone(),
            execution: None,
        }
    }
}

const CONFIG_LABEL: &str = ".agentguard/config.yaml";
const LEGACY_LABEL: &str = ".agent-security.yml";

/// `Ok(true)` if `path` is a regular file, `Ok(false)` if absent, an error if anything else.
fn regular_file(path: &Path, label: &'static str) -> Result<bool, ProjectConfigError> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(_) => Err(ProjectConfigError::Io {
            path: label,
            action: "inspected",
        }),
        Ok(meta) if meta.file_type().is_file() => Ok(true),
        Ok(_) => Err(ProjectConfigError::Insecure {
            path: label,
            rule: "must be a regular file, not a symlink or directory",
        }),
    }
}

fn config_dir_state(root: &NormalizedPath) -> Result<bool, ProjectConfigError> {
    match fs::symlink_metadata(root.as_path().join(CONFIG_DIR)) {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(_) => Err(ProjectConfigError::Io {
            path: CONFIG_DIR,
            action: "inspected",
        }),
        Ok(meta) if meta.file_type().is_dir() => Ok(true),
        Ok(_) => Err(ProjectConfigError::Insecure {
            path: CONFIG_DIR,
            rule: "must be a directory, not a symlink",
        }),
    }
}

/// Find the project configuration without reading it.
pub fn locate_project_config(
    root: &NormalizedPath,
) -> Result<Option<ConfigSource>, ProjectConfigError> {
    let config_path = root.as_path().join(CONFIG_DIR).join(CONFIG_FILE);
    let has_config = config_dir_state(root)? && regular_file(&config_path, CONFIG_LABEL)?;
    let legacy_path = root.as_path().join(POLICY_FILE_NAME);
    let has_legacy = regular_file(&legacy_path, LEGACY_LABEL)?;
    match (has_config, has_legacy) {
        (true, true) => Err(ProjectConfigError::Ambiguous),
        (true, false) => Ok(Some(ConfigSource::ConfigYaml(config_path))),
        (false, true) => Ok(Some(ConfigSource::Legacy(legacy_path))),
        (false, false) => Ok(None),
    }
}

fn read_text(path: &Path, label: &'static str) -> Result<String, ProjectConfigError> {
    config::read_limited(path).map_err(|_| ProjectConfigError::Io {
        path: label,
        action: "read",
    })
}

fn validate(config: &ProjectConfigFile, label: &'static str) -> Result<(), ProjectConfigError> {
    if config.version != CONFIG_VERSION {
        return Err(ProjectConfigError::Invalid {
            path: label,
            message: format!(
                "unsupported version {}; expected {CONFIG_VERSION}",
                config.version
            ),
        });
    }
    validate_document(
        Layer::Project,
        &PolicyDocument {
            rules: config.rules.clone(),
            profile: None,
            approvals: None,
            sensitive: config.sensitive.clone(),
            execution: None,
        },
    )
    .map_err(|e| ProjectConfigError::Invalid {
        path: label,
        message: e.to_string(),
    })
}

/// Parse and validate configuration text (`.agentguard/config.yaml` format).
pub fn parse_project_config(text: &str) -> Result<ProjectConfigFile, ProjectConfigError> {
    let config: ProjectConfigFile =
        serde_yaml::from_str(text).map_err(|e| ProjectConfigError::Parse {
            path: CONFIG_LABEL,
            message: e.to_string(),
        })?;
    validate(&config, CONFIG_LABEL)?;
    Ok(config)
}

fn load_legacy(path: &Path) -> Result<ProjectConfigFile, ProjectConfigError> {
    let text = read_text(path, LEGACY_LABEL)?;
    let parsed = config::parse_str(path, &text).map_err(|e| ProjectConfigError::Parse {
        path: LEGACY_LABEL,
        message: e.to_string(),
    })?;
    let ProjectConfig::V1(v1) = parsed else {
        return Err(ProjectConfigError::Invalid {
            path: LEGACY_LABEL,
            message: "unsupported version".into(),
        });
    };
    let rules: Vec<Rule> = match v1.rules {
        None | Some(serde_yaml::Value::Null) => Vec::new(),
        Some(value) => serde_yaml::from_value(value).map_err(|e| ProjectConfigError::Parse {
            path: LEGACY_LABEL,
            message: e.to_string(),
        })?,
    };
    let config = ProjectConfigFile {
        version: CONFIG_VERSION,
        project: ProjectMetadata::default(),
        profile: None,
        rules,
        sensitive: None,
        integrations: BTreeMap::new(),
    };
    validate(&config, LEGACY_LABEL)?;
    Ok(config)
}

/// Load and validate the project configuration. `Ok(None)` when the project has none.
pub fn load_project_config(
    root: &NormalizedPath,
) -> Result<Option<LoadedConfig>, ProjectConfigError> {
    let Some(source) = locate_project_config(root)? else {
        return Ok(None);
    };
    let config = match &source {
        ConfigSource::ConfigYaml(path) => parse_project_config(&read_text(path, CONFIG_LABEL)?)?,
        ConfigSource::Legacy(path) => load_legacy(path)?,
    };
    Ok(Some(LoadedConfig { source, config }))
}

const TEMPLATE_HEADER: &str = "\
# AI Defender project configuration. This file is UNTRUSTED input.
#
# Restrictions listed under `rules` are a proposal: they take effect only after a human approves
# them (`ai-defender init` or `ai-defender project trust`), which copies them into AI Defender's
# signed trust store. Editing this file later changes nothing until it is approved again.
# Projects can only add restrictions (DENY or REQUIRE_APPROVAL); they cannot allow anything the
# global policy and the mandatory baseline do not. `profile` is an expectation that is checked
# against the profile selected by the global policy. Never put secrets in this file.
#
# Rule example:
#   rules:
#     - id: migrations-need-review
#       decision: REQUIRE_APPROVAL
#       reason: schema changes need a DBA
#       match:
#         category: filesystem
#         resource: \"db/migrations/**\"
#         conditions:
#           - capability: write
#
# Sensitive files and secret detection (additions only):
#   sensitive:
#     protected_patterns: [\"config/keys/**\", \"*.secret\"]
#     scan_exclusions: [\"fixtures/**\"]   # still reported as excluded, never as clean
# Full schema: docs/POLICY_EVALUATION.md (rules) and docs/CLI.md (this file).
";

/// Write a new `.agentguard/config.yaml`. Refuses if any project configuration exists; never
/// writes through a symlink. Returns the path written.
pub fn write_initial_config(
    root: &NormalizedPath,
    metadata: ProjectMetadata,
    profile: ProfileName,
) -> Result<PathBuf, ProjectConfigError> {
    if locate_project_config(root)?.is_some() {
        return Err(ProjectConfigError::Exists);
    }
    let dir = root.as_path().join(CONFIG_DIR);
    if !config_dir_state(root)? {
        DirBuilder::new()
            .unix_mode(0o755)
            .create(&dir)
            .map_err(|_| ProjectConfigError::Io {
                path: CONFIG_DIR,
                action: "created",
            })?;
    }
    let config = ProjectConfigFile {
        version: CONFIG_VERSION,
        project: metadata,
        profile: Some(profile),
        rules: Vec::new(),
        sensitive: None,
        integrations: BTreeMap::new(),
    };
    let body = serde_yaml::to_string(&config).map_err(|e| ProjectConfigError::Invalid {
        path: CONFIG_LABEL,
        message: e.to_string(),
    })?;
    // Round-trip what will be written so a template bug can never produce an invalid file.
    parse_project_config(&body)?;
    let path = dir.join(CONFIG_FILE);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .unix_mode(0o644)
        .open_no_follow(&path)
        .map_err(|e| {
            if e.kind() == ErrorKind::AlreadyExists {
                ProjectConfigError::Exists
            } else {
                ProjectConfigError::Io {
                    path: CONFIG_LABEL,
                    action: "created",
                }
            }
        })?;
    file.write_all(TEMPLATE_HEADER.as_bytes())
        .and_then(|()| file.write_all(body.as_bytes()))
        .and_then(|()| file.sync_all())
        .map_err(|_| ProjectConfigError::Io {
            path: CONFIG_LABEL,
            action: "written",
        })?;
    Ok(path)
}

/// Read the proposed project policy. `Ok(None)` when the project has no configuration.
pub fn read_project_policy(root: &NormalizedPath) -> Result<Option<PolicyDocument>, TrustError> {
    Ok(load_project_config(root)?.map(|loaded| loaded.policy()))
}

/// Whether the project's configuration differs from the approved policy. A missing file and an
/// empty rule list both mean "no restrictions proposed". An unreadable, malformed or ambiguous
/// configuration counts as drift.
#[must_use]
pub fn has_drift(root: &NormalizedPath, approved: Option<&ContentHash>) -> bool {
    let empty = ContentHash::of(&PolicyDocument::default()).ok();
    let proposed = match read_project_policy(root) {
        Ok(Some(doc)) => ContentHash::of(&doc).ok(),
        Ok(None) => empty,
        Err(_) => return true,
    };
    let approved = approved.copied().or(empty);
    proposed != approved
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> (tempfile::TempDir, NormalizedPath) {
        let dir = tempfile::tempdir().unwrap();
        let p = NormalizedPath::new(
            agentguard_platform::fs::canonicalize(dir.path())
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap();
        (dir, p)
    }

    fn meta() -> ProjectMetadata {
        ProjectMetadata {
            name: Some(BoundedText::new("demo \"app\"").unwrap()),
            kind: Some(BoundedText::new("rust").unwrap()),
        }
    }

    #[test]
    fn writes_valid_config_once() {
        let (_d, r) = root();
        let path = write_initial_config(&r, meta(), ProfileName::Balanced).unwrap();
        let loaded = load_project_config(&r).unwrap().unwrap();
        assert_eq!(loaded.source, ConfigSource::ConfigYaml(path));
        assert_eq!(loaded.config.project.name.unwrap().as_str(), "demo \"app\"");
        assert_eq!(
            write_initial_config(&r, meta(), ProfileName::Balanced),
            Err(ProjectConfigError::Exists)
        );
    }

    #[test]
    fn rejects_allow_rules_unknown_fields_and_versions() {
        for text in [
            "version: 1\nrules:\n  - id: x\n    decision: ALLOW\n    reason: r\n    match: { category: terminal }\n",
            "version: 1\nbypass: true\n",
            "version: 2\n",
            "version: 1\nprofile: yolo\n",
        ] {
            assert!(parse_project_config(text).is_err(), "{text}");
        }
        assert!(parse_project_config("version: 1\nrules:\n  - id: x\n    decision: DENY\n    reason: r\n    match: { category: network }\n").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_configuration_is_refused() {
        let (_d, r) = root();
        let elsewhere = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), r.as_path().join(CONFIG_DIR)).unwrap();
        assert!(matches!(
            locate_project_config(&r),
            Err(ProjectConfigError::Insecure { .. })
        ));
        assert!(write_initial_config(&r, meta(), ProfileName::Balanced).is_err());
        assert!(
            !elsewhere.path().join(CONFIG_FILE).exists(),
            "nothing written through the link"
        );
    }

    #[test]
    fn ambiguous_configuration_is_refused() {
        let (_d2, r2) = root();
        fs::create_dir(r2.as_path().join(CONFIG_DIR)).unwrap();
        fs::write(
            r2.as_path().join(CONFIG_DIR).join(CONFIG_FILE),
            "version: 1\n",
        )
        .unwrap();
        fs::write(
            r2.as_path().join(POLICY_FILE_NAME),
            "version: 1\nmode: DEVELOPMENT\n",
        )
        .unwrap();
        assert_eq!(
            locate_project_config(&r2),
            Err(ProjectConfigError::Ambiguous)
        );
    }

    #[test]
    fn legacy_file_is_read_when_alone() {
        let (_d, r) = root();
        fs::write(
            r.as_path().join(POLICY_FILE_NAME),
            "version: 1\nmode: DEVELOPMENT\nrules: []\n",
        )
        .unwrap();
        let loaded = load_project_config(&r).unwrap().unwrap();
        assert!(matches!(loaded.source, ConfigSource::Legacy(_)));
        assert_eq!(
            write_initial_config(&r, meta(), ProfileName::Balanced),
            Err(ProjectConfigError::Exists)
        );
    }
}
