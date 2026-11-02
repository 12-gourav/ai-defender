//! Version 1 of the project policy document: top-level shape only.
//!
//! Every known section is accepted as an opaque YAML mapping so a well-formed Phase 2 policy
//! file already passes Phase 1 structural checks, while unknown top-level keys are rejected
//! because an unrecognised security key must never be silently ignored.

use agentguard_core::PermissionLevel;
use serde::{Deserialize, Deserializer};
use serde_yaml::Value;

use super::{Problem, Validate, ValidationReport};

/// Top-level document, format version 1.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfigV1 {
    /// Format version; always 1 here.
    pub version: u32,
    /// Security mode.
    pub mode: PermissionLevel,
    /// Optional named profile.
    #[serde(default)]
    pub profile: Option<String>,
    /// Filesystem rules (opaque until Phase 2).
    #[serde(default, deserialize_with = "section")]
    pub filesystem: Option<Value>,
    /// Command rules (opaque until Phase 2).
    #[serde(default, deserialize_with = "section")]
    pub commands: Option<Value>,
    /// Git rules (opaque until Phase 2).
    #[serde(default, deserialize_with = "section")]
    pub git: Option<Value>,
    /// Network rules (opaque until Phase 2).
    #[serde(default, deserialize_with = "section")]
    pub network: Option<Value>,
    /// Dependency rules (opaque until Phase 2).
    #[serde(default, deserialize_with = "section")]
    pub dependencies: Option<Value>,
    /// Database rules (opaque until Phase 2).
    #[serde(default, deserialize_with = "section")]
    pub databases: Option<Value>,
    /// Deployment rules (opaque until Phase 2).
    #[serde(default, deserialize_with = "section")]
    pub deployment: Option<Value>,
    /// Agent-specific settings (opaque until Phase 2).
    #[serde(default, deserialize_with = "section")]
    pub agents: Option<Value>,
    /// Approval settings (opaque until Phase 2).
    #[serde(default, deserialize_with = "section")]
    pub approvals: Option<Value>,
    /// Audit settings (opaque until Phase 2).
    #[serde(default, deserialize_with = "section")]
    pub audit: Option<Value>,
    /// Sandbox settings (opaque until Phase 2).
    #[serde(default, deserialize_with = "section")]
    pub sandbox: Option<Value>,
    /// Project restriction rules, a list. Parsed and enforced by the trust layer, and only
    /// after a human approves them; the repository copy is a proposal.
    #[serde(default, deserialize_with = "section")]
    pub rules: Option<Value>,
}

/// Deserialise a section so that an explicit `null` is kept as `Some(Value::Null)` rather than
/// collapsing to `None`; the two parse paths (text and value) then agree and an empty section
/// is reported as a warning on both.
fn section<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}

/// Section names in document order.
pub const SECTION_NAMES: &[&str] = &[
    "filesystem",
    "commands",
    "git",
    "network",
    "dependencies",
    "databases",
    "deployment",
    "agents",
    "approvals",
    "audit",
    "sandbox",
];

impl ProjectConfigV1 {
    fn sections(&self) -> [(&'static str, &Option<Value>); 11] {
        [
            ("filesystem", &self.filesystem),
            ("commands", &self.commands),
            ("git", &self.git),
            ("network", &self.network),
            ("dependencies", &self.dependencies),
            ("databases", &self.databases),
            ("deployment", &self.deployment),
            ("agents", &self.agents),
            ("approvals", &self.approvals),
            ("audit", &self.audit),
            ("sandbox", &self.sandbox),
        ]
    }

    /// Names of the sections present.
    #[must_use]
    pub fn present_sections(&self) -> Vec<&'static str> {
        self.sections()
            .into_iter()
            .filter(|(_, v)| v.is_some())
            .map(|(n, _)| n)
            .chain(self.rules.as_ref().map(|_| "rules"))
            .collect()
    }
}

fn valid_profile_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

impl Validate for ProjectConfigV1 {
    fn validate(&self) -> ValidationReport {
        let mut problems = Vec::new();
        if self.version != 1 {
            problems.push(Problem::error(
                "version",
                "must be 1 for this document shape",
            ));
        }
        if let Some(profile) = &self.profile {
            if !valid_profile_name(profile) {
                problems.push(Problem::error(
                    "profile",
                    "must be 1 to 64 characters of letters, digits, '-' or '_'",
                ));
            }
        }
        for (name, value) in self.sections() {
            match value {
                Some(Value::Mapping(_)) | None => {}
                Some(Value::Null) => {
                    problems.push(Problem::warning(name, "section is present but empty"));
                }
                Some(_) => {
                    problems.push(Problem::error(name, "section must be a mapping"));
                }
            }
        }
        match &self.rules {
            Some(Value::Sequence(_)) | None => {}
            Some(Value::Null) => {
                problems.push(Problem::warning("rules", "section is present but empty"));
            }
            Some(_) => problems.push(Problem::error("rules", "must be a list of rules")),
        }
        ValidationReport { problems }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> ProjectConfigV1 {
        serde_yaml::from_str(text).unwrap()
    }

    #[test]
    fn all_sections_as_mappings_validate_clean() {
        let mut text = "version: 1\nmode: RESTRICTED\nprofile: strict\n".to_owned();
        for s in SECTION_NAMES {
            text.push_str(s);
            text.push_str(":\n  key: value\n");
        }
        let cfg = parse(&text);
        assert_eq!(cfg.present_sections(), SECTION_NAMES);
        let report = cfg.validate();
        assert!(report.problems.is_empty(), "{report:?}");
    }

    #[test]
    fn scalar_section_is_error_and_null_is_warning() {
        let cfg = parse("version: 1\nmode: DEVELOPMENT\ngit: 5\nnetwork:\n");
        let report = cfg.validate();
        assert!(report.has_errors());
        assert_eq!(report.errors().len(), 1);
        assert_eq!(report.errors()[0].path, "git");
        assert_eq!(report.warnings().len(), 1);
        assert_eq!(report.warnings()[0].path, "network");
    }

    #[test]
    fn profile_name_rules() {
        assert_eq!(
            parse("version: 1\nmode: DEVELOPMENT\nprofile: ok-name_1\n")
                .validate()
                .problems,
            Vec::new()
        );
        assert!(
            parse("version: 1\nmode: DEVELOPMENT\nprofile: 'bad name'\n")
                .validate()
                .has_errors()
        );
        assert!(parse("version: 1\nmode: DEVELOPMENT\nprofile: ''\n")
            .validate()
            .has_errors());
    }

    #[test]
    fn rules_must_be_a_list() {
        let ok = parse("version: 1\nmode: DEVELOPMENT\nrules:\n  - id: x\n");
        assert!(!ok.validate().has_errors());
        assert!(ok.present_sections().contains(&"rules"));
        let bad = parse("version: 1\nmode: DEVELOPMENT\nrules:\n  id: x\n");
        assert_eq!(bad.validate().errors()[0].path, "rules");
    }

    #[test]
    fn unknown_field_rejected_at_parse() {
        let r: Result<ProjectConfigV1, _> =
            serde_yaml::from_str("version: 1\nmode: DEVELOPMENT\nextra: 1\n");
        assert!(r.is_err());
    }
}
