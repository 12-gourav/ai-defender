//! Sensitive resources: finer-grained categories, trusted configuration, and the detectors the
//! engine uses to inspect content.
//!
//! Sensitivity comes from three sources, strongest first:
//! 1. **Configured patterns** from trusted policy (`sensitive.protected_patterns`): a matching
//!    path is treated as a credential file whatever its name. Global and project policy may
//!    both add patterns; adding protection can only tighten.
//! 2. **Names**: the resource classifier's file-name rules (`.env*`, `id_*`, `*.pem`,
//!    `.aws/credentials`, `*.tfstate`, ...).
//! 3. **Content**: detected secrets in an otherwise ordinary file make it
//!    [`SensitiveCategory::SourceWithSecrets`] (see [`crate::content`]).

use std::fmt;
use std::sync::{Arc, LazyLock};

use agentguard_secrets::{CustomDetector, DetectorSet, SecretCategory, Severity};
use serde::{Deserialize, Serialize};

use crate::pattern::Pattern;
use crate::resource::{ResourceClassification, ResourceKind};

/// What kind of sensitive material a resource holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SensitiveCategory {
    /// `.env` files and environment configuration.
    EnvironmentConfig,
    /// Private keys, keystores and signing material.
    PrivateKeyMaterial,
    /// Cloud and cluster credentials (`.aws`, `.kube`, `.azure`, `gcloud`, service accounts).
    CloudCredential,
    /// Infrastructure state and variable files that commonly hold secrets (`*.tfstate`,
    /// `*.tfvars`).
    InfrastructureState,
    /// Application credential files (`.netrc`, `.npmrc`, `credentials.*`, `secrets.*`).
    ApplicationCredential,
    /// A secret store entry.
    SecretStore,
    /// An ordinary file in which a secret was detected.
    SourceWithSecrets,
    /// Matched a protected pattern from trusted configuration.
    ConfiguredProtected,
}

impl SensitiveCategory {
    /// Kebab-case name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            SensitiveCategory::EnvironmentConfig => "environment-config",
            SensitiveCategory::PrivateKeyMaterial => "private-key-material",
            SensitiveCategory::CloudCredential => "cloud-credential",
            SensitiveCategory::InfrastructureState => "infrastructure-state",
            SensitiveCategory::ApplicationCredential => "application-credential",
            SensitiveCategory::SecretStore => "secret-store",
            SensitiveCategory::SourceWithSecrets => "source-with-secrets",
            SensitiveCategory::ConfiguredProtected => "configured-protected",
        }
    }

    /// Whether this is a sensitive *location* (as opposed to content found in ordinary code).
    #[must_use]
    pub const fn is_protected_resource(self) -> bool {
        !matches!(self, SensitiveCategory::SourceWithSecrets)
    }
}

impl fmt::Display for SensitiveCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A custom detector from trusted configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomDetectorSpec {
    /// 1 to 64 of `[a-z0-9-]`; reported as `custom:<id>`.
    pub id: String,
    /// A `regex` pattern (linear time; at most 512 characters). Group 1, when present, is the
    /// secret value.
    pub pattern: String,
    /// Category reported for matches.
    #[serde(default = "custom_category")]
    pub category: SecretCategory,
    /// Severity reported for matches.
    #[serde(default = "high")]
    pub severity: Severity,
    /// A public, fixed prefix of the value that may be shown in redacted output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_prefix: Option<String>,
}

const fn custom_category() -> SecretCategory {
    SecretCategory::Custom
}

const fn high() -> Severity {
    Severity::High
}

/// Most protected patterns, custom detectors and exclusions per layer.
pub const MAX_SENSITIVE_ENTRIES: usize = 256;
/// Most custom detectors per layer.
pub const MAX_CUSTOM_DETECTORS: usize = 32;

/// Sensitive-resource configuration in a policy layer. Every field only adds protection or
/// detection (or, for exclusions, changes what a scan reports, never what policy allows), so
/// both the global and the project layer may carry it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SensitiveConfig {
    /// Paths treated as credential files: project-relative globs (`config/keys/**`), absolute
    /// globs, or bare names matched at any depth (`*.secret`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected_patterns: Vec<Pattern>,
    /// Extra detectors.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detectors: Vec<CustomDetectorSpec>,
    /// Paths `agentguard secrets scan` excludes by default (always reported as excluded).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scan_exclusions: Vec<String>,
}

impl SensitiveConfig {
    /// Validate bounds and compile every detector.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.protected_patterns.len() > MAX_SENSITIVE_ENTRIES
            || self.scan_exclusions.len() > MAX_SENSITIVE_ENTRIES
        {
            return Err("too many sensitive-resource entries");
        }
        if self.detectors.len() > MAX_CUSTOM_DETECTORS {
            return Err("too many custom detectors");
        }
        for d in &self.detectors {
            compile(d)?;
        }
        if self
            .scan_exclusions
            .iter()
            .any(|e| agentguard_secrets::scan::glob_regex(e).is_err())
        {
            return Err("invalid scan exclusion pattern");
        }
        Ok(())
    }
}

fn compile(spec: &CustomDetectorSpec) -> Result<CustomDetector, &'static str> {
    CustomDetector::new(
        &spec.id,
        &spec.pattern,
        spec.category,
        spec.severity,
        spec.public_prefix.clone(),
    )
    .map_err(|_| "invalid custom detector (identifier [a-z0-9-], pattern at most 512 characters and within size limits)")
}

/// The merged sensitivity configuration an evaluation runs with.
#[derive(Clone)]
pub struct Sensitivity {
    config: SensitiveConfig,
    detectors: Arc<DetectorSet>,
    block_severity: Severity,
}

impl fmt::Debug for Sensitivity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sensitivity")
            .field("config", &self.config)
            .field("block_severity", &self.block_severity)
            .finish_non_exhaustive()
    }
}

/// The built-in detectors, compiled once per process.
static BUILTIN_DETECTORS: LazyLock<Arc<DetectorSet>> =
    LazyLock::new(|| Arc::new(DetectorSet::builtin()));

impl Default for Sensitivity {
    fn default() -> Self {
        Self {
            config: SensitiveConfig::default(),
            detectors: Arc::clone(&BUILTIN_DETECTORS),
            block_severity: Severity::High,
        }
    }
}

impl Sensitivity {
    /// Merge layers (union of every list) and compile the detectors.
    pub fn merge(layers: &[Option<&SensitiveConfig>]) -> Result<Self, &'static str> {
        let mut config = SensitiveConfig::default();
        for layer in layers.iter().flatten() {
            layer.validate()?;
            config
                .protected_patterns
                .extend(layer.protected_patterns.iter().cloned());
            config.detectors.extend(layer.detectors.iter().cloned());
            config
                .scan_exclusions
                .extend(layer.scan_exclusions.iter().cloned());
        }
        let detectors = if config.detectors.is_empty() {
            Arc::clone(&BUILTIN_DETECTORS)
        } else {
            let mut set = DetectorSet::builtin();
            for spec in &config.detectors {
                set.push(Box::new(compile(spec)?));
            }
            Arc::new(set)
        };
        Ok(Self {
            config,
            detectors,
            block_severity: Severity::High,
        })
    }

    /// The merged configuration (part of the policy version).
    #[must_use]
    pub const fn config(&self) -> &SensitiveConfig {
        &self.config
    }

    /// Built-in plus configured detectors.
    #[must_use]
    pub fn detectors(&self) -> &DetectorSet {
        &self.detectors
    }

    /// Detected secrets at or above this severity count as secret data for policy.
    #[must_use]
    pub const fn block_severity(&self) -> Severity {
        self.block_severity
    }

    /// Whether a target identifier matches a protected pattern.
    #[must_use]
    pub fn is_protected(&self, target: &str) -> bool {
        let name = target.rsplit('/').next().unwrap_or(target);
        self.config.protected_patterns.iter().any(|p| {
            p.matches(target, true) || (!p.as_str().contains('/') && p.matches(name, true))
        })
    }
}

fn category_from_name(kind: ResourceKind, targets: &[String]) -> Option<SensitiveCategory> {
    use SensitiveCategory as S;
    let lowered: Vec<String> = targets.iter().map(|t| t.to_ascii_lowercase()).collect();
    let any = |f: &dyn Fn(&str) -> bool| lowered.iter().any(|t| f(t));
    match kind {
        ResourceKind::EnvironmentFile => Some(S::EnvironmentConfig),
        ResourceKind::PrivateKey => Some(S::PrivateKeyMaterial),
        ResourceKind::SecretStore => Some(S::SecretStore),
        ResourceKind::CredentialFile => {
            let cloud = any(&|t| {
                [
                    ".aws/",
                    ".kube/",
                    ".azure/",
                    "gcloud/",
                    "service-account",
                    "kubeconfig",
                ]
                .iter()
                .any(|m| t.contains(m))
            });
            let keystore = any(&|t| {
                [".p12", ".pfx", ".jks", ".keystore"]
                    .iter()
                    .any(|s| t.ends_with(s))
            });
            Some(if cloud {
                S::CloudCredential
            } else if keystore {
                S::PrivateKeyMaterial
            } else {
                S::ApplicationCredential
            })
        }
        ResourceKind::Infrastructure
            if any(&|t| t.contains(".tfstate") || t.ends_with(".tfvars")) =>
        {
            Some(S::InfrastructureState)
        }
        _ => None,
    }
}

/// Apply configured patterns and name categories to a classification. A protected pattern
/// upgrades the kind to a credential file, so every credential-file rule applies to it.
pub fn categorize(resource: &mut ResourceClassification, sensitivity: &Sensitivity) {
    if resource.targets.iter().any(|t| sensitivity.is_protected(t)) {
        if !resource.kind.is_secret() {
            resource.kind = ResourceKind::CredentialFile;
        }
        resource.sensitive = Some(SensitiveCategory::ConfiguredProtected);
        return;
    }
    resource.sensitive = category_from_name(resource.kind, &resource.targets);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::ResourceLocation;

    fn res(kind: ResourceKind, target: &str) -> ResourceClassification {
        ResourceClassification {
            kind,
            location: ResourceLocation::InsideProject,
            identifier: target.to_owned(),
            targets: vec![target.to_owned()],
            uncertain: false,
            sensitive: None,
        }
    }

    #[test]
    fn categories_from_names() {
        let s = Sensitivity::default();
        for (kind, target, expected) in [
            (
                ResourceKind::EnvironmentFile,
                ".env.production",
                Some(SensitiveCategory::EnvironmentConfig),
            ),
            (
                ResourceKind::PrivateKey,
                "deploy/id_rsa",
                Some(SensitiveCategory::PrivateKeyMaterial),
            ),
            (
                ResourceKind::CredentialFile,
                "/home/u/.aws/credentials",
                Some(SensitiveCategory::CloudCredential),
            ),
            (
                ResourceKind::CredentialFile,
                "certs/app.p12",
                Some(SensitiveCategory::PrivateKeyMaterial),
            ),
            (
                ResourceKind::CredentialFile,
                ".npmrc",
                Some(SensitiveCategory::ApplicationCredential),
            ),
            (
                ResourceKind::Infrastructure,
                "infra/terraform.tfstate",
                Some(SensitiveCategory::InfrastructureState),
            ),
            (ResourceKind::Infrastructure, "infra/main.tf", None),
            (ResourceKind::SourceCode, "src/main.rs", None),
        ] {
            let mut r = res(kind, target);
            categorize(&mut r, &s);
            assert_eq!(r.sensitive, expected, "{target}");
        }
    }

    #[test]
    fn configured_patterns_upgrade_to_credentials() {
        let config = SensitiveConfig {
            protected_patterns: vec![
                Pattern::new("config/keys/**").unwrap(),
                Pattern::new("*.secret").unwrap(),
            ],
            ..SensitiveConfig::default()
        };
        let s = Sensitivity::merge(&[Some(&config)]).unwrap();
        for target in ["config/keys/signing.txt", "deep/dir/app.SECRET"] {
            let mut r = res(ResourceKind::SourceCode, target);
            categorize(&mut r, &s);
            assert_eq!(r.kind, ResourceKind::CredentialFile, "{target}");
            assert_eq!(r.sensitive, Some(SensitiveCategory::ConfiguredProtected));
        }
        let mut r = res(ResourceKind::SourceCode, "src/keys.rs");
        categorize(&mut r, &s);
        assert_eq!(r.kind, ResourceKind::SourceCode);
    }

    #[test]
    fn invalid_configuration_is_rejected() {
        let bad = SensitiveConfig {
            detectors: vec![CustomDetectorSpec {
                id: "x".into(),
                pattern: "(".into(),
                category: SecretCategory::Custom,
                severity: Severity::High,
                public_prefix: None,
            }],
            ..SensitiveConfig::default()
        };
        assert!(bad.validate().is_err());
        assert!(Sensitivity::merge(&[Some(&bad)]).is_err());
        let exclusions = SensitiveConfig {
            scan_exclusions: vec![String::new()],
            ..SensitiveConfig::default()
        };
        assert!(exclusions.validate().is_err());
    }
}
