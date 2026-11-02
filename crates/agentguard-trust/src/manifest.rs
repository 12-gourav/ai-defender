//! Signed policy manifests.
//!
//! A manifest carries one policy layer (the global organisation/user policy, or one project's
//! approved restrictions), its version, the hash of the version it replaces, and who authorised
//! it. Manifests are immutable once written; an update writes a new version.

use std::time::Duration;

use agentguard_core::{ApprovalTiming, BoundedText, Name, ProjectId};
use agentguard_engine::{ProfileSettings, Rule};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::canonical::{ContentHash, Signed, VersionRef};
use crate::crypto::{PublicKey, Purpose};
use crate::error::TrustError;

/// Schema identifier of a manifest.
pub const MANIFEST_SCHEMA: &str = "agentguard.policy-manifest.v1";
/// Upper bound on rules in one policy layer.
pub const MAX_RULES: usize = 1000;

/// Which layer a manifest holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyScope {
    /// The trusted organisation/user policy, applied to every project.
    Global,
    /// One project's approved restrictions.
    Project(ProjectId),
}

impl PolicyScope {
    /// Name used in errors and audit records.
    #[must_use]
    pub const fn object(self) -> &'static str {
        match self {
            PolicyScope::Global => "global policy manifest",
            PolicyScope::Project(_) => "project policy manifest",
        }
    }
}

/// The content of one policy layer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    /// The layer's rules.
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Security profile selection and settings (global layer only). Omitted from the canonical
    /// form when absent, so documents written before profiles existed keep their signatures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileSettings>,
    /// Approval timing (global layer only). Omitted when absent, like `profile`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approvals: Option<ApprovalSettings>,
    /// Sensitive-resource configuration: protected patterns, custom detectors, scan
    /// exclusions. Allowed in both layers because every entry only adds protection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<agentguard_engine::SensitiveConfig>,
    /// Managed execution settings (global layer only). Omitted when absent, like `profile`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<ExecutionSettings>,
}

/// Hard maximum time limit of one managed execution, in seconds.
pub const MAX_EXECUTION_TIMEOUT_SECONDS: u64 = 3600;
/// Default time limit of one managed execution, in seconds.
pub const DEFAULT_EXECUTION_TIMEOUT_SECONDS: u64 = 600;
/// Most extra environment variable names a policy may pass through.
pub const MAX_EXTRA_ENVIRONMENT: usize = 64;

/// Managed execution settings, set by the trusted global policy only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionSettings {
    /// Environment profile used when a request names none: `minimal` or `development`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_profile: Option<String>,
    /// Time limit used when a request states none, in seconds (1 to 3600).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_timeout_seconds: Option<u64>,
    /// Extra variable names the `development` profile passes through. Names that look like
    /// credentials or that inject code are refused (see `agentguard_core::envvars`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environment: Vec<String>,
}

impl ExecutionSettings {
    /// Reject settings that are malformed or would weaken environment isolation.
    pub fn validate(&self) -> Result<(), &'static str> {
        if let Some(p) = &self.default_profile {
            if !matches!(p.as_str(), "minimal" | "development") {
                return Err("execution.default_profile must be minimal or development");
            }
        }
        if let Some(t) = self.default_timeout_seconds {
            if t == 0 || t > MAX_EXECUTION_TIMEOUT_SECONDS {
                return Err("execution.default_timeout_seconds must be between 1 and 3600");
            }
        }
        if self.environment.len() > MAX_EXTRA_ENVIRONMENT {
            return Err("execution.environment lists too many names");
        }
        if self
            .environment
            .iter()
            .any(|n| !agentguard_core::envvars::may_pass(n))
        {
            return Err(
                "execution.environment may not name credentials or variables that inject code",
            );
        }
        Ok(())
    }
}

/// Approval timing set by the trusted global policy. Each value may only shorten the default
/// up to the hard maximums in [`ApprovalTiming`]; a project or an agent cannot set either.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSettings {
    /// How long a pending request waits for a human, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_timeout_seconds: Option<u64>,
    /// How long an issued grant stays valid, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_validity_seconds: Option<u64>,
}

impl ApprovalSettings {
    /// The timing these settings select, within the hard bounds.
    pub fn timing(&self) -> Result<ApprovalTiming, &'static str> {
        let defaults = ApprovalTiming::default();
        ApprovalTiming::new(
            self.pending_timeout_seconds
                .map_or(defaults.pending_timeout, Duration::from_secs),
            self.grant_validity_seconds
                .map_or(defaults.token_validity, Duration::from_secs),
        )
        .map_err(|_| "approval timeouts must be between 1 second and the hard maximums (pending 900 s, grant 300 s)")
    }
}

impl PolicyDocument {
    /// The approval timing this (global) document selects. Fails closed: invalid settings are
    /// rejected when the document is validated, so this only falls back for documents that
    /// predate the field.
    pub fn approval_timing(&self) -> Result<ApprovalTiming, &'static str> {
        self.approvals.unwrap_or_default().timing()
    }
}

/// A versioned, attributed policy layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestBody {
    /// Always [`MANIFEST_SCHEMA`].
    pub schema: String,
    /// Which layer.
    pub scope: PolicyScope,
    /// Monotonic version, starting at 1.
    pub sequence: u64,
    /// Body hash of the version this one replaces.
    pub previous: Option<ContentHash>,
    /// The policy.
    pub policy: PolicyDocument,
    /// Hash of `policy`, so the policy can be referenced independently of its manifest.
    pub policy_hash: ContentHash,
    /// Why it changed.
    pub reason: BoundedText<256>,
    /// The human who authorised it, as named by the trusted channel.
    pub authorized_by: Name,
    /// When it was issued.
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
}

/// Verify a manifest: signed by a trusted key, for the expected scope, internally consistent,
/// and exactly the pinned version.
pub fn verify_manifest<'a>(
    signed: &'a Signed<ManifestBody>,
    signers: &[PublicKey],
    scope: PolicyScope,
    pinned: &VersionRef,
) -> Result<&'a ManifestBody, TrustError> {
    let object = scope.object();
    let body = signed.verify(Purpose::PolicyManifest, signers, object)?;
    if body.schema != MANIFEST_SCHEMA {
        return Err(TrustError::Malformed { object });
    }
    if body.scope != scope {
        return Err(TrustError::Inconsistent {
            object,
            rule: "manifest is for a different scope",
        });
    }
    if body.policy_hash != ContentHash::of(&body.policy)? {
        return Err(TrustError::Inconsistent {
            object,
            rule: "policy hash does not match the policy",
        });
    }
    if body.policy.rules.len() > MAX_RULES {
        return Err(TrustError::Inconsistent {
            object,
            rule: "too many rules",
        });
    }
    pinned.check(
        object,
        &VersionRef {
            sequence: body.sequence,
            hash: signed.body_hash()?,
        },
    )?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Ed25519Signer, Signer};
    use zeroize::Zeroizing;

    fn body(scope: PolicyScope, seq: u64) -> ManifestBody {
        let policy = PolicyDocument::default();
        ManifestBody {
            schema: MANIFEST_SCHEMA.to_owned(),
            scope,
            sequence: seq,
            previous: None,
            policy_hash: ContentHash::of(&policy).unwrap(),
            policy,
            reason: BoundedText::new("initial").unwrap(),
            authorized_by: Name::new("dev").unwrap(),
            issued_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn verifies_scope_hash_and_pin() {
        let s = Ed25519Signer::from_seed(&Zeroizing::new([5; 32]));
        let keys = [s.public_key()];
        let signed =
            Signed::sign(body(PolicyScope::Global, 1), Purpose::PolicyManifest, &s).unwrap();
        let pin = VersionRef {
            sequence: 1,
            hash: signed.body_hash().unwrap(),
        };
        assert!(verify_manifest(&signed, &keys, PolicyScope::Global, &pin).is_ok());
        let project = PolicyScope::Project(ProjectId::from_hex(&"ab".repeat(32)).unwrap());
        assert!(matches!(
            verify_manifest(&signed, &keys, project, &pin),
            Err(TrustError::Inconsistent { .. })
        ));

        let mut bad = body(PolicyScope::Global, 1);
        bad.policy_hash = ContentHash::of(&"other").unwrap();
        let signed_bad = Signed::sign(bad, Purpose::PolicyManifest, &s).unwrap();
        let pin_bad = VersionRef {
            sequence: 1,
            hash: signed_bad.body_hash().unwrap(),
        };
        assert!(verify_manifest(&signed_bad, &keys, PolicyScope::Global, &pin_bad).is_err());
    }
}
