//! The integrity state: the single signed pointer to every current trusted object.
//!
//! It pins the root key ID and the exact version (sequence and body hash) of the key set, the
//! global policy manifest and the project registry; the registry in turn pins each project's
//! approved manifest. Every trusted object is therefore reachable from one signed value, and
//! any object that is missing, older, newer or different from what it pins is detected.
//!
//! The high-water mark records the highest integrity sequence ever committed. Replacing the
//! integrity state with an older (validly signed) copy is detected as long as the mark is
//! intact; see the known limitations for an attacker who rewrites both.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::canonical::VersionRef;
use crate::crypto::KeyId;
use crate::error::TrustError;

/// Schema identifier of the integrity state.
pub const INTEGRITY_SCHEMA: &str = "agentguard.integrity.v1";
/// Schema identifier of the high-water mark.
pub const HIGH_WATER_SCHEMA: &str = "agentguard.integrity-high-water.v1";

/// Pins every current trusted object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrityBody {
    /// Always [`INTEGRITY_SCHEMA`].
    pub schema: String,
    /// Monotonic version, incremented by every committed trust change.
    pub sequence: u64,
    /// The root key this state was created under.
    pub root_key: KeyId,
    /// Current key set.
    pub keyset: VersionRef,
    /// Current global policy manifest.
    pub global_policy: VersionRef,
    /// Current project registry.
    pub registry: VersionRef,
    /// When this version was issued.
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
}

impl IntegrityBody {
    /// Check the schema and sequence.
    pub fn validate(&self) -> Result<(), TrustError> {
        if self.schema != INTEGRITY_SCHEMA {
            return Err(TrustError::Malformed {
                object: "integrity state",
            });
        }
        if self.sequence == 0 {
            return Err(TrustError::Inconsistent {
                object: "integrity state",
                rule: "sequence starts at 1",
            });
        }
        Ok(())
    }

    /// The next version of this state with the given changes applied.
    #[must_use]
    pub fn next(
        &self,
        keyset: Option<VersionRef>,
        global_policy: Option<VersionRef>,
        registry: Option<VersionRef>,
        issued_at: OffsetDateTime,
    ) -> Self {
        Self {
            schema: INTEGRITY_SCHEMA.to_owned(),
            sequence: self.sequence + 1,
            root_key: self.root_key,
            keyset: keyset.unwrap_or(self.keyset),
            global_policy: global_policy.unwrap_or(self.global_policy),
            registry: registry.unwrap_or(self.registry),
            issued_at,
        }
    }
}

/// The highest integrity sequence ever committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighWaterMark {
    /// Always [`HIGH_WATER_SCHEMA`].
    pub schema: String,
    /// Highest integrity sequence committed.
    pub sequence: u64,
    /// Highest key-set sequence committed, so a forged state cannot point back at a key set
    /// that still lists a rotated-out key.
    pub keyset_sequence: u64,
}

impl HighWaterMark {
    /// The mark for a committed integrity state.
    #[must_use]
    pub fn for_state(state: &IntegrityBody) -> Self {
        Self {
            schema: HIGH_WATER_SCHEMA.to_owned(),
            sequence: state.sequence,
            keyset_sequence: state.keyset.sequence,
        }
    }

    /// Reject an integrity state older than the mark. A newer one is accepted: the commit
    /// writes the integrity state before raising the mark, so a crash between the two leaves
    /// the state ahead of the mark, never behind it.
    pub fn check(&self, state: &IntegrityBody) -> Result<(), TrustError> {
        if self.schema != HIGH_WATER_SCHEMA {
            return Err(TrustError::Malformed {
                object: "integrity high-water mark",
            });
        }
        if state.sequence < self.sequence {
            return Err(TrustError::Rollback {
                object: "integrity state",
                found: state.sequence,
                pinned: self.sequence,
            });
        }
        if state.keyset.sequence < self.keyset_sequence {
            return Err(TrustError::Rollback {
                object: "key set",
                found: state.keyset.sequence,
                pinned: self.keyset_sequence,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::canonical::ContentHash;
    use crate::crypto::{Ed25519Signer, Signer};
    use zeroize::Zeroizing;

    fn state(sequence: u64, keyset: u64) -> IntegrityBody {
        let pin = |sequence| VersionRef {
            sequence,
            hash: ContentHash::of(&0u8).unwrap(),
        };
        IntegrityBody {
            schema: INTEGRITY_SCHEMA.to_owned(),
            sequence,
            root_key: Ed25519Signer::from_seed(&Zeroizing::new([1; 32]))
                .public_key()
                .key_id(),
            keyset: pin(keyset),
            global_policy: pin(1),
            registry: pin(1),
            issued_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn high_water_rejects_only_older() {
        let mark = HighWaterMark::for_state(&state(5, 2));
        assert!(mark.check(&state(5, 2)).is_ok());
        assert!(mark.check(&state(6, 3)).is_ok());
        assert!(matches!(
            mark.check(&state(4, 2)),
            Err(TrustError::Rollback {
                found: 4,
                pinned: 5,
                ..
            })
        ));
        assert!(matches!(
            mark.check(&state(9, 1)),
            Err(TrustError::Rollback {
                object: "key set",
                ..
            })
        ));
    }
}
