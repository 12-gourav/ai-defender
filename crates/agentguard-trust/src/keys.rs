//! The root anchor and the policy-signing key set.
//!
//! The root key is the root of trust. Its private half is kept offline by the developer or
//! administrator and is used only to sign key sets (and to re-sign trusted objects during a key
//! rotation). Day-to-day policy changes are signed by a policy-signing key listed in the key
//! set. Changing the key set requires the root key.

use agentguard_core::Name;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::canonical::{ContentHash, Signed};
use crate::crypto::{PublicKey, Purpose};
use crate::error::TrustError;

/// Schema identifier of the root anchor.
pub const ROOT_ANCHOR_SCHEMA: &str = "agentguard.root-anchor.v1";
/// Schema identifier of the key set.
pub const KEYSET_SCHEMA: &str = "agentguard.keyset.v1";
/// Upper bound on keys in a key set.
pub const MAX_KEYS: usize = 32;

/// The root public key, as provisioned. Unsigned: its authority comes from where it is stored
/// (an administrator-owned system anchor, or the user's trust store created by an explicit
/// initialisation) and from the integrity state pinning its key ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootAnchor {
    /// Always [`ROOT_ANCHOR_SCHEMA`].
    pub schema: String,
    /// The root public key.
    pub public_key: PublicKey,
    /// When it was provisioned.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl RootAnchor {
    /// A new anchor for `public_key`.
    #[must_use]
    pub fn new(public_key: PublicKey, created_at: OffsetDateTime) -> Self {
        Self {
            schema: ROOT_ANCHOR_SCHEMA.to_owned(),
            public_key,
            created_at,
        }
    }

    /// Check the schema.
    pub fn validate(&self, object: &'static str) -> Result<(), TrustError> {
        if self.schema == ROOT_ANCHOR_SCHEMA {
            Ok(())
        } else {
            Err(TrustError::Malformed { object })
        }
    }
}

/// What a key may sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyRole {
    /// Policy manifests, the project registry and the integrity state.
    PolicySigner,
}

/// One key in the key set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyEntry {
    /// The public key.
    pub public_key: PublicKey,
    /// What it may sign.
    pub role: KeyRole,
    /// Human label, for example the owner's name.
    pub label: Name,
    /// When it was added.
    #[serde(with = "time::serde::rfc3339")]
    pub added_at: OffsetDateTime,
}

/// The set of policy-signing keys, signed by the root key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySetBody {
    /// Always [`KEYSET_SCHEMA`].
    pub schema: String,
    /// Monotonic version, starting at 1.
    pub sequence: u64,
    /// Body hash of the previous key set.
    pub previous: Option<ContentHash>,
    /// The keys.
    pub keys: Vec<KeyEntry>,
    /// When this version was issued.
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
}

impl KeySetBody {
    /// Structural rules: schema, sequence, 1 to [`MAX_KEYS`] distinct keys.
    pub fn validate(&self) -> Result<(), TrustError> {
        let object = "key set";
        if self.schema != KEYSET_SCHEMA {
            return Err(TrustError::Malformed { object });
        }
        if self.sequence == 0 {
            return Err(TrustError::Inconsistent {
                object,
                rule: "sequence starts at 1",
            });
        }
        if self.keys.is_empty() || self.keys.len() > MAX_KEYS {
            return Err(TrustError::Inconsistent {
                object,
                rule: "must list between 1 and 32 keys",
            });
        }
        let mut ids: Vec<_> = self.keys.iter().map(|k| k.public_key.key_id()).collect();
        ids.sort_unstable();
        ids.dedup();
        if ids.len() != self.keys.len() {
            return Err(TrustError::Inconsistent {
                object,
                rule: "keys must be distinct",
            });
        }
        Ok(())
    }

    /// The policy-signing public keys.
    #[must_use]
    pub fn policy_signers(&self) -> Vec<PublicKey> {
        self.keys
            .iter()
            .filter(|k| k.role == KeyRole::PolicySigner)
            .map(|k| k.public_key)
            .collect()
    }
}

/// Verify a key set against the root anchor. A key set signed by anything other than the root
/// key is an unauthorised key change.
pub fn verify_keyset(
    root: &RootAnchor,
    signed: &Signed<KeySetBody>,
) -> Result<Vec<PublicKey>, TrustError> {
    let body = signed
        .verify(Purpose::KeySet, &[root.public_key], "key set")
        .map_err(|e| match e {
            TrustError::UntrustedSigner { .. } | TrustError::SignatureInvalid { .. } => {
                TrustError::KeyChange {
                    rule: "the key set is not signed by the root key",
                }
            }
            other => other,
        })?;
    body.validate()?;
    Ok(body.policy_signers())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Ed25519Signer, Signer};
    use zeroize::Zeroizing;

    fn signer(b: u8) -> Ed25519Signer {
        Ed25519Signer::from_seed(&Zeroizing::new([b; 32]))
    }

    fn keyset(keys: &[&Ed25519Signer]) -> KeySetBody {
        KeySetBody {
            schema: KEYSET_SCHEMA.to_owned(),
            sequence: 1,
            previous: None,
            keys: keys
                .iter()
                .map(|s| KeyEntry {
                    public_key: s.public_key(),
                    role: KeyRole::PolicySigner,
                    label: Name::new("dev").unwrap(),
                    added_at: OffsetDateTime::UNIX_EPOCH,
                })
                .collect(),
            issued_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn only_root_signed_keysets_verify() {
        let root = signer(1);
        let anchor = RootAnchor::new(root.public_key(), OffsetDateTime::UNIX_EPOCH);
        let policy = signer(2);
        let good = Signed::sign(keyset(&[&policy]), Purpose::KeySet, &root).unwrap();
        assert_eq!(
            verify_keyset(&anchor, &good).unwrap(),
            vec![policy.public_key()]
        );

        let attacker = signer(3);
        let forged = Signed::sign(keyset(&[&attacker]), Purpose::KeySet, &attacker).unwrap();
        assert!(matches!(
            verify_keyset(&anchor, &forged),
            Err(TrustError::KeyChange { .. })
        ));
    }

    #[test]
    fn structural_rules() {
        let a = signer(4);
        let mut k = keyset(&[&a, &a]);
        assert!(k.validate().is_err(), "duplicates");
        k = keyset(&[]);
        assert!(k.validate().is_err(), "empty");
        k = keyset(&[&a]);
        k.sequence = 0;
        assert!(k.validate().is_err(), "sequence 0");
    }
}
