//! Canonical serialisation, content hashes, signed envelopes and version references.
//!
//! The canonical form of a trusted value is the compact `serde_json` serialisation of its typed
//! representation. Trusted types contain only structs, enums, strings, integers, booleans and
//! ordered sequences (no hash maps, no floats), so the form is deterministic. Verification
//! parses the stored file into the typed value and re-serialises it, so whitespace or key order
//! in the file does not matter, while any semantic change does.

use std::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::crypto::{KeyId, PublicKey, Purpose, Signature, Signer};
use crate::error::TrustError;

/// Canonical bytes of `value`.
pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, TrustError> {
    serde_json::to_vec(value).map_err(|_| TrustError::Canonicalisation)
}

/// SHA-256 of a canonical serialisation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ContentHash([u8; 32]);

impl ContentHash {
    /// Hash the canonical form of `value`.
    pub fn of<T: Serialize>(value: &T) -> Result<Self, TrustError> {
        Ok(Self(Sha256::digest(canonical_bytes(value)?).into()))
    }

    /// Lowercase hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl TryFrom<String> for ContentHash {
    type Error = TrustError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(&value, &mut bytes).map_err(|_| TrustError::Malformed {
            object: "content hash",
        })?;
        Ok(Self(bytes))
    }
}

impl From<ContentHash> for String {
    fn from(value: ContentHash) -> Self {
        value.to_hex()
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.to_hex();
        write!(f, "ContentHash({})", hex.get(..12).unwrap_or(&hex))
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// A pinned version of a trusted object: its sequence number and the hash of its body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionRef {
    /// Monotonic sequence number, starting at 1.
    pub sequence: u64,
    /// Hash of the signed body.
    pub hash: ContentHash,
}

impl fmt::Display for VersionRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.hash.to_hex();
        write!(f, "v{} ({})", self.sequence, hex.get(..12).unwrap_or(&hex))
    }
}

impl VersionRef {
    /// Check that an object found with `found` is exactly the pinned version. Distinguishes a
    /// rollback (older), an unauthorised advance (newer) and a replacement (same version,
    /// different content).
    pub fn check(&self, object: &'static str, found: &VersionRef) -> Result<(), TrustError> {
        if found.sequence < self.sequence {
            return Err(TrustError::Rollback {
                object,
                found: found.sequence,
                pinned: self.sequence,
            });
        }
        if found.sequence > self.sequence {
            return Err(TrustError::UnexpectedVersion {
                object,
                found: found.sequence,
                pinned: self.sequence,
            });
        }
        if found.hash != self.hash {
            return Err(TrustError::Replaced { object });
        }
        Ok(())
    }
}

/// A body plus a signature over its canonical form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed<T> {
    /// The signed content.
    pub body: T,
    /// Which key signed it.
    pub signer: KeyId,
    /// Ed25519 signature over the purpose-separated canonical body.
    pub signature: Signature,
}

impl<T: Serialize + DeserializeOwned> Signed<T> {
    /// Sign `body`.
    pub fn sign(body: T, purpose: Purpose, signer: &dyn Signer) -> Result<Self, TrustError> {
        let bytes = canonical_bytes(&body)?;
        Ok(Self {
            signature: signer.sign(purpose, &bytes),
            signer: signer.public_key().key_id(),
            body,
        })
    }

    /// Verify against the keys trusted for this object. The signer must be one of `trusted`.
    pub fn verify(
        &self,
        purpose: Purpose,
        trusted: &[PublicKey],
        object: &'static str,
    ) -> Result<&T, TrustError> {
        let key = trusted
            .iter()
            .find(|k| k.key_id() == self.signer)
            .ok_or(TrustError::UntrustedSigner { object })?;
        key.verify(purpose, &canonical_bytes(&self.body)?, &self.signature)
            .map_err(|_| TrustError::SignatureInvalid { object })?;
        Ok(&self.body)
    }

    /// Hash of the body (what other objects pin).
    pub fn body_hash(&self) -> Result<ContentHash, TrustError> {
        ContentHash::of(&self.body)
    }
}

/// `t` truncated to whole seconds, so stored timestamps round-trip exactly.
#[must_use]
pub fn whole_seconds(t: OffsetDateTime) -> OffsetDateTime {
    t.replace_nanosecond(0).unwrap_or(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Ed25519Signer;
    use zeroize::Zeroizing;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        a: u64,
        b: String,
    }

    #[test]
    fn signed_round_trip_tolerates_formatting_not_edits() {
        let s = Ed25519Signer::from_seed(&Zeroizing::new([9; 32]));
        let signed = Signed::sign(
            Body {
                a: 1,
                b: "x".into(),
            },
            Purpose::Registry,
            &s,
        )
        .unwrap();
        let keys = [s.public_key()];
        let pretty = serde_json::to_string_pretty(&signed).unwrap();
        let back: Signed<Body> = serde_json::from_str(&pretty).unwrap();
        assert!(back.verify(Purpose::Registry, &keys, "body").is_ok());

        let edited: Signed<Body> = serde_json::from_str(&pretty.replace("\"x\"", "\"y\"")).unwrap();
        assert_eq!(
            edited.verify(Purpose::Registry, &keys, "body"),
            Err(TrustError::SignatureInvalid { object: "body" })
        );
        let other = Ed25519Signer::from_seed(&Zeroizing::new([8; 32]));
        assert_eq!(
            back.verify(Purpose::Registry, &[other.public_key()], "body"),
            Err(TrustError::UntrustedSigner { object: "body" })
        );
        assert!(back.verify(Purpose::Integrity, &keys, "body").is_err());
    }

    #[test]
    fn version_ref_classifies_changes() {
        let h1 = ContentHash::of(&1u8).unwrap();
        let h2 = ContentHash::of(&2u8).unwrap();
        let pinned = VersionRef {
            sequence: 3,
            hash: h1,
        };
        assert!(pinned.check("x", &pinned).is_ok());
        assert!(matches!(
            pinned.check(
                "x",
                &VersionRef {
                    sequence: 2,
                    hash: h1
                }
            ),
            Err(TrustError::Rollback {
                found: 2,
                pinned: 3,
                ..
            })
        ));
        assert!(matches!(
            pinned.check(
                "x",
                &VersionRef {
                    sequence: 4,
                    hash: h1
                }
            ),
            Err(TrustError::UnexpectedVersion { .. })
        ));
        assert!(matches!(
            pinned.check(
                "x",
                &VersionRef {
                    sequence: 3,
                    hash: h2
                }
            ),
            Err(TrustError::Replaced { .. })
        ));
    }
}
