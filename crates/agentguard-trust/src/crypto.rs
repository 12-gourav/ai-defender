//! Signatures: Ed25519 (RFC 8032) through `ed25519-dalek`.
//!
//! - Verification uses `verify_strict`, which rejects non-canonical signatures and small-order
//!   points, so a signature cannot be malleated into a second valid one.
//! - Weak (small-order) public keys are refused when parsed.
//! - Every signed message is domain separated by [`Purpose`], so a signature made for one kind
//!   of object can never verify as another.
//! - Private keys exist only inside an [`Ed25519Signer`], which never serialises them, prints
//!   them, or writes them anywhere; they are zeroised on drop.

use std::fmt;

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// What a signature is for. Mixed into every signed message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// The set of policy-signing keys, signed by the root key.
    KeySet,
    /// A policy manifest.
    PolicyManifest,
    /// The project registry.
    Registry,
    /// The integrity state.
    Integrity,
    /// A human approval decision and the authorization grant it issues.
    ApprovalGrant,
}

impl Purpose {
    const fn domain(self) -> &'static [u8] {
        match self {
            Purpose::KeySet => b"agentguard.keyset.v1\0",
            Purpose::PolicyManifest => b"agentguard.policy-manifest.v1\0",
            Purpose::Registry => b"agentguard.registry.v1\0",
            Purpose::Integrity => b"agentguard.integrity.v1\0",
            Purpose::ApprovalGrant => b"agentguard.approval-grant.v1\0",
        }
    }

    fn message(self, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.domain().len() + body.len());
        out.extend_from_slice(self.domain());
        out.extend_from_slice(body);
        out
    }
}

/// Signature failures. Never carry key or signature bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// Not a valid encoding.
    #[error("malformed key or signature encoding")]
    Encoding,
    /// The public key is a small-order point.
    #[error("weak public key")]
    WeakKey,
    /// The signature does not verify.
    #[error("signature does not verify")]
    BadSignature,
    /// The operating system's random source failed.
    #[error("random source unavailable")]
    Random,
}

/// Short identifier of a public key: the first 16 bytes of SHA-256 over a domain-separated
/// encoding of the key, as hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct KeyId([u8; 16]);

impl KeyId {
    /// Lowercase hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl TryFrom<String> for KeyId {
    type Error = CryptoError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut bytes = [0u8; 16];
        hex::decode_to_slice(&value, &mut bytes).map_err(|_| CryptoError::Encoding)?;
        Ok(Self(bytes))
    }
}

impl From<KeyId> for String {
    fn from(value: KeyId) -> Self {
        value.to_hex()
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// An Ed25519 public key, serialised as 64 hex characters.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    /// Parse 32 raw bytes, refusing weak keys.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        let key = VerifyingKey::from_bytes(bytes).map_err(|_| CryptoError::Encoding)?;
        if key.is_weak() {
            return Err(CryptoError::WeakKey);
        }
        Ok(Self(key))
    }

    /// Raw bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The key's identifier.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        let mut hasher = Sha256::new();
        hasher.update(b"agentguard.key-id.v1\0");
        hasher.update(self.0.as_bytes());
        let digest = hasher.finalize();
        let mut id = [0u8; 16];
        id.copy_from_slice(digest.get(..16).unwrap_or(&[0u8; 16]));
        KeyId(id)
    }

    /// Verify `signature` over `body` for `purpose`.
    pub fn verify(
        &self,
        purpose: Purpose,
        body: &[u8],
        signature: &Signature,
    ) -> Result<(), CryptoError> {
        let sig = ed25519_dalek::Signature::from_bytes(&signature.0);
        self.0
            .verify_strict(&purpose.message(body), &sig)
            .map_err(|_| CryptoError::BadSignature)
    }
}

impl TryFrom<String> for PublicKey {
    type Error = CryptoError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(&value, &mut bytes).map_err(|_| CryptoError::Encoding)?;
        Self::from_bytes(&bytes)
    }
}

impl From<PublicKey> for String {
    fn from(value: PublicKey) -> Self {
        hex::encode(value.0.as_bytes())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.key_id())
    }
}

/// An Ed25519 signature, serialised as 128 hex characters.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Signature([u8; 64]);

impl Signature {
    /// Wrap raw bytes (for tests that construct forgeries).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Raw bytes.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; 64] {
        self.0
    }
}

impl TryFrom<String> for Signature {
    type Error = CryptoError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut bytes = [0u8; 64];
        hex::decode_to_slice(&value, &mut bytes).map_err(|_| CryptoError::Encoding)?;
        Ok(Self(bytes))
    }
}

impl From<Signature> for String {
    fn from(value: Signature) -> Self {
        hex::encode(value.0)
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Signature(..)")
    }
}

/// Something that can sign for a public key. Implemented by [`Ed25519Signer`]; a later phase
/// can implement it over a hardware token or an agent socket so the private key never enters
/// AgentGuard's process at all.
pub trait Signer {
    /// The public key signatures verify against.
    fn public_key(&self) -> PublicKey;

    /// Sign `body` for `purpose`.
    fn sign(&self, purpose: Purpose, body: &[u8]) -> Signature;
}

/// An in-process Ed25519 private key. Supplied by the human performing an authorised
/// operation and dropped (zeroised) afterwards; AgentGuard never stores one.
pub struct Ed25519Signer {
    key: SigningKey,
}

impl Ed25519Signer {
    /// Generate a key from the operating system's random source.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut_slice()).map_err(|_| CryptoError::Random)?;
        Ok(Self::from_seed(&seed))
    }

    /// Build from a 32-byte seed (the RFC 8032 secret key).
    #[must_use]
    pub fn from_seed(seed: &Zeroizing<[u8; 32]>) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }
}

impl Signer for Ed25519Signer {
    fn public_key(&self) -> PublicKey {
        PublicKey(self.key.verifying_key())
    }

    fn sign(&self, purpose: Purpose, body: &[u8]) -> Signature {
        Signature(self.key.sign(&purpose.message(body)).to_bytes())
    }
}

impl fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519Signer({})", self.public_key().key_id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer(b: u8) -> Ed25519Signer {
        Ed25519Signer::from_seed(&Zeroizing::new([b; 32]))
    }

    #[test]
    fn sign_verify_and_domain_separation() {
        let s = signer(1);
        let sig = s.sign(Purpose::PolicyManifest, b"body");
        let pk = s.public_key();
        assert!(pk.verify(Purpose::PolicyManifest, b"body", &sig).is_ok());
        assert_eq!(
            pk.verify(Purpose::Registry, b"body", &sig),
            Err(CryptoError::BadSignature)
        );
        assert!(pk.verify(Purpose::PolicyManifest, b"bodY", &sig).is_err());
        assert!(signer(2)
            .public_key()
            .verify(Purpose::PolicyManifest, b"body", &sig)
            .is_err());
        let mut bytes = sig.to_bytes();
        bytes[0] ^= 1;
        assert!(pk
            .verify(
                Purpose::PolicyManifest,
                b"body",
                &Signature::from_bytes(bytes)
            )
            .is_err());
    }

    #[test]
    fn rfc8032_test_vector_1() {
        // RFC 8032 section 7.1, TEST 1 (empty message), verified against our wrapper with the
        // domain prefix removed by signing through dalek directly.
        let seed: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap();
        let pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let s = Ed25519Signer::from_seed(&Zeroizing::new(seed));
        assert_eq!(String::from(s.public_key()), pk_hex);
        let sig = s.key.sign(b"");
        assert_eq!(
            hex::encode(sig.to_bytes()),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
    }

    #[test]
    fn encodings_and_weak_keys() {
        let pk = signer(3).public_key();
        let hex = String::from(pk);
        assert_eq!(PublicKey::try_from(hex).unwrap(), pk);
        assert!(PublicKey::try_from("zz".to_owned()).is_err());
        // The identity point is small-order.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(PublicKey::from_bytes(&identity), Err(CryptoError::WeakKey));
        assert_eq!(pk.key_id(), signer(3).public_key().key_id());
        assert_ne!(pk.key_id(), signer(4).public_key().key_id());
        assert!(!format!("{:?}", signer(3)).contains(&hex::encode([3u8; 32])));
    }

    #[test]
    fn generate_produces_distinct_keys() {
        let a = Ed25519Signer::generate().unwrap();
        let b = Ed25519Signer::generate().unwrap();
        assert_ne!(a.public_key(), b.public_key());
    }
}
