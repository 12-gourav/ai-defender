//! Passphrase-protected signing key files.
//!
//! A signing key is stored only encrypted: the passphrase is stretched with Argon2id
//! (RFC 9106) and the 32-byte Ed25519 seed is sealed with XChaCha20-Poly1305. The file's header
//! (schema, role, public key, KDF parameters, cipher, creation time) is authenticated as
//! associated data, so editing any of it makes decryption fail. KDF parameters read from a file
//! are bounded before use, so a modified file can neither weaken the derivation below the
//! minimum nor exhaust memory.
//!
//! The passphrase is typed by a human. Without it, a process that can read the file (including
//! an agent running as the same user) cannot sign anything. With it, it can: see the trust
//! model's local-user limitations.

use agentguard_platform::fs::{OpenNoFollow, UnixMode};
use std::fmt;
use std::fs::{DirBuilder, OpenOptions};
use std::io::Write;
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::canonical::{canonical_bytes, whole_seconds};
use crate::crypto::{Ed25519Signer, PublicKey, Signer};
use crate::error::TrustError;

/// Schema identifier of an encrypted key file.
pub const KEYFILE_SCHEMA: &str = "agentguard.encrypted-signing-key.v1";
/// Minimum passphrase length in characters.
pub const MIN_PASSPHRASE_CHARS: usize = 12;
/// Maximum passphrase length in bytes.
pub const MAX_PASSPHRASE_BYTES: usize = 1024;
const CIPHER: &str = "xchacha20poly1305";
const KDF: &str = "argon2id";

/// Key file failures. Never carry the passphrase or key bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KeyFileError {
    /// The passphrase is too short or too long.
    #[error("passphrase must be between 12 characters and 1024 bytes")]
    WeakPassphrase,
    /// The file is not a valid key file, or its parameters are out of bounds.
    #[error("signing key file is malformed")]
    Malformed,
    /// Decryption failed: wrong passphrase, or the file was modified.
    #[error("the passphrase is wrong or the signing key file was modified")]
    Unlock,
    /// The decrypted key does not match the public key the file declares.
    #[error("signing key file is inconsistent")]
    Mismatch,
    /// The file is not for the expected role.
    #[error("signing key file is for a different role")]
    WrongRole,
    /// The operating system's random source failed.
    #[error("random source unavailable")]
    Random,
    /// The key file already exists.
    #[error("signing key file already exists; refusing to overwrite it")]
    Exists,
    /// The key file is missing.
    #[error("signing key file not found")]
    Missing,
    /// The file could not be read or written, or is insecure.
    #[error("signing key file: {0}")]
    Store(TrustError),
}

/// A passphrase. Zeroised on drop; never printed.
pub struct Passphrase(Zeroizing<String>);

impl Passphrase {
    /// Validate length.
    pub fn new(value: String) -> Result<Self, KeyFileError> {
        let value = Zeroizing::new(value);
        if value.chars().count() < MIN_PASSPHRASE_CHARS || value.len() > MAX_PASSPHRASE_BYTES {
            return Err(KeyFileError::WeakPassphrase);
        }
        Ok(Self(value))
    }

    fn bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Passphrase(..)")
    }
}

/// What a signing key is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningRole {
    /// The root key (key-set changes).
    Root,
    /// A policy-signing key (policies, registrations).
    Policy,
}

impl SigningRole {
    /// File name within the signing directory.
    #[must_use]
    pub const fn file_name(self) -> &'static str {
        match self {
            SigningRole::Root => "root.key",
            SigningRole::Policy => "policy.key",
        }
    }
}

/// Argon2id cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfCost {
    /// Memory in KiB.
    pub memory_kib: u32,
    /// Passes.
    pub iterations: u32,
    /// Lanes.
    pub parallelism: u32,
}

impl KdfCost {
    /// The default: 19 MiB, 2 passes, 1 lane (the OWASP-recommended Argon2id minimum).
    pub const DEFAULT: Self = Self {
        memory_kib: 19_456,
        iterations: 2,
        parallelism: 1,
    };
    /// Lowest cost accepted from a file.
    pub const MINIMUM: Self = Self {
        memory_kib: 1024,
        iterations: 1,
        parallelism: 1,
    };
}

/// KDF parameters as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfParams {
    /// Always `argon2id`.
    pub algorithm: String,
    /// Memory in KiB.
    pub memory_kib: u32,
    /// Passes.
    pub iterations: u32,
    /// Lanes.
    pub parallelism: u32,
    /// 16-byte salt, hex.
    pub salt: String,
}

impl KdfParams {
    fn validate(&self) -> Result<[u8; 16], KeyFileError> {
        let in_range = self.algorithm == KDF
            && (KdfCost::MINIMUM.memory_kib..=1_048_576).contains(&self.memory_kib)
            && (KdfCost::MINIMUM.iterations..=10).contains(&self.iterations)
            && (KdfCost::MINIMUM.parallelism..=4).contains(&self.parallelism)
            && self.memory_kib >= 8 * self.parallelism;
        if !in_range {
            return Err(KeyFileError::Malformed);
        }
        let mut salt = [0u8; 16];
        hex::decode_to_slice(&self.salt, &mut salt).map_err(|_| KeyFileError::Malformed)?;
        Ok(salt)
    }

    fn derive(&self, passphrase: &Passphrase) -> Result<Zeroizing<[u8; 32]>, KeyFileError> {
        let salt = self.validate()?;
        let params = Params::new(self.memory_kib, self.iterations, self.parallelism, Some(32))
            .map_err(|_| KeyFileError::Malformed)?;
        let mut key = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(passphrase.bytes(), &salt, key.as_mut_slice())
            .map_err(|_| KeyFileError::Malformed)?;
        Ok(key)
    }
}

/// An encrypted signing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedKey {
    /// Always [`KEYFILE_SCHEMA`].
    pub schema: String,
    /// What the key is for.
    pub role: SigningRole,
    /// The public half.
    pub public_key: PublicKey,
    /// Key derivation.
    pub kdf: KdfParams,
    /// Always `xchacha20poly1305`.
    pub cipher: String,
    /// 24-byte nonce, hex.
    pub nonce: String,
    /// Sealed seed (32 bytes + 16-byte tag), hex.
    pub ciphertext: String,
    /// When it was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Serialize)]
struct Header<'a> {
    schema: &'a str,
    role: SigningRole,
    public_key: &'a PublicKey,
    kdf: &'a KdfParams,
    cipher: &'a str,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

impl EncryptedKey {
    fn header_bytes(&self) -> Result<Vec<u8>, KeyFileError> {
        canonical_bytes(&Header {
            schema: &self.schema,
            role: self.role,
            public_key: &self.public_key,
            kdf: &self.kdf,
            cipher: &self.cipher,
            created_at: self.created_at,
        })
        .map_err(|_| KeyFileError::Malformed)
    }

    /// Decrypt with `passphrase`, checking the role and that the key matches the declared
    /// public key.
    pub fn open(
        &self,
        role: SigningRole,
        passphrase: &Passphrase,
    ) -> Result<Ed25519Signer, KeyFileError> {
        if self.schema != KEYFILE_SCHEMA || self.cipher != CIPHER {
            return Err(KeyFileError::Malformed);
        }
        if self.role != role {
            return Err(KeyFileError::WrongRole);
        }
        let mut nonce = [0u8; 24];
        hex::decode_to_slice(&self.nonce, &mut nonce).map_err(|_| KeyFileError::Malformed)?;
        let ciphertext = hex::decode(&self.ciphertext).map_err(|_| KeyFileError::Malformed)?;
        if ciphertext.len() != 48 {
            return Err(KeyFileError::Malformed);
        }
        let key = self.kdf.derive(passphrase)?;
        let aad = self.header_bytes()?;
        let cipher = XChaCha20Poly1305::new(key.as_slice().into());
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| KeyFileError::Unlock)?,
        );
        let mut seed = Zeroizing::new([0u8; 32]);
        if plain.len() != 32 {
            return Err(KeyFileError::Malformed);
        }
        seed.copy_from_slice(&plain);
        let signer = Ed25519Signer::from_seed(&seed);
        if signer.public_key() != self.public_key {
            return Err(KeyFileError::Mismatch);
        }
        Ok(signer)
    }
}

fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>, KeyFileError> {
    let mut out = Zeroizing::new([0u8; N]);
    getrandom::fill(out.as_mut_slice()).map_err(|_| KeyFileError::Random)?;
    Ok(out)
}

/// Seal `seed` for `role` under `passphrase` with `cost`.
pub fn seal(
    seed: &Zeroizing<[u8; 32]>,
    role: SigningRole,
    passphrase: &Passphrase,
    cost: KdfCost,
    now: OffsetDateTime,
) -> Result<EncryptedKey, KeyFileError> {
    let salt = random::<16>()?;
    let nonce = random::<24>()?;
    let mut key = EncryptedKey {
        schema: KEYFILE_SCHEMA.to_owned(),
        role,
        public_key: Ed25519Signer::from_seed(seed).public_key(),
        kdf: KdfParams {
            algorithm: KDF.to_owned(),
            memory_kib: cost.memory_kib,
            iterations: cost.iterations,
            parallelism: cost.parallelism,
            salt: hex::encode(salt.as_slice()),
        },
        cipher: CIPHER.to_owned(),
        nonce: hex::encode(nonce.as_slice()),
        ciphertext: String::new(),
        created_at: whole_seconds(now),
    };
    let derived = key.kdf.derive(passphrase)?;
    let aad = key.header_bytes()?;
    let cipher = XChaCha20Poly1305::new(derived.as_slice().into());
    let sealed = cipher
        .encrypt(
            XNonce::from_slice(nonce.as_slice()),
            Payload {
                msg: seed.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| KeyFileError::Malformed)?;
    key.ciphertext = hex::encode(sealed);
    Ok(key)
}

/// Generate a fresh key for `role` and seal it with the default cost.
pub fn generate_sealed(
    role: SigningRole,
    passphrase: &Passphrase,
    now: OffsetDateTime,
) -> Result<(EncryptedKey, Ed25519Signer), KeyFileError> {
    generate_sealed_with(role, passphrase, KdfCost::DEFAULT, now)
}

/// Generate a fresh key for `role` and seal it with `cost`.
pub fn generate_sealed_with(
    role: SigningRole,
    passphrase: &Passphrase,
    cost: KdfCost,
    now: OffsetDateTime,
) -> Result<(EncryptedKey, Ed25519Signer), KeyFileError> {
    let seed = random::<32>()?;
    let sealed = seal(&seed, role, passphrase, cost, now)?;
    Ok((sealed, Ed25519Signer::from_seed(&seed)))
}

/// Write a key file that must not exist yet (mode 0600, never through a symlink). The parent
/// directory is created with mode 0700.
pub fn write_key_file(path: &Path, key: &EncryptedKey) -> Result<(), KeyFileError> {
    let io = |action| {
        KeyFileError::Store(TrustError::Io {
            object: "signing key file",
            action,
        })
    };
    if let Some(parent) = path.parent() {
        DirBuilder::new()
            .recursive(true)
            .unix_mode(0o700)
            .create(parent)
            .map_err(|_| io("created"))?;
    }
    let bytes = serde_json::to_vec_pretty(key).map_err(|_| KeyFileError::Malformed)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .unix_mode(0o600)
        .open_no_follow(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                KeyFileError::Exists
            } else {
                io("created")
            }
        })?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| io("written"))
}

/// Read a key file with the trust store's file safety checks.
pub fn read_key_file(path: &Path) -> Result<EncryptedKey, KeyFileError> {
    crate::store::read_object(path, "signing key file").map_err(|e| match e {
        TrustError::Unavailable { .. } => KeyFileError::Missing,
        TrustError::Malformed { .. } => KeyFileError::Malformed,
        other => KeyFileError::Store(other),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfCost = KdfCost::MINIMUM;

    fn pass(s: &str) -> Passphrase {
        Passphrase::new(s.to_owned()).unwrap()
    }

    #[test]
    fn seal_open_round_trip_and_wrong_passphrase() {
        let (sealed, signer) = generate_sealed_with(
            SigningRole::Policy,
            &pass("correct horse battery"),
            FAST,
            OffsetDateTime::UNIX_EPOCH,
        )
        .unwrap();
        let opened = sealed
            .open(SigningRole::Policy, &pass("correct horse battery"))
            .unwrap();
        assert_eq!(opened.public_key(), signer.public_key());
        assert!(matches!(
            sealed.open(SigningRole::Policy, &pass("wrong horse battery")),
            Err(KeyFileError::Unlock)
        ));
    }

    #[test]
    fn header_tampering_and_weak_parameters_are_rejected() {
        let p = pass("correct horse battery");
        let (sealed, _) =
            generate_sealed_with(SigningRole::Policy, &p, FAST, OffsetDateTime::UNIX_EPOCH)
                .unwrap();
        let mut other_key = sealed.clone();
        other_key.public_key = Ed25519Signer::from_seed(&Zeroizing::new([9; 32])).public_key();
        assert!(matches!(
            other_key.open(SigningRole::Policy, &p),
            Err(KeyFileError::Unlock)
        ));
        let mut weaker = sealed.clone();
        weaker.kdf.memory_kib = 8;
        assert!(matches!(
            weaker.open(SigningRole::Policy, &p),
            Err(KeyFileError::Malformed)
        ));
        let mut huge = sealed.clone();
        huge.kdf.memory_kib = u32::MAX;
        assert!(matches!(
            huge.open(SigningRole::Policy, &p),
            Err(KeyFileError::Malformed)
        ));
        assert!(matches!(
            sealed.open(SigningRole::Root, &p),
            Err(KeyFileError::WrongRole)
        ));
        let mut flipped = sealed;
        let mut bytes = hex::decode(&flipped.ciphertext).unwrap();
        bytes[0] ^= 1;
        flipped.ciphertext = hex::encode(bytes);
        assert!(matches!(
            flipped.open(SigningRole::Policy, &p),
            Err(KeyFileError::Unlock)
        ));
    }

    #[test]
    fn passphrase_rules_and_debug() {
        assert!(Passphrase::new("short".into()).is_err());
        assert!(Passphrase::new("x".repeat(1025)).is_err());
        assert_eq!(
            format!("{:?}", pass("correct horse battery")),
            "Passphrase(..)"
        );
    }

    #[test]
    fn files_are_private_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing/policy.key");
        let (sealed, _) = generate_sealed_with(
            SigningRole::Policy,
            &pass("correct horse battery"),
            FAST,
            OffsetDateTime::UNIX_EPOCH,
        )
        .unwrap();
        write_key_file(&path, &sealed).unwrap();
        #[cfg(unix)]
        assert_eq!(
            agentguard_platform::fs::unix_mode(&std::fs::metadata(&path).unwrap()),
            Some(0o600)
        );
        assert_eq!(write_key_file(&path, &sealed), Err(KeyFileError::Exists));
        assert_eq!(read_key_file(&path).unwrap(), sealed);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("correct horse"));
        assert_eq!(
            read_key_file(&dir.path().join("missing.key")),
            Err(KeyFileError::Missing)
        );
    }
}
