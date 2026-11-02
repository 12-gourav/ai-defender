//! Claim tokens.
//!
//! A claim token is the requester's proof that it is the party an approval request was made
//! for, in the manner of the device code in the OAuth 2.0 Device Authorization Grant
//! (RFC 8628): the requester holds a secret, the human approves by a public reference (the
//! approval ID), and only the secret's holder can redeem the approval.
//!
//! - 256 bits from the operating system's CSPRNG; never derived from IDs or timestamps.
//! - Returned once, to the requester; stored only as a [`TokenVerifier`]: SHA-256 over a
//!   domain prefix and the token. A preimage search over 256 random bits is infeasible, so a
//!   fast hash is sufficient (a slow password hash protects low-entropy secrets, which this is
//!   not).
//! - Useless on its own: redeeming also needs a human-approved, signed, unexpired, unconsumed
//!   grant for the exact operation presented.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const VERIFIER_DOMAIN: &[u8] = b"agentguard.claim-token.v1\0";
const PREFIX: &str = "agc1_";

/// A claim token. Never logged, displayed or stored; `Debug` shows nothing.
pub struct ClaimToken(Zeroizing<[u8; 32]>);

/// Why a claim token was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// The operating system's random source failed.
    #[error("the system random source is unavailable")]
    Random,
    /// The text is not a claim token.
    #[error("not a valid claim token")]
    Malformed,
}

impl ClaimToken {
    /// A fresh token.
    pub fn generate() -> Result<Self, TokenError> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut_slice()).map_err(|_| TokenError::Random)?;
        Ok(Self(bytes))
    }

    /// Parse the transport form (`agc1_` and 64 hexadecimal characters).
    pub fn parse(text: &str) -> Result<Self, TokenError> {
        let hex_part = text.strip_prefix(PREFIX).ok_or(TokenError::Malformed)?;
        let mut bytes = Zeroizing::new([0u8; 32]);
        if hex_part.len() != 64 || hex::decode_to_slice(hex_part, bytes.as_mut_slice()).is_err() {
            return Err(TokenError::Malformed);
        }
        Ok(Self(bytes))
    }

    /// The transport form, for the one response that hands the token to its requester.
    #[must_use]
    pub fn reveal(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("{PREFIX}{}", hex::encode(self.0.as_slice())))
    }

    /// The verifier stored in place of the token.
    #[must_use]
    pub fn verifier(&self) -> TokenVerifier {
        let mut hasher = Sha256::new();
        hasher.update(VERIFIER_DOMAIN);
        hasher.update(self.0.as_slice());
        TokenVerifier(hasher.finalize().into())
    }
}

impl fmt::Debug for ClaimToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClaimToken(..)")
    }
}

/// SHA-256 verifier of a claim token, serialised as hex. Holding a verifier does not let
/// anyone redeem a grant.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TokenVerifier([u8; 32]);

impl TokenVerifier {
    /// Constant-time comparison.
    #[must_use]
    pub fn matches(&self, other: &TokenVerifier) -> bool {
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }

    /// Whether any of `verifiers` matches `token`, comparing every entry.
    #[must_use]
    pub fn any_matches(verifiers: &[TokenVerifier], token: &ClaimToken) -> bool {
        let presented = token.verifier();
        verifiers
            .iter()
            .fold(false, |found, v| v.matches(&presented) | found)
    }
}

impl TryFrom<String> for TokenVerifier {
    type Error = TokenError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(&value, &mut bytes).map_err(|_| TokenError::Malformed)?;
        Ok(Self(bytes))
    }
}

impl From<TokenVerifier> for String {
    fn from(value: TokenVerifier) -> Self {
        hex::encode(value.0)
    }
}

impl fmt::Debug for TokenVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenVerifier(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_verify() {
        let token = ClaimToken::generate().unwrap();
        let text = token.reveal();
        assert!(text.starts_with(PREFIX));
        assert_eq!(text.len(), PREFIX.len() + 64);
        let parsed = ClaimToken::parse(&text).unwrap();
        assert!(parsed.verifier().matches(&token.verifier()));
        let other = ClaimToken::generate().unwrap();
        assert!(!other.verifier().matches(&token.verifier()));
        assert!(TokenVerifier::any_matches(
            &[other.verifier(), token.verifier()],
            &parsed
        ));
        assert!(!TokenVerifier::any_matches(&[other.verifier()], &parsed));
    }

    #[test]
    fn tokens_are_unpredictable_and_never_printed() {
        let a = ClaimToken::generate().unwrap();
        let b = ClaimToken::generate().unwrap();
        assert_ne!(*a.reveal(), *b.reveal());
        assert_eq!(format!("{a:?}"), "ClaimToken(..)");
        assert_eq!(format!("{:?}", a.verifier()), "TokenVerifier(..)");
        let stored = serde_json::to_string(&a.verifier()).unwrap();
        assert!(!stored.contains(&a.reveal()[PREFIX.len()..]));
    }

    #[test]
    fn malformed_tokens_are_refused() {
        for bad in ["", "agc1_", "agc1_zz", &format!("agc2_{}", "0".repeat(64))] {
            assert_eq!(ClaimToken::parse(bad).unwrap_err(), TokenError::Malformed);
        }
    }
}
