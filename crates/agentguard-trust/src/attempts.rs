//! Backoff after wrong signing-key passphrases.
//!
//! Five wrong passphrases in a row are free; after that each further attempt must wait 30
//! seconds, doubling per failure up to 15 minutes. A correct passphrase resets the count. The
//! state is a small unsigned file in the private `keys` directory: it slows guessing through
//! AgentGuard itself. It is not what protects the key against someone who can read the key file
//! (Argon2id does that), and anyone who can delete the file is already past the trust store's
//! permission checks.

use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::store::{atomic_replace, TrustStore};

/// Consecutive wrong passphrases accepted without delay.
pub const FREE_ATTEMPTS: u32 = 5;
/// Delay after the first failure beyond [`FREE_ATTEMPTS`].
pub const BASE_DELAY_SECS: i64 = 30;
/// Longest delay.
pub const MAX_DELAY_SECS: i64 = 15 * 60;

const SCHEMA: &str = "agentguard.passphrase-attempts.v1";
const MAX_FILE_BYTES: u64 = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema: String,
    failures: u32,
    last_failure: i64,
}

/// The passphrase attempt record of one trust store.
#[derive(Debug, Clone)]
pub struct AttemptGate {
    path: PathBuf,
}

/// Unlocking must wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wait {
    /// Seconds until the next attempt is allowed.
    pub retry_after_secs: i64,
    /// Consecutive wrong passphrases so far.
    pub failures: u32,
}

/// The delay owed after `failures` consecutive wrong passphrases.
#[must_use]
pub fn delay_after(failures: u32) -> i64 {
    if failures < FREE_ATTEMPTS {
        return 0;
    }
    let doublings = (failures - FREE_ATTEMPTS).min(20);
    BASE_DELAY_SECS
        .saturating_mul(1i64 << doublings)
        .min(MAX_DELAY_SECS)
}

impl AttemptGate {
    /// The gate for `store`.
    #[must_use]
    pub fn new(store: &TrustStore) -> Self {
        Self {
            path: store.root().join("keys").join("attempts.json"),
        }
    }

    fn read(&self) -> Option<State> {
        match fs::symlink_metadata(&self.path) {
            Err(e) if e.kind() == ErrorKind::NotFound => return None,
            Ok(meta) if meta.is_file() && meta.len() <= MAX_FILE_BYTES => {}
            // Unreadable or odd records cost one delay step rather than none.
            _ => return Some(Self::suspect()),
        }
        let parsed = fs::read(&self.path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<State>(&bytes).ok())
            .filter(|s| s.schema == SCHEMA);
        Some(parsed.unwrap_or_else(Self::suspect))
    }

    fn suspect() -> State {
        State {
            schema: SCHEMA.to_owned(),
            failures: FREE_ATTEMPTS,
            last_failure: OffsetDateTime::now_utc().unix_timestamp(),
        }
    }

    /// Whether an attempt may be made at `now`.
    pub fn check(&self, now: OffsetDateTime) -> Result<(), Wait> {
        let Some(state) = self.read() else {
            return Ok(());
        };
        let until = state
            .last_failure
            .saturating_add(delay_after(state.failures));
        let now = now.unix_timestamp();
        if now < until {
            Err(Wait {
                retry_after_secs: until - now,
                failures: state.failures,
            })
        } else {
            Ok(())
        }
    }

    /// Record a wrong passphrase at `now`. Best effort: a failure to record is not reported,
    /// so it cannot be used to make unlocking itself fail.
    pub fn record_failure(&self, now: OffsetDateTime) {
        let failures = self.read().map_or(0, |s| s.failures).saturating_add(1);
        let state = State {
            schema: SCHEMA.to_owned(),
            failures,
            last_failure: now.unix_timestamp(),
        };
        if let Ok(bytes) = serde_json::to_vec(&state) {
            let _ = atomic_replace(&self.path, &bytes, "passphrase attempt record");
        }
    }

    /// Record a correct passphrase: the count starts again.
    pub fn record_success(&self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AnchorConfig;
    use time::Duration;

    fn gate() -> (tempfile::TempDir, AttemptGate) {
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStore::new(
            dir.path().join("store"),
            AnchorConfig {
                system_anchor: None,
                required_owner: crate::AnchorOwner::System,
            },
        );
        fs::create_dir_all(store.root().join("keys")).unwrap();
        (dir, AttemptGate::new(&store))
    }

    #[test]
    fn delays_double_after_five_failures_and_cap() {
        assert_eq!(delay_after(0), 0);
        assert_eq!(delay_after(4), 0);
        assert_eq!(delay_after(5), 30);
        assert_eq!(delay_after(6), 60);
        assert_eq!(delay_after(9), 480);
        assert_eq!(delay_after(10), MAX_DELAY_SECS);
        assert_eq!(delay_after(u32::MAX), MAX_DELAY_SECS);
    }

    #[test]
    fn five_free_attempts_then_backoff_then_reset() {
        let (_d, g) = gate();
        let t0 = OffsetDateTime::UNIX_EPOCH + Duration::days(20_000);
        for i in 0..4 {
            assert!(g.check(t0).is_ok(), "attempt {i}");
            g.record_failure(t0);
        }
        assert!(g.check(t0).is_ok());
        g.record_failure(t0);
        let wait = g.check(t0).unwrap_err();
        assert_eq!(
            wait,
            Wait {
                retry_after_secs: 30,
                failures: 5
            }
        );
        assert!(g.check(t0 + Duration::seconds(29)).is_err());
        assert!(g.check(t0 + Duration::seconds(30)).is_ok());
        g.record_failure(t0 + Duration::seconds(30));
        assert_eq!(
            g.check(t0 + Duration::seconds(30))
                .unwrap_err()
                .retry_after_secs,
            60
        );
        // A clock set back does not shorten the wait.
        assert!(g.check(t0).is_err());
        g.record_success();
        assert!(g.check(t0).is_ok());
    }

    #[test]
    fn a_damaged_record_costs_a_delay_instead_of_none() {
        let (_d, g) = gate();
        fs::write(&g.path, b"{not json").unwrap();
        assert!(g.check(OffsetDateTime::now_utc()).is_err());
    }
}
