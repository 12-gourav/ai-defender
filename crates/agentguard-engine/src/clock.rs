//! Time source, injectable so approval expiry is testable.

use std::sync::Mutex;

use time::OffsetDateTime;

/// Supplies the current time.
pub trait Clock: Send + Sync {
    /// Now, in UTC.
    fn now(&self) -> OffsetDateTime;
}

/// The system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// A manually advanced clock, for tests.
#[derive(Debug)]
pub struct ManualClock {
    now: Mutex<OffsetDateTime>,
}

impl ManualClock {
    /// A clock reading `start`.
    #[must_use]
    pub const fn new(start: OffsetDateTime) -> Self {
        Self {
            now: Mutex::new(start),
        }
    }

    /// Move the clock forward.
    pub fn advance(&self, by: time::Duration) {
        if let Ok(mut now) = self.now.lock() {
            *now += by;
        }
    }
}

impl Clock for ManualClock {
    fn now(&self) -> OffsetDateTime {
        // A poisoned lock means a test panicked mid-advance; the last value is still usable.
        *self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
