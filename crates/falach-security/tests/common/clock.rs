//! Deterministic `Clock` implementation for integration tests.
//!
//! [`FakeClock`] wraps an `Arc<Mutex<Instant>>` so a single instance
//! can be cloned across threads (rarely needed in MVP — the
//! controller is `Send + !Sync` and runs on one thread — but the
//! invariant lets Phase 3's clipboard tests share it freely if they
//! ever need to). The clock starts at a caller-supplied `Instant`
//! and advances only when [`Self::advance`] is called.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use falach_security::Clock;

/// Deterministic clock for tests. See module docs.
#[derive(Debug, Clone)]
pub struct FakeClock {
    now: Arc<Mutex<Instant>>,
}

impl FakeClock {
    /// Construct a clock fixed at `start`. Callers typically pass
    /// `Instant::now()` so the clock's absolute values remain
    /// realistic (though the only thing that matters is relative
    /// advancement).
    pub fn new(start: Instant) -> Self {
        Self {
            now: Arc::new(Mutex::new(start)),
        }
    }

    /// Advance the clock by `by`. Panics on overflow — bump the
    /// `start` `Instant` if you hit that (unlikely).
    pub fn advance(&self, by: Duration) {
        let mut t = self.now.lock().expect("FakeClock mutex poisoned");
        *t = t
            .checked_add(by)
            .expect("FakeClock overflow — pick an earlier start Instant");
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Instant {
        *self.now.lock().expect("FakeClock mutex poisoned")
    }
}
