//! Abstract source of monotonic time.
//!
//! Production code uses [`SystemClock`], which delegates to
//! `std::time::Instant::now()`. Unit tests use a `FakeClock` (arrives
//! in Phase 2, `tests/common/clock.rs`) that lets the test set the
//! current `Instant` deterministically.
//!
//! ## Design note
//!
//! `crate::auto_lock::AutoLockController` (Phase 2) does NOT itself
//! hold a `Clock`. The frontend passes the current `Instant` to
//! `tick()` and `register_activity()`; the controller stays a pure
//! state machine. The trait exists for any consumer that wants a
//! clock-injection seam at its own level (TUI, agent), and the future
//! `falach-agent` shares this trait so test infrastructure
//! (`FakeClock`) can be re-used across crates.

use std::time::Instant;

/// Abstract source of monotonic time.
///
/// `Send + Sync` is required so the trait object can be shared between
/// threads. Production [`SystemClock`] is trivially `Send + Sync`
/// because it holds no state.
pub trait Clock: Send + Sync {
    /// Return the current `Instant`. Implementations must be
    /// monotonic (later calls return non-decreasing values) so callers
    /// can rely on `Instant` arithmetic without wrap-around handling.
    fn now(&self) -> Instant;
}

/// Production clock — thin wrapper over `std::time::Instant::now()`.
///
/// Zero-sized; `Default::default()` is the canonical constructor.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_now_is_monotonic_across_two_calls() {
        // `Instant` itself guarantees monotonicity; this test asserts
        // `SystemClock::now()` doesn't undermine that guarantee. A
        // future regression that wraps `now()` in some way that lets
        // time go backwards would corrupt every idle accounting
        // downstream.
        let clock = SystemClock;
        let t1 = clock.now();
        let t2 = clock.now();
        assert!(t2 >= t1, "successive Instants must be non-decreasing");
    }

    #[test]
    fn system_clock_default_constructs() {
        // Zero-sized; `Default` derive is trivially correct. Smoke
        // test to guard against accidental removal of the derive
        // (which would break future `FakeClock`-style consumers that
        // want a no-arg constructor).
        let clock = SystemClock;
        let _ = clock.now();
        // Confirm the `Default` impl resolves; `clippy::default_constructed_unit_structs`
        // flags `SystemClock::default()` so we go through the trait method.
        let from_default = <SystemClock as Default>::default();
        let _ = from_default.now();
    }

    #[test]
    fn system_clock_is_send_and_sync() {
        // Compile-time gate — if `SystemClock`'s field set ever gains
        // a `!Send` or `!Sync` member, this fn fails to compile.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SystemClock>();
    }
}
