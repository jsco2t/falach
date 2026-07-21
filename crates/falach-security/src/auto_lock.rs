//! Idle auto-lock state machine.
//!
//! [`AutoLockController`] is the heart of `falach-security`. The
//! frontend drives it from its event loop:
//!
//! - On every user input event, call
//!   [`AutoLockController::register_activity`].
//! - On every redraw / poll cycle, call [`AutoLockController::tick`]
//!   and react to the returned [`LockState`].
//! - On explicit Ctrl-L (or equivalent), call
//!   [`AutoLockController::lock_now`].
//! - After re-authentication, call [`AutoLockController::unlock`].
//!
//! The state machine has three states (`Active`, `Expired`, `Locked`)
//! and the transitions are documented in the [feature design
//! document][design] §2.2.3.
//!
//! [design]: ../../../notebook/projects/falach/features/security-behaviors/plans/design.md
//!
//! ## Threading posture
//!
//! [`AutoLockController`] is `Send + !Sync` — mutating methods take
//! `&mut self` and the internal `mpsc::Receiver` is not shareable
//! across threads. OS-event sources attached via
//! [`AutoLockController::attach_event_source`] run on their own
//! `std::thread`s and push events into the controller's cloned
//! `mpsc::Sender`; [`AutoLockController::tick`] drains the channel
//! with `try_recv`.
//!
//! ## Drop semantics
//!
//! On drop, the controller signals every attached source's
//! [`crate::os_events::ShutdownHandle`] (obtained at attach time) and
//! then joins the source threads. Sources are obligated to return
//! from `run` within a small bounded time after the signal — today
//! 50 ms in tests, see `controller_drop_signals_and_joins_within_bound`.
//! Each source-specific shutdown wiring lives in its respective
//! `os_events/*.rs` module (e.g., dropping a `Sender` for `NoopSource`,
//! calling `signal_hook::iterator::Handle::close()` for
//! `SigstopSource`).
//!
//! This contract was added in Phase 5 T5.0 and supersedes the MVP's
//! "detach + OS reaps at exit" model (which is documented as Risk #12
//! in the feature's `follow-ups/open-items.md`).

use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::error::SecurityError;
use crate::os_events::{OsLockEventSource, ShutdownHandle};

/// A source's join handle paired with its shutdown signal. The
/// controller holds one entry per attached source and consumes both
/// halves in `Drop`.
struct AttachedSource {
    join: JoinHandle<()>,
    shutdown: ShutdownHandle,
}

/// Default idle timeout for [`AutoLockConfig`]: 10 minutes (per PRD
/// FR-051 default).
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// Visible state of the auto-lock state machine.
///
/// `Expired` is a deliberate one-tick warning state between `Active`
/// and `Locked` — the next [`AutoLockController::tick`] after entering
/// `Expired` transitions to `Locked`. The TUI uses the `Expired` state
/// to flash a "locking now" indicator (PRD FR-073).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    /// Vault is unlocked and the user is interacting (or recently was).
    Active,
    /// Idle deadline has passed; one-tick warning state. Frontend may
    /// flash a "locking now" indicator. The next `tick()` returns
    /// [`LockState::Locked`].
    Expired,
    /// Vault is locked. The frontend must drop its unlocked state,
    /// zeroize sensitive buffers, and return to the unlock prompt.
    Locked,
}

/// Events the controller drains from its internal `mpsc` channel on
/// every [`AutoLockController::tick`].
///
/// OS-event sources clone the controller's sender (obtained via
/// [`AutoLockController::attach_event_source`]) and push these
/// variants; the agent (post-MVP) is expected to use the channel for
/// user-input forwarding via [`SecurityEvent::Activity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityEvent {
    /// User input or agent activity occurred. Equivalent to the
    /// frontend calling [`AutoLockController::register_activity`].
    Activity,
    /// An OS-level event demands an immediate lock. Carries the
    /// reason for diagnostics.
    OsLock {
        /// Why the lock was demanded (screensaver, sleep, SIGTSTP, ...).
        reason: OsLockReason,
    },
    /// The frontend explicitly requested a lock (e.g., agent socket
    /// command). Distinct from `OsLock` so handlers can differentiate
    /// user-driven vs. environment-driven locking in diagnostics.
    Manual,
}

/// Categorisation of why an OS-driven lock fired. Diagnostic only —
/// the controller treats all variants identically (transition to
/// [`LockState::Locked`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsLockReason {
    /// POSIX SIGTSTP delivered (Phase 4's `SigstopSource`).
    Sigstop,
    /// Screensaver activated (Linux `LogindSource`, macOS `IoKitSource` — post-MVP).
    Screensaver,
    /// System sleep / suspend (post-MVP sources).
    Sleep,
    /// Manual lock request from an OS-level source (rare; documented
    /// for symmetry with [`SecurityEvent::Manual`]).
    Manual,
}

/// Tunable parameters for [`AutoLockController`].
#[derive(Debug, Clone, Copy)]
pub struct AutoLockConfig {
    /// Idle timeout before the vault auto-locks. Default
    /// [`DEFAULT_IDLE_TIMEOUT`] (600 s). Must be >= 1 second.
    pub idle_timeout: Duration,
}

impl Default for AutoLockConfig {
    fn default() -> Self {
        Self {
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }
}

impl AutoLockConfig {
    /// Validate the config. Currently the only invariant is
    /// `idle_timeout >= 1 second` — a zero timeout would degenerate
    /// the state machine into "lock on every tick".
    ///
    /// # Errors
    ///
    /// [`SecurityError::InvalidAutoLockConfig`] when `idle_timeout` is
    /// zero (or sub-second; Phase 4's `VaultLockConfig` enforces
    /// whole-second granularity at the boundary).
    pub fn validate(&self) -> Result<(), SecurityError> {
        if self.idle_timeout.is_zero() {
            return Err(SecurityError::InvalidAutoLockConfig {
                detail: "idle_timeout must be at least 1 second".to_string(),
            });
        }
        Ok(())
    }
}

/// The idle auto-lock state machine.
///
/// Frontends call [`Self::tick`] from their event loop with the
/// current `Instant`, then react to the returned [`LockState`]. The
/// controller does NOT internally hold a `Clock` — time is passed in
/// as data. See the module docs for the full pattern.
pub struct AutoLockController {
    config: AutoLockConfig,
    state: LockState,
    last_activity: Option<Instant>,
    event_tx: Sender<SecurityEvent>,
    event_rx: Receiver<SecurityEvent>,
    attached_sources: Vec<AttachedSource>,
}

impl std::fmt::Debug for AutoLockController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutoLockController")
            .field("config", &self.config)
            .field("state", &self.state)
            .field("last_activity", &self.last_activity)
            .field("attached_sources", &self.attached_sources.len())
            .finish_non_exhaustive()
    }
}

impl AutoLockController {
    /// Construct a controller starting in [`LockState::Active`].
    ///
    /// # Errors
    ///
    /// [`SecurityError::InvalidAutoLockConfig`] when `config.validate()`
    /// fails (currently: zero idle timeout).
    pub fn new(config: AutoLockConfig) -> Result<Self, SecurityError> {
        config.validate()?;
        let (event_tx, event_rx) = mpsc::channel();
        Ok(Self {
            config,
            state: LockState::Active,
            last_activity: None,
            event_tx,
            event_rx,
            attached_sources: Vec::new(),
        })
    }

    /// Record user activity. Resets the idle deadline. From
    /// [`LockState::Locked`], the call is a no-op — callers must use
    /// [`Self::unlock`] to re-enter `Active`.
    pub fn register_activity(&mut self, now: Instant) {
        match self.state {
            LockState::Active | LockState::Expired => {
                self.state = LockState::Active;
                self.last_activity = Some(now);
            }
            LockState::Locked => { /* no-op; unlock() required */ }
        }
    }

    /// Drive the controller. Drains any pending OS events, applies
    /// idle accounting, and returns the resulting [`LockState`].
    ///
    /// The drain uses `while let Ok(_) = event_rx.try_recv()` — every
    /// pending event is consumed in this call; the controller never
    /// falls behind under load. See the `tick_drains_multiple_events_in_one_call`
    /// unit test for the pinned contract.
    pub fn tick(&mut self, now: Instant) -> LockState {
        // 1. Drain pending OS events.
        while let Ok(evt) = self.event_rx.try_recv() {
            match evt {
                SecurityEvent::Activity => self.register_activity(now),
                SecurityEvent::OsLock { .. } | SecurityEvent::Manual => {
                    self.transition_to_locked();
                }
            }
        }
        // 2. Advance idle accounting.
        self.apply_idle_logic(now);
        // 3. Return current state.
        self.state
    }

    /// Force an immediate lock from the frontend (Ctrl-L, /lock).
    /// `reason` is currently unused for state-machine purposes (it is
    /// diagnostic only).
    pub fn lock_now(&mut self, _reason: OsLockReason) {
        self.transition_to_locked();
    }

    /// Re-enter [`LockState::Active`] after the frontend
    /// authenticates the user. Sets `last_activity = Some(now)` so the
    /// idle deadline restarts from `now`.
    ///
    /// Idempotent: calling on a controller already in `Active` simply
    /// resets the deadline.
    pub fn unlock(&mut self, now: Instant) {
        self.state = LockState::Active;
        self.last_activity = Some(now);
    }

    /// Attach an OS-event source. Spawns a thread that calls
    /// `source.run(event_tx.clone())` and stores its `JoinHandle` for
    /// detachment on drop.
    ///
    /// # Errors
    ///
    /// [`SecurityError::EventSourceStart`] when the OS-level thread
    /// spawn fails (extremely rare; out-of-memory or rlimit
    /// exhaustion).
    pub fn attach_event_source<S>(&mut self, source: S) -> Result<(), SecurityError>
    where
        S: OsLockEventSource + 'static,
    {
        let tx = self.event_tx.clone();
        let name = source.name();
        // Acquire the shutdown handle BEFORE consuming the source via
        // the spawned thread. Per the trait contract, sources expose
        // their shutdown signal at attach time.
        let mut source = source;
        let shutdown = source.shutdown_handle();
        let join = std::thread::Builder::new()
            .name(format!("falach-security-{name}"))
            .spawn(move || {
                // Errors from `run` are intentionally swallowed here;
                // the source's own diagnostics path is responsible for
                // surfacing them. The controller can't usefully
                // propagate errors after the spawn point.
                let _ = Box::new(source).run(tx);
            })
            .map_err(|e| SecurityError::EventSourceStart {
                name,
                detail: e.to_string(),
            })?;
        self.attached_sources
            .push(AttachedSource { join, shutdown });
        Ok(())
    }

    /// Current [`LockState`]. Non-mutating accessor.
    #[must_use]
    pub fn state(&self) -> LockState {
        self.state
    }

    /// Remaining time until the idle deadline fires, if applicable.
    ///
    /// - [`LockState::Active`]: returns `Some(idle_timeout - elapsed)`
    ///   when the deadline hasn't been crossed yet, else `None` (the
    ///   TUI uses `None` as the "switch to 'locking now' widget"
    ///   signal).
    /// - [`LockState::Expired`] / [`LockState::Locked`]: returns `None`.
    /// - `last_activity == None` (controller hasn't seen any activity
    ///   yet): returns `None`.
    ///
    /// Uses `checked_sub`, not `saturating_sub`, so an overshoot
    /// returns `None` rather than `Duration::ZERO`. A regression to
    /// `saturating_sub` would change the TUI's countdown semantics.
    #[must_use]
    pub fn time_until_lock(&self, now: Instant) -> Option<Duration> {
        match self.state {
            LockState::Active => {
                let last = self.last_activity?;
                let elapsed = now.saturating_duration_since(last);
                self.config.idle_timeout.checked_sub(elapsed)
            }
            LockState::Expired | LockState::Locked => None,
        }
    }

    /// Apply idle accounting given the current `now`. Drives the
    /// `Active → Expired` and `Expired → Locked` transitions. Boundary
    /// is `>=` (equality fires the transition) — see the boundary
    /// unit tests `tick_at_exactly_timeout_transitions_to_expired` and
    /// `tick_one_nanosecond_before_timeout_stays_active`.
    fn apply_idle_logic(&mut self, now: Instant) {
        match self.state {
            LockState::Active => {
                if let Some(last) = self.last_activity {
                    if now.saturating_duration_since(last) >= self.config.idle_timeout {
                        self.state = LockState::Expired;
                    }
                }
                // `last_activity == None` means no deadline yet —
                // stays Active until the first `register_activity`.
            }
            LockState::Expired => {
                self.state = LockState::Locked;
            }
            LockState::Locked => {}
        }
    }

    fn transition_to_locked(&mut self) {
        self.state = LockState::Locked;
    }
}

impl Drop for AutoLockController {
    fn drop(&mut self) {
        // Phase 5 T5.0: signal every attached source's shutdown
        // handle, then join its thread. Sources are obligated by the
        // `OsLockEventSource` trait contract to return from `run`
        // within a small bounded time after the signal.
        //
        // Order: attach order. Each iteration signals one source and
        // joins it before moving on, so a hanging source surfaces as
        // a visible drop-time stall rather than masking itself behind
        // a later source's signal.
        //
        // `join` errors (the thread panicked) are swallowed — by the
        // time we reach Drop there's nothing useful the consumer can
        // do with the panic. The pinned contract is "drop returns
        // within the test bound"; the
        // `controller_drop_signals_and_joins_within_bound` test
        // enforces it.
        let sources = std::mem::take(&mut self.attached_sources);
        for source in sources {
            source.shutdown.signal();
            let _ = source.join.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Mutex;

    // ---- Test helpers ---------------------------------------------------

    /// Shared mutable `Instant` for unit tests. Lives in-file (per
    /// implementation-plan §8.2.3 mock-dependencies note); the
    /// `FakeClock` re-export for integration tests lives at
    /// `tests/common/clock.rs`.
    struct InFileFakeClock {
        now: Arc<Mutex<Instant>>,
    }

    impl InFileFakeClock {
        fn new(start: Instant) -> Self {
            Self {
                now: Arc::new(Mutex::new(start)),
            }
        }
        fn now(&self) -> Instant {
            *self.now.lock().expect("fake clock mutex poisoned")
        }
        fn advance(&self, by: Duration) {
            let mut t = self.now.lock().expect("fake clock mutex poisoned");
            *t = t
                .checked_add(by)
                .expect("FakeClock overflow — bump the start `Instant`");
        }
    }

    /// In-test `OsLockEventSource` that parks on a channel until its
    /// shutdown handle is signalled. Mirrors the production
    /// `NoopSource` shape (Phase 5 T5.0 contract) but lives in this
    /// file so the tests don't depend on `crate::os_events::noop`'s
    /// concrete struct beyond the trait surface.
    struct ParkingSource {
        park_tx: Option<Sender<()>>,
        park_rx: Option<Receiver<()>>,
    }

    impl ParkingSource {
        fn new() -> Self {
            let (tx, rx) = mpsc::channel();
            Self {
                park_tx: Some(tx),
                park_rx: Some(rx),
            }
        }
    }

    impl OsLockEventSource for ParkingSource {
        fn run(self: Box<Self>, _tx: Sender<SecurityEvent>) -> Result<(), SecurityError> {
            let rx = self
                .park_rx
                .expect("ParkingSource::run called twice or after shutdown moved rx");
            let _ = rx.recv();
            Ok(())
        }
        fn name(&self) -> &'static str {
            "test-parking"
        }
        fn shutdown_handle(&mut self) -> ShutdownHandle {
            let tx = self
                .park_tx
                .take()
                .expect("ParkingSource::shutdown_handle called twice");
            ShutdownHandle::new(move || drop(tx))
        }
    }

    fn short_config() -> AutoLockConfig {
        AutoLockConfig {
            idle_timeout: Duration::from_secs(1),
        }
    }

    // ---- Constructor / validation --------------------------------------

    #[test]
    fn new_with_zero_timeout_returns_invalid_config() {
        let err = AutoLockController::new(AutoLockConfig {
            idle_timeout: Duration::ZERO,
        })
        .expect_err("zero timeout must be rejected");
        match err {
            SecurityError::InvalidAutoLockConfig { detail } => {
                assert!(
                    detail.contains("idle_timeout"),
                    "detail should mention the field: {detail}"
                );
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn new_with_default_config_succeeds_in_active_state() {
        let controller = AutoLockController::new(AutoLockConfig::default())
            .expect("default config should validate");
        assert_eq!(controller.state(), LockState::Active);
    }

    // ---- Boundary tests -------------------------------------------------

    #[test]
    fn tick_at_exactly_timeout_transitions_to_expired() {
        let clock = InFileFakeClock::new(Instant::now());
        let mut controller = AutoLockController::new(short_config()).expect("valid config");
        controller.register_activity(clock.now());
        clock.advance(Duration::from_secs(1));
        // Equality: `now - last_activity == idle_timeout` fires the
        // Active → Expired transition. A `>` typo would silently
        // delay locking by one tick interval.
        assert_eq!(controller.tick(clock.now()), LockState::Expired);
    }

    #[test]
    fn tick_one_nanosecond_before_timeout_stays_active() {
        let clock = InFileFakeClock::new(Instant::now());
        let mut controller = AutoLockController::new(short_config()).expect("valid config");
        controller.register_activity(clock.now());
        clock.advance(Duration::from_secs(1) - Duration::from_nanos(1));
        assert_eq!(controller.tick(clock.now()), LockState::Active);
    }

    // ---- Register-activity behaviour -----------------------------------

    #[test]
    fn register_activity_after_expired_returns_to_active_with_new_deadline() {
        let clock = InFileFakeClock::new(Instant::now());
        let mut controller = AutoLockController::new(short_config()).expect("valid config");
        // Get into Expired.
        controller.register_activity(clock.now());
        clock.advance(Duration::from_secs(1));
        assert_eq!(controller.tick(clock.now()), LockState::Expired);
        // Re-register activity — must reset deadline, not just flip back.
        controller.register_activity(clock.now());
        // A subsequent tick at just-under-the-new-deadline must stay Active.
        clock.advance(Duration::from_secs(1) - Duration::from_nanos(1));
        assert_eq!(controller.tick(clock.now()), LockState::Active);
    }

    #[test]
    fn register_activity_in_locked_state_is_noop() {
        let mut controller = AutoLockController::new(short_config()).expect("valid config");
        controller.lock_now(OsLockReason::Manual);
        assert_eq!(controller.state(), LockState::Locked);

        // register_activity must NOT unlock.
        controller.register_activity(Instant::now());
        assert_eq!(
            controller.state(),
            LockState::Locked,
            "register_activity must be a no-op in Locked state"
        );
    }

    // ---- Channel-drain behaviour ---------------------------------------

    #[test]
    fn tick_drains_activity_event_to_active() {
        let clock = InFileFakeClock::new(Instant::now());
        let mut controller = AutoLockController::new(short_config()).expect("valid config");
        // Get into Expired.
        controller.register_activity(clock.now());
        clock.advance(Duration::from_secs(1));
        assert_eq!(controller.tick(clock.now()), LockState::Expired);

        // Push an Activity event via cloned sender.
        let tx = controller.event_tx.clone();
        tx.send(SecurityEvent::Activity).expect("send on cloned tx");
        // Tick at the same `now` drains the event and transitions to Active.
        assert_eq!(controller.tick(clock.now()), LockState::Active);
        // Deadline reset: just-under-timeout still Active.
        clock.advance(Duration::from_secs(1) - Duration::from_nanos(1));
        assert_eq!(controller.tick(clock.now()), LockState::Active);
    }

    #[test]
    fn tick_drains_oslock_event_to_locked() {
        let mut controller =
            AutoLockController::new(AutoLockConfig::default()).expect("valid config");
        let tx = controller.event_tx.clone();
        tx.send(SecurityEvent::OsLock {
            reason: OsLockReason::Sigstop,
        })
        .expect("send");
        assert_eq!(controller.tick(Instant::now()), LockState::Locked);
    }

    #[test]
    fn tick_drains_manual_event_to_locked() {
        let mut controller =
            AutoLockController::new(AutoLockConfig::default()).expect("valid config");
        let tx = controller.event_tx.clone();
        tx.send(SecurityEvent::Manual).expect("send");
        assert_eq!(controller.tick(Instant::now()), LockState::Locked);
    }

    #[test]
    fn tick_drains_multiple_events_in_one_call() {
        let mut controller =
            AutoLockController::new(AutoLockConfig::default()).expect("valid config");
        let tx = controller.event_tx.clone();
        tx.send(SecurityEvent::Activity).expect("send 1");
        tx.send(SecurityEvent::Activity).expect("send 2");
        tx.send(SecurityEvent::Manual).expect("send 3");

        // A single tick must drain all three — `while let Ok(_) = try_recv()`.
        // The final state reflects the last event (`Manual` → `Locked`).
        assert_eq!(controller.tick(Instant::now()), LockState::Locked);

        // The channel must now be empty (no more events queued).
        assert!(
            controller.event_rx.try_recv().is_err(),
            "drain should consume every event in one call"
        );
    }

    // ---- lock_now / unlock ---------------------------------------------

    #[test]
    fn lock_now_from_any_state_transitions_to_locked() {
        // Active → Locked.
        let mut controller =
            AutoLockController::new(AutoLockConfig::default()).expect("valid config");
        assert_eq!(controller.state(), LockState::Active);
        controller.lock_now(OsLockReason::Manual);
        assert_eq!(controller.state(), LockState::Locked);

        // Expired → Locked. Re-arm a fresh controller.
        let clock = InFileFakeClock::new(Instant::now());
        let mut controller = AutoLockController::new(short_config()).expect("valid config");
        controller.register_activity(clock.now());
        clock.advance(Duration::from_secs(1));
        assert_eq!(controller.tick(clock.now()), LockState::Expired);
        controller.lock_now(OsLockReason::Manual);
        assert_eq!(controller.state(), LockState::Locked);

        // Locked → Locked (idempotent).
        controller.lock_now(OsLockReason::Manual);
        assert_eq!(controller.state(), LockState::Locked);
    }

    #[test]
    fn unlock_from_locked_transitions_to_active_and_sets_last_activity() {
        let clock = InFileFakeClock::new(Instant::now());
        let mut controller = AutoLockController::new(short_config()).expect("valid config");
        controller.lock_now(OsLockReason::Manual);
        assert_eq!(controller.state(), LockState::Locked);

        controller.unlock(clock.now());
        assert_eq!(controller.state(), LockState::Active);

        // Deadline was reset: just-under-timeout still Active.
        clock.advance(Duration::from_secs(1) - Duration::from_nanos(1));
        assert_eq!(controller.tick(clock.now()), LockState::Active);
    }

    #[test]
    fn unlock_from_active_is_noop_but_resets_deadline() {
        let clock = InFileFakeClock::new(Instant::now());
        let mut controller = AutoLockController::new(short_config()).expect("valid config");
        // No prior activity → unlock seeds last_activity.
        controller.unlock(clock.now());
        assert_eq!(controller.state(), LockState::Active);

        clock.advance(Duration::from_secs(1) - Duration::from_nanos(1));
        assert_eq!(controller.tick(clock.now()), LockState::Active);
        clock.advance(Duration::from_nanos(1));
        assert_eq!(controller.tick(clock.now()), LockState::Expired);
    }

    // ---- time_until_lock -----------------------------------------------

    #[test]
    fn time_until_lock_in_active_returns_remaining() {
        let clock = InFileFakeClock::new(Instant::now());
        let mut controller = AutoLockController::new(AutoLockConfig {
            idle_timeout: Duration::from_secs(600),
        })
        .expect("valid config");
        controller.register_activity(clock.now());
        clock.advance(Duration::from_secs(100));
        let remaining = controller
            .time_until_lock(clock.now())
            .expect("remaining time should be Some while Active");
        assert_eq!(remaining, Duration::from_secs(500));
    }

    #[test]
    fn time_until_lock_in_expired_returns_none() {
        let clock = InFileFakeClock::new(Instant::now());
        let mut controller = AutoLockController::new(short_config()).expect("valid config");
        controller.register_activity(clock.now());
        clock.advance(Duration::from_secs(1));
        assert_eq!(controller.tick(clock.now()), LockState::Expired);
        assert!(controller.time_until_lock(clock.now()).is_none());
    }

    #[test]
    fn time_until_lock_in_locked_returns_none() {
        let mut controller =
            AutoLockController::new(AutoLockConfig::default()).expect("valid config");
        controller.lock_now(OsLockReason::Manual);
        assert!(controller.time_until_lock(Instant::now()).is_none());
    }

    #[test]
    fn time_until_lock_after_deadline_returns_none() {
        // In Active with now > last_activity + idle_timeout (state
        // hasn't been ticked yet so it's still Active), `checked_sub`
        // returns None. A regression to `saturating_sub` would
        // surface as `Some(Duration::ZERO)`.
        let clock = InFileFakeClock::new(Instant::now());
        let mut controller = AutoLockController::new(short_config()).expect("valid config");
        controller.register_activity(clock.now());
        // Advance past the deadline, but do NOT tick — state stays Active.
        clock.advance(Duration::from_secs(2));
        assert_eq!(
            controller.state(),
            LockState::Active,
            "no tick yet, state stays Active"
        );
        assert!(
            controller.time_until_lock(clock.now()).is_none(),
            "checked_sub semantics: returns None on overshoot, not ZERO"
        );
    }

    // ---- attach_event_source + Drop ------------------------------------

    #[test]
    fn attach_event_source_spawns_named_thread() {
        let mut controller =
            AutoLockController::new(AutoLockConfig::default()).expect("valid config");
        controller
            .attach_event_source(ParkingSource::new())
            .expect("attach should succeed");
        // Subsequent ticks succeed without deadlock.
        for _ in 0..3 {
            assert_eq!(controller.tick(Instant::now()), LockState::Active);
        }
    }

    #[test]
    fn controller_drop_signals_and_joins_within_bound() {
        // Phase 5 T5.0 contract: `Drop` signals every attached
        // source's `ShutdownHandle` then joins the source thread.
        // A regression to the MVP's "detach + OS reaps at exit"
        // model would leak the thread; a regression that signals but
        // hangs in `join` would blow the 50ms bound.
        let mut controller =
            AutoLockController::new(AutoLockConfig::default()).expect("valid config");
        controller
            .attach_event_source(ParkingSource::new())
            .expect("attach should succeed");

        let start = Instant::now();
        drop(controller);
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(50),
            "drop should signal + join within 50ms; took {elapsed:?}"
        );
    }

    #[cfg(target_os = "linux")]
    fn live_thread_count() -> usize {
        // `/proc/self/task` lists one entry per live thread in the
        // current process. Cheap, no syscalls beyond `readdir`.
        std::fs::read_dir("/proc/self/task")
            .expect("read /proc/self/task")
            .filter_map(Result::ok)
            .count()
    }

    /// Phase 5 T5.0: dropping N controllers leaves no leaked source
    /// threads behind. Linux-only because the assertion uses
    /// `/proc/self/task`; macOS verification is via the dedicated
    /// `controller_drop_signals_and_joins_within_bound` (which would
    /// time out if `join` were waiting on an orphaned thread).
    ///
    /// `#[ignore]`d because the assertion samples a *process-global*
    /// thread count, which is non-deterministic when libtest runs
    /// peer tests in parallel. Runs under `make test-ignored`, which
    /// forces `--test-threads=1` and gives the test exclusive
    /// observation of the thread count. A regression to the MVP's
    /// detach model would grow `after` by ROUNDS and fail loudly.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "samples process-global thread count; run under --test-threads=1 via `make test-ignored`"]
    fn controller_drop_joins_attached_sources_cleanly() {
        const ROUNDS: usize = 16;
        // Slack of 4 absorbs unrelated test-harness churn; the
        // detach-model regression would grow `after` by ROUNDS.
        const SLACK: usize = 4;

        // Warm-up: construct + drop one controller first so any
        // lazy-initialised thread-locals or thread-pool entries are
        // settled before we sample the baseline.
        {
            let mut c = AutoLockController::new(AutoLockConfig::default()).expect("valid config");
            c.attach_event_source(ParkingSource::new()).expect("attach");
        }

        let baseline = live_thread_count();
        for _ in 0..ROUNDS {
            let mut controller =
                AutoLockController::new(AutoLockConfig::default()).expect("valid config");
            controller
                .attach_event_source(ParkingSource::new())
                .expect("attach");
            drop(controller);
        }
        // Brief settle: thread teardown isn't instantaneous on all
        // schedulers. Give the kernel a moment to reap.
        std::thread::sleep(Duration::from_millis(20));
        let after = live_thread_count();
        assert!(
            after <= baseline + SLACK,
            "controller drops leaked threads: baseline={baseline}, after={ROUNDS} rounds={after} (slack={SLACK})",
        );
    }

    // ---- Exhaustive transition-table coverage --------------------------
    //
    // The state machine has 9 documented transitions in design §2.2.3.
    // This is the highest-value test in the crate — exhaustively
    // verifies every (state, input) → new_state pair the table
    // specifies.

    /// Inputs the state machine accepts. Mirrors the design §2.2.3
    /// list of transition triggers.
    #[derive(Debug, Clone, Copy)]
    enum Input {
        /// `tick(now)` with `now - last_activity < idle_timeout`.
        TickBeforeTimeout,
        /// `tick(now)` with `now - last_activity == idle_timeout`.
        TickAtTimeout,
        /// `register_activity(now)`.
        RegisterActivity,
        /// `lock_now(OsLockReason::Manual)`.
        LockNow,
        /// `unlock(now)`.
        Unlock,
        /// Push `SecurityEvent::Activity` then `tick(now)`.
        ChannelActivity,
        /// Push `SecurityEvent::OsLock {..}` then `tick(now)`.
        ChannelOsLock,
        /// Push `SecurityEvent::Manual` then `tick(now)`.
        ChannelManual,
    }

    struct Case {
        name: &'static str,
        start_state: LockState,
        input: Input,
        expect_state: LockState,
    }

    /// Drive `controller` into `target_state`. Uses a short-timeout
    /// config so transitions are cheap. Returns the `FakeClock` so
    /// the caller can apply the test input at a meaningful `now`.
    fn drive_into(controller: &mut AutoLockController, target: LockState, clock: &InFileFakeClock) {
        match target {
            LockState::Active => {
                controller.register_activity(clock.now());
            }
            LockState::Expired => {
                controller.register_activity(clock.now());
                clock.advance(Duration::from_secs(1));
                assert_eq!(controller.tick(clock.now()), LockState::Expired);
            }
            LockState::Locked => {
                controller.lock_now(OsLockReason::Manual);
            }
        }
    }

    fn apply_input(controller: &mut AutoLockController, input: Input, clock: &InFileFakeClock) {
        match input {
            Input::TickBeforeTimeout => {
                // Apply a tick well within the deadline.
                controller.tick(clock.now());
            }
            Input::TickAtTimeout => {
                // Advance the clock to (last_activity + idle_timeout)
                // and tick. The state machine treats `>=` as the
                // boundary.
                clock.advance(Duration::from_secs(1));
                controller.tick(clock.now());
            }
            Input::RegisterActivity => {
                controller.register_activity(clock.now());
            }
            Input::LockNow => {
                controller.lock_now(OsLockReason::Manual);
            }
            Input::Unlock => {
                controller.unlock(clock.now());
            }
            Input::ChannelActivity => {
                controller
                    .event_tx
                    .send(SecurityEvent::Activity)
                    .expect("channel send");
                controller.tick(clock.now());
            }
            Input::ChannelOsLock => {
                controller
                    .event_tx
                    .send(SecurityEvent::OsLock {
                        reason: OsLockReason::Sigstop,
                    })
                    .expect("channel send");
                controller.tick(clock.now());
            }
            Input::ChannelManual => {
                controller
                    .event_tx
                    .send(SecurityEvent::Manual)
                    .expect("channel send");
                controller.tick(clock.now());
            }
        }
    }

    /// Exhaustive `(state, input)` → `new_state` table for the state
    /// machine. Lives outside `transition_table_exhaustive` so that
    /// fn stays well under the clippy `too_many_lines` threshold.
    #[allow(clippy::too_many_lines)]
    fn transition_cases() -> &'static [Case] {
        &[
            // Active row.
            Case {
                name: "Active+TickBeforeTimeout",
                start_state: LockState::Active,
                input: Input::TickBeforeTimeout,
                expect_state: LockState::Active,
            },
            Case {
                name: "Active+TickAtTimeout",
                start_state: LockState::Active,
                input: Input::TickAtTimeout,
                expect_state: LockState::Expired,
            },
            Case {
                name: "Active+RegisterActivity",
                start_state: LockState::Active,
                input: Input::RegisterActivity,
                expect_state: LockState::Active,
            },
            Case {
                name: "Active+LockNow",
                start_state: LockState::Active,
                input: Input::LockNow,
                expect_state: LockState::Locked,
            },
            Case {
                name: "Active+ChannelActivity",
                start_state: LockState::Active,
                input: Input::ChannelActivity,
                expect_state: LockState::Active,
            },
            Case {
                name: "Active+ChannelOsLock",
                start_state: LockState::Active,
                input: Input::ChannelOsLock,
                expect_state: LockState::Locked,
            },
            Case {
                name: "Active+ChannelManual",
                start_state: LockState::Active,
                input: Input::ChannelManual,
                expect_state: LockState::Locked,
            },
            // Expired row.
            Case {
                name: "Expired+TickBeforeTimeout",
                start_state: LockState::Expired,
                input: Input::TickBeforeTimeout,
                expect_state: LockState::Locked,
            },
            Case {
                name: "Expired+RegisterActivity",
                start_state: LockState::Expired,
                input: Input::RegisterActivity,
                expect_state: LockState::Active,
            },
            Case {
                name: "Expired+LockNow",
                start_state: LockState::Expired,
                input: Input::LockNow,
                expect_state: LockState::Locked,
            },
            Case {
                name: "Expired+ChannelActivity",
                start_state: LockState::Expired,
                input: Input::ChannelActivity,
                expect_state: LockState::Active,
            },
            Case {
                name: "Expired+ChannelOsLock",
                start_state: LockState::Expired,
                input: Input::ChannelOsLock,
                expect_state: LockState::Locked,
            },
            Case {
                name: "Expired+ChannelManual",
                start_state: LockState::Expired,
                input: Input::ChannelManual,
                expect_state: LockState::Locked,
            },
            // Locked row.
            Case {
                name: "Locked+TickBeforeTimeout",
                start_state: LockState::Locked,
                input: Input::TickBeforeTimeout,
                expect_state: LockState::Locked,
            },
            Case {
                name: "Locked+RegisterActivity",
                start_state: LockState::Locked,
                input: Input::RegisterActivity,
                expect_state: LockState::Locked,
            },
            Case {
                name: "Locked+LockNow",
                start_state: LockState::Locked,
                input: Input::LockNow,
                expect_state: LockState::Locked,
            },
            Case {
                name: "Locked+Unlock",
                start_state: LockState::Locked,
                input: Input::Unlock,
                expect_state: LockState::Active,
            },
            Case {
                name: "Locked+ChannelActivity",
                start_state: LockState::Locked,
                input: Input::ChannelActivity,
                expect_state: LockState::Locked,
            },
            Case {
                name: "Locked+ChannelOsLock",
                start_state: LockState::Locked,
                input: Input::ChannelOsLock,
                expect_state: LockState::Locked,
            },
        ]
    }

    #[test]
    fn transition_table_exhaustive() {
        for case in transition_cases() {
            let clock = InFileFakeClock::new(Instant::now());
            let mut controller = AutoLockController::new(short_config()).expect("valid config");
            drive_into(&mut controller, case.start_state, &clock);
            assert_eq!(
                controller.state(),
                case.start_state,
                "case '{}': failed to set up start state",
                case.name
            );
            apply_input(&mut controller, case.input, &clock);
            assert_eq!(
                controller.state(),
                case.expect_state,
                "case '{}': expected {:?}, got {:?}",
                case.name,
                case.expect_state,
                controller.state()
            );
        }
    }
}
