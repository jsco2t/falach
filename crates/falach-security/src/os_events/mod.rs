//! OS lock-event sources.
//!
//! Frontends compose `falach-security` with one or more
//! [`OsLockEventSource`] implementations. Each source runs on its own
//! thread (spawned by [`crate::auto_lock::AutoLockController::attach_event_source`])
//! and pushes [`crate::auto_lock::SecurityEvent`]s into the
//! controller's internal channel; the controller drains that channel
//! during [`crate::auto_lock::AutoLockController::tick`].
//!
//! ## MVP sources (this crate)
//!
//! - [`NoopSource`] — always available; produces no events. Useful as
//!   a default on platforms where no native source has been wired up
//!   yet, and as the "do nothing" baseline in tests.
//! - [`SigstopSource`] — Unix only. Catches `SIGTSTP` (terminal stop),
//!   emits `SecurityEvent::OsLock { reason: Sigstop }`, then re-raises
//!   `SIGSTOP` to actually stop the process. `SIGCONT` is observed but
//!   not forwarded — when the process resumes the vault is already
//!   locked and the user re-authenticates normally. See the
//!   [feature design][design] §3.4 for the PRD-literal "SIGSTOP" →
//!   SIGTSTP-catching discrepancy.
//!
//! [design]: ../../../notebook/projects/falach/features/security-behaviors/plans/design.md
//!
//! ## Post-MVP sources (Phase 5)
//!
//! - `LogindSource` (Linux, `zbus`) — subscribes to systemd-logind's
//!   `PrepareForSleep` and `Session.Lock` signals.
//! - `IoKitSource` (macOS, `objc2`) — observes `NSWorkspace`
//!   screensaver and sleep notifications via `IOKit`.
//!
//! Both implement the same trait; consumers add them with
//! `attach_event_source` exactly like the MVP sources.
//!
//! ## Trait contract
//!
//! [`OsLockEventSource::run`] takes `self: Box<Self>` — the controller
//! boxes the source before spawning its thread, then calls `run`
//! which consumes the box. There are no restart semantics; if a
//! source's run loop exits (clean or error), the source is gone.
//! Design §3.9 records the rationale.
//!
//! ## Clean shutdown (Phase 5 T5.0)
//!
//! Before consuming the source via `run`, the controller calls
//! [`OsLockEventSource::shutdown_handle`] to obtain a
//! [`ShutdownHandle`]. The controller stores the handle alongside the
//! source's `JoinHandle` and, on `Drop`, invokes the handle to signal
//! the source's run loop to exit and then joins the thread. Sources
//! that block on a kernel-side primitive (signal-hook self-pipe,
//! `DBus` connection, `CFRunLoop`) wake on the signal and return
//! from `run` with `Ok(())`.
//!
//! Implementations choose how to wire the signal: typically by holding
//! a clone of an upstream "close" handle (`signal_hook::iterator::Handle`,
//! `zbus::Connection`, `CFRunLoopRef`) and returning a closure that
//! invokes it. See [`NoopSource::shutdown_handle`] and
//! [`SigstopSource::shutdown_handle`] for two reference patterns.
//!
//! Risk #12 in the feature's `follow-ups/open-items.md` (MVP's "OS
//! reaps source threads at process exit") is resolved by this
//! contract.

use std::sync::mpsc::Sender;

use crate::auto_lock::SecurityEvent;
use crate::error::SecurityError;

pub mod noop;
#[cfg(unix)]
pub mod sigstop;

#[cfg(all(target_os = "linux", feature = "logind"))]
pub mod logind;

#[cfg(all(target_os = "macos", feature = "iokit"))]
pub mod macos;

pub use noop::NoopSource;

#[cfg(unix)]
pub use sigstop::SigstopSource;

#[cfg(all(target_os = "linux", feature = "logind"))]
pub use logind::LogindSource;

#[cfg(all(target_os = "macos", feature = "iokit"))]
pub use macos::IoKitSource;

/// Single-shot closure the controller invokes from `Drop` to ask an
/// attached [`OsLockEventSource`] to exit its run loop.
///
/// Sources construct one via [`ShutdownHandle::new`] from inside their
/// [`OsLockEventSource::shutdown_handle`] impl. The closure typically
/// captures a clone of an upstream "close" / "stop" handle (e.g.,
/// `signal_hook::iterator::Handle`, a held `Sender<()>` whose drop
/// wakes a parked `recv`, or `CFRunLoopStop` on macOS).
///
/// The closure runs exactly once. The handle itself is not `Clone`
/// (we want at-most-once semantics); the controller takes ownership at
/// `attach_event_source` time and consumes the handle in `Drop`.
pub struct ShutdownHandle {
    signal: Box<dyn FnOnce() + Send + 'static>,
}

impl ShutdownHandle {
    /// Wrap an arbitrary `FnOnce` closure into a [`ShutdownHandle`].
    pub fn new<F>(signal: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        Self {
            signal: Box::new(signal),
        }
    }

    /// Invoke the shutdown closure. Called by
    /// [`crate::auto_lock::AutoLockController`] from its `Drop`.
    pub(crate) fn signal(self) {
        (self.signal)();
    }
}

impl std::fmt::Debug for ShutdownHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShutdownHandle").finish_non_exhaustive()
    }
}

/// An OS-level event source that produces [`SecurityEvent`]s into a
/// sender supplied by the controller.
///
/// Implementations own their own threading or run-loop;
/// [`crate::auto_lock::AutoLockController::attach_event_source`] calls
/// [`Self::shutdown_handle`], spawns one `std::thread` that calls
/// [`Self::run`], and stores both halves. On controller `Drop` the
/// handle is invoked and the thread is joined.
///
/// The trait takes `self: Box<Self>` so implementations can move owned
/// state (file descriptors, `DBus` connections) into the run-loop
/// without further bounds.
///
/// `Send` is required (the source runs on a separate thread); the
/// trait is **not** `Sync` because most platform run-loops are not
/// shareable across threads.
pub trait OsLockEventSource: Send {
    /// Run the source's event loop, sending `SecurityEvent`s into
    /// `sender` until either the loop terminates naturally, the
    /// channel is closed, or the shutdown handle obtained via
    /// [`Self::shutdown_handle`] is invoked by the controller.
    ///
    /// # Errors
    ///
    /// - [`SecurityError::EventSourceStart`] when the source cannot
    ///   initialise its OS primitive (signal-hook registration, `DBus`
    ///   connection, etc.).
    /// - [`SecurityError::EventChannelClosed`] when the controller has
    ///   been dropped before the source.
    fn run(self: Box<Self>, sender: Sender<SecurityEvent>) -> Result<(), SecurityError>;

    /// Diagnostic name. Used in error variants and log lines. Must be
    /// a compile-time constant (e.g., `"sigstop"`, `"noop"`,
    /// `"logind"`).
    fn name(&self) -> &'static str;

    /// Produce a [`ShutdownHandle`] the controller will invoke from
    /// `Drop` to ask this source to exit its run loop.
    ///
    /// Called exactly once, at attach time, by
    /// [`crate::auto_lock::AutoLockController::attach_event_source`],
    /// before the source is consumed by `run`. Implementations
    /// typically capture a clone of an upstream "stop" handle (e.g.,
    /// `signal_hook::iterator::Handle::close()`, dropping a held
    /// `Sender`) in the returned closure.
    ///
    /// The contract: once the closure runs, `Self::run` must return
    /// `Ok(())` within a small bounded time (the controller's `Drop`
    /// budget; today 50 ms in tests). Sources that need a longer
    /// shutdown budget should be reflected in the test bound at the
    /// time they ship.
    fn shutdown_handle(&mut self) -> ShutdownHandle;
}
