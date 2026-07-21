//! `SigstopSource` — POSIX signal-driven [`OsLockEventSource`].
//!
//! ## What we actually catch
//!
//! The PRD (§6.6 FR-052) says "lock on SIGSTOP." The literal
//! [`libc::SIGSTOP`](https://man7.org/linux/man-pages/man7/signal.7.html)
//! cannot be caught — that's the kernel-enforced property that makes
//! it useful in the first place. The catchable cousin is `SIGTSTP`
//! (terminal stop, sent by Ctrl-Z or `kill -TSTP <pid>`).
//!
//! This source catches `SIGTSTP`, emits `OsLock { Sigstop }` on the
//! controller's channel, then re-raises `SIGSTOP` so the kernel
//! actually stops the process. When the user later runs `fg` (or
//! anything else that delivers `SIGCONT`), the process resumes — but
//! the controller is already in `Locked`, so the user re-authenticates
//! normally. `SIGCONT` itself is observed and ignored; if we forwarded
//! it as an `Activity` event, any process that can send `SIGCONT`
//! could keep the vault unlocked.
//!
//! Feature design records this discrepancy in §3.4.
//!
//! ## Dependency posture
//!
//! `signal-hook` is the catching side (its `iterator::Signals` is a
//! safe self-pipe wrapper); `signal_hook::low_level::raise` is the
//! re-stop side. We do not add `nix` as a production dep — using
//! signal-hook for both halves keeps the runtime dep count minimal.

use std::sync::mpsc::Sender;

use signal_hook::consts::{SIGCONT, SIGSTOP, SIGTSTP};
use signal_hook::iterator::{Handle, Signals};

use crate::auto_lock::{OsLockReason, SecurityEvent};
use crate::error::SecurityError;

use super::{OsLockEventSource, ShutdownHandle};

/// `OsLockEventSource` that maps `SIGTSTP` to an immediate lock and
/// then re-raises `SIGSTOP` so the kernel still stops the process.
///
/// Construct with [`Self::new`]; attach via
/// [`crate::auto_lock::AutoLockController::attach_event_source`]. Once
/// attached, every `SIGTSTP` the process receives triggers an
/// `OsLock { Sigstop }` event before the process is suspended.
///
/// ## Shutdown (Phase 5 T5.0)
///
/// The source retains a clone of the `signal_hook::iterator::Handle`
/// returned by [`Signals::handle`]. When the controller drops, it
/// invokes the [`ShutdownHandle`] returned from
/// [`OsLockEventSource::shutdown_handle`], which calls `Handle::close()`.
/// The `forever` iterator then drains any pending signals and returns
/// `None`; the loop in `run` exits and the function returns `Ok(())`.
pub struct SigstopSource {
    signals: Signals,
    /// Cloned at construction so the source can hand a shutdown
    /// closure (invoking `Handle::close()`) to the controller without
    /// having to take a reference into `self` after `run` consumes
    /// the box.
    handle: Handle,
}

impl SigstopSource {
    /// Register handlers for `SIGTSTP` and `SIGCONT`.
    ///
    /// # Errors
    ///
    /// Returns [`SecurityError::EventSourceStart`] (with
    /// `name = "sigstop"`) if `signal-hook` cannot register the
    /// handlers — typically because the process is already in a
    /// signal-disposition state the registration can't reconcile.
    pub fn new() -> Result<Self, SecurityError> {
        let signals =
            Signals::new([SIGTSTP, SIGCONT]).map_err(|e| SecurityError::EventSourceStart {
                name: "sigstop",
                detail: e.to_string(),
            })?;
        let handle = signals.handle();
        Ok(Self { signals, handle })
    }
}

impl OsLockEventSource for SigstopSource {
    fn run(self: Box<Self>, sender: Sender<SecurityEvent>) -> Result<(), SecurityError> {
        // `Signals::forever` consumes the iterator on `self`; we move
        // it out of the box.
        let mut signals = self.signals;
        for signal in signals.forever() {
            match signal {
                SIGTSTP => {
                    // Notify the controller first — if we re-raise
                    // SIGSTOP before sending, the kernel stops us and
                    // the event sits in the iterator queue until the
                    // process resumes, which is too late for a vault
                    // that should already be locked.
                    if sender
                        .send(SecurityEvent::OsLock {
                            reason: OsLockReason::Sigstop,
                        })
                        .is_err()
                    {
                        return Err(SecurityError::EventChannelClosed { name: "sigstop" });
                    }
                    // Re-raise SIGSTOP so the kernel actually stops
                    // the process — preserves shell `fg` UX. Errors
                    // here are unrecoverable (means the kernel refused
                    // to deliver a signal to ourselves, which is not
                    // a state we can usefully react to); surface as
                    // EventSourceStart for diagnostics.
                    signal_hook::low_level::raise(SIGSTOP).map_err(|e| {
                        SecurityError::EventSourceStart {
                            name: "sigstop",
                            detail: format!("raise(SIGSTOP) failed: {e}"),
                        }
                    })?;
                }
                SIGCONT => {
                    // Deliberately ignored. The process is resuming
                    // after a SIGTSTP/SIGSTOP pair; the controller is
                    // already `Locked` and stays that way until the
                    // frontend re-authenticates via `unlock`. Mapping
                    // SIGCONT to `Activity` here would let any process
                    // that can deliver SIGCONT keep the vault open —
                    // a security regression we explicitly guard
                    // against (see US-052 `sigcont_alone_does_not_unlock_helper`).
                }
                _ => {
                    // `Signals::new` only subscribed to `[SIGTSTP,
                    // SIGCONT]`; any other signal here is a
                    // signal-hook bug we want to surface loudly.
                    unreachable!("signal_hook delivered an unsubscribed signal: {signal}");
                }
            }
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "sigstop"
    }

    fn shutdown_handle(&mut self) -> ShutdownHandle {
        // `Handle` is `Clone`; capturing a clone in the closure lets
        // the source still own its `Signals` (which the run loop
        // consumes via `forever()`). On signal, `Handle::close()`
        // causes the iterator to drain and return `None`.
        let handle = self.handle.clone();
        ShutdownHandle::new(move || {
            handle.close();
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Both tests are `#[ignore]`d because `Signals::new` installs a
    // process-wide handler. They run only under `make test-ignored`
    // which serialises with `--test-threads=1`. The tests acquire no
    // additional lock because the test binary's invocation already
    // forces single-threaded execution.

    #[test]
    #[ignore = "installs a process-wide signal handler; run via `make test-ignored`"]
    fn name_returns_sigstop() {
        let source = SigstopSource::new().expect("SigstopSource::new on a Unix host");
        assert_eq!(source.name(), "sigstop");
    }

    #[test]
    #[ignore = "installs a process-wide signal handler; run via `make test-ignored`"]
    fn new_succeeds_on_unix() {
        // Smoke test: confirm the `signal_hook::iterator::Signals::new`
        // call wires up correctly. A regression that, e.g., subscribes
        // to a bogus signal number would fail here with `EventSourceStart`.
        let _source =
            SigstopSource::new().expect("Signals::new with [SIGTSTP, SIGCONT] should succeed");
    }

    /// Phase 5 T5.0: `SigstopSource::run` returns `Ok(())` cleanly
    /// when the shutdown handle is invoked. Validates the
    /// `Handle::close()` wiring without needing a real `SIGTSTP`.
    #[test]
    #[ignore = "installs a process-wide signal handler; run via `make test-ignored`"]
    fn run_returns_ok_when_shutdown_signaled() {
        use std::sync::mpsc;
        use std::time::Duration;

        let mut source = SigstopSource::new().expect("SigstopSource::new on Unix");
        let shutdown = source.shutdown_handle();
        let (sender_for_run, _drop_receiver) = mpsc::channel::<SecurityEvent>();
        let (result_tx, result_rx) = mpsc::channel::<Result<(), SecurityError>>();

        let worker = std::thread::spawn(move || {
            let outcome = Box::new(source).run(sender_for_run);
            let _ = result_tx.send(outcome);
        });

        // Signal: `Handle::close()` makes `Signals::forever` return
        // `None`; the `for` loop in `run` exits and the function
        // returns `Ok(())`.
        shutdown.signal();

        match result_rx.recv_timeout(Duration::from_millis(500)) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!("SigstopSource::run returned Err: {e:?}"),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("SigstopSource::run did not return within 500ms after Handle::close()")
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("worker channel closed unexpectedly")
            }
        }
        worker.join().expect("worker thread panicked");
    }
}
