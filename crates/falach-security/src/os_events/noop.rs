//! `NoopSource` — the always-available, do-nothing
//! [`OsLockEventSource`].
//!
//! Used as the default on platforms without a native lock-event
//! source wired up, and as a baseline in tests. `run` parks the
//! calling thread on an `mpsc::Receiver<()>`; the controller's
//! `Drop` invokes this source's [`ShutdownHandle`], which drops the
//! held `Sender<()>` so the receiver unblocks with `RecvError` and
//! `run` returns `Ok(())` cleanly.

use std::sync::mpsc::{self, Receiver, Sender};

use crate::auto_lock::SecurityEvent;
use crate::error::SecurityError;

use super::{OsLockEventSource, ShutdownHandle};

/// `OsLockEventSource` that produces no events.
///
/// The run loop blocks on `rx.recv()` against a `Sender<()>` owned by
/// the source struct. When the controller drops it invokes the
/// shutdown handle, which drops the sender; the receiver then
/// unblocks with `RecvError` and `run` returns `Ok(())`. No
/// `std::mem::forget` is involved — every thread cleanly joins.
pub struct NoopSource {
    /// Held until [`Self::shutdown_handle`] is called (at which point
    /// it is moved into the returned closure and dropped on signal).
    /// Once `shutdown_handle` has been called, this is `None` and
    /// `run` will see an already-disconnected receiver.
    park_tx: Option<Sender<()>>,
    /// Receiver that `run` blocks on. Moved out of the struct in
    /// `run`.
    park_rx: Option<Receiver<()>>,
}

impl NoopSource {
    /// Construct a [`NoopSource`]. Allocates the parking channel that
    /// keeps `run` blocked until the controller signals shutdown.
    #[must_use]
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            park_tx: Some(tx),
            park_rx: Some(rx),
        }
    }
}

impl Default for NoopSource {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for NoopSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoopSource").finish_non_exhaustive()
    }
}

impl OsLockEventSource for NoopSource {
    fn run(self: Box<Self>, _sender: Sender<SecurityEvent>) -> Result<(), SecurityError> {
        // `shutdown_handle` may already have consumed `park_tx`; if so
        // `recv` returns immediately with `RecvError`. Otherwise we
        // hold the sender alongside the receiver and `recv` parks
        // forever — but in practice `shutdown_handle` is always called
        // by `attach_event_source` before `run`, so this branch is
        // only relevant if the source is used outside the controller
        // (e.g., a unit test calling `run` directly without going
        // through `attach_event_source`).
        let rx = self
            .park_rx
            .expect("NoopSource::run called twice or after shutdown_handle moved rx");
        // `recv` returns `Err(RecvError)` once all senders are
        // dropped — that is exactly the shutdown signal.
        let _ = rx.recv();
        Ok(())
    }

    fn name(&self) -> &'static str {
        "noop"
    }

    fn shutdown_handle(&mut self) -> ShutdownHandle {
        // Move the sender out of `self`; the returned closure owns it
        // and drops it on signal, unblocking `run`'s `rx.recv()`.
        let tx = self
            .park_tx
            .take()
            .expect("NoopSource::shutdown_handle called twice");
        ShutdownHandle::new(move || {
            drop(tx);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn name_returns_noop() {
        assert_eq!(NoopSource::new().name(), "noop");
    }

    #[test]
    fn run_returns_ok_when_shutdown_signaled() {
        // Build a source, take its shutdown handle, spawn `run` on a
        // worker thread, then signal shutdown. Assert `run` returned
        // `Ok(())` and the worker joined within a small bound.
        let mut source = NoopSource::new();
        let shutdown = source.shutdown_handle();
        let (sender_for_run, _drop_receiver) = mpsc::channel::<SecurityEvent>();

        let (result_tx, result_rx) = mpsc::channel::<Result<(), SecurityError>>();
        let worker = std::thread::spawn(move || {
            let outcome = Box::new(source).run(sender_for_run);
            let _ = result_tx.send(outcome);
        });

        // Signal shutdown — `run` should return Ok within ~milliseconds.
        shutdown.signal();

        match result_rx.recv_timeout(Duration::from_millis(500)) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!("NoopSource::run returned Err: {e:?}"),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("NoopSource::run did not return within 500ms after shutdown signal")
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("worker channel closed unexpectedly")
            }
        }
        worker.join().expect("worker thread panicked");
    }

    #[test]
    fn run_blocks_when_no_shutdown_signaled() {
        // Sanity check: a fresh source holds its parking sender (no
        // `mem::forget` regression) and `park_rx` blocks while the
        // sender is alive — which is the contract `run` relies on
        // for its "park until shutdown" behaviour.
        //
        // We deliberately do NOT spawn a worker thread for the parked
        // `run` — that would leak one OS thread per test run, which
        // would pollute the process-global thread count read by
        // `auto_lock::tests::controller_drop_joins_attached_sources_cleanly`
        // (same crate, same test binary under `cargo test --lib`).
        // Instead we observe the channel state directly: while the
        // source's sender is held, `park_rx.try_recv` returns `Empty`
        // and `park_rx.recv_timeout(20ms)` returns `Timeout`. These
        // are the exact observations `run`'s `rx.recv()` would make.
        let source = NoopSource::new();
        let rx = source
            .park_rx
            .as_ref()
            .expect("freshly-constructed source has its parking receiver");

        assert!(
            matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "park_rx should be empty while the sender is held",
        );
        assert!(
            matches!(
                rx.recv_timeout(Duration::from_millis(20)),
                Err(mpsc::RecvTimeoutError::Timeout),
            ),
            "park_rx should still be blocking after a short wait",
        );
        // Dropping `source` at end of scope drops the held sender;
        // the receiver would unblock with `Disconnected` if we still
        // held it — that's the path exercised by
        // `run_returns_ok_when_shutdown_signaled` (the live `run`).
    }
}
