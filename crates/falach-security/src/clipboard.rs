//! Clipboard auto-clear with content-bound compare-and-clear semantics.
//!
//! [`Clipboard::copy_with_autoclear`] writes a value to the system
//! clipboard via [`arboard`] and spawns a timer thread. When the TTL
//! fires, the timer reads the current clipboard contents and clears
//! them **only** if they byte-equal the value Falach originally wrote
//! — so an intervening user copy is never stomped. The returned
//! [`AutoClearGuard`] cancels the timer on drop.
//!
//! ## Threading
//!
//! Each `copy_with_autoclear` call opens a fresh `arboard::Clipboard`
//! for the timer thread. `arboard::Clipboard` is `!Send` on several
//! backends; constructing inside the new thread side-steps the
//! constraint and lets the timer outlive a short-lived caller (the
//! CLI case — see design §3.6).
//!
//! ## Test seam
//!
//! The `ClipboardBackend` trait is `pub(crate)` so unit tests under
//! `#[cfg(test)]` can drive `copy_with_autoclear_inner` against a
//! `FakeClipboardBackend` without a real display. The trait is
//! deliberately NOT public: every consumer goes through [`Clipboard`].

use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::error::SecurityError;
use crate::secret::ZeroizingString;

/// Internal seam over the platform clipboard.
///
/// Production code uses [`ArboardBackend`]. Unit tests use a fake
/// implementation that records calls and returns programmable values.
///
/// The trait is `pub(crate)` — promoting it to `pub` would be a public
/// API change and is intentionally avoided.
pub(crate) trait ClipboardBackend: Send {
    /// Write `text` to the system clipboard.
    fn set_text(&mut self, text: &str) -> Result<(), arboard::Error>;
    /// Read the current clipboard contents as UTF-8.
    fn get_text(&mut self) -> Result<String, arboard::Error>;
}

/// Production [`ClipboardBackend`] wrapping `arboard::Clipboard`.
pub(crate) struct ArboardBackend(arboard::Clipboard);

impl ArboardBackend {
    /// Open the system clipboard. Maps initialisation failures to
    /// [`SecurityError::ClipboardUnavailable`].
    fn new() -> Result<Self, SecurityError> {
        arboard::Clipboard::new()
            .map(Self)
            .map_err(|e| SecurityError::ClipboardUnavailable(e.to_string()))
    }
}

impl ClipboardBackend for ArboardBackend {
    fn set_text(&mut self, text: &str) -> Result<(), arboard::Error> {
        // `arboard::Clipboard::set_text` takes `Into<Cow<'_, str>>`;
        // pass an owned `String` so the call doesn't borrow our buffer
        // longer than needed.
        self.0.set_text(text.to_owned())
    }

    fn get_text(&mut self) -> Result<String, arboard::Error> {
        self.0.get_text()
    }
}

/// Handle to the system clipboard.
///
/// Open once via [`Self::new`]; every secret-copy operation goes
/// through [`Self::copy_with_autoclear`], which arms a compare-and-
/// clear timer for the supplied TTL.
pub struct Clipboard {
    backend: Box<dyn ClipboardBackend>,
}

impl Clipboard {
    /// Open the system clipboard.
    ///
    /// # Errors
    ///
    /// - [`SecurityError::ClipboardUnavailable`] when the platform
    ///   clipboard cannot be initialised (e.g., no `DISPLAY` /
    ///   `WAYLAND_DISPLAY` on Linux, `NSPasteboard` FFI failure on
    ///   macOS).
    pub fn new() -> Result<Self, SecurityError> {
        Ok(Self {
            backend: Box::new(ArboardBackend::new()?),
        })
    }

    /// Copy `text` to the clipboard and arm an auto-clear timer for
    /// `ttl`. Returns an [`AutoClearGuard`] whose drop cancels the
    /// timer.
    ///
    /// **Restoration semantics:** when the timer fires it re-reads
    /// the clipboard and clears it *only* if the contents are
    /// byte-equal to `text`. If another application has overwritten
    /// the clipboard in the meantime, the timer walks away.
    ///
    /// # Errors
    ///
    /// - [`SecurityError::ClipboardIo`] when the arming write fails.
    /// - [`SecurityError::ClipboardUnavailable`] when the timer
    ///   thread cannot open its own clipboard handle.
    /// - [`SecurityError::EventSourceStart`] (with `name =
    ///   "clipboard-autoclear"`) when the timer thread cannot be
    ///   spawned.
    pub fn copy_with_autoclear(
        &mut self,
        text: String,
        ttl: Duration,
    ) -> Result<AutoClearGuard, SecurityError> {
        // Per design §3.6: the timer thread owns its own backend
        // because `arboard::Clipboard` is `!Send` on some backends.
        let timer_backend: Box<dyn ClipboardBackend> = Box::new(ArboardBackend::new()?);
        copy_with_autoclear_inner(&mut *self.backend, timer_backend, text, ttl)
    }
}

/// Test-injectable arming-and-timer setup. Used by `copy_with_autoclear`
/// in production (with `ArboardBackend`s) and by unit tests (with a
/// `FakeClipboardBackend`).
pub(crate) fn copy_with_autoclear_inner(
    arming: &mut dyn ClipboardBackend,
    timer_backend: Box<dyn ClipboardBackend>,
    text: String,
    ttl: Duration,
) -> Result<AutoClearGuard, SecurityError> {
    // Self-zeroing buffer for the arming write — even if `set_text`
    // panics, the bytes are wiped when this stack frame unwinds.
    let payload = zeroize::Zeroizing::new(text);
    arming
        .set_text(payload.as_str())
        .map_err(|e| SecurityError::ClipboardIo {
            detail: e.to_string(),
        })?;

    // Comparison copy lives on the timer thread; zeroized on drop.
    let comparison = ZeroizingString::new(payload.as_str());

    let (cancel_tx, cancel_rx) = mpsc::channel::<()>();
    let (fired_tx, fired_rx) = mpsc::channel::<()>();

    let join = std::thread::Builder::new()
        .name("falach-clipboard-autoclear".to_owned())
        .spawn(move || {
            run_autoclear(timer_backend, comparison, ttl, &cancel_rx);
            // Notify any `wait_for_clear` consumer. Best-effort: if the
            // guard has already been dropped the send fails silently.
            let _ = fired_tx.send(());
        })
        .map_err(|e| SecurityError::EventSourceStart {
            name: "clipboard-autoclear",
            detail: e.to_string(),
        })?;

    Ok(AutoClearGuard {
        cancel_tx,
        fired_rx,
        _join: join,
    })
}

/// Timer-thread body — the heart of compare-and-clear. Public to the
/// crate so tests in this module can call it under documented inputs.
///
/// `comparison` is intentionally passed by value (rather than by
/// reference) so the zeroizing buffer drops — and zeroes its bytes —
/// the moment this function returns, instead of lingering until the
/// outer spawn-closure finishes. The `clippy::needless_pass_by_value`
/// lint flags this because the body only borrows `comparison`; the
/// allow below documents that the move is the point.
#[allow(clippy::needless_pass_by_value)]
fn run_autoclear(
    mut backend: Box<dyn ClipboardBackend>,
    comparison: ZeroizingString,
    ttl: Duration,
    cancel_rx: &Receiver<()>,
) {
    use std::sync::mpsc::RecvTimeoutError;
    match cancel_rx.recv_timeout(ttl) {
        Ok(()) | Err(RecvTimeoutError::Disconnected) => {
            // Cancelled (explicit drop, explicit `cancel()`, or guard
            // gone). Walk away — leave the clipboard exactly as the
            // arming write left it.
        }
        Err(RecvTimeoutError::Timeout) => {
            // TTL fired. Read-then-compare-then-maybe-clear.
            match backend.get_text() {
                Ok(current) if current == *comparison => {
                    // Contents match — safe to clear.
                    let _ = backend.set_text("");
                }
                Ok(_) | Err(_) => {
                    // Either another application replaced the
                    // clipboard (`Ok` with a non-matching value) or
                    // the read itself failed (`Err` — e.g., display
                    // disconnected). In both cases we can't be sure
                    // what's on the clipboard, so we refuse to write
                    // to it.
                }
            }
        }
    }
}

/// RAII handle for an armed auto-clear timer.
///
/// Dropping the guard cancels the timer before it fires, leaving the
/// clipboard exactly as the arming write left it. The consuming
/// [`Self::cancel`] method does the same — both rely on
/// `Drop` for the actual cancellation.
///
/// Holds the spawned timer thread's `JoinHandle` so the thread is
/// owned by the guard's lifetime. Dropping the handle does not
/// block; the thread runs to completion on its own (either the
/// cancellation arrives or the TTL fires).
pub struct AutoClearGuard {
    cancel_tx: Sender<()>,
    fired_rx: Receiver<()>,
    // Held for ownership; never joined. Dropping a `JoinHandle`
    // detaches the thread without blocking.
    _join: JoinHandle<()>,
}

impl AutoClearGuard {
    /// Cancel the timer explicitly. The clipboard is left as-is.
    ///
    /// Equivalent to `drop(guard)` — both go through [`Drop`].
    pub fn cancel(self) {
        // Just consume self; `Drop` does the work.
    }

    /// Block the current thread until the timer fires (or has already
    /// fired). Returns immediately if the guard has already been
    /// cancelled by an earlier `Drop` / `cancel()` — the cancellation
    /// path also drops `fired_tx` inside the timer thread, which we
    /// treat as "done."
    ///
    /// Intended for the CLI's Wayland case: the clipboard on Wayland
    /// does not survive the source-process lifetime, so a one-shot
    /// `falach entry get --copy` must keep its process alive until
    /// the timer has done its work.
    ///
    /// # Errors
    ///
    /// Currently infallible. The signature returns `Result` so a
    /// future version can distinguish "fired cleanly" from "fired
    /// after the backend errored" without a breaking change.
    pub fn wait_for_clear(&mut self) -> Result<(), SecurityError> {
        // `recv()` returns `Ok(())` when the timer thread sent its
        // completion signal, and `Err(RecvError)` when the sender was
        // dropped without sending — either way the work is done; we
        // collapse both to `Ok(())`. The simpler contract (per task
        // doc T3.2 Tech Notes) keeps the public surface terse.
        let _ = self.fired_rx.recv();
        Ok(())
    }
}

impl Drop for AutoClearGuard {
    fn drop(&mut self) {
        // Best-effort: if the timer thread already exited (timeout
        // fired, clear ran), `send` returns `Err` which we discard.
        let _ = self.cancel_tx.send(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// Calls recorded by [`FakeClipboardBackend`]. Tests assert on
    /// shape and order.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        Set(String),
        Get,
    }

    /// In-test `ClipboardBackend` that records every call and lets the
    /// test program `get_text` to return a specific value or error.
    struct FakeClipboardBackend {
        calls: Arc<Mutex<Vec<Call>>>,
        // Queue of canned `get_text` results — popped front on each
        // call. When empty, defaults to `Ok(String::new())`.
        get_text_responses: Arc<Mutex<Vec<Result<String, arboard::Error>>>>,
        // Canned `set_text` failure — applied on the *next* set_text
        // call only.
        set_text_failure: Arc<Mutex<Option<arboard::Error>>>,
    }

    impl FakeClipboardBackend {
        fn new() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                get_text_responses: Arc::new(Mutex::new(Vec::new())),
                set_text_failure: Arc::new(Mutex::new(None)),
            }
        }

        fn calls_handle(&self) -> Arc<Mutex<Vec<Call>>> {
            Arc::clone(&self.calls)
        }

        fn queue_get_text(&self, response: Result<String, arboard::Error>) {
            self.get_text_responses
                .lock()
                .expect("poisoned")
                .push(response);
        }

        fn arm_set_text_failure(&self, err: arboard::Error) {
            *self.set_text_failure.lock().expect("poisoned") = Some(err);
        }
    }

    impl ClipboardBackend for FakeClipboardBackend {
        fn set_text(&mut self, text: &str) -> Result<(), arboard::Error> {
            if let Some(err) = self.set_text_failure.lock().expect("poisoned").take() {
                return Err(err);
            }
            self.calls
                .lock()
                .expect("poisoned")
                .push(Call::Set(text.to_owned()));
            Ok(())
        }

        fn get_text(&mut self) -> Result<String, arboard::Error> {
            self.calls.lock().expect("poisoned").push(Call::Get);
            self.get_text_responses
                .lock()
                .expect("poisoned")
                .pop()
                // VecDeque-ish behaviour: front-pop would be nicer but
                // tests only ever queue one response, so `pop()` (back)
                // is equivalent.
                .unwrap_or(Ok(String::new()))
        }
    }

    fn unknown(msg: &str) -> arboard::Error {
        arboard::Error::Unknown {
            description: msg.to_owned(),
        }
    }

    /// Sleep slightly longer than `ttl` to give the timer thread room
    /// to fire and record its calls. The unit-test assertion is about
    /// the recorded call log, not precise wall-clock timing, so the
    /// generous grace shields against scheduler jitter.
    fn wait_past_ttl(ttl: Duration) {
        std::thread::sleep(ttl + Duration::from_millis(200));
    }

    #[test]
    fn copy_with_autoclear_calls_set_text_once_with_payload() {
        let mut arming = FakeClipboardBackend::new();
        let arming_log = arming.calls_handle();
        let timer = FakeClipboardBackend::new();

        // Long TTL — we only care about the arming write, not the timer firing.
        let guard = copy_with_autoclear_inner(
            &mut arming,
            Box::new(timer),
            "hunter2".to_owned(),
            Duration::from_secs(10),
        )
        .expect("arming write should succeed");

        let log = arming_log.lock().expect("poisoned").clone();
        assert_eq!(
            log,
            vec![Call::Set("hunter2".to_owned())],
            "arming backend should record exactly one set_text(\"hunter2\")",
        );
        drop(guard); // cancels the timer immediately
    }

    #[test]
    fn autoclear_clears_on_timeout_when_contents_match() {
        let mut arming = FakeClipboardBackend::new();
        let timer = FakeClipboardBackend::new();
        let timer_log = timer.calls_handle();
        // Timer-thread `get_text` returns the same value Falach wrote.
        timer.queue_get_text(Ok("hunter2".to_owned()));

        let ttl = Duration::from_millis(50);
        let guard =
            copy_with_autoclear_inner(&mut arming, Box::new(timer), "hunter2".to_owned(), ttl)
                .expect("arming should succeed");

        // We need the timer to fire; intentionally do not drop the
        // guard before the sleep elapses.
        wait_past_ttl(ttl);

        let log = timer_log.lock().expect("poisoned").clone();
        assert_eq!(
            log,
            vec![Call::Get, Call::Set(String::new())],
            "timer should get_text then set_text(\"\") when contents match",
        );
        drop(guard);
    }

    #[test]
    fn autoclear_walks_away_when_contents_differ() {
        let mut arming = FakeClipboardBackend::new();
        let timer = FakeClipboardBackend::new();
        let timer_log = timer.calls_handle();
        // Timer-thread `get_text` returns a DIFFERENT value (another
        // app overwrote the clipboard).
        timer.queue_get_text(Ok("user-copied-something-else".to_owned()));

        let ttl = Duration::from_millis(50);
        let guard =
            copy_with_autoclear_inner(&mut arming, Box::new(timer), "hunter2".to_owned(), ttl)
                .expect("arming should succeed");

        wait_past_ttl(ttl);

        let log = timer_log.lock().expect("poisoned").clone();
        assert_eq!(
            log,
            vec![Call::Get],
            "timer should read but NOT write when contents differ",
        );
        drop(guard);
    }

    #[test]
    fn autoclear_walks_away_when_get_text_errors() {
        let mut arming = FakeClipboardBackend::new();
        let timer = FakeClipboardBackend::new();
        let timer_log = timer.calls_handle();
        timer.queue_get_text(Err(unknown("display disconnected")));

        let ttl = Duration::from_millis(50);
        let guard =
            copy_with_autoclear_inner(&mut arming, Box::new(timer), "hunter2".to_owned(), ttl)
                .expect("arming should succeed");

        wait_past_ttl(ttl);

        let log = timer_log.lock().expect("poisoned").clone();
        assert_eq!(
            log,
            vec![Call::Get],
            "timer should attempt the read but never write on error",
        );
        drop(guard);
    }

    #[test]
    fn guard_drop_cancels_timer_before_fire() {
        let mut arming = FakeClipboardBackend::new();
        let timer = FakeClipboardBackend::new();
        let timer_log = timer.calls_handle();
        // If the timer DID fire it would see the matching value and
        // clear — so the assertion below (no `Get`, no `Set("")`)
        // catches that regression.
        timer.queue_get_text(Ok("hunter2".to_owned()));

        let ttl = Duration::from_millis(500);
        let guard =
            copy_with_autoclear_inner(&mut arming, Box::new(timer), "hunter2".to_owned(), ttl)
                .expect("arming should succeed");
        drop(guard); // cancel BEFORE the TTL elapses

        // Wait past the original TTL — if the timer is still alive
        // it would have fired by now.
        wait_past_ttl(ttl);

        let log = timer_log.lock().expect("poisoned").clone();
        assert!(
            log.is_empty(),
            "timer thread should have been cancelled before reading or writing; saw {log:?}",
        );
    }

    #[test]
    fn guard_explicit_cancel_does_not_clear() {
        let mut arming = FakeClipboardBackend::new();
        let timer = FakeClipboardBackend::new();
        let timer_log = timer.calls_handle();
        timer.queue_get_text(Ok("hunter2".to_owned()));

        let ttl = Duration::from_millis(500);
        let guard =
            copy_with_autoclear_inner(&mut arming, Box::new(timer), "hunter2".to_owned(), ttl)
                .expect("arming should succeed");
        guard.cancel(); // consuming method — must behave like Drop

        wait_past_ttl(ttl);

        let log = timer_log.lock().expect("poisoned").clone();
        assert!(
            log.is_empty(),
            "cancel() must cancel just like Drop; saw {log:?}",
        );
    }

    #[test]
    fn arming_backend_failure_returns_clipboard_io_error() {
        let mut arming = FakeClipboardBackend::new();
        arming.arm_set_text_failure(unknown("x11 down"));
        let timer = FakeClipboardBackend::new();
        let timer_log = timer.calls_handle();

        let result = copy_with_autoclear_inner(
            &mut arming,
            Box::new(timer),
            "hunter2".to_owned(),
            Duration::from_secs(10),
        );

        match result {
            Err(SecurityError::ClipboardIo { detail }) => {
                assert!(
                    detail.contains("x11 down"),
                    "ClipboardIo detail should propagate the upstream message; got {detail:?}",
                );
            }
            Err(other) => panic!("expected ClipboardIo, got {other:?}"),
            Ok(_) => panic!("expected arming write to fail"),
        }

        let log = timer_log.lock().expect("poisoned").clone();
        assert!(
            log.is_empty(),
            "timer thread must NOT spawn when arming write fails; saw {log:?}",
        );
    }

    #[test]
    fn multiple_concurrent_armings_each_get_their_own_timer() {
        // Two independent arming calls. Drop the FIRST guard, leave
        // the SECOND alive past its TTL — the second's timer must
        // still fire. Variable names are aligned to the payloads
        // (`first` / `second`) rather than `_a`/`_b` so the
        // intentional asymmetry reads clearly and so we steer clear
        // of `clippy::similar_names`.
        let mut arming_first = FakeClipboardBackend::new();
        let timer_first = FakeClipboardBackend::new();
        let recorded_first = timer_first.calls_handle();
        timer_first.queue_get_text(Ok("first".to_owned()));

        let mut arming_second = FakeClipboardBackend::new();
        let timer_second = FakeClipboardBackend::new();
        let recorded_second = timer_second.calls_handle();
        timer_second.queue_get_text(Ok("second".to_owned()));

        let ttl = Duration::from_millis(100);
        let guard_first = copy_with_autoclear_inner(
            &mut arming_first,
            Box::new(timer_first),
            "first".to_owned(),
            ttl,
        )
        .expect("arming `first` should succeed");
        let guard_second = copy_with_autoclear_inner(
            &mut arming_second,
            Box::new(timer_second),
            "second".to_owned(),
            ttl,
        )
        .expect("arming `second` should succeed");

        drop(guard_first); // cancel the first
                           // Leave `guard_second` alive

        wait_past_ttl(ttl);

        let calls_first = recorded_first.lock().expect("poisoned").clone();
        assert!(
            calls_first.is_empty(),
            "the first guard was cancelled; its timer must not fire; saw {calls_first:?}",
        );

        let calls_second = recorded_second.lock().expect("poisoned").clone();
        assert_eq!(
            calls_second,
            vec![Call::Get, Call::Set(String::new())],
            "the second guard was NOT cancelled; its timer must still fire and clear",
        );
        drop(guard_second);
    }
}
