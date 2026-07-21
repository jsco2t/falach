//! US-053 — Clipboard auto-clear (real `arboard`).
//!
//! These cases drive the production [`falach_security::Clipboard`]
//! against the actual system clipboard, so they require either an X11
//! display (Linux, typically via `xvfb-run`) or a real macOS
//! Pasteboard. All three are `#[ignore]`d so the default `cargo test`
//! invocation skips them on headless hosts (e.g., the `make check`
//! gate runs unit tests only). Run via `make test-clipboard`, which
//! invokes:
//!
//! ```text
//! cargo test -p falach-security --offline --locked \
//!     --test us_053_clipboard_autoclear -- --ignored --test-threads=1
//! ```
//!
//! Selecting the test binary by `--test us_053_clipboard_autoclear`
//! (rather than a positional name filter) is intentional: cargo's
//! positional argument filters test *function names*, and our test
//! functions are named after the behaviour they verify (e.g.,
//! `clipboard_clears_after_ttl_when_we_still_own_contents`), not after
//! the US identifier.
//!
//! `--test-threads=1` is required: the system clipboard is a
//! process-global resource, and we open multiple `arboard::Clipboard`
//! handles inside these cases. Running them in parallel would let one
//! test's arming write race another's `get_text` assertion.
//!
//! ## CI
//!
//! No CI job *runs* these cases — they need a real display/pasteboard
//! that hosted runners don't provide; the runtime verification is
//! local (`make test-clipboard`, wrapped in `xvfb-run -a` on a headless
//! Linux box) plus the manual
//! `notebook/.../verifications/security.md` US-053 pass. CI does
//! *compile* this file via `make check-feature-gates` so API refactors
//! can't silently break it.
//!
//! ## Feature gate
//!
//! The whole file is gated behind the `clipboard-tests` cargo feature.
//! Without it the file is not compiled, so the blanket `make
//! test-ignored` sweep (`cargo test --workspace -- --ignored`) can never
//! reach these cases on a headless host. `make test-clipboard` enables
//! the feature; nothing else does. Mirrors the `logind`-feature gate on
//! `us_052_post_mvp_logind.rs`.
#![cfg(feature = "clipboard-tests")]

use std::time::Duration;

use falach_security::Clipboard;

/// TTL used by every case here. Short enough that the test suite
/// stays fast; long enough that the arming write completes before we
/// race the cancellation/overwrite.
const TTL: Duration = Duration::from_millis(500);

/// Wall-clock grace on top of `TTL` to absorb scheduler jitter and
/// arboard's X11/Wayland round-trip overhead. 200ms is two orders of
/// magnitude above any plausible jitter on the targets we support.
const GRACE: Duration = Duration::from_millis(200);

/// Best-effort housekeeping between cases. Each case ends by writing
/// an empty string to the clipboard so the next test starts from a
/// known state. Ignores errors (the next test would observe them
/// anyway).
fn clear_clipboard_best_effort() {
    if let Ok(mut cb) = Clipboard::new() {
        // Re-arm with an empty payload + a tiny TTL to avoid leaving
        // a long-running timer behind. The drop cancels the timer; the
        // arming write itself is what leaves "" on the clipboard.
        let _ = cb.copy_with_autoclear(String::new(), Duration::from_millis(1));
    }
}

/// US-053 AC #1: when the TTL fires and the clipboard still holds
/// what Falach wrote, the timer clears it.
#[test]
#[ignore = "requires a real display; run via `make test-clipboard`"]
fn clipboard_clears_after_ttl_when_we_still_own_contents() {
    let mut clipboard = Clipboard::new().expect("clipboard should open");
    let mut guard = clipboard
        .copy_with_autoclear("hunter2-clears-after-ttl".to_owned(), TTL)
        .expect("arming write should succeed");

    // Block until the timer thread reports completion. `wait_for_clear`
    // is the exact path the Wayland CLI consumer will use.
    guard
        .wait_for_clear()
        .expect("wait_for_clear infallible today");

    // Some platforms surface a cleared clipboard as
    // `Err(ContentNotAvailable)` rather than `Ok("")`; treat both as
    // "cleared."
    let read_back = arboard::Clipboard::new()
        .and_then(|mut cb| cb.get_text())
        .unwrap_or_default();
    assert_eq!(
        read_back, "",
        "clipboard should be empty after the timer fired",
    );

    drop(guard);
    clear_clipboard_best_effort();
}

/// US-053 AC #2 — **the high-value contract.** If another application
/// overwrites the clipboard between our arming write and the TTL, the
/// timer must walk away without touching the user's value.
#[test]
#[ignore = "requires a real display; run via `make test-clipboard`"]
fn clipboard_preserved_when_another_app_overwrites_mid_ttl() {
    let mut clipboard = Clipboard::new().expect("clipboard should open");
    let mut guard = clipboard
        .copy_with_autoclear("hunter2-overwritten-mid-ttl".to_owned(), TTL)
        .expect("arming write should succeed");

    // Simulate another app: open an independent arboard handle and
    // overwrite the clipboard with a different value immediately.
    let user_value = "user-copied-this-mid-ttl";
    {
        let mut other = arboard::Clipboard::new().expect("second clipboard handle should open");
        other
            .set_text(user_value.to_owned())
            .expect("overwriting the clipboard should succeed");
    }

    // Block until the timer thread has done whatever it was going to
    // do, then add the grace window for OS-side round-trips.
    guard
        .wait_for_clear()
        .expect("wait_for_clear infallible today");
    std::thread::sleep(GRACE);

    let read_back = arboard::Clipboard::new()
        .and_then(|mut cb| cb.get_text())
        .expect("clipboard should be readable after the timer fired");
    assert_eq!(
        read_back, user_value,
        "Falach must NOT stomp the user's intervening copy",
    );

    drop(guard);
    clear_clipboard_best_effort();
}

/// US-053 AC #3: dropping the [`AutoClearGuard`] before the TTL fires
/// cancels the timer — Falach's value stays on the clipboard until
/// some other action clears it.
#[test]
#[ignore = "requires a real display; run via `make test-clipboard`"]
fn clipboard_preserved_when_guard_dropped_before_ttl() {
    let value = "hunter2-guard-dropped-early";
    {
        let mut clipboard = Clipboard::new().expect("clipboard should open");
        let _guard = clipboard
            .copy_with_autoclear(value.to_owned(), TTL)
            .expect("arming write should succeed");
        // `_guard` drops here — well before TTL elapses.
    }

    // Wait past the original TTL — if the timer is still alive it
    // would have cleared by now.
    std::thread::sleep(TTL + GRACE);

    let read_back = arboard::Clipboard::new()
        .and_then(|mut cb| cb.get_text())
        .expect("clipboard should be readable after the guard dropped");
    assert_eq!(
        read_back, value,
        "the cancelled timer must not clear the clipboard",
    );

    clear_clipboard_best_effort();
}
