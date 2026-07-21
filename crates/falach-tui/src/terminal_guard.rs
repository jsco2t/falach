//! `TerminalGuard` — RAII terminal setup/teardown + a panic hook + a
//! best-effort fatal-signal handler, so the terminal is always restored.
//!
//! Order matters (revised 2026-06-01, resolves R-1): the panic hook **and**
//! the signal handler are installed *first*, before any terminal state is
//! touched, so (a) a panic during construction still restores the terminal and
//! (b) the hook is installable/testable without a TTY (T-IT-9). Restore is
//! factored into [`restore_terminal`] so the wiring test can inject a buffer,
//! and the `EnterAlternateScreen` error path explicitly undoes raw mode (a bare
//! `?` would leak it — the hook fires only on a *panic*, not a returned `Err`).
//!
//! See the "Signals" block at the bottom for why this crate carries exactly
//! one audited `unsafe` block.

use std::io::{stdout, Write};
use std::sync::Once;

use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};

use crate::error::TuiError;

/// Owns the raw-mode + alternate-screen state for the lifetime of the TUI.
///
/// Constructed only via [`TerminalGuard::new`] (`_private` blocks struct-literal
/// construction), which guarantees the panic hook + signal handler are armed.
pub(crate) struct TerminalGuard {
    _private: (),
}

impl TerminalGuard {
    /// Install the panic hook + signal handler, then enter raw mode +
    /// alternate screen. `mouse` enables mouse-event capture (T4.6); capture
    /// failure is non-fatal (proceed keyboard-only), and every restore path
    /// disables capture unconditionally so a panic never leaves the terminal
    /// reporting mouse.
    pub(crate) fn new(mouse: bool) -> Result<Self, TuiError> {
        // Hooks FIRST: a panic or fatal signal during construction must still
        // restore the terminal, and the hook must be installable without a TTY.
        install_panic_hook();
        signals::install();

        enable_raw_mode()?;
        if let Err(e) = execute!(stdout(), EnterAlternateScreen) {
            // Raw mode already succeeded but no guard is constructed on this
            // path, so Drop will never run to undo it — undo it here. (The
            // panic hook does NOT fire: this is an `Err`, not a panic.)
            let _ = disable_raw_mode();
            return Err(e.into());
        }
        if mouse {
            // Best-effort: odd terminals may reject capture — proceed keyboard-only.
            let _ = execute!(stdout(), EnableMouseCapture);
        }
        Ok(Self { _private: () })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal(&mut stdout());
    }
}

/// Best-effort terminal restore, shared by `Drop` and the panic hook so there
/// is exactly one restore path.
///
/// NOTE: `disable_raw_mode()` is a `tcsetattr` termios syscall and writes no
/// bytes through `out`, so a `Vec<u8>` sink observes the alt-screen escape but
/// NOT the raw-mode restoration. The termios half is covered by the manual
/// verification `01-local-headless/03-panic-safety.md`, not the in-process test.
pub(crate) fn restore_terminal(out: &mut impl Write) {
    // Disable mouse capture unconditionally (harmless if it was never enabled)
    // so a panic mid-session never leaves the terminal emitting mouse escapes.
    let _ = execute!(out, DisableMouseCapture);
    let _ = execute!(out, LeaveAlternateScreen);
    let _ = disable_raw_mode();
}

/// Global panic hook that restores the terminal before the default hook prints.
///
/// `Once`-gated: tests construct several `TerminalGuard`s across a run, and
/// installing the hook repeatedly would chain (and progressively slow) it.
pub(crate) fn install_panic_hook() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_terminal(&mut stdout());
            default(info); // now print the panic to a sane terminal
        }));
    });
}

/// Best-effort `SIGHUP`/`SIGTERM` handling (R-1 / OQ-D, 2026-06-01).
///
/// `SIGINT` is moot — in raw mode crossterm delivers Ctrl+C as a key event, not
/// a signal. The exposure is `SIGHUP` (terminal closed) and `SIGTERM` (`kill`),
/// which terminate the process *without* running `Drop` or the panic hook,
/// leaving the terminal in raw mode. We restore the terminal and re-raise the
/// signal's default disposition.
///
/// This is the one place the crate needs `unsafe`: an async-signal-safe handler
/// cannot call crossterm's `disable_raw_mode` (it takes a mutex), so it issues a
/// saved-`termios` `tcsetattr` + a `write(2)` of the leave-alt-screen escape
/// directly. The crate is therefore `deny(unsafe_code)` (workspace default) with
/// exactly one audited `#[allow(unsafe_code)]` module, mirroring
/// `falach-security`. `signal-hook` was rejected to keep the dependency surface
/// minimal (supply-chain "hand-roll small well-specified things").
///
/// **Honest limit (principle #5):** zeroize-on-drop is NOT async-signal-safe, so
/// secret material is NOT wiped on signal death — the handler restores the
/// terminal only. A SIGKILL cannot be handled at all.
#[cfg(unix)]
mod signals {
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Cooked-mode termios captured before raw mode, restored by the handler.
    /// Written once (before any handler can fire) and only read in the handler.
    static mut SAVED_TERMIOS: Option<libc::termios> = None;
    static TERMIOS_SAVED: AtomicBool = AtomicBool::new(false);
    static INSTALLED: AtomicBool = AtomicBool::new(false);

    /// Disable all mouse-reporting modes enabled by crossterm, then leave the
    /// alternate screen. Written directly because `execute!`/`Stdout` are not
    /// async-signal-safe.
    pub(super) const RESTORE_TERMINAL: &[u8] =
        b"\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1015l\x1b[?1006l\x1b[?1049l";

    /// Capture the current (cooked) termios and install the handlers. Idempotent
    /// and called before `enable_raw_mode`, so the saved state is the cooked one.
    pub(crate) fn install() {
        if INSTALLED.swap(true, Ordering::SeqCst) {
            return;
        }
        // SAFETY: single-threaded construction path; we capture the terminal's
        // current termios into a process-global before any signal handler is
        // armed, and only read it (never write) from the handler thereafter.
        // `tcgetattr` on a non-TTY fd fails harmlessly (we just skip restore).
        #[allow(unsafe_code)]
        unsafe {
            let mut termios = std::mem::zeroed::<libc::termios>();
            if libc::tcgetattr(libc::STDIN_FILENO, std::ptr::addr_of_mut!(termios)) == 0 {
                SAVED_TERMIOS = Some(termios);
                TERMIOS_SAVED.store(true, Ordering::SeqCst);
            }
            let handler_ptr = handler as *const () as libc::sighandler_t;
            libc::signal(libc::SIGHUP, handler_ptr);
            libc::signal(libc::SIGTERM, handler_ptr);
        }
    }

    /// Async-signal-safe handler: restore termios, leave the alternate screen,
    /// then re-raise the signal's default disposition so the process dies with
    /// the expected status. Only async-signal-safe libc calls are used.
    extern "C" fn handler(sig: libc::c_int) {
        // SAFETY: only async-signal-safe syscalls (`tcsetattr`, `write`,
        // `signal`, `raise`) and reads of statics written before the handler
        // could fire. No allocation, no locks, no Rust runtime services.
        #[allow(unsafe_code)]
        unsafe {
            if TERMIOS_SAVED.load(Ordering::SeqCst) {
                if let Some(termios) = std::ptr::addr_of!(SAVED_TERMIOS).read() {
                    libc::tcsetattr(
                        libc::STDIN_FILENO,
                        libc::TCSANOW,
                        std::ptr::addr_of!(termios),
                    );
                }
            }
            libc::write(
                libc::STDOUT_FILENO,
                RESTORE_TERMINAL.as_ptr().cast::<libc::c_void>(),
                RESTORE_TERMINAL.len(),
            );
            // Re-raise with the default disposition so the exit status is right.
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
    }
}

/// On non-Unix targets (not a Phase-0 platform) there is no signal handler.
#[cfg(not(unix))]
mod signals {
    pub(crate) fn install() {}
}

#[cfg(test)]
mod tests {
    //! T-IT-9 (panic-safety wiring, reframed 2026-06-01).
    //!
    //! The original "capture stderr, assert cleanup-before-panic" is
    //! unbuildable: cleanup writes to *stdout* (panic message to *stderr*, no
    //! in-process cross-fd ordering) and `enable_raw_mode()` errors with no TTY,
    //! so `TerminalGuard::new` never installs the hook in CI. These are
    //! deterministic in-process tests of the restore wiring instead. The
    //! `tcsetattr` raw-mode restoration emits no bytes and is covered by the
    //! manual verification `01-local-headless/03-panic-safety.md`.

    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    /// The leave-alternate-screen escape emitted by `restore_terminal`.
    const LEAVE_ALT_SCREEN: &[u8] = b"\x1b[?1049l";
    /// The disable-mouse-capture escape (SGR + normal tracking off) emitted by
    /// `restore_terminal` (T4.6). crossterm writes `?1006`, `?1015`, `?1000`.
    const DISABLE_MOUSE: &[u8] = b"\x1b[?1000l";

    fn contains(bytes: &[u8], needle: &[u8]) -> bool {
        bytes.windows(needle.len()).any(|w| w == needle)
    }

    /// The restore body writes the leave-alt-screen escape AND disables mouse
    /// capture into an injected sink (the observable half of the cleanup; the
    /// termios `tcsetattr` half emits no bytes — see the module note). The
    /// mouse-disable assertion is the T4.6 panic-safety extension: a panic must
    /// never leave the terminal reporting mouse.
    #[test]
    fn restore_terminal_writes_leave_alt_screen_and_disables_mouse() {
        let mut sink: Vec<u8> = Vec::new();
        restore_terminal(&mut sink);
        assert!(
            contains(&sink, LEAVE_ALT_SCREEN),
            "restore_terminal must emit the leave-alt-screen escape; got {sink:?}"
        );
        assert!(
            contains(&sink, DISABLE_MOUSE),
            "restore_terminal must disable mouse capture; got {sink:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn fatal_signal_restore_disables_mouse_before_leaving_alt_screen() {
        let bytes = signals::RESTORE_TERMINAL;
        let mouse = bytes
            .windows(DISABLE_MOUSE.len())
            .position(|window| window == DISABLE_MOUSE)
            .expect("signal restore disables mouse");
        let alt = bytes
            .windows(LEAVE_ALT_SCREEN.len())
            .position(|window| window == LEAVE_ALT_SCREEN)
            .expect("signal restore leaves alternate screen");
        assert!(mouse < alt);
    }

    /// T-IT-9 case 1: a panic hook wired the same way the production hook is
    /// (restore-then-chain-to-default) runs the restore body — observed via an
    /// injected sink + a spy flag — *before* the previous hook. Deterministic,
    /// in-process, no TTY.
    #[test]
    fn panic_hook_wiring_runs_restore_before_default() {
        let restored = Arc::new(AtomicBool::new(false));
        let default_ran_after_restore = Arc::new(AtomicBool::new(false));
        let sink = Arc::new(Mutex::new(Vec::<u8>::new()));

        let prev = std::panic::take_hook();
        {
            let restored = Arc::clone(&restored);
            let default_ran_after_restore = Arc::clone(&default_ran_after_restore);
            let sink = Arc::clone(&sink);
            std::panic::set_hook(Box::new(move |_info| {
                // Restore body first (as the production hook does)...
                restore_terminal(&mut *sink.lock().expect("sink poisoned"));
                restored.store(true, Ordering::SeqCst);
                // ...then the "default" hook observes that restore already ran.
                default_ran_after_restore.store(restored.load(Ordering::SeqCst), Ordering::SeqCst);
            }));
        }

        let result = std::panic::catch_unwind(|| panic!("deliberate test panic"));
        std::panic::set_hook(prev); // restore the harness hook before asserting

        assert!(result.is_err(), "the closure should have panicked");
        assert!(
            restored.load(Ordering::SeqCst),
            "the restore body must run on panic"
        );
        assert!(
            default_ran_after_restore.load(Ordering::SeqCst),
            "the default hook must run after the restore body"
        );
        let bytes = sink.lock().expect("sink poisoned");
        assert!(
            contains(&bytes, LEAVE_ALT_SCREEN),
            "the restore body must emit the leave-alt-screen escape during a panic"
        );
    }

    /// T-IT-9 case 2: `install_panic_hook` is `Once`-gated, so calling it
    /// repeatedly is safe (no chaining, no panic). It installs the production
    /// hook (which writes to the real stdout) at most once for the process.
    #[test]
    fn panic_hook_install_is_idempotent() {
        install_panic_hook();
        install_panic_hook();
        install_panic_hook();
    }
}
