//! `ClipboardSink` — the TUI's testable seam over `falach_security::Clipboard`
//! (T5.5).
//!
//! Copy actions (`c` password, `C` username) go through this trait so that:
//!
//! * tests run headless — `falach_security::Clipboard::new()` needs a display
//!   (`DISPLAY`/`WAYLAND_DISPLAY`/`NSPasteboard`), so the real sink can't be
//!   constructed in CI; tests inject [`RecordingClipboard`] instead
//!   (sibling-contract #8);
//! * the §3.9 armed-guard cap (8, oldest-dropped) lives in the real impl rather
//!   than on `App` (a documented deviation from design U.2's `clip_guards`
//!   field — `AutoClearGuard` is not mockable, so keeping guard ownership in the
//!   sink is what makes the trait injectable). The TUI never calls
//!   `wait_for_clear` (sibling-contract #2); dropping a guard cancels its timer.

use std::time::Duration;

use falach_security::{AutoClearGuard, Clipboard, SecurityError};

/// Maximum simultaneously-armed auto-clear timers (design §3.9). The oldest is
/// dropped (cancelling its timer) when a 9th copy arrives.
const MAX_GUARDS: usize = 8;

/// How long a copied secret lingers before auto-clear (FR-053).
pub(crate) const CLIPBOARD_TTL: Duration = Duration::from_secs(30);

/// Copy text to the clipboard with an armed auto-clear timer.
pub(crate) trait ClipboardSink {
    /// Copy `text` and arm a `ttl` auto-clear. `Ok(())` on success.
    fn copy(&mut self, text: String, ttl: Duration) -> Result<(), SecurityError>;
}

/// Real clipboard backed by `falach_security::Clipboard`, owning the armed
/// guards so their timers stay alive across frames.
pub(crate) struct SystemClipboard {
    inner: Clipboard,
    guards: Vec<AutoClearGuard>,
}

impl SystemClipboard {
    /// Open the system clipboard. Fails on headless platforms (no display).
    pub(crate) fn new() -> Result<Self, SecurityError> {
        Ok(Self {
            inner: Clipboard::new()?,
            guards: Vec::new(),
        })
    }
}

impl ClipboardSink for SystemClipboard {
    fn copy(&mut self, text: String, ttl: Duration) -> Result<(), SecurityError> {
        let guard = self.inner.copy_with_autoclear(text, ttl)?;
        if self.guards.len() >= MAX_GUARDS {
            // Dropping the oldest guard cancels its (still-pending) timer.
            self.guards.remove(0);
        }
        self.guards.push(guard);
        Ok(())
    }
}

/// Fallback sink when no system clipboard is available (headless launch). Copy
/// attempts return an error so the App surfaces a status message instead of the
/// TUI failing to start.
pub(crate) struct UnavailableClipboard;

impl ClipboardSink for UnavailableClipboard {
    fn copy(&mut self, _text: String, _ttl: Duration) -> Result<(), SecurityError> {
        Err(SecurityError::ClipboardUnavailable(
            "no system clipboard (headless?)".to_string(),
        ))
    }
}

/// Build the production sink, falling back to [`UnavailableClipboard`] when the
/// platform clipboard can't be opened (so the TUI still launches headless).
pub(crate) fn system_or_unavailable() -> Box<dyn ClipboardSink> {
    match SystemClipboard::new() {
        Ok(c) => Box::new(c),
        Err(_) => Box::new(UnavailableClipboard),
    }
}

/// Shared record of clipboard activity, so a test can both inject the sink into
/// an `App` and inspect what it captured afterwards.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct RecordingLog {
    pub(crate) last: Option<(String, Duration)>,
    pub(crate) copies: usize,
    pub(crate) fail: bool,
}

/// Test sink writing into a shared [`RecordingLog`]. Set `fail = true` on the
/// log to exercise the copy-failure status path.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct RecordingClipboard {
    pub(crate) log: std::rc::Rc<std::cell::RefCell<RecordingLog>>,
}

#[cfg(test)]
impl RecordingClipboard {
    pub(crate) fn new() -> Self {
        Self {
            log: std::rc::Rc::new(std::cell::RefCell::new(RecordingLog::default())),
        }
    }
}

#[cfg(test)]
impl ClipboardSink for RecordingClipboard {
    fn copy(&mut self, text: String, ttl: Duration) -> Result<(), SecurityError> {
        let mut log = self.log.borrow_mut();
        if log.fail {
            return Err(SecurityError::ClipboardUnavailable("test".to_string()));
        }
        log.copies += 1;
        log.last = Some((text, ttl));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_sink_captures_copy() {
        let mut sink = RecordingClipboard::new();
        sink.copy("secret".to_string(), CLIPBOARD_TTL).unwrap();
        let log = sink.log.borrow();
        assert_eq!(log.copies, 1);
        assert_eq!(log.last.as_ref().unwrap().0, "secret");
        assert_eq!(log.last.as_ref().unwrap().1, CLIPBOARD_TTL);
    }

    #[test]
    fn unavailable_sink_errors() {
        let mut sink = UnavailableClipboard;
        assert!(sink.copy("x".to_string(), CLIPBOARD_TTL).is_err());
    }
}
