//! `PasswordInput` — an echo-suppressed text field over `Zeroizing<String>`.
//!
//! Memory-hygiene contract (CLAUDE.md / `kb/memory-hygiene.md`): the typed
//! buffer is never displayed (only `•` per character), `Ctrl`-modified keys are
//! ignored, and the buffer zeroizes whenever the widget is dropped (cancel,
//! lock, screen change) or consumed via [`PasswordInput::take`]. The caller
//! converts the taken buffer straight into `MasterPassword::new(..)`, which is
//! itself zeroize-on-drop.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Rect;
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use zeroize::Zeroizing;

use crate::theme::Theme;

/// The outcome of feeding a key event to the widget.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InputAction {
    /// Keystroke consumed; keep showing the prompt.
    Continue,
    /// `Enter` pressed; the caller should `take()` the buffer and submit.
    Submit,
    /// `Esc` pressed; the caller should drop the widget (zeroize fires).
    Cancel,
}

/// An echo-suppressed single-line password field.
pub(crate) struct PasswordInput {
    /// The typed bytes. `Zeroizing` zeroizes them on drop.
    buffer: Zeroizing<String>,
    /// Cursor position as a byte offset into `buffer` (always on a UTF-8
    /// char boundary).
    cursor: usize,
}

impl PasswordInput {
    pub(crate) fn new() -> Self {
        Self {
            buffer: Zeroizing::new(String::new()),
            cursor: 0,
        }
    }

    /// Seed the field with an existing value (editing an entry's password). The
    /// seed lives in the same `Zeroizing` buffer and is masked like typed input;
    /// the cursor starts at the end.
    pub(crate) fn with_value(seed: &str) -> Self {
        Self {
            buffer: Zeroizing::new(seed.to_string()),
            cursor: seed.len(),
        }
    }

    /// Borrow the typed buffer without consuming the widget.
    ///
    /// This deliberately relaxes the "never read out" contract for the Edit
    /// overlay, which must hand the typed password to `add_entry`/`update_entry`
    /// (and to the masked-or-revealed render). Callers must not log it or render
    /// it in the clear except behind an explicit reveal toggle.
    pub(crate) fn as_str(&self) -> &str {
        &self.buffer
    }

    /// Replace the buffer wholesale (used when the Generate panel fills the
    /// password field). The previous buffer zeroizes as it is dropped.
    pub(crate) fn set_value(&mut self, value: &str) {
        self.buffer = Zeroizing::new(value.to_string());
        self.cursor = self.buffer.len();
    }

    /// Feed a key event. Returns the action the caller should take.
    pub(crate) fn on_key(&mut self, key: &KeyEvent) -> InputAction {
        match key.code {
            KeyCode::Enter => InputAction::Submit,
            KeyCode::Esc => InputAction::Cancel,
            KeyCode::Backspace => {
                self.backspace();
                InputAction::Continue
            }
            KeyCode::Left => {
                self.cursor_left();
                InputAction::Continue
            }
            KeyCode::Right => {
                self.cursor_right();
                InputAction::Continue
            }
            // Printable characters — but never Ctrl-modified ones (no
            // Ctrl+V-as-keystroke; OS terminal paste still arrives as plain
            // `Char` events and is accepted).
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.insert_char(c);
                InputAction::Continue
            }
            _ => InputAction::Continue,
        }
    }

    /// Number of typed characters (for the masked render).
    pub(crate) fn len_chars(&self) -> usize {
        self.buffer.chars().count()
    }

    /// Cursor position as a character index (for caret rendering when this
    /// widget backs a visible in-form field, e.g. the otpauth URI).
    pub(crate) fn cursor_chars(&self) -> usize {
        self.buffer[..self.cursor].chars().count()
    }

    /// Render the masked field: one `•` per typed character, clamped to the
    /// available width. Never renders the underlying characters.
    pub(crate) fn render(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let dots = self.len_chars().min(area.width as usize);
        let masked: String = "•".repeat(dots);
        frame.render_widget(Paragraph::new(masked).style(theme.header()), area);
    }

    /// Consume the widget, returning the buffer for `MasterPassword::new`.
    /// Moving `self` means the widget can't be reused (compile-time enforced).
    pub(crate) fn take(self) -> Zeroizing<String> {
        self.buffer
    }

    /// Test-only: zeroize the buffer in place and return its `(ptr, len)` so a
    /// caller can volatile-read the bytes *while still allocated* — the
    /// `password_input` drop-guarantee pattern (drop-then-read is flaky on
    /// macOS). Used by overlays that hold a `PasswordInput` to prove their own
    /// secret buffers zeroize (PMF-1).
    #[cfg(test)]
    pub(crate) fn zeroize_and_expose(&mut self) -> (*const u8, usize) {
        use zeroize::Zeroize;
        let ptr = self.buffer.as_ptr();
        let len = self.buffer.len();
        self.buffer.zeroize();
        (ptr, len)
    }

    fn insert_char(&mut self, c: char) {
        self.buffer.insert(self.cursor, c);
        self.cursor += c.len_utf8();
    }

    fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let prev = prev_char_boundary(&self.buffer, self.cursor);
        self.buffer.remove(prev);
        self.cursor = prev;
    }

    fn cursor_left(&mut self) {
        if self.cursor > 0 {
            self.cursor = prev_char_boundary(&self.buffer, self.cursor);
        }
    }

    fn cursor_right(&mut self) {
        if self.cursor < self.buffer.len() {
            self.cursor = next_char_boundary(&self.buffer, self.cursor);
        }
    }
}

/// Byte offset of the char boundary immediately before `byte_pos`.
/// `byte_pos` must be a char boundary > 0.
fn prev_char_boundary(s: &str, byte_pos: usize) -> usize {
    s[..byte_pos]
        .char_indices()
        .next_back()
        .map_or(0, |(i, _)| i)
}

/// Byte offset of the char boundary immediately after `byte_pos`.
/// `byte_pos` must be a char boundary < `s.len()`.
fn next_char_boundary(s: &str, byte_pos: usize) -> usize {
    s[byte_pos..]
        .chars()
        .next()
        .map_or(byte_pos, |c| byte_pos + c.len_utf8())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ch(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }

    fn code(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn typed(s: &str) -> PasswordInput {
        let mut input = PasswordInput::new();
        for c in s.chars() {
            input.on_key(&ch(c));
        }
        input
    }

    #[test]
    fn insert_char_appends_to_buffer() {
        let input = typed("hunter2");
        assert_eq!(&*input.buffer, "hunter2");
        assert_eq!(input.cursor, "hunter2".len());
        assert_eq!(input.len_chars(), 7);
    }

    #[test]
    fn insert_handles_unicode_multibyte() {
        // "pä🔑" — a 2-byte char and a 4-byte char; cursor must track bytes.
        let input = typed("pä🔑");
        assert_eq!(&*input.buffer, "pä🔑");
        assert_eq!(input.cursor, "pä🔑".len());
        assert_eq!(
            input.len_chars(),
            3,
            "three characters, regardless of bytes"
        );
    }

    #[test]
    fn backspace_removes_previous_char_and_is_noop_at_start() {
        let mut input = typed("aé"); // 'é' is 2 bytes
        input.on_key(&code(KeyCode::Backspace));
        assert_eq!(&*input.buffer, "a");
        assert_eq!(input.cursor, 1);
        input.on_key(&code(KeyCode::Backspace));
        assert_eq!(&*input.buffer, "");
        assert_eq!(input.cursor, 0);
        // Backspace at start is a no-op.
        input.on_key(&code(KeyCode::Backspace));
        assert_eq!(input.cursor, 0);
        assert!(input.buffer.is_empty());
    }

    #[test]
    fn cursor_left_and_right_respect_boundaries() {
        let mut input = typed("aé"); // bytes: a(1) é(2) → len 3
                                     // At end; right is a no-op.
        input.on_key(&code(KeyCode::Right));
        assert_eq!(input.cursor, 3);
        // Left across the 2-byte char lands on a boundary, not mid-char.
        input.on_key(&code(KeyCode::Left));
        assert_eq!(input.cursor, 1);
        input.on_key(&code(KeyCode::Left));
        assert_eq!(input.cursor, 0);
        // Left at start is a no-op.
        input.on_key(&code(KeyCode::Left));
        assert_eq!(input.cursor, 0);
    }

    #[test]
    fn enter_returns_submit_and_esc_returns_cancel() {
        let mut input = typed("x");
        assert_eq!(input.on_key(&code(KeyCode::Enter)), InputAction::Submit);
        assert_eq!(input.on_key(&code(KeyCode::Esc)), InputAction::Cancel);
    }

    #[test]
    fn ctrl_modified_chars_are_ignored() {
        let mut input = PasswordInput::new();
        let ctrl_v = KeyEvent::new(KeyCode::Char('v'), KeyModifiers::CONTROL);
        assert_eq!(input.on_key(&ctrl_v), InputAction::Continue);
        assert!(
            input.buffer.is_empty(),
            "Ctrl+V must not insert a character"
        );
    }

    #[test]
    fn take_consumes_widget_returning_buffer() {
        let input = typed("secret");
        let buf = input.take();
        assert_eq!(&*buf, "secret");
        // `input` is moved-from here; using it again would not compile.
    }

    // Headline guarantee: the buffer's bytes are zeroed by the same `zeroize`
    // call that `Zeroizing`'s `Drop` performs.
    //
    // We mirror vault-core's `secret.rs` precedent: read the bytes *after an
    // explicit `zeroize()` while the buffer is still allocated*, NOT after drop.
    // Reading freed heap is unreliable — on macOS the allocator immediately
    // overwrites a freed slot with bookkeeping data, masking zeroize's work and
    // producing misleading results. `Zeroizing<String>::drop` calls exactly the
    // `zeroize()` exercised here, so this faithfully tests the drop guarantee.
    #[cfg(test)]
    #[allow(unsafe_code)] // documented volatile-read zeroize verification
    #[test]
    fn buffer_zeroizes_its_bytes() {
        use zeroize::Zeroize;

        let mut input = typed("supersecret-password-bytes");
        let ptr: *const u8 = input.buffer.as_ptr();
        let len = input.buffer.len();
        assert!(len > 0);

        // The operation `Zeroizing`'s Drop runs.
        input.buffer.zeroize();

        for i in 0..len {
            // SAFETY: the buffer is still allocated (we only zeroized, did not
            // drop); `ptr` came from the live `String` and is valid for `len`
            // bytes. The read happens before any deallocation.
            let byte = unsafe { std::ptr::read_volatile(ptr.add(i)) };
            assert_eq!(byte, 0, "password byte at offset {i} not zeroed");
        }
    }
}
