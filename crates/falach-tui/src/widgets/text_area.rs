//! `TextArea` — a minimal multi-line text editor for the Edit overlay's notes
//! field (T5.2).
//!
//! `tui_input::Input` is single-line, so notes (which legitimately contain line
//! breaks) get this small hand-rolled buffer instead: a `Vec<String>` of lines
//! with a `(row, col)` cursor, where `col` is a byte offset on a UTF-8 boundary
//! (the same discipline as [`crate::widgets::password_input`]). It handles
//! character insert, `Enter` (split line), `Backspace` (delete / merge), and
//! arrow navigation. Notes are not secret, so a plain `String` is fine.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// A multi-line plaintext editor.
#[derive(Debug, Clone)]
pub(crate) struct TextArea {
    lines: Vec<String>,
    /// Cursor line index (always `< lines.len()`).
    row: usize,
    /// Cursor byte offset within `lines[row]` (always on a char boundary).
    col: usize,
}

impl TextArea {
    /// An empty area with a single blank line.
    pub(crate) fn new() -> Self {
        Self {
            lines: vec![String::new()],
            row: 0,
            col: 0,
        }
    }

    /// Seed from existing notes, splitting on `\n`. Always keeps ≥1 line:
    /// `str::split('\n')` yields ≥1 element for any input (even `""` yields a
    /// single empty string), so `lines` is never empty and `lines.len() - 1`
    /// below cannot underflow.
    pub(crate) fn from_str(value: &str) -> Self {
        let lines: Vec<String> = value.split('\n').map(str::to_string).collect();
        let row = lines.len() - 1;
        let col = lines[row].len();
        Self { lines, row, col }
    }

    /// The full text with `\n` between lines.
    pub(crate) fn value(&self) -> String {
        self.lines.join("\n")
    }

    /// Lines for rendering (read-only borrow).
    pub(crate) fn lines(&self) -> &[String] {
        &self.lines
    }

    /// `(row, visual_col)` for placing the terminal cursor. `visual_col` is the
    /// character count before the cursor (good enough for ASCII/BMP notes).
    pub(crate) fn cursor(&self) -> (usize, usize) {
        let visual_col = self.lines[self.row][..self.col].chars().count();
        (self.row, visual_col)
    }

    /// Feed a key event. Returns `true` when the key was consumed by the editor
    /// (so the caller knows it was a text edit, not a field-navigation key).
    pub(crate) fn on_key(&mut self, key: &KeyEvent) -> bool {
        match key.code {
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.insert_char(c);
                true
            }
            KeyCode::Enter => {
                self.split_line();
                true
            }
            KeyCode::Backspace => {
                self.backspace();
                true
            }
            KeyCode::Left => {
                self.move_left();
                true
            }
            KeyCode::Right => {
                self.move_right();
                true
            }
            KeyCode::Up => {
                self.move_up();
                true
            }
            KeyCode::Down => {
                self.move_down();
                true
            }
            _ => false,
        }
    }

    fn insert_char(&mut self, c: char) {
        self.lines[self.row].insert(self.col, c);
        self.col += c.len_utf8();
    }

    fn split_line(&mut self) {
        let tail = self.lines[self.row].split_off(self.col);
        self.lines.insert(self.row + 1, tail);
        self.row += 1;
        self.col = 0;
    }

    fn backspace(&mut self) {
        if self.col > 0 {
            let prev = prev_boundary(&self.lines[self.row], self.col);
            self.lines[self.row].remove(prev);
            self.col = prev;
        } else if self.row > 0 {
            // Merge this line onto the end of the previous one.
            let current = self.lines.remove(self.row);
            self.row -= 1;
            self.col = self.lines[self.row].len();
            self.lines[self.row].push_str(&current);
        }
    }

    fn move_left(&mut self) {
        if self.col > 0 {
            self.col = prev_boundary(&self.lines[self.row], self.col);
        } else if self.row > 0 {
            self.row -= 1;
            self.col = self.lines[self.row].len();
        }
    }

    fn move_right(&mut self) {
        let line_len = self.lines[self.row].len();
        if self.col < line_len {
            self.col = next_boundary(&self.lines[self.row], self.col);
        } else if self.row + 1 < self.lines.len() {
            self.row += 1;
            self.col = 0;
        }
    }

    fn move_up(&mut self) {
        if self.row > 0 {
            self.row -= 1;
            self.col = self.col.min(self.lines[self.row].len());
            self.col = floor_boundary(&self.lines[self.row], self.col);
        }
    }

    fn move_down(&mut self) {
        if self.row + 1 < self.lines.len() {
            self.row += 1;
            self.col = self.col.min(self.lines[self.row].len());
            self.col = floor_boundary(&self.lines[self.row], self.col);
        }
    }
}

impl Default for TextArea {
    fn default() -> Self {
        Self::new()
    }
}

fn prev_boundary(s: &str, byte_pos: usize) -> usize {
    s[..byte_pos]
        .char_indices()
        .next_back()
        .map_or(0, |(i, _)| i)
}

fn next_boundary(s: &str, byte_pos: usize) -> usize {
    s[byte_pos..]
        .chars()
        .next()
        .map_or(byte_pos, |c| byte_pos + c.len_utf8())
}

/// Round `byte_pos` down to the nearest char boundary `<= byte_pos`.
fn floor_boundary(s: &str, byte_pos: usize) -> usize {
    let mut p = byte_pos.min(s.len());
    while p > 0 && !s.is_char_boundary(p) {
        p -= 1;
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ch(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }
    fn code(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    fn typed(s: &str) -> TextArea {
        let mut ta = TextArea::new();
        for c in s.chars() {
            if c == '\n' {
                ta.on_key(&code(KeyCode::Enter));
            } else {
                ta.on_key(&ch(c));
            }
        }
        ta
    }

    #[test]
    fn insert_and_value_roundtrip() {
        let ta = typed("hello");
        assert_eq!(ta.value(), "hello");
        assert_eq!(ta.cursor(), (0, 5));
    }

    #[test]
    fn enter_splits_into_multiple_lines() {
        let ta = typed("a\nbc");
        assert_eq!(ta.value(), "a\nbc");
        assert_eq!(ta.lines().len(), 2);
        assert_eq!(ta.cursor(), (1, 2));
    }

    #[test]
    fn backspace_at_line_start_merges_with_previous() {
        let mut ta = typed("a\nb");
        // Cursor at (1,1) end of "b"; move to (1,0).
        ta.on_key(&code(KeyCode::Left));
        assert_eq!(ta.cursor(), (1, 0));
        ta.on_key(&code(KeyCode::Backspace));
        assert_eq!(ta.value(), "ab");
        assert_eq!(ta.cursor(), (0, 1));
    }

    #[test]
    fn from_str_splits_on_newlines() {
        let ta = TextArea::from_str("one\ntwo\nthree");
        assert_eq!(ta.lines().len(), 3);
        assert_eq!(ta.value(), "one\ntwo\nthree");
    }

    #[test]
    fn from_str_empty_keeps_one_line() {
        let ta = TextArea::from_str("");
        assert_eq!(ta.lines().len(), 1);
        assert_eq!(ta.value(), "");
    }

    #[test]
    fn arrows_navigate_across_lines_and_unicode() {
        let mut ta = typed("é\nx"); // line0 "é" (2 bytes), line1 "x"
                                    // Cursor at (1,1). Up → (0, col clamped onto a boundary).
        ta.on_key(&code(KeyCode::Up));
        let (row, _) = ta.cursor();
        assert_eq!(row, 0);
        // Left/right must never panic mid-codepoint.
        ta.on_key(&code(KeyCode::Left));
        ta.on_key(&code(KeyCode::Right));
        assert_eq!(ta.value(), "é\nx");
    }
}
