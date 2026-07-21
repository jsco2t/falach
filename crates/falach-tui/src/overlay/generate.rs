//! Generate panel — nested inside the Edit overlay (T5.3, ADR: not a peer
//! overlay).
//!
//! Launched with `Ctrl+G` from the Edit overlay's password field; on accept the
//! preview replaces the Edit password field and the panel closes. The preview
//! is kept in a [`Zeroizing`] buffer so it is wiped on drop (cancel, accept,
//! lock). Generation delegates to `falach-genpw` (`PasswordBuilder` /
//! `PassphraseBuilder`) — the TUI holds no generation logic of its own.

use falach_core::Zeroizing;
use falach_genpw::{CharSet, PassphraseBuilder, PasswordBuilder};

/// Which generator the panel drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GenKind {
    Password,
    Passphrase,
}

/// Inclusive bounds so `+`/`-` adjustments stay in a sane, generator-valid
/// range (a 0-length password or a 1-word passphrase is useless).
pub(crate) const MIN_LENGTH: usize = 8;
pub(crate) const MAX_LENGTH: usize = 128;
pub(crate) const MIN_WORDS: usize = 3;
pub(crate) const MAX_WORDS: usize = 12;

/// State of the generate panel. The `preview` is regenerated on every change
/// and on explicit re-roll (`r`).
pub(crate) struct GenState {
    pub(crate) kind: GenKind,
    pub(crate) length: usize,
    pub(crate) words: usize,
    pub(crate) classes: CharSet,
    pub(crate) exclude_ambiguous: bool,
    pub(crate) preview: Zeroizing<String>,
    /// A non-secret error string (e.g. all char classes disabled) when the last
    /// generation failed; the preview is left empty in that case.
    pub(crate) error: Option<String>,
}

impl GenState {
    /// A fresh panel with sensible defaults, eagerly generating a first preview.
    pub(crate) fn new() -> Self {
        let mut state = Self {
            kind: GenKind::Password,
            length: falach_genpw::DEFAULT_LENGTH,
            words: falach_genpw::DEFAULT_WORDS,
            classes: CharSet::ALL,
            exclude_ambiguous: false,
            preview: Zeroizing::new(String::new()),
            error: None,
        };
        state.regenerate();
        state
    }

    /// Re-roll the preview from the current settings (CSPRNG via `falach-genpw`).
    pub(crate) fn regenerate(&mut self) {
        let result = match self.kind {
            GenKind::Password => PasswordBuilder::new()
                .length(self.length)
                .classes(self.classes)
                .exclude_ambiguous(self.exclude_ambiguous)
                .generate(),
            GenKind::Passphrase => PassphraseBuilder::new().words(self.words).generate(),
        };
        match result {
            Ok(secret) => {
                self.preview = secret;
                self.error = None;
            }
            Err(e) => {
                self.preview = Zeroizing::new(String::new());
                self.error = Some(e.to_string());
            }
        }
    }

    pub(crate) fn toggle_kind(&mut self) {
        self.kind = match self.kind {
            GenKind::Password => GenKind::Passphrase,
            GenKind::Passphrase => GenKind::Password,
        };
        self.regenerate();
    }

    /// `+` — grow the relevant size dimension (length or word count) and re-roll.
    pub(crate) fn grow(&mut self) {
        match self.kind {
            GenKind::Password => self.length = (self.length + 1).min(MAX_LENGTH),
            GenKind::Passphrase => self.words = (self.words + 1).min(MAX_WORDS),
        }
        self.regenerate();
    }

    /// `-` — shrink the relevant size dimension and re-roll.
    pub(crate) fn shrink(&mut self) {
        match self.kind {
            GenKind::Password => self.length = self.length.saturating_sub(1).max(MIN_LENGTH),
            GenKind::Passphrase => self.words = self.words.saturating_sub(1).max(MIN_WORDS),
        }
        self.regenerate();
    }

    /// Toggle one password character class (no-op for passphrases) and re-roll.
    pub(crate) fn toggle_class(&mut self, class: Class) {
        if self.kind != GenKind::Password {
            return;
        }
        let field = match class {
            Class::Lower => &mut self.classes.lowercase,
            Class::Upper => &mut self.classes.uppercase,
            Class::Digits => &mut self.classes.digits,
            Class::Symbols => &mut self.classes.symbols,
        };
        *field = !*field;
        self.regenerate();
    }

    pub(crate) fn toggle_ambiguous(&mut self) {
        if self.kind != GenKind::Password {
            return;
        }
        self.exclude_ambiguous = !self.exclude_ambiguous;
        self.regenerate();
    }
}

/// A togglable password character class (the `l`/`u`/`d`/`s` keys).
#[derive(Debug, Clone, Copy)]
pub(crate) enum Class {
    Lower,
    Upper,
    Digits,
    Symbols,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_generates_a_password_preview() {
        let state = GenState::new();
        assert_eq!(state.kind, GenKind::Password);
        assert!(state.error.is_none());
        assert_eq!(state.preview.len(), falach_genpw::DEFAULT_LENGTH);
    }

    #[test]
    fn toggle_kind_switches_and_regenerates() {
        let mut state = GenState::new();
        state.toggle_kind();
        assert_eq!(state.kind, GenKind::Passphrase);
        // A diceware passphrase has the requested number of words separated by
        // the default separator → (words - 1) separators present.
        assert!(state.error.is_none());
        assert!(!state.preview.is_empty());
    }

    #[test]
    fn grow_and_shrink_clamp_to_bounds() {
        let mut state = GenState::new();
        state.length = MAX_LENGTH;
        state.grow();
        assert_eq!(state.length, MAX_LENGTH, "grow clamps at MAX_LENGTH");
        state.length = MIN_LENGTH;
        state.shrink();
        assert_eq!(state.length, MIN_LENGTH, "shrink clamps at MIN_LENGTH");
    }

    #[test]
    fn disabling_all_classes_sets_error_and_empties_preview() {
        let mut state = GenState::new();
        state.toggle_class(Class::Lower);
        state.toggle_class(Class::Upper);
        state.toggle_class(Class::Digits);
        state.toggle_class(Class::Symbols);
        assert_eq!(state.classes, CharSet::NONE);
        assert!(state.error.is_some(), "no classes → generation error");
        assert!(state.preview.is_empty());
    }

    #[test]
    fn class_toggles_are_noop_for_passphrase() {
        let mut state = GenState::new();
        state.toggle_kind(); // → Passphrase
        let before = state.classes;
        state.toggle_class(Class::Symbols);
        assert_eq!(
            state.classes, before,
            "class toggles ignored for passphrase"
        );
    }
}
