//! Character classes and the ambiguous-character set for random
//! password generation.
//!
//! Per design §2.2.1: a hand-rolled `CharSet` struct rather than the
//! `bitflags` crate — the surface is four booleans and the readability
//! win from a macro is small. The four class constants (`LOWERCASE`,
//! `UPPERCASE`, `DIGITS`, `SYMBOLS`) and [`AMBIGUOUS_CHARS`] are
//! pinned by unit tests so a silent edit is impossible.

/// Lowercase ASCII letters.
pub(crate) const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";

/// Uppercase ASCII letters.
pub(crate) const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Decimal digits.
pub(crate) const DIGITS: &str = "0123456789";

/// Printable-ASCII symbols. Deliberately omits whitespace, backslash,
/// and single/double quotes (shell-metacharacter footguns with no
/// ergonomic benefit). The exact set is pinned by
/// `symbols_class_matches_documented_set`.
pub(crate) const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>?/~";

/// Characters considered "ambiguous" — visually confusable in many
/// fonts. Excluded from generated passwords when
/// `PasswordBuilder::exclude_ambiguous(true)`.
///
/// Set: `0`, `O`, `o`, `1`, `l`, `I`, `|`, backtick — verbatim from US-022.
pub const AMBIGUOUS_CHARS: &str = "0Oo1lI|`";

/// Selection of enabled character classes for password generation.
///
/// Constructed via [`Self::ALL`] / [`Self::NONE`] or struct-literal
/// syntax (`CharSet { lowercase: true, digits: true, ..CharSet::NONE }`).
///
/// `clippy::struct_excessive_bools` is allowed: the four-boolean shape
/// is the deliberate API choice documented in design §3.3 (hand-rolled
/// over `bitflags` to keep one fewer vendored dep).
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CharSet {
    /// Whether to include lowercase ASCII letters (a–z).
    pub lowercase: bool,
    /// Whether to include uppercase ASCII letters (A–Z).
    pub uppercase: bool,
    /// Whether to include decimal digits (0–9).
    pub digits: bool,
    /// Whether to include the documented symbol set.
    pub symbols: bool,
}

impl CharSet {
    /// All four classes enabled.
    pub const ALL: Self = Self {
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols: true,
    };

    /// No classes enabled. An invalid state for generation —
    /// [`crate::PasswordBuilder::generate`] returns
    /// `GenError::NoClassesEnabled` when handed this value.
    pub const NONE: Self = Self {
        lowercase: false,
        uppercase: false,
        digits: false,
        symbols: false,
    };

    /// Number of enabled classes (0..=4).
    pub fn popcount(self) -> usize {
        usize::from(self.lowercase)
            + usize::from(self.uppercase)
            + usize::from(self.digits)
            + usize::from(self.symbols)
    }

    /// Iterator over the `(class-name, filtered-chars)` of each
    /// enabled class, in lowercase → uppercase → digits → symbols
    /// order.
    ///
    /// The `class-name` is for diagnostic value (future log lines);
    /// current callers consume only the chars. Filtering removes any
    /// character listed in [`AMBIGUOUS_CHARS`] when
    /// `exclude_ambiguous == true`.
    pub(crate) fn enabled_classes(
        self,
        exclude_ambiguous: bool,
    ) -> impl Iterator<Item = (&'static str, String)> {
        [
            ("lowercase", self.lowercase, LOWERCASE),
            ("uppercase", self.uppercase, UPPERCASE),
            ("digits", self.digits, DIGITS),
            ("symbols", self.symbols, SYMBOLS),
        ]
        .into_iter()
        .filter(|(_, enabled, _)| *enabled)
        .map(move |(name, _, raw)| (name, filter_ambiguous(raw, exclude_ambiguous)))
    }

    /// Concatenated alphabet of all enabled classes, with the
    /// ambiguous filter applied when requested.
    pub(crate) fn alphabet(self, exclude_ambiguous: bool) -> String {
        let mut out = String::new();
        for (_, chars) in self.enabled_classes(exclude_ambiguous) {
            out.push_str(&chars);
        }
        out
    }
}

fn filter_ambiguous(raw: &str, exclude_ambiguous: bool) -> String {
    if exclude_ambiguous {
        raw.chars()
            .filter(|c| !AMBIGUOUS_CHARS.contains(*c))
            .collect()
    } else {
        raw.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowercase_class_contains_26_letters_a_through_z() {
        assert_eq!(LOWERCASE, "abcdefghijklmnopqrstuvwxyz");
        assert_eq!(LOWERCASE.chars().count(), 26);
    }

    #[test]
    fn uppercase_class_contains_26_letters_a_through_z() {
        assert_eq!(UPPERCASE, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        assert_eq!(UPPERCASE.chars().count(), 26);
    }

    #[test]
    fn digits_class_contains_ten_digits_0_through_9() {
        assert_eq!(DIGITS, "0123456789");
        assert_eq!(DIGITS.chars().count(), 10);
    }

    #[test]
    fn symbols_class_matches_documented_set() {
        // Pinned exactly — a silent edit to the symbol set is a
        // semantic change that should require touching this test.
        assert_eq!(SYMBOLS, "!@#$%^&*()-_=+[]{};:,.<>?/~");
    }

    #[test]
    fn ambiguous_set_matches_documented_us_022_list() {
        // Verbatim US-022: 0, O, o, 1, l, I, |, backtick.
        assert_eq!(AMBIGUOUS_CHARS, "0Oo1lI|`");
        assert_eq!(AMBIGUOUS_CHARS.chars().count(), 8);
    }

    #[test]
    fn charset_popcount_returns_number_of_enabled_classes() {
        let cases: &[(CharSet, usize)] = &[
            (CharSet::NONE, 0),
            (
                CharSet {
                    lowercase: true,
                    ..CharSet::NONE
                },
                1,
            ),
            (
                CharSet {
                    lowercase: true,
                    digits: true,
                    ..CharSet::NONE
                },
                2,
            ),
            (
                CharSet {
                    lowercase: true,
                    uppercase: true,
                    digits: true,
                    ..CharSet::NONE
                },
                3,
            ),
            (CharSet::ALL, 4),
        ];
        for (cs, expected) in cases {
            assert_eq!(cs.popcount(), *expected, "case: {cs:?}");
        }
    }

    #[test]
    fn charset_alphabet_unions_enabled_classes() {
        // All classes, no filter: union is exactly the four constants
        // concatenated in the documented order.
        let alpha = CharSet::ALL.alphabet(false);
        let expected = format!("{LOWERCASE}{UPPERCASE}{DIGITS}{SYMBOLS}");
        assert_eq!(alpha, expected);

        // With the ambiguous filter, none of the documented ambiguous
        // chars survive.
        let alpha = CharSet::ALL.alphabet(true);
        for ambiguous in AMBIGUOUS_CHARS.chars() {
            assert!(
                !alpha.contains(ambiguous),
                "ambiguous char {ambiguous:?} leaked into filtered alphabet"
            );
        }
    }

    #[test]
    fn no_class_is_empty_after_ambiguous_filter() {
        // A future change to either the class strings or the ambiguous
        // set could accidentally empty a class. The reserve step in
        // password::generate would then return `AlphabetEmpty` at
        // runtime; this test catches the regression at `make test`.
        for (name, chars) in CharSet::ALL.enabled_classes(true) {
            assert!(
                !chars.is_empty(),
                "class {name:?} is empty after ambiguous filter"
            );
        }
    }
}
