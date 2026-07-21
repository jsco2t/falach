//! US-021 — Generate a password with custom length and character classes.
//!
//! Verifies:
//! - Length-32 with letters+digits-no-symbols produces 32-character
//!   output with no symbol characters (defined here as "anything that
//!   isn't ASCII alphanumeric").
//! - The at-least-one-of-each-enabled-class invariant holds across a
//!   sample (the reserve step's contract).
//! - The boundary case length=8 with all four classes still satisfies
//!   the invariant.

use falach_genpw::{CharSet, PasswordBuilder};

/// "Symbol" is defined here by exclusion: any character that is not
/// ASCII alphanumeric. Avoids duplicating `charset::SYMBOLS` (which is
/// crate-private) and stays robust if the documented symbol set is
/// ever revised.
fn is_symbol(c: char) -> bool {
    !c.is_ascii_alphanumeric()
}

#[test]
fn length_32_letters_digits_no_symbols() {
    let builder = PasswordBuilder::new().length(32).classes(CharSet {
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols: false,
    });
    for _ in 0..100 {
        let pw = builder.generate().expect("OS CSPRNG available");
        assert_eq!(pw.chars().count(), 32);
        for c in pw.chars() {
            assert!(
                !is_symbol(c),
                "non-alphanumeric char {c:?} appeared in symbols-disabled output: {}",
                pw.as_str()
            );
        }
    }
}

#[test]
fn at_least_one_of_each_enabled_class_across_sample() {
    let builder = PasswordBuilder::new().length(32).classes(CharSet {
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols: false,
    });
    for i in 0..100 {
        let pw = builder.generate().expect("OS CSPRNG available");
        let s: &str = &pw;
        assert!(
            s.chars().any(|c| c.is_ascii_lowercase()),
            "iter {i}: missing lowercase in {s}"
        );
        assert!(
            s.chars().any(|c| c.is_ascii_uppercase()),
            "iter {i}: missing uppercase in {s}"
        );
        assert!(
            s.chars().any(|c| c.is_ascii_digit()),
            "iter {i}: missing digit in {s}"
        );
    }
}

#[test]
fn length_8_with_all_four_classes_still_satisfies_at_least_one() {
    // Boundary case: length = popcount(classes), the shortest length
    // that the reserve step can satisfy. Every sample must contain
    // exactly the required minimum coverage.
    let builder = PasswordBuilder::new().length(8).classes(CharSet::ALL);
    for i in 0..100 {
        let pw = builder.generate().expect("OS CSPRNG available");
        assert_eq!(pw.chars().count(), 8, "iter {i}");
        let s: &str = &pw;
        assert!(s.chars().any(|c| c.is_ascii_lowercase()), "iter {i}: {s}");
        assert!(s.chars().any(|c| c.is_ascii_uppercase()), "iter {i}: {s}");
        assert!(s.chars().any(|c| c.is_ascii_digit()), "iter {i}: {s}");
        assert!(s.chars().any(is_symbol), "iter {i}: {s}");
    }
}
