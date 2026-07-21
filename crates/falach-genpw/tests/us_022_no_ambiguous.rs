//! US-022 — Exclude ambiguous characters.
//!
//! Verifies that across a 1,000-sample population of default-length
//! passwords with `exclude_ambiguous(true)`, **zero** ambiguous
//! characters appear. The acceptance criterion is hard — a single
//! ambiguous character in 20,000 sampled chars is an instant failure
//! and indicates a real bug.

use falach_genpw::{CharSet, PasswordBuilder, AMBIGUOUS_CHARS};

#[test]
fn one_thousand_sample_zero_ambiguous_chars() {
    let builder = PasswordBuilder::new()
        .length(20)
        .classes(CharSet::ALL)
        .exclude_ambiguous(true);
    let mut total_chars = 0usize;
    for i in 0..1000 {
        let pw = builder.generate().expect("OS CSPRNG available");
        assert_eq!(pw.chars().count(), 20);
        for c in pw.chars() {
            assert!(
                !AMBIGUOUS_CHARS.contains(c),
                "iter {i}: ambiguous char {c:?} leaked into output {}",
                pw.as_str()
            );
            total_chars += 1;
        }
    }
    assert_eq!(total_chars, 20_000);
}

#[test]
fn documented_ambiguous_set_matches_us022_examples() {
    // The US-022 verbatim list: 0, O, o, 1, l, I, |, backtick.
    for ch in ['0', 'O', 'o', '1', 'l', 'I', '|', '`'] {
        assert!(
            AMBIGUOUS_CHARS.contains(ch),
            "US-022 character {ch:?} missing from AMBIGUOUS_CHARS"
        );
    }
    assert_eq!(AMBIGUOUS_CHARS.chars().count(), 8);
}
