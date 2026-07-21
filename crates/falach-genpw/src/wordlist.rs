//! EFF large wordlist embed and accessor.
//!
//! Per design §2.2.2: the wordlist asset is committed at
//! `src/assets/eff_large_wordlist.txt`, embedded into the binary via
//! `include_str!`, and parsed exactly once into a fixed-size array of
//! `&'static str`. The fixed-size array shape (`[&str; 7776]`) means a
//! "wrong line count" bug is caught at the runtime `assert_eq!` in
//! [`load_wordlist`] *and* by the unit test
//! `wordlist_has_exactly_7776_entries`.
//!
//! See `LICENSES/EFF-wordlist.md` for provenance and license rationale.

use std::sync::OnceLock;

/// The EFF large wordlist file count.
pub(crate) const WORDLIST_LEN: usize = 7776;

/// Return the EFF large wordlist, parsing the embedded asset on first
/// access and caching the result for the life of the process.
pub(crate) fn eff_large_wordlist() -> &'static [&'static str; WORDLIST_LEN] {
    static WORDS: OnceLock<[&'static str; WORDLIST_LEN]> = OnceLock::new();
    WORDS.get_or_init(load_wordlist)
}

// The wordlist array is 7,776 × 16 bytes ≈ 124 KiB on the stack —
// past clippy's default 16 KiB stack-array threshold. The size is
// the deliberate compile-time guarantee per design §3.8 (fixed
// `[&str; 7776]` so any "wrong line count" embed is a build / test
// failure). The array is constructed on the stack inside this
// initializer and then moved into the `OnceLock`-owned static
// storage, so the large allocation is a one-shot init cost.
#[allow(clippy::large_stack_arrays)]
fn load_wordlist() -> [&'static str; WORDLIST_LEN] {
    const RAW: &str = include_str!("assets/eff_large_wordlist.txt");
    let mut words: [&'static str; WORDLIST_LEN] = [""; WORDLIST_LEN];
    let mut count = 0;
    for (i, line) in RAW.lines().enumerate() {
        assert!(
            i < WORDLIST_LEN,
            "EFF wordlist has more than {WORDLIST_LEN} lines",
        );
        let (_, word) = line
            .split_once('\t')
            .expect("EFF wordlist line missing tab separator");
        words[i] = word;
        count += 1;
    }
    assert_eq!(
        count, WORDLIST_LEN,
        "EFF wordlist has wrong length: got {count}, expected {WORDLIST_LEN}",
    );
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_has_exactly_7776_entries() {
        let words = eff_large_wordlist();
        assert_eq!(words.len(), WORDLIST_LEN);
    }

    #[test]
    fn first_and_last_words_match_canonical_eff_list() {
        let words = eff_large_wordlist();
        assert_eq!(
            words[0], "abacus",
            "first word changed — has the asset been replaced with a non-EFF-large list?"
        );
        assert_eq!(
            words[WORDLIST_LEN - 1],
            "zoom",
            "last word changed — has the asset been replaced with a non-EFF-large list?"
        );
    }

    #[test]
    fn every_word_is_lowercase_ascii_3_to_9_chars() {
        // The canonical EFF large list is overwhelmingly `[a-z]+` but
        // contains four hyphenated entries: `drop-down`, `felt-tip`,
        // `t-shirt`, `yo-yo`. The accepted character set therefore is
        // `[a-z-]`. This still catches the failure modes that motivate
        // the test: a BOM-injected first word, non-ASCII smuggled in,
        // or the wrong wordlist (EFF small list, BIP-39, etc.) with a
        // different character profile.
        let words = eff_large_wordlist();
        for (i, w) in words.iter().enumerate() {
            assert!(
                w.is_ascii(),
                "word at index {i} is not ASCII (BOM in the embedded asset?): {w:?}",
            );
            let len = w.chars().count();
            assert!(
                (3..=9).contains(&len),
                "word at index {i} has length {len}, expected 3..=9: {w:?}",
            );
            for c in w.chars() {
                assert!(
                    c.is_ascii_lowercase() || c == '-',
                    "word at index {i} has unexpected char {c:?}: {w:?}",
                );
            }
        }
    }

    #[test]
    fn no_duplicate_words_in_list() {
        let words = eff_large_wordlist();
        let unique: std::collections::HashSet<&'static str> = words.iter().copied().collect();
        assert_eq!(
            unique.len(),
            WORDLIST_LEN,
            "wordlist contains duplicates — embed corruption?",
        );
    }

    #[test]
    fn load_wordlist_is_idempotent() {
        // `OnceLock::get_or_init` returns the same `&'static` slice on
        // every call; comparing raw pointers documents that contract.
        let a: *const [&'static str; WORDLIST_LEN] = eff_large_wordlist();
        let b: *const [&'static str; WORDLIST_LEN] = eff_large_wordlist();
        assert!(std::ptr::eq(a, b));
    }
}
