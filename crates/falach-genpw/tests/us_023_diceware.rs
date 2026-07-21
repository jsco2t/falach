//! US-023 — Generate an EFF diceware passphrase.
//!
//! Verifies:
//! - A 6-word, `-`-separated passphrase produced by the builder
//!   contains 6 words from the EFF large list.
//! - Successive default-knob passphrases differ (RNG is not stuck).
//! - The `default_passphrase()` convenience matches the documented
//!   defaults.
//! - Across a large sample of single-word generations, every output
//!   is in the EFF wordlist — confirms the sampler never lands
//!   outside `[0, 7776)` (catches an off-by-one in `uniform_index`).
//!
//! ## Note on the separator
//!
//! The default separator is `-`, but the EFF large list contains four
//! hyphenated entries (`drop-down`, `felt-tip`, `t-shirt`, `yo-yo`).
//! Splitting a `-`-separated output on `-` therefore cannot reliably
//! recover the sampled word boundaries — a passphrase that includes
//! `felt-tip` would yield `felt` and `tip` as separate tokens. The
//! word-membership tests below use the `|` separator to sidestep
//! this ambiguity; `|` is guaranteed not to appear in any EFF
//! wordlist entry.

use std::sync::OnceLock;

use falach_genpw::{
    default_passphrase, PassphraseBuilder, Zeroizing, DEFAULT_SEPARATOR, DEFAULT_WORDS,
};

/// EFF large wordlist as a `HashSet<&'static str>`, built once per
/// integration-test binary. Each integration test compiles into its
/// own binary, so this `OnceLock` is scoped to this file; embedding
/// the wordlist via `include_str!` keeps the test self-contained and
/// independent of `falach-genpw`'s internal `wordlist` module.
fn wordlist_set() -> &'static std::collections::HashSet<&'static str> {
    static SET: OnceLock<std::collections::HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| {
        const RAW: &str = include_str!("../src/assets/eff_large_wordlist.txt");
        RAW.lines()
            .map(|line| line.split_once('\t').expect("malformed line").1)
            .collect()
    })
}

fn wordlist_membership_check(pp: &str, sep: char) {
    let set = wordlist_set();
    for w in pp.split(sep) {
        assert!(set.contains(w), "token {w:?} not in EFF wordlist");
    }
}

#[test]
fn six_word_dash_passphrase_well_formed() {
    // Build a sentinel-separator output to verify the "6 words from
    // the EFF list" contract without conflating with hyphens inside
    // hyphenated EFF entries. The default `-` separator is verified
    // separately in `convenience_default_passphrase_matches_us023_defaults`.
    let pp: Zeroizing<String> = PassphraseBuilder::new()
        .words(6)
        .separator("|")
        .generate()
        .expect("OS CSPRNG available");
    assert_eq!(pp.split('|').count(), 6);
    wordlist_membership_check(&pp, '|');
}

#[test]
fn successive_passphrase_invocations_differ() {
    // 100 default-knob passphrases must all differ. With ≈77 bits
    // of entropy per draw, the collision probability is below
    // cosmic-ray-flip-a-bit.
    let builder = PassphraseBuilder::new();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..100 {
        let pp = builder.generate().expect("OS CSPRNG available");
        seen.insert(pp.to_string());
    }
    assert_eq!(seen.len(), 100, "expected 100 distinct passphrases");
}

#[test]
fn convenience_default_passphrase_matches_us023_defaults() {
    // Pin the documented constants — US-023 hint says 6 words, `-`
    // separator.
    assert_eq!(DEFAULT_WORDS, 6);
    assert_eq!(DEFAULT_SEPARATOR, "-");

    // Output sanity: non-empty, lowercase-ASCII-or-hyphen only,
    // length in the 23..=59 range that six EFF words joined by five
    // dashes can produce.
    let pp = default_passphrase().expect("OS CSPRNG available");
    assert!(!pp.is_empty());
    let len = pp.chars().count();
    assert!(
        (23..=59).contains(&len),
        "default output length {len} outside expected 23..=59: {}",
        pp.as_str()
    );
    for c in pp.chars() {
        assert!(
            c.is_ascii_lowercase() || c == '-',
            "unexpected char {c:?}: {}",
            pp.as_str()
        );
    }
}

#[test]
fn every_word_in_eff_wordlist_across_large_sample() {
    // 1,000 single-word passphrases = 1,000 sampled indices into
    // the EFF list. Every result must be in the list — catches an
    // off-by-one or modulo-bias regression that would let an index
    // land at or past 7,776.
    let builder = PassphraseBuilder::new().words(1).separator("|");
    for i in 0..1_000 {
        let pp = builder.generate().expect("OS CSPRNG available");
        // Single-word output: no separator inserted; the whole
        // string is the sampled word.
        wordlist_membership_check(&pp, '|');
        let _ = i;
    }
}
