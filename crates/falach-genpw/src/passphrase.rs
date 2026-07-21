//! Diceware passphrase generation — `PassphraseBuilder`, generator,
//! and the [`default_passphrase`] convenience.
//!
//! Per design §2.2.4 with the implementation-plan Revision Log
//! applied: the generator pulls bytes from the OS CSPRNG via
//! `getrandom::fill` rather than going through `rand::rngs::OsRng`,
//! and word indices are drawn via [`ByteCursor::uniform_index`] —
//! the same rejection-sampling primitive used by
//! [`crate::password`]. There is no `%` on a single raw byte
//! anywhere in the indexing path.
//!
//! The algorithm is the obvious one: validate `words >= 1`, draw
//! `words` indices into the EFF large wordlist, and join the chosen
//! words with the caller-supplied separator (inserted verbatim — no
//! escaping, no sanitization).
//!
//! ## Test seam
//!
//! Same shape as [`crate::password`]: [`PassphraseBuilder::generate`]
//! gathers entropy from `getrandom::fill` then delegates to the
//! `#[doc(hidden)] pub fn generate_from_bytes` test seam. Unit and
//! integration tests that need a deterministic stream call
//! `generate_from_bytes` directly with a precomputed buffer.

use zeroize::Zeroizing;

use crate::error::GenError;
use crate::sampling::{ByteCursor, BYTES_PER_DRAW};
use crate::wordlist::eff_large_wordlist;

/// Default passphrase word count. Yields ≈ 77 bits of entropy on the
/// EFF large list — EFF's own recommendation.
pub const DEFAULT_WORDS: usize = 6;

/// Default separator inserted between words.
pub const DEFAULT_SEPARATOR: &str = "-";

/// Extra rejection-loop margin per `generate` call. Same role as the
/// `OVERSAMPLE` in [`crate::password`]: keep the rejection loop
/// slackful so the entropy buffer is never exhausted in practice.
const OVERSAMPLE: usize = 64;

/// Diceware passphrase builder. Constructed via [`Self::new`] or
/// [`Default::default`]; each method consumes and returns `self` for
/// chaining.
#[derive(Debug, Clone)]
pub struct PassphraseBuilder {
    words: usize,
    separator: String,
}

impl Default for PassphraseBuilder {
    fn default() -> Self {
        Self {
            words: DEFAULT_WORDS,
            separator: DEFAULT_SEPARATOR.to_owned(),
        }
    }
}

impl PassphraseBuilder {
    /// New builder with default knobs (6 words, `-` separator).
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the number of words. Zero is invalid (returns
    /// [`GenError::InvalidWordCount`] from [`Self::generate`]).
    #[must_use]
    pub fn words(mut self, n: usize) -> Self {
        self.words = n;
        self
    }

    /// Set the separator between words. Inserted verbatim; an empty
    /// string yields concatenated words.
    #[must_use]
    pub fn separator(mut self, sep: impl Into<String>) -> Self {
        self.separator = sep.into();
        self
    }

    /// Generate a passphrase using the OS CSPRNG.
    ///
    /// Internally calls `getrandom::fill` to gather entropy, then
    /// delegates to [`Self::generate_from_bytes`] for the algorithm.
    /// A [`GenError::Csprng`] is propagated if the platform CSPRNG
    /// fails.
    pub fn generate(&self) -> Result<Zeroizing<String>, GenError> {
        self.validate()?;

        // Worst case: one 4-byte draw per word, plus rejection-loop
        // slack. The rejection rate for a 7,776-bucket draw on a
        // u32 is `7776 / 2^32 ≈ 1.8e-6`; OVERSAMPLE = 64 extra
        // draws is more than enough headroom.
        let needed = self
            .words
            .saturating_add(OVERSAMPLE)
            .saturating_mul(BYTES_PER_DRAW);
        let mut bytes = vec![0u8; needed];
        getrandom::fill(&mut bytes)?;

        let result = self.generate_from_bytes(&bytes);
        bytes.fill(0); // best-effort: scrub the entropy buffer
        result
    }

    fn validate(&self) -> Result<(), GenError> {
        if self.words == 0 {
            return Err(GenError::InvalidWordCount);
        }
        Ok(())
    }

    /// Algorithmic core: turn a precomputed byte buffer into a
    /// passphrase. Reserved for tests that need a deterministic seed —
    /// production callers should use [`Self::generate`], which feeds
    /// `getrandom::fill`-sourced bytes through this same code path.
    ///
    /// Hidden from rendered API docs because it exists for the
    /// in-tree distribution test; downstream callers should never
    /// reach for it.
    #[doc(hidden)]
    pub fn generate_from_bytes(&self, bytes: &[u8]) -> Result<Zeroizing<String>, GenError> {
        self.validate()?;

        let wordlist = eff_large_wordlist();
        let mut cursor = ByteCursor::new(bytes);
        let mut chosen: Vec<&'static str> = Vec::with_capacity(self.words);
        for _ in 0..self.words {
            let idx = cursor.uniform_index(wordlist.len())?;
            chosen.push(wordlist[idx]);
        }
        Ok(Zeroizing::new(chosen.join(&self.separator)))
    }
}

/// Convenience: generate a default-knob passphrase using the OS CSPRNG.
pub fn default_passphrase() -> Result<Zeroizing<String>, GenError> {
    PassphraseBuilder::new().generate()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn long_pattern() -> Vec<u8> {
        (0u32..2048).flat_map(u32::to_le_bytes).collect::<Vec<u8>>()
    }

    #[test]
    fn default_builder_uses_documented_defaults() {
        // Pin the documented constants. Splitting a default-knob
        // (`-`-separated) output on `-` cannot reliably recover word
        // boundaries because the EFF list contains four hyphenated
        // entries (`drop-down`, `felt-tip`, `t-shirt`, `yo-yo`); a
        // strict split-and-count would be flaky at ~0.3% per draw.
        // The word-membership check lives in
        // `each_word_in_passphrase_is_in_eff_wordlist`, which uses a
        // sentinel separator to avoid the ambiguity.
        assert_eq!(DEFAULT_WORDS, 6);
        assert_eq!(DEFAULT_SEPARATOR, "-");

        let pp = PassphraseBuilder::new()
            .generate()
            .expect("OS CSPRNG available");
        // Sanity: output is non-empty and uses only lowercase ASCII
        // and `-`. Six EFF words (3..=9 chars each) joined by five
        // separator dashes is between 23 and 59 characters.
        assert!(!pp.is_empty());
        let len = pp.chars().count();
        assert!(
            (23..=59).contains(&len),
            "default output length {len} outside the expected 23..=59 range: {}",
            pp.as_str()
        );
        for c in pp.chars() {
            assert!(
                c.is_ascii_lowercase() || c == '-',
                "unexpected char {c:?} in default output: {}",
                pp.as_str()
            );
        }
    }

    #[test]
    fn word_count_zero_returns_invalid_word_count() {
        let err = PassphraseBuilder::new()
            .words(0)
            .generate()
            .expect_err("words=0 must error");
        assert!(matches!(err, GenError::InvalidWordCount));
    }

    #[test]
    fn each_word_in_passphrase_is_in_eff_wordlist() {
        // Use `|` as the separator: that character cannot appear in
        // any EFF wordlist entry (every entry is `[a-z-]+`), so
        // splitting on it cleanly recovers each sampled word. The
        // default `-` separator can't be used here because the EFF
        // list contains four hyphenated entries (`drop-down`,
        // `felt-tip`, `t-shirt`, `yo-yo`); a `-`-split output with
        // one of those entries would yield ambiguous tokens. This is
        // a known property of the default separator, not a bug in
        // generation — see `separator_is_inserted_verbatim`.
        let builder = PassphraseBuilder::new().words(10).separator("|");
        let wordlist: std::collections::HashSet<&'static str> =
            eff_large_wordlist().iter().copied().collect();
        for i in 0..100 {
            let pp = builder.generate().expect("OS CSPRNG available");
            for w in pp.split('|') {
                assert!(
                    wordlist.contains(w),
                    "iter {i}: word {w:?} not in EFF wordlist; passphrase: {}",
                    pp.as_str()
                );
            }
        }
    }

    #[test]
    fn separator_is_inserted_verbatim() {
        let pp = PassphraseBuilder::new()
            .separator(" :: ")
            .generate()
            .expect("OS CSPRNG available");
        let tokens: Vec<&str> = pp.split(" :: ").collect();
        assert_eq!(tokens.len(), 6);
    }

    #[test]
    fn empty_separator_produces_concatenated_words() {
        let pp = PassphraseBuilder::new()
            .separator("")
            .generate()
            .expect("OS CSPRNG available");
        // Six concatenated lowercase EFF words (3–9 chars each plus
        // 4 hyphenated entries) produces 18..=54 chars, no `-`
        // beyond those internal to hyphenated EFF entries.
        assert!(!pp.is_empty());
        // Every char is lowercase ASCII or hyphen (the 4 hyphenated
        // EFF entries: drop-down, felt-tip, t-shirt, yo-yo).
        for c in pp.chars() {
            assert!(
                c.is_ascii_lowercase() || c == '-',
                "unexpected char {c:?} in empty-separator output: {}",
                pp.as_str()
            );
        }
    }

    #[test]
    fn successive_outputs_differ() {
        let builder = PassphraseBuilder::new();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            let pp = builder.generate().expect("OS CSPRNG available");
            seen.insert(pp.to_string());
        }
        assert_eq!(seen.len(), 100, "expected 100 distinct passphrases");
    }

    #[test]
    fn generate_from_bytes_is_deterministic() {
        let bytes = long_pattern();
        let a = PassphraseBuilder::new()
            .generate_from_bytes(&bytes)
            .unwrap();
        let b = PassphraseBuilder::new()
            .generate_from_bytes(&bytes)
            .unwrap();
        assert_eq!(a.as_str(), b.as_str());
    }

    #[test]
    fn output_is_zeroizing_string() {
        let _: Zeroizing<String> = PassphraseBuilder::new().generate().unwrap();
    }
}
