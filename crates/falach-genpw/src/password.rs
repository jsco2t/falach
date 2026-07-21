//! Random password generation — `PasswordBuilder`, generator, and the
//! [`default_password`] convenience.
//!
//! Per design §2.2.3 with the implementation-plan Revision Log applied:
//! the generator pulls bytes from the OS CSPRNG via `getrandom::fill`
//! rather than going through `rand::rngs::OsRng`. The algorithm is
//! reserve-and-fill + shuffle:
//!
//! 1. Reserve one position per enabled class, drawing each character
//!    from that class's filtered alphabet.
//! 2. Fill the remaining positions from the unioned alphabet.
//! 3. Fisher–Yates shuffle the result so the reserved positions are
//!    not predictably at the start.
//!
//! Every randomness draw goes through `ByteCursor::uniform_index`,
//! which performs rejection sampling on a 32-bit value — no `%` on
//! a single raw byte ever appears in the indexing path.
//!
//! ## Test seam
//!
//! [`PasswordBuilder::generate`] gathers entropy from `getrandom::fill`
//! and then calls into the private `generate_from_bytes` helper. Unit
//! and integration tests that need a deterministic stream call
//! `generate_from_bytes` directly with a precomputed buffer. Tests that
//! exercise the *full* production path (including `getrandom`) call
//! `generate` and assert post-conditions.

use zeroize::Zeroizing;

use crate::charset::CharSet;
use crate::error::GenError;
use crate::sampling::{ByteCursor, BYTES_PER_DRAW};

/// Default password length (characters). Yields ≈ 131 bits of entropy
/// with all four classes enabled.
pub const DEFAULT_LENGTH: usize = 20;

/// Extra rejection-loop margin per `generate` call. Padding above the
/// worst-case "one draw per character" budget so the rejection loop
/// in `ByteCursor::uniform_index` has slack on every realistic input.
const OVERSAMPLE: usize = 64;

/// Random-password builder. Constructed via [`Self::new`] or
/// [`Default::default`]; each method consumes and returns `self` for
/// chaining.
#[derive(Debug, Clone)]
pub struct PasswordBuilder {
    length: usize,
    classes: CharSet,
    exclude_ambiguous: bool,
}

impl Default for PasswordBuilder {
    fn default() -> Self {
        Self {
            length: DEFAULT_LENGTH,
            classes: CharSet::ALL,
            exclude_ambiguous: false,
        }
    }
}

impl PasswordBuilder {
    /// New builder with default knobs (length=20, all classes, no
    /// ambiguous filter).
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the password length in characters. Length 0 is invalid
    /// (returns [`GenError::InvalidLength`] from
    /// [`Self::generate`]).
    #[must_use]
    pub fn length(mut self, len: usize) -> Self {
        self.length = len;
        self
    }

    /// Set the enabled character classes. [`CharSet::NONE`] is invalid.
    #[must_use]
    pub fn classes(mut self, classes: CharSet) -> Self {
        self.classes = classes;
        self
    }

    /// Enable or disable filtering of ambiguous characters
    /// (`0/O/o`, `1/l/I`, `|`, backtick).
    #[must_use]
    pub fn exclude_ambiguous(mut self, yes: bool) -> Self {
        self.exclude_ambiguous = yes;
        self
    }

    /// Generate a password using the OS CSPRNG.
    ///
    /// Internally calls `getrandom::fill` to gather entropy, then
    /// delegates to `generate_from_bytes` for the algorithm. A
    /// `GenError::Csprng` is propagated if the platform CSPRNG fails.
    pub fn generate(&self) -> Result<Zeroizing<String>, GenError> {
        // Validate first so we don't pull entropy we won't use.
        self.validate()?;

        // Worst-case bytes: one 4-byte draw per output character (for
        // reserve + fill) plus one per shuffle step. The `2x +
        // OVERSAMPLE` margin keeps the rejection loop slackful so we
        // never exhaust the buffer in practice; if we ever do,
        // `generate_from_bytes` returns `GenError::Csprng` for the
        // caller to retry.
        let needed = self
            .length
            .saturating_mul(2)
            .saturating_add(OVERSAMPLE)
            .saturating_mul(BYTES_PER_DRAW);
        let mut bytes = vec![0u8; needed];
        getrandom::fill(&mut bytes)?;

        let result = self.generate_from_bytes(&bytes);
        bytes.fill(0); // best-effort: scrub the entropy buffer
        result
    }

    /// Validate knob values without consuming entropy.
    fn validate(&self) -> Result<(), GenError> {
        if self.length == 0 {
            return Err(GenError::InvalidLength);
        }
        let popcount = self.classes.popcount();
        if popcount == 0 {
            return Err(GenError::NoClassesEnabled);
        }
        if self.length < popcount {
            return Err(GenError::LengthTooShort {
                length: self.length,
                classes: popcount,
            });
        }
        Ok(())
    }

    /// Algorithmic core: turn a precomputed byte buffer into a
    /// password. Reserved for tests that need a deterministic seed —
    /// production callers should use [`Self::generate`], which feeds
    /// `getrandom::fill`-sourced bytes through this same code path.
    ///
    /// The buffer must contain enough entropy for the rejection-loop
    /// worst case; [`Self::generate`] sizes its buffer with a margin.
    /// Callers that supply too few bytes get
    /// [`GenError::Csprng`] wrapping [`getrandom::Error::UNEXPECTED`].
    ///
    /// Hidden from rendered API docs because it exists for the
    /// in-tree distribution test; downstream callers should never
    /// reach for it.
    #[doc(hidden)]
    pub fn generate_from_bytes(&self, bytes: &[u8]) -> Result<Zeroizing<String>, GenError> {
        self.validate()?;

        let popcount = self.classes.popcount();
        let union: Vec<char> = self
            .classes
            .alphabet(self.exclude_ambiguous)
            .chars()
            .collect();
        if union.is_empty() {
            return Err(GenError::AlphabetEmpty);
        }

        let mut cursor = ByteCursor::new(bytes);
        let mut out: Vec<char> = Vec::with_capacity(self.length);

        // Reserve: one char from each enabled class's filtered alphabet.
        for (_, class_chars) in self.classes.enabled_classes(self.exclude_ambiguous) {
            let class_vec: Vec<char> = class_chars.chars().collect();
            if class_vec.is_empty() {
                return Err(GenError::AlphabetEmpty);
            }
            let idx = cursor.uniform_index(class_vec.len())?;
            out.push(class_vec[idx]);
        }

        // Fill: remaining positions from the union alphabet.
        let remaining = self.length - popcount;
        for _ in 0..remaining {
            let idx = cursor.uniform_index(union.len())?;
            out.push(union[idx]);
        }

        // Shuffle (Fisher–Yates) so reserved characters aren't pinned
        // to the start of the output. `swap(i, i)` for the last
        // element is a no-op; we skip the final iteration.
        for i in (1..out.len()).rev() {
            let j = cursor.uniform_index(i + 1)?;
            out.swap(i, j);
        }

        Ok(Zeroizing::new(out.into_iter().collect()))
    }
}

/// Convenience: generate a default-knob password using the OS CSPRNG.
pub fn default_password() -> Result<Zeroizing<String>, GenError> {
    PasswordBuilder::new().generate()
}

#[cfg(test)]
#[allow(unsafe_code)] // volatile-read zeroize verification — mirrors falach-core::secret pattern
mod tests {
    use super::*;
    use crate::charset::AMBIGUOUS_CHARS;

    /// A deterministic byte stream sized for typical test lengths. The
    /// distribution test in `tests/distribution.rs` uses a richer
    /// `SplitMix64` stream; these unit tests are happy with a long
    /// repeating pattern that exercises the rejection loop but never
    /// triggers it (every byte is < threshold for the small ranges
    /// here).
    fn long_pattern() -> Vec<u8> {
        (0u32..2048).flat_map(u32::to_le_bytes).collect::<Vec<u8>>()
    }

    #[test]
    fn default_builder_produces_20_char_all_classes_password() {
        let pw = PasswordBuilder::new()
            .generate()
            .expect("OsRng available in tests");
        assert_eq!(pw.chars().count(), 20);
        // With length=20 and all 4 classes, every class must appear at
        // least once by the reserve step's contract.
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
        assert!(pw.chars().any(|c| crate::charset::SYMBOLS.contains(c)));
    }

    #[test]
    fn length_zero_returns_invalid_length() {
        let err = PasswordBuilder::new()
            .length(0)
            .generate()
            .expect_err("length 0 must error");
        assert!(matches!(err, GenError::InvalidLength));
    }

    #[test]
    fn no_classes_enabled_returns_no_classes_enabled() {
        let err = PasswordBuilder::new()
            .classes(CharSet::NONE)
            .generate()
            .expect_err("empty class set must error");
        assert!(matches!(err, GenError::NoClassesEnabled));
    }

    #[test]
    fn length_less_than_class_count_returns_length_too_short() {
        let err = PasswordBuilder::new()
            .length(2)
            .classes(CharSet::ALL)
            .generate()
            .expect_err("length < popcount must error");
        assert!(matches!(
            err,
            GenError::LengthTooShort {
                length: 2,
                classes: 4,
            }
        ));
    }

    #[test]
    fn output_length_matches_requested_length() {
        for &len in &[1usize, 4, 8, 16, 32, 64, 128] {
            // Choose a class-set with popcount <= len for the small
            // lengths (popcount=4 fails the reserve invariant at len<4).
            let classes = if len >= 4 {
                CharSet::ALL
            } else {
                CharSet {
                    lowercase: true,
                    ..CharSet::NONE
                }
            };
            let pw = PasswordBuilder::new()
                .length(len)
                .classes(classes)
                .generate()
                .unwrap_or_else(|e| panic!("len={len}: {e}"));
            assert_eq!(pw.chars().count(), len, "len={len}");
        }
    }

    #[test]
    fn at_least_one_of_each_enabled_class_present() {
        let builder = PasswordBuilder::new().length(8).classes(CharSet::ALL);
        for i in 0..1000 {
            let pw = builder.generate().expect("OsRng available");
            let s: &str = &pw;
            assert!(s.chars().any(|c| c.is_ascii_lowercase()), "iter {i}: {s}");
            assert!(s.chars().any(|c| c.is_ascii_uppercase()), "iter {i}: {s}");
            assert!(s.chars().any(|c| c.is_ascii_digit()), "iter {i}: {s}");
            assert!(
                s.chars().any(|c| crate::charset::SYMBOLS.contains(c)),
                "iter {i}: {s}"
            );
        }
    }

    #[test]
    fn output_contains_no_chars_outside_alphabet() {
        let builder = PasswordBuilder::new().length(20).classes(CharSet {
            lowercase: true,
            digits: true,
            ..CharSet::NONE
        });
        let allowed: String = format!("{}{}", crate::charset::LOWERCASE, crate::charset::DIGITS);
        for _ in 0..100 {
            let pw = builder.generate().expect("OsRng available");
            for c in pw.chars() {
                assert!(
                    allowed.contains(c),
                    "char {c:?} outside lowercase+digits alphabet"
                );
            }
        }
    }

    #[test]
    fn exclude_ambiguous_removes_ambiguous_chars() {
        let builder = PasswordBuilder::new()
            .length(50)
            .classes(CharSet::ALL)
            .exclude_ambiguous(true);
        for _ in 0..100 {
            let pw = builder.generate().expect("OsRng available");
            let s: &str = &pw;
            for c in s.chars() {
                assert!(
                    !AMBIGUOUS_CHARS.contains(c),
                    "ambiguous char {c:?} leaked into output: {s}"
                );
            }
        }
    }

    #[test]
    fn successive_outputs_differ() {
        let builder = PasswordBuilder::new();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            let pw = builder.generate().expect("OsRng available");
            seen.insert(pw.to_string());
        }
        assert_eq!(seen.len(), 100, "expected 100 distinct outputs");
    }

    #[test]
    fn output_is_zeroizing_string() {
        // Compile-time pin on the public surface type.
        let _: Zeroizing<String> = PasswordBuilder::new().generate().unwrap();
    }

    #[test]
    fn generate_from_bytes_is_deterministic() {
        // Same bytes → same output.
        let bytes = long_pattern();
        let a = PasswordBuilder::new()
            .length(16)
            .generate_from_bytes(&bytes)
            .unwrap();
        let b = PasswordBuilder::new()
            .length(16)
            .generate_from_bytes(&bytes)
            .unwrap();
        assert_eq!(a.as_str(), b.as_str());
    }

    #[test]
    fn generate_from_bytes_exhausted_buffer_returns_csprng_error() {
        // Two bytes can't even produce one u32. Expect a Csprng error
        // bearing the upstream `UNEXPECTED` marker.
        let err = PasswordBuilder::new()
            .length(8)
            .generate_from_bytes(&[0u8, 0])
            .expect_err("buffer too small");
        assert!(matches!(err, GenError::Csprng(_)));
    }

    #[test]
    fn zeroizing_output_zeroes_on_drop() {
        // Mirrors the falach-core::secret idiom (see comment block in
        // falach-core/src/secret.rs). We call `.zeroize()` explicitly
        // rather than relying on drop-then-read because the system
        // allocator may immediately overwrite freed bytes with
        // bookkeeping data, masking zeroize's work.
        use zeroize::Zeroize;

        let mut pw = PasswordBuilder::new()
            .length(64)
            .generate()
            .expect("OsRng available");
        let len = pw.len();
        let ptr: *const u8 = pw.as_str().as_ptr();

        // SAFETY: we read bytes through `ptr` while the buffer is
        // still allocated — `pw` is mutably borrowed by `.zeroize()`
        // and the read happens before any drop. The pointer was
        // obtained from the live `Zeroizing<String>` and is valid for
        // `len` bytes.
        pw.zeroize();
        for i in 0..len {
            let byte = unsafe { std::ptr::read_volatile(ptr.add(i)) };
            assert_eq!(
                byte, 0,
                "Zeroizing<String> byte at offset {i} should be zero after .zeroize()"
            );
        }
    }
}
