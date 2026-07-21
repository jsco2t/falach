//! Test-only helpers.
//!
//! Phase 2's [`distribution`](super) test needs a reproducible random
//! byte stream — a deterministic seed means the chi-squared statistic
//! is the same on every machine, so the test never flakes in CI. The
//! task plan originally specified `rand_chacha::ChaCha20Rng`, but the
//! crate intentionally avoids depending on `rand` (see the crate-level
//! lib.rs and the implementation-plan Revision Log). Pulling
//! `rand_chacha` into dev-dependencies would re-introduce the
//! `rand` / `rand_core` / `getrandom 0.2` transitive surface we
//! deliberately dropped.
//!
//! Instead we use a hand-rolled `SplitMix64` — Sebastiano Vigna's
//! tiny mix-bit-finalizer, public domain, ~10 lines of code,
//! deterministic, and statistically suitable for catching the kinds
//! of regressions a chi-squared sanity test exists to catch (modulo
//! bias from `%`, a broken shuffle that pins reserved characters,
//! etc.). It is **not** cryptographic — but the test isn't testing
//! cryptography; the *production* CSPRNG is `getrandom::fill`, which
//! is exercised by every other unit and integration test.

#![allow(dead_code)] // emitted by each integration-test binary that pulls in this module

/// `SplitMix64` deterministic byte stream. Same seed → same bytes.
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Construct a stream seeded from the given 64-bit value.
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Advance the stream and return the next 64-bit output. The
    /// algorithm is from Sebastiano Vigna's 2014 paper, used in
    /// `std` as the initial seed-mixer for many RNGs (it is the
    /// recommended "tiny" stateful PRNG when you don't need
    /// cryptographic strength).
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Fill the buffer with deterministic bytes.
    pub fn fill(&mut self, dest: &mut [u8]) {
        let mut chunks = dest.chunks_exact_mut(8);
        for chunk in &mut chunks {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        let remainder = chunks.into_remainder();
        if !remainder.is_empty() {
            let tail = self.next_u64().to_le_bytes();
            remainder.copy_from_slice(&tail[..remainder.len()]);
        }
    }

    /// Allocate and return a buffer of deterministic bytes.
    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        self.fill(&mut out);
        out
    }
}
