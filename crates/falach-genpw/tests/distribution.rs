//! Distribution sanity test for the random-password generator.
//!
//! Per Phase 2 task plan §T2.4: a deterministic chi-squared test that
//! catches a regression to modulo bias in the index-sampling helper.
//! The deterministic stream is `SplitMix64::new(0xDEAD)` — see
//! `tests/common/mod.rs` for why we use `SplitMix64` rather than
//! `ChaCha20Rng` (keeps the crate free of `rand`/`rand_chacha`).
//!
//! ## Why single-class?
//!
//! The "reserve-and-fill" algorithm intentionally biases the
//! per-output distribution toward smaller classes (a class of size 10
//! contributes a reserve character with probability `1/length`, but
//! each individual digit is `1/10` likely within that draw versus
//! `1/union_size` in the fill step). A chi-squared test against a
//! uniform-over-union expectation would flag this *correct* behavior
//! as a failure.
//!
//! Instead this test exercises a **single-class** builder
//! (lowercase only, 26 chars), where reserve + fill draw from the
//! same alphabet and the per-character expected distribution is
//! genuinely uniform. This isolates the rejection-sampler — the only
//! place a `% n` regression could hide.
//!
//! ## Expected behavior
//!
//! 10,000 length-100 lowercase passwords = 1,000,000 sampled
//! characters across 26 buckets. Expected count per bucket ≈ 38,461.5.
//! For 25 degrees of freedom the chi-squared critical value at
//! p = 0.001 is approximately 52.6. With a true uniform sampler and
//! our fixed seed the observed statistic is single- to low-double
//! digits; a regression to `%` on a single raw byte produces values
//! in the hundreds. The headroom is enormous.

// Counts fit comfortably below 2^52 (10k × 100 = 1M; 26 buckets) so
// the integer → f64 casts are precise. Truncation lints are silenced
// because this is well-understood arithmetic on bounded test data.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

mod common;

use common::SplitMix64;
use falach_genpw::{CharSet, PasswordBuilder};

/// Number of samples in the histogram population.
const SAMPLES: usize = 10_000;

/// Password length per sample.
const LENGTH: usize = 100;

const TOTAL_CHARS: usize = SAMPLES * LENGTH;

const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";

/// Chi-squared critical value at p=0.001 using the Wilson–Hilferty
/// approximation (`χ²(dof) ≈ dof * (1 - 2/(9*dof) + z * sqrt(2/(9*dof)))^3`).
/// Accurate to ~1% for `dof ≥ 10` and avoids embedding a full
/// chi-squared table for one test.
const Z_AT_P001: f64 = 3.0902;
fn chi_squared_critical(dof: usize) -> f64 {
    let k = dof as f64;
    let term = 2.0 / (9.0 * k);
    let inner = 1.0 - term + Z_AT_P001 * term.sqrt();
    k * inner.powi(3)
}

#[test]
fn single_class_distribution_is_uniform_under_seeded_stream() {
    let mut rng = SplitMix64::new(0xDEAD);

    // Histogram across all SAMPLES × LENGTH characters.
    let mut hist = [0u64; 26];
    let mut total = 0u64;

    // Each draw needs at most (length + OVERSAMPLE) × 4 bytes; oversize
    // the buffer to keep margin against the rejection loop.
    let bytes_per_sample = (LENGTH * 2 + 256) * 4;
    let builder = PasswordBuilder::new().length(LENGTH).classes(CharSet {
        lowercase: true,
        ..CharSet::NONE
    });
    for i in 0..SAMPLES {
        let bytes = rng.bytes(bytes_per_sample);
        let pw = builder
            .generate_from_bytes(&bytes)
            .unwrap_or_else(|e| panic!("sample {i}: {e}"));
        for c in pw.chars() {
            let idx = LOWERCASE
                .find(c)
                .unwrap_or_else(|| panic!("non-lowercase character {c:?} in single-class output"));
            hist[idx] += 1;
            total += 1;
        }
    }
    assert_eq!(total as usize, TOTAL_CHARS);

    let expected = total as f64 / 26.0;
    let mut chi_squared = 0.0_f64;
    for &observed in &hist {
        let diff = observed as f64 - expected;
        chi_squared += diff * diff / expected;
    }

    let critical = chi_squared_critical(25);
    assert!(
        chi_squared < critical,
        "chi-squared statistic {chi_squared:.2} exceeded critical value {critical:.2} \
         (25 dof, p=0.001). With a uniform sampler the statistic should be in the \
         single to low-double digits; a value in the hundreds usually means modulo \
         bias was reintroduced on RNG output. Histogram: {hist:?}"
    );
}
