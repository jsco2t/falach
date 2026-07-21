//! US-020 — Generate a random password with default settings.
//!
//! Verifies the default-knob path end-to-end through the public API:
//! the documented default length, distinct successive outputs, and
//! that the convenience `default_password()` is equivalent to a
//! freshly-constructed builder's output.
//!
//! The "uses the OS CSPRNG" property (US-020 AC #3) is established
//! structurally rather than dynamically: there is no `generate(&mut R)`
//! parameter for a caller to subvert, and `PasswordBuilder::generate`
//! is wired to `getrandom::fill` in the crate source. The crate's
//! library tests pin both behaviors.

use falach_genpw::{default_password, PasswordBuilder, Zeroizing, DEFAULT_LENGTH};

#[test]
fn default_password_has_documented_length() {
    let pw: Zeroizing<String> = PasswordBuilder::new()
        .generate()
        .expect("OS CSPRNG available");
    assert_eq!(pw.chars().count(), DEFAULT_LENGTH);
    assert_eq!(DEFAULT_LENGTH, 20, "PRD-derived default is 20 chars");
}

#[test]
fn default_password_successive_invocations_differ() {
    // 100 default-builder calls produce 100 distinct outputs.
    // Collision probability across the 131-bit space is below
    // cosmic-ray-flips-a-bit; any failure here is a real bug.
    let builder = PasswordBuilder::new();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..100 {
        let pw = builder.generate().expect("OS CSPRNG available");
        seen.insert(pw.to_string());
    }
    assert_eq!(seen.len(), 100, "expected 100 distinct outputs");
}

#[test]
fn convenience_default_password_function_matches_builder() {
    // Two outputs from the convenience facade and the builder path
    // should be indistinguishable in shape (length).
    let a = default_password().expect("OS CSPRNG available");
    let b = PasswordBuilder::new()
        .generate()
        .expect("OS CSPRNG available");
    assert_eq!(a.chars().count(), b.chars().count());
    assert_eq!(a.chars().count(), DEFAULT_LENGTH);
}
