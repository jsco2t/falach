//! Password and passphrase generation for Falach.
//!
//! This crate owns generation of new secret material for the workspace.
//! It exposes two builders:
//!
//! - [`PasswordBuilder`] — random ASCII passwords with configurable
//!   length, character classes, and optional ambiguous-character
//!   exclusion.
//! - [`PassphraseBuilder`] — EFF large-wordlist diceware passphrases
//!   with configurable word count and separator.
//!
//! Generated values are returned as [`Zeroizing<String>`] so they are
//! zeroed if the caller drops them without consuming.
//!
//! # Example
//!
//! ```
//! use falach_genpw::{CharSet, PasswordBuilder, PassphraseBuilder, Zeroizing};
//!
//! // Random password with default knobs (length=20, all four classes,
//! // no ambiguous-character filter).
//! let pw: Zeroizing<String> = PasswordBuilder::new()
//!     .generate()
//!     .expect("OS CSPRNG available");
//! assert_eq!(pw.chars().count(), 20);
//!
//! // 32-character letters+digits, no symbols.
//! let pw = PasswordBuilder::new()
//!     .length(32)
//!     .classes(CharSet {
//!         lowercase: true,
//!         uppercase: true,
//!         digits: true,
//!         ..CharSet::NONE
//!     })
//!     .generate()
//!     .expect("OS CSPRNG available");
//! assert_eq!(pw.chars().count(), 32);
//!
//! // EFF diceware passphrase with default knobs (6 words, `-` separator).
//! let pp: Zeroizing<String> = PassphraseBuilder::new()
//!     .generate()
//!     .expect("OS CSPRNG available");
//! assert!(!pp.is_empty());
//!
//! // 4-word passphrase with a space separator.
//! let pp = PassphraseBuilder::new()
//!     .words(4)
//!     .separator(" ")
//!     .generate()
//!     .expect("OS CSPRNG available");
//! assert_eq!(pp.split(' ').count(), 4);
//! ```
//!
//! # Output handling
//!
//! Outputs are [`Zeroizing<String>`]: the inner buffer is zeroed on
//! drop, so a value dropped without use (panic unwind, early return,
//! cancelled flow) does not linger in the allocator's free list.
//! Callers can use the value as a `&str` via `Deref`; do **not**
//! `println!` it in production paths (the `Debug`/`Display` impls
//! pass through to `String` and reveal the value).
//!
//! # CSPRNG source
//!
//! All random material comes from the operating system CSPRNG via the
//! [`getrandom`](https://docs.rs/getrandom/0.4) crate. We deliberately do
//! **not** depend on `rand` / `rand::rngs::OsRng`: `rand 0.8` pins
//! `getrandom 0.2`, which would duplicate the `getrandom 0.4` already in
//! the workspace tree (via `keepass-rs`, `tempfile`, `uuid`). The PRD's
//! "`OsRng` from `rand`" phrasing is a planning artifact; `OsRng` was only
//! ever a thin newtype wrapper around `getrandom::getrandom`. Going
//! direct preserves the security property (OS CSPRNG, FR-023) while
//! satisfying CLAUDE.md's "Limited External Dependencies" rule.
//!
//! ## Implementer guidance — sampling uniformly in a range
//!
//! For things like "pick one character from a charset" or "pick one word
//! from the EFF list", use **rejection sampling** to avoid modulo bias.
//! `getrandom::fill(&mut buf)` produces uniform random bytes; reject any
//! value above `u32::MAX - (u32::MAX % range)` to get a uniform integer
//! in `[0, range)`. See `password::ByteCursor::uniform_index` for the
//! in-tree implementation.
//!
//! The rejection probability is bounded by `range / 2^32` per draw — for
//! typical password-charset sizes (≤96) and the EFF wordlist (7,776
//! words) the expected loop count is essentially 1.

#![cfg_attr(not(test), forbid(unsafe_code))]

pub mod charset;
mod error;
mod passphrase;
mod password;
mod sampling;
mod wordlist;

pub use charset::{CharSet, AMBIGUOUS_CHARS};
pub use error::GenError;
pub use passphrase::{default_passphrase, PassphraseBuilder, DEFAULT_SEPARATOR, DEFAULT_WORDS};
pub use password::{default_password, PasswordBuilder, DEFAULT_LENGTH};

// Re-export so callers don't need a separate `zeroize` import.
pub use zeroize::Zeroizing;
