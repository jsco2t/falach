// Domain acronyms saturate this module; see the same note on
// `crate::auth::error` and `crate::s3::mod` for the rationale.
#![allow(clippy::doc_markdown)]

//! Read-only environment-variable source (design.md §2.2.9).
//!
//! Production code reads `std::env::var` through [`SystemEnvSource`];
//! tests inject a `MockEnvSource` holding a `HashMap` so the env-var
//! credential-resolution path can be exercised without mutating the
//! process environment.
//!
//! **Why a trait at all?** Rust 1.80 marked `std::env::set_var` as
//! `unsafe` (race against concurrent `getenv` from any other thread,
//! including libc internals). This crate's `#![forbid(unsafe_code)]`
//! posture would force `#[allow(unsafe_code)]` opt-outs at every test
//! site that wanted to populate an env var — a cost that adds up across
//! the EnvVars credential resolver's ~6 test cases. The `EnvSource`
//! seam keeps tests pure-safe and serial-test-free.
//!
//! `std::env::var` (the *read* API) is NOT `unsafe` — only `set_var`
//! gained that bound. `SystemEnvSource` delegates to `var_os` and
//! converts via `OsString::into_string`.

#[cfg(any(test, feature = "test-helpers"))]
use std::collections::HashMap;

/// Read-only environment-variable source. Single method that mirrors
/// `std::env::var`'s "absent or non-UTF-8 → None" semantics.
///
/// **Send/Sync:** deliberately not bounded. Phase-0 credential
/// resolution is single-threaded (called from the orchestrator on the
/// same thread the sync runs on); adding `Send + Sync` later is
/// non-breaking. Keeping it off now lets `MockEnvSource` hold a plain
/// `HashMap` without an `Arc<RwLock<...>>` wrapper.
pub trait EnvSource {
    /// Return the value of the named environment variable, or `None`
    /// when it is unset or its value is not valid UTF-8 (matches
    /// `std::env::var`).
    fn get(&self, name: &str) -> Option<String>;
}

/// Production implementation: reads `std::env::var_os` and converts
/// to `String`. The `_os` form is preferred over `std::env::var` so
/// non-UTF-8 values surface as `None` rather than a `VarError`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemEnvSource;

impl EnvSource for SystemEnvSource {
    fn get(&self, name: &str) -> Option<String> {
        std::env::var_os(name).and_then(|v| v.into_string().ok())
    }
}

/// Test-only [`EnvSource`] backed by a `HashMap`. Construct via the
/// `Default` impl + `vars` field, or via `MockEnvSource::with([...])`
/// for inline literal construction.
///
/// Feature-gated `test-helpers` so the type compiles into integration
/// tests in sibling crates without leaking into production binaries.
#[cfg(any(test, feature = "test-helpers"))]
#[derive(Debug, Default, Clone)]
pub struct MockEnvSource {
    /// The mapped (name → value) pairs. Public so tests can mutate the
    /// map mid-test if the resolver flow needs it.
    pub vars: HashMap<String, String>,
}

#[cfg(any(test, feature = "test-helpers"))]
impl MockEnvSource {
    /// Construct from an iterable of `(name, value)` pairs.
    pub fn with<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Self {
            vars: pairs
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        }
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl EnvSource for MockEnvSource {
    fn get(&self, name: &str) -> Option<String> {
        self.vars.get(name).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- TC-ENV-001 ---------------------------------------------------------
    #[test]
    fn mock_env_source_returns_inserted_values() {
        let env = MockEnvSource::with([("K", "V")]);
        assert_eq!(env.get("K").as_deref(), Some("V"));
        assert_eq!(env.get("MISSING"), None);
    }

    // -- TC-ENV-002 ---------------------------------------------------------
    // PATH is universally set in test environments (CI shell, developer
    // shell, `cargo test`). Asserting `Some(_)` rather than a specific
    // value keeps the test portable.
    #[test]
    fn system_env_source_reads_a_known_env_var() {
        let env = SystemEnvSource;
        assert!(
            env.get("PATH").is_some(),
            "PATH must be set in any environment that can run `cargo test`"
        );
    }
}
