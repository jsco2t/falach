//! [`TuiError`] — the crate's single public error type.
//!
//! Discipline (CLAUDE.md "No plaintext to disk, ever" / "Never log entry
//! contents"): no variant ever embeds secret material. `Display` strings are
//! hard-coded prefixes plus already-redacted inner errors; `Internal` carries
//! a `&'static str` programmer message, never user/secret input.

use std::io;
use thiserror::Error;

/// Errors surfaced by the `falach-tui` binary.
///
/// `#[non_exhaustive]` so later phases can add variants (e.g. richer config or
/// settings errors) without a breaking change to the matching sites.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum TuiError {
    /// A recognized option is deliberately reserved for a tracked later task.
    #[error("{0}")]
    UnsupportedOption(String),
    /// Terminal / backend I/O (raw mode, alternate screen, draw, poll).
    #[error("terminal I/O error: {0}")]
    Io(#[from] io::Error),

    /// An error bubbled up from `falach-core` (vault open, registry, entries).
    #[error("vault-core error: {0}")]
    Core(#[from] falach_core::VaultError),

    /// An error bubbled up from `falach-security` (auto-lock controller,
    /// clipboard). Its `Display` is secret-free.
    #[error("security error: {0}")]
    Security(#[from] falach_security::SecurityError),

    /// An error bubbled up from the real sync engine (`falach-sync`). The
    /// inner `SyncError`'s `Display` is already secret-free (it never carries
    /// endpoint credentials or key material).
    #[error("sync error: {0}")]
    Sync(#[from] falach_sync::SyncError),

    /// Reading or writing the TUI's own non-secret `tui.toml` failed. Kept
    /// distinct from [`TuiError::Io`] (terminal I/O) so config failures can be
    /// surfaced non-fatally (status-bar warning, keep running on in-memory
    /// state) per design U.5. Wired in Phase 4.
    #[error("could not access the TUI config file: {0}")]
    ConfigIo(io::Error),

    /// The TUI's `tui.toml` could not be parsed; the loader falls back to
    /// defaults. The message is a parser diagnostic, never file contents that
    /// could carry secrets (the config holds only prefs + UUIDs). Wired in
    /// Phase 4.
    #[error("could not parse the TUI config: {0}")]
    ConfigParse(String),

    /// No vaults are registered in `vaults.toml`.
    #[error("no vaults registered (run `falach vault create` to make one)")]
    NoVaultsRegistered,

    /// `--vault NAME` named a vault that is not in the registry. The name is a
    /// user-chosen vault label (never secret). Reported pre-terminal so it
    /// prints on a normal screen (T3.2).
    #[error("vault '{0}' is not registered (see 'falach vault list')")]
    UnknownVault(String),

    /// The user cancelled an in-progress operation (e.g. dismissed a prompt).
    #[error("user cancelled")]
    Cancelled,

    /// A programmer-error invariant was violated. The message is a hard-coded
    /// literal (never user input) so it cannot leak secrets.
    #[error("internal invariant violated: {0}")]
    Internal(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Representative instances of every variant we can construct without an
    /// upstream error value. (`Io`/`Core`/`Sync` wrap foreign errors whose
    /// `Display` is owned by those crates; the `#[from]` correctness is checked
    /// separately and is compile-time guaranteed.)
    fn sample_errors() -> Vec<TuiError> {
        vec![
            TuiError::ConfigIo(io::Error::new(io::ErrorKind::NotFound, "no such file")),
            TuiError::ConfigParse("expected a table at line 3".to_string()),
            TuiError::NoVaultsRegistered,
            TuiError::UnknownVault("personal".to_string()),
            TuiError::Cancelled,
            TuiError::Internal("vault is None in Phase::Workspace"),
        ]
    }

    /// CLAUDE.md non-negotiable: no error string may carry secret material.
    /// Our hard-coded messages are clean by construction; this regression test
    /// guards against a future variant accidentally interpolating a password,
    /// master password, key, or vault contents into `Display`/`Debug`.
    #[test]
    fn display_and_debug_never_leak_secret_markers() {
        const BANNED: &[&str] = &["password", "secret", "master", "begin ", "-----"];
        for e in sample_errors() {
            let shown = format!("{e}").to_lowercase();
            let debugged = format!("{e:?}").to_lowercase();
            for banned in BANNED {
                assert!(
                    !shown.contains(banned),
                    "Display of {e:?} leaked banned marker {banned:?}: {shown}"
                );
                assert!(
                    !debugged.contains(banned),
                    "Debug of {e:?} leaked banned marker {banned:?}: {debugged}"
                );
            }
        }
    }

    /// `#[from] io::Error` maps into the terminal-I/O variant (not `ConfigIo`,
    /// which is constructed explicitly so the two I/O sources stay distinct).
    #[test]
    fn io_error_converts_into_io_variant() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let tui: TuiError = io_err.into();
        assert!(matches!(tui, TuiError::Io(_)), "expected Io, got {tui:?}");
    }

    /// Every variant renders a non-empty, human-readable message.
    #[test]
    fn every_sample_variant_has_a_nonempty_message() {
        for e in sample_errors() {
            assert!(!format!("{e}").trim().is_empty(), "empty Display for {e:?}");
        }
    }
}
