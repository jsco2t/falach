//! Falach core library.
//!
//! This crate owns the on-disk story for KDBX vaults: read/write through
//! `keepass-rs`, atomic file writes, advisory file locking, the
//! `vaults.toml` registry, and zeroize-on-drop wrappers for sensitive
//! buffers. It is the only crate in the workspace that links `keepass-rs`;
//! every UI feature (CLI, TUI, agent) consumes vault functionality through
//! this crate.
//!
//! Primary API types:
//!
//! - [`Vault`] opens, creates, mutates, saves, and rekeys KDBX vault files
//!   while holding an exclusive advisory lock.
//! - [`VaultReadOnly`] opens a vault with a shared advisory lock.
//! - [`VaultRegistry`] manages the user's `vaults.toml` registry records,
//!   represented as [`RegisteredVault`] values.
//! - [`MasterPassword`] and [`Keyfile`] wrap unlock material without exposing
//!   it in debug output.
//! - [`KdfParams`] configures Argon2id settings for new vaults, and
//!   [`NoRecoveryConfirmed`] is the creation-time marker that the caller has
//!   shown the no-recovery warning.
//! - [`VaultError`] is the single public error type and does not carry secret
//!   material.
//!
//! # Example
//!
//! ```no_run
//! use falach_core::{fields, KdfParams, MasterPassword, NoRecoveryConfirmed, Vault};
//!
//! # fn main() -> Result<(), falach_core::VaultError> {
//! let path = std::path::Path::new("example.kdbx");
//! let master = MasterPassword::new("correct horse battery staple".to_string());
//!
//! let mut vault = Vault::create(
//!     path,
//!     &master,
//!     None,
//!     KdfParams::default(),
//!     NoRecoveryConfirmed::yes(),
//! )?;
//! vault.database_mut().root_mut().add_entry().edit(|entry| {
//!     entry.set_unprotected(fields::TITLE, "Example");
//!     entry.set_protected(fields::PASSWORD, "secret");
//! });
//! vault.save()?;
//! drop(vault);
//!
//! let reopened = Vault::open(path, &master, None)?;
//! assert!(reopened.database().root().entry_by_name("Example").is_some());
//! # Ok(())
//! # }
//! ```

// Production code: deny unsafe by default. The only production opt-outs
// are the locally-audited `mlock`/`munlock` blocks in `secret.rs`
// (best-effort master-password memory locking — the follow-on that
// design §3.9 anticipated when this was still `forbid`); test-only
// modules opt in via `#[allow(unsafe_code)]` annotations on individual
// items (see secret.rs and paths.rs test modules).
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod atomic;
mod entry;
pub mod error;
pub mod locking;
pub mod paths;
pub mod registry;
pub mod secret;
mod unlock;
pub mod vault;

pub use entry::{
    fuzzy_match, fuzzy_match_terms, Attachment, EntryBuilder, EntryDraft, EntryKind, EntryView,
    EntryViewMut, FuzzyMatch, GroupDeleteBehavior, GroupView, HistoryCap, HistoryView,
    MatchedField, OtpAuthUriError, SearchMode, SearchOptions, SearchResult, SearchScope, Tag, Totp,
    TotpAlgorithm, DEFAULT_MAX_ATTACHMENT_BYTES, MAX_ATTACHMENT_BYTES_KEY,
    MAX_ATTACHMENT_BYTES_UPPER_BOUND,
};
pub use error::VaultError;
pub use keepass::config::DatabaseConfig;
pub use keepass::db::{fields, Entry, EntryRef, Group, GroupRef, Times, Value};
pub use keepass::Database;
pub use locking::{ExclusiveLock, SharedLock};
pub use paths::FalachPaths;
pub use registry::{RegisteredVault, VaultRegistry, SCHEMA_VERSION};
pub use secret::{Keyfile, MasterPassword};
pub use uuid::Uuid;
pub use vault::{KdfParams, NoRecoveryConfirmed, Vault, VaultReadOnly};
pub use zeroize::Zeroizing;
