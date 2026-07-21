//! Entry management on an already-unlocked KDBX vault.
//!
//! This module owns everything that happens *to* the in-memory KDBX
//! [`keepass::Database`] once vault-core has unlocked it: typed
//! construction of new entries ([`EntryBuilder`]), read/write façades
//! ([`EntryView`], [`EntryViewMut`]), CRUD methods on [`crate::Vault`],
//! group + tag operations, free-text and wildcard search
//! ([`SearchOptions`]), TOTP generation ([`Totp`]), file attachments
//! ([`Attachment`]), and per-entry expiration metadata. Persistence is
//! always through [`crate::Vault::save`] — this module never touches
//! disk directly.
//!
//! # The UUID stability contract (FR-011)
//!
//! The merge engine in `features/sync-git/` keys collision detection on
//! the KDBX-native entry UUID, so an edit must never silently produce a
//! "new" UUID for what users perceive as the same entry. The public API
//! is shaped to make that contract impossible to violate accidentally:
//!
//! - [`Vault::add_entry`] is the **only** function that allocates a
//!   fresh UUID. It returns the new UUID for downstream use.
//! - Every other mutation — [`Vault::update_entry`],
//!   [`Vault::move_entry`], [`Vault::add_attachment`],
//!   [`Vault::remove_attachment`], [`Vault::set_expiration`],
//!   [`Vault::clear_expiration`], tag changes, and history pruning —
//!   looks an entry up by UUID and preserves it byte-for-byte across
//!   save+reopen.
//! - [`Vault::purge_entry`] permanently destroys the entry and its UUID;
//!   it is the explicit opt-in for "I really do want this gone."
//!
//! The contract is enforced by `tests/us_011_uuid_stable.rs`, which
//! exercises every preserving operation against the same entry and
//! asserts UUID byte-equality across save+reopen. Any failure of that
//! test is a P0 sync-breaking regression.
//!
//! # Automatic history (FR-012)
//!
//! [`Vault::update_entry`] takes a closure that mutates an
//! [`EntryViewMut`]. Before the closure runs, the prior entry state is
//! snapshotted into the entry's KDBX-native history list; FIFO pruning
//! keeps history within [`crate::Vault::history_cap`] (default cap 10,
//! matching `KeePassXC`; the KDBX conventions "negative = unlimited" and
//! "0 = disabled" are honored). If the closure returns `Err`, the entry —
//! including its history list — is rolled back to its pre-call state,
//! so history reflects committed changes only.
//!
//! "Metadata side-channel" operations deliberately **do not** append
//! history, matching `KeePassXC`'s UX convention:
//!
//! - [`Vault::add_attachment`] / [`Vault::remove_attachment`]
//! - [`Vault::set_expiration`] / [`Vault::clear_expiration`]
//! - [`Vault::move_entry`]
//!
//! # Recommended usage
//!
//! For edits, prefer [`Vault::update_entry`] over
//! [`Vault::get_entry_mut`] — the closure form guarantees the
//! history-append-once invariant regardless of how many fields the
//! closure touches:
//!
//! ```no_run
//! use falach_core::{EntryBuilder, KdfParams, MasterPassword, NoRecoveryConfirmed, Vault};
//!
//! # fn main() -> Result<(), falach_core::VaultError> {
//! let dir = tempfile::TempDir::new().expect("tempdir");
//! let path = dir.path().join("notes.kdbx");
//! let master = MasterPassword::new("correct horse battery staple".to_string());
//! let mut vault = Vault::create(
//!     &path,
//!     &master,
//!     None,
//!     KdfParams::default(),
//!     NoRecoveryConfirmed::yes(),
//! )?;
//! let root = vault.root_group_uuid();
//!
//! // Add a credential.
//! let uuid = vault.add_entry(
//!     root,
//!     EntryBuilder::credential("Example")
//!         .username("alice")
//!         .password("first password")
//!         .url("https://example.test")
//!         .build(),
//! )?;
//!
//! // Rotate the password — exactly one history entry is appended,
//! // recording the prior state.
//! vault.update_entry(uuid, |entry| {
//!     entry.set_password("rotated");
//!     Ok(())
//! })?;
//!
//! vault.save()?;
//! # Ok(())
//! # }
//! ```
//!
//! # Search
//!
//! Two modes per FR-014:
//!
//! - Default: case-insensitive substring match — `SearchOptions::new("query")`.
//! - Opt-in: case-insensitive wildcard match anchored to the whole field —
//!   `.wildcard(true)`. `*` matches any sequence; `?` matches exactly one
//!   character. To express "field contains FOO", pad with `*`:
//!   `*FOO*`.
//!
//! ```no_run
//! use falach_core::{SearchOptions, Vault};
//!
//! # fn main() -> Result<(), falach_core::VaultError> {
//! # let path = std::path::Path::new("notes.kdbx");
//! # let master = falach_core::MasterPassword::new("pw".to_string());
//! let vault = Vault::open(path, &master, None)?;
//!
//! // Substring (default).
//! let _ = vault.search(SearchOptions::new("example"))?;
//!
//! // Wildcards (anchored).
//! let _ = vault.search(SearchOptions::new("Login*").wildcard(true))?;
//! # Ok(())
//! # }
//! ```
//!
//! # TOTP
//!
//! TOTP entries store an `otpauth://totp/...` URI as the `KeePassXC`-
//! convention `otp` custom field. [`Vault::totp`] generates the current
//! code and remaining-seconds-in-window. Phase 0 supports HMAC-SHA1
//! only (see the [`totp`] module docs for the full rationale).
//!
//! ```no_run
//! use falach_core::{EntryBuilder, Vault};
//!
//! # fn main() -> Result<(), falach_core::VaultError> {
//! # let path = std::path::Path::new("notes.kdbx");
//! # let master = falach_core::MasterPassword::new("pw".to_string());
//! let mut vault = Vault::open(path, &master, None)?;
//! let root = vault.root_group_uuid();
//! let uuid = vault.add_entry(
//!     root,
//!     EntryBuilder::totp(
//!         "Example",
//!         "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&issuer=Example",
//!     )?
//!     .build(),
//! )?;
//! let (code, remaining) = vault.totp(uuid)?;
//! println!("{code} ({remaining}s remaining)");
//! # Ok(())
//! # }
//! ```
//!
//! # Attachments
//!
//! Add raw bytes with [`Vault::add_attachment`]; size is checked against
//! [`Vault::max_attachment_bytes`] (default 5 MiB, configurable to 100
//! MiB) at insert time. Reads return a self-zeroizing
//! [`zeroize::Zeroizing<Vec<u8>>`].
//!
//! ```no_run
//! use falach_core::{EntryBuilder, Vault};
//!
//! # fn main() -> Result<(), falach_core::VaultError> {
//! # let path = std::path::Path::new("notes.kdbx");
//! # let master = falach_core::MasterPassword::new("pw".to_string());
//! let mut vault = Vault::open(path, &master, None)?;
//! let root = vault.root_group_uuid();
//! let uuid = vault.add_entry(root, EntryBuilder::credential("With Doc").build())?;
//! vault.add_attachment(uuid, "notes.txt", b"hello")?;
//! let bytes = vault.get_attachment(uuid, "notes.txt")?;
//! assert_eq!(bytes.as_slice(), b"hello");
//! # Ok(())
//! # }
//! ```
//!
//! # Expiration
//!
//! [`Vault::set_expiration`] / [`Vault::clear_expiration`] manipulate
//! the KDBX-native `Times.Expires` / `Times.ExpiryTime` fields;
//! [`Vault::is_expired`] returns `true` when `now >= expiry_time`
//! (inclusive of the expiry moment). Expiration does not append history
//! by design — it's metadata about the entry, not an edit to its
//! content.

mod attachment;
mod builder;
mod crud;
mod expiration;
mod fuzzy;
mod group;
mod search;
pub(crate) mod totp;
mod types;
mod view;

pub use attachment::{
    DEFAULT_MAX_ATTACHMENT_BYTES, MAX_ATTACHMENT_BYTES_KEY, MAX_ATTACHMENT_BYTES_UPPER_BOUND,
};

pub use builder::{EntryBuilder, EntryDraft, EntryKind};
pub use crud::HistoryCap;
pub use fuzzy::{fuzzy_match, fuzzy_match_terms, FuzzyMatch};
pub use group::{GroupDeleteBehavior, GroupView};
pub use search::{MatchedField, SearchMode, SearchOptions, SearchResult, SearchScope};
pub use totp::{OtpAuthUriError, Totp, TotpAlgorithm};
pub use types::{Attachment, Tag};
pub use view::{EntryView, EntryViewMut, HistoryView};
