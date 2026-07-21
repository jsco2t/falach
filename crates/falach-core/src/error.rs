//! Single public error type for the `falach-core` crate.
//!
//! Per design §2.2.3 and §2.5: every fallible operation returns
//! [`VaultError`]. Variants carry only structured, non-secret context
//! (paths, names, source errors). No variant ever embeds a master
//! password, a derived key, or decrypted vault contents.
//!
//! ## Source payload provenance
//!
//! `InvalidFormat` and `WriteFailed` carry upstream `keepass-rs` error
//! types as `#[source]`; `InvalidOtpUri` carries an in-tree
//! [`crate::entry::totp::OtpAuthUriError`]. The variant identities are
//! stable; only the wrapped source types may change when a dependency
//! upgrade reshapes its error surface.

use std::io;
use std::path::PathBuf;
use uuid::Uuid;

/// Errors returned by every fallible operation in `falach-core`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VaultError {
    /// `$HOME` is not set or not resolvable to a path.
    ///
    /// Returned by [`crate::paths::FalachPaths::from_env`] when the
    /// process environment does not contain a usable `HOME` variable.
    #[error("$HOME is not set or not resolvable to a path")]
    HomeUnresolvable,

    /// The given path already exists. `Vault::create` refuses to
    /// overwrite an existing file.
    #[error("path already exists: {}", path.display())]
    PathExists {
        /// Path that already exists.
        path: PathBuf,
    },

    /// The given vault file does not exist.
    #[error("vault file not found: {}", path.display())]
    FileNotFound {
        /// Path that was expected to contain a vault file.
        path: PathBuf,
    },

    /// The master password (and/or keyfile) did not decrypt the vault.
    ///
    /// Deliberately does not distinguish "wrong password" from "wrong
    /// keyfile" — see US-004 AC #3.
    #[error("authentication failed")]
    AuthenticationFailed,

    /// The vault file is currently locked by another process.
    ///
    /// `holder` is `Some(pid)` on Linux (via `/proc/locks`) when we can
    /// identify the holder, and `None` on macOS. Phase 0 ships `None`
    /// on both platforms; PID extraction is deferred (follow-ups OQ-4).
    #[error("vault is held by another process")]
    Contended {
        /// Process ID of the lock holder when known.
        holder: Option<u32>,
    },

    /// The vault file is not a valid KDBX file (bad header, truncated,
    /// not a KDBX container, etc.).
    #[error("vault file is corrupted or not a KDBX file")]
    InvalidFormat {
        /// Upstream KDBX parse/open error.
        #[source]
        source: keepass::db::DatabaseOpenError,
    },

    /// I/O error from an underlying filesystem operation. `path`
    /// captures the file the error relates to (errors without their
    /// path are miserable to debug — design §2.5).
    #[error("I/O error on {}: {source}", path.display())]
    Io {
        /// Underlying filesystem error.
        #[source]
        source: io::Error,
        /// Path associated with the failing filesystem operation.
        path: PathBuf,
    },

    /// Writing the KDBX file failed.
    #[error("KDBX write failed")]
    WriteFailed {
        /// Upstream KDBX save error.
        #[source]
        source: keepass::db::DatabaseSaveError,
    },

    /// The `vaults.toml` registry file is malformed (read path).
    ///
    /// `source` is `Some` when the failure was a TOML parse error
    /// (from `toml::de::Error`) and `None` when the file parsed but
    /// failed a structural check (e.g., unsupported `version`).
    /// Schema-version mismatches are surfaced via this variant rather
    /// than a separate `UnsupportedVersion` so callers handle the
    /// "the registry is unreadable in some way" case uniformly.
    ///
    /// This variant is **read-path only**. Serialization failures
    /// during `VaultRegistry::save` use
    /// [`VaultError::RegistrySerializationFailed`] so callers can
    /// distinguish "the file on disk is broken" from "we failed to
    /// produce a file."
    #[error("vault registry file is malformed")]
    RegistryMalformed {
        /// TOML parser error, when malformed syntax caused the failure.
        #[source]
        source: Option<toml::de::Error>,
    },

    /// `vaults.toml` changed after this registry snapshot was loaded. The
    /// caller must reload before retrying so it cannot overwrite another
    /// process's completed edit.
    #[error("vault registry changed concurrently; reload and retry")]
    RegistryChanged,

    /// Serializing the in-memory registry to TOML failed (write path).
    ///
    /// Nearly impossible in practice — values that round-tripped from a
    /// valid TOML load always re-serialize cleanly, and the registry's
    /// own fields are all serializable. Surfaces as a distinct variant
    /// (rather than reusing [`VaultError::RegistryMalformed`]) so the
    /// error message doesn't misleadingly imply the on-disk file is
    /// corrupted when in fact no file has been written yet.
    #[error("vault registry serialization failed")]
    RegistrySerializationFailed {
        /// TOML serialization error.
        #[source]
        source: toml::ser::Error,
    },

    /// No registered vault with the given name.
    #[error("registered vault not found: {name}")]
    NotRegistered {
        /// Registry name that was not found.
        name: String,
    },

    /// A vault with the given name is already registered.
    #[error("registered vault already exists: {name}")]
    AlreadyRegistered {
        /// Registry name that already exists.
        name: String,
    },

    /// `Vault::create` was called without the caller obtaining a
    /// `NoRecoveryConfirmed` from the user. Compile-time prevention is
    /// preferred (the type is zero-sized and constructible only via an
    /// explicit `yes()` call); this variant exists for defense in depth
    /// and to satisfy FR-005.
    #[error("no-recovery warning must be confirmed before vault creation")]
    NoRecoveryNotConfirmed,

    /// No entry exists with the given UUID.
    #[error("entry not found: {uuid}")]
    EntryNotFound {
        /// Entry UUID that was not found.
        uuid: Uuid,
    },

    /// No group exists with the given UUID.
    #[error("group not found: {uuid}")]
    GroupNotFound {
        /// Group UUID that was not found.
        uuid: Uuid,
    },

    /// The entry exists, but it does not contain a TOTP/HOTP field.
    #[error("entry has no TOTP/HOTP otp field: {uuid}")]
    EntryHasNoTotp {
        /// Entry UUID that lacks an `otp` field.
        uuid: Uuid,
    },

    /// An attachment exceeds the configured per-attachment size cap.
    #[error("attachment too large: {actual} bytes exceeds limit of {limit} bytes")]
    AttachmentTooLarge {
        /// Actual attachment size in bytes.
        actual: u64,
        /// Configured attachment size limit in bytes.
        limit: u64,
    },

    /// No attachment exists on an entry with the requested name.
    #[error("attachment not found: {name}")]
    AttachmentNotFound {
        /// Attachment name that was not found.
        name: String,
    },

    /// An `otpauth://` URI is malformed.
    #[error("invalid otpauth URI: {source}")]
    InvalidOtpUri {
        /// Underlying otpauth URI parse error.
        #[source]
        source: crate::entry::totp::OtpAuthUriError,
    },

    /// The requested attachment cap is outside the supported range.
    #[error("invalid attachment cap: must be between 1 byte and 104857600 bytes")]
    InvalidAttachmentCap,

    /// A group delete was refused because the group is not empty.
    #[error(
        "group is not empty: {uuid}; use GroupDeleteBehavior::Recurse to delete with children"
    )]
    GroupNotEmpty {
        /// Group UUID that was not empty.
        uuid: Uuid,
    },

    /// The requested tag is invalid for KeePassXC-compatible tag storage.
    #[error("invalid tag: {value}; tags cannot contain ';'")]
    InvalidTag {
        /// Tag value that failed validation.
        value: String,
    },

    /// The root group cannot be moved or deleted.
    #[error("cannot move or delete the root group")]
    CannotModifyRoot,

    /// The requested destination group is not valid for this operation.
    #[error("invalid group target: {reason}")]
    InvalidGroupTarget {
        /// Human-readable non-secret reason.
        reason: &'static str,
    },

    /// A database being installed via [`crate::Vault::replace_database`] does
    /// not describe the same vault: its root-group UUID differs from the
    /// current one. Installing it would silently swap the vault's identity, so
    /// the operation is refused.
    #[error(
        "database identity mismatch: root group {found} does not match the vault's {expected}"
    )]
    DatabaseIdentityMismatch {
        /// Root-group UUID of the current (target) database.
        expected: Uuid,
        /// Root-group UUID of the database that was offered.
        found: Uuid,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn authentication_failed_debug_carries_no_secret_material() {
        // `AuthenticationFailed` has no fields, so this test asserts the
        // structural invariant: no field can be added in the future that
        // would carry user-supplied bytes. We assert the Debug output is
        // exactly the variant name — any added field would lengthen it.
        let dbg = format!("{:?}", VaultError::AuthenticationFailed);
        assert_eq!(dbg, "AuthenticationFailed");
    }

    #[test]
    fn source_chain_traverses_to_underlying_io_error() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "nope");
        let err = VaultError::Io {
            source: io_err,
            path: PathBuf::from("/some/path"),
        };

        let source = err.source().expect("Io variant should expose its source");
        let downcast = source
            .downcast_ref::<io::Error>()
            .expect("source should be an io::Error");
        assert_eq!(downcast.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn entry_error_display_includes_actionable_context() {
        let uuid = Uuid::nil();
        assert_eq!(
            VaultError::EntryNotFound { uuid }.to_string(),
            format!("entry not found: {uuid}")
        );
        assert_eq!(
            VaultError::AttachmentTooLarge {
                actual: 10,
                limit: 5,
            }
            .to_string(),
            "attachment too large: 10 bytes exceeds limit of 5 bytes"
        );
        assert_eq!(
            VaultError::InvalidTag {
                value: "a;b".to_string(),
            }
            .to_string(),
            "invalid tag: a;b; tags cannot contain ';'"
        );
    }
}
