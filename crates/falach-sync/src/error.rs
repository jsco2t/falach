//! The crate's single public error type (design §2.5).
//!
//! Variants name the failure mode (auth, not-found, precondition, transport,
//! etc.) so callers can branch on them programmatically. No variant ever
//! carries plaintext passwords, decrypted vault contents, KDBX bytes, or any
//! credential material — the same discipline `falach-core::VaultError`
//! follows. The enum is `#[non_exhaustive]` so later phases can add variants
//! without a `SemVer` break.

use std::path::PathBuf;

use crate::auth::AuthError;
use crate::merge::MergeError;
use crate::s3::S3Error;

/// Errors surfaced by the sync layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SyncError {
    /// Sync is not configured for this vault. The vault has no
    /// `[sync]` block, or the block exists but fails to deserialize into
    /// a [`crate::SyncConfig`] (e.g. a hand-edited / pre-T5.1
    /// git-shape carryover). The user should run
    /// `falach vault set-sync ...`.
    #[error("sync is not configured for this vault (run `falach vault set-sync ...`)")]
    NotConfigured,

    /// The S3 endpoint could not be reached (network failure, DNS, TLS,
    /// 5xx storm after retries).
    #[error("S3 endpoint unreachable: {endpoint} ({source})")]
    RemoteUnreachable {
        /// The endpoint URL the request targeted.
        endpoint: String,
        /// The underlying transport error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Authentication against the remote failed (403, signature rejected,
    /// credentials missing or expired). `reason` is a non-secret
    /// description suitable for logging.
    #[error("authentication failed for {endpoint}: {reason}")]
    AuthFailed {
        /// The endpoint URL the auth attempt targeted.
        endpoint: String,
        /// A non-secret reason string.
        reason: String,
    },

    /// The conditional-PUT retry loop exhausted its budget — remote
    /// advanced concurrently more than `attempts` times. The caller
    /// should re-run sync (the next attempt sees the new state).
    #[error("conditional PUT exhausted after {attempts} retries; remote has advanced concurrently; retry `falach sync`")]
    ConditionalPutExhausted {
        /// Number of attempts consumed before exhaustion.
        attempts: usize,
    },

    /// Two vaults configured to the same canonicalized S3 target
    /// (ADR-6). `Sync::configure_remote` refuses to write the colliding
    /// config; the user must change one vault's bucket / key / endpoint.
    #[error("two vaults configured to the same S3 target ({endpoint:?} bucket={bucket} key={key}); existing vault: `{existing_vault}`")]
    DuplicateTarget {
        /// The endpoint URL (`None` = AWS default for region).
        endpoint: Option<String>,
        /// The bucket name.
        bucket: String,
        /// The object key.
        key: String,
        /// The other vault already using this target.
        existing_vault: String,
    },

    /// The configured backend does not support a feature the orchestrator
    /// requires (and graceful degradation has been explicitly disabled).
    /// In Phase 0 this is surfaced only when the sentinel-key probe (ADR-5)
    /// classifies a backend as `Degraded` and the caller has opted out of
    /// the degraded path.
    #[error("S3 backend lacks required feature `{feature}`; either upgrade the backend or accept the documented degradation path")]
    UnsupportedBackend {
        /// Feature name (e.g. "conditional-put").
        feature: String,
    },

    /// The master password or KDF parameters differ between the local
    /// and remote vaults — almost always a master-password change on
    /// another device that hasn't been re-synced. The orchestrator
    /// refuses to merge; the user resolves manually.
    #[error("master password or KDF parameters differ between local and remote vault")]
    MasterPasswordMismatch,

    /// A merge could not be auto-resolved (same-second divergence with
    /// differing content). The pre-merge `.kdbx.bak` is preserved.
    #[error("merge cannot proceed: {reason}; pre-merge state preserved at {backup_path}")]
    Unresolvable {
        /// Non-secret description of the conflict.
        reason: String,
        /// Path to the preserved `.kdbx.bak` snapshot.
        backup_path: PathBuf,
    },

    /// Writing the pre-merge `.kdbx.bak` snapshot failed.
    #[error("pre-merge backup creation failed: {source}")]
    BackupFailed {
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A stored credential could not be decrypted — typically because the
    /// container is corrupt OR the master password is wrong. The two are
    /// intentionally indistinguishable (an attacker mustn't learn which).
    #[error("invalid credential container (corrupt or wrong master password)")]
    CredentialDecryption,

    /// The credential discovery layer ([`crate::auth::resolve`]) returned
    /// an error. Wraps [`AuthError`] for context — the specific failure
    /// mode (missing file, missing env var, IMDS unreachable, etc.) is
    /// in the source chain.
    #[error("credential discovery failed: {0}")]
    Auth(#[from] AuthError),

    /// The merge engine returned an error. Wraps [`MergeError`] for
    /// context.
    #[error("merge engine error: {0}")]
    Merge(#[from] MergeError),

    /// An S3 protocol error occurred (anything wire-level — auth, not-found,
    /// 5xx, malformed `ETag`, etc.). Wraps [`S3Error`] for context.
    #[error("S3 protocol error: {0}")]
    S3(#[from] S3Error),

    /// A vault-layer (`falach-core`) error occurred.
    #[error("vault error: {0}")]
    Vault(#[from] falach_core::VaultError),

    /// Reading or writing the on-disk vault `.kdbx` failed during sync —
    /// distinct from the [`Self::Vault`] variant (which wraps logical
    /// vault errors like `AuthenticationFailed` or
    /// `DatabaseIdentityMismatch`). `path` names the file the syscall
    /// failed against.
    #[error("vault I/O during sync: {path:?}: {source}")]
    VaultIo {
        /// The file path the I/O failure was against.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}
