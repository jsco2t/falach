//! The [`SyncTransport`] trait (FR-046; design.md §2.2.1, ADR-3) and its
//! content-addressable types.
//!
//! Refactored in `features/s3-sync/` T3.1 from the archive's seven-method
//! git-shaped surface (`fetch` / `local_head` / `remote_head` / `merge_base`
//! / `read_vault_at` / `commit_and_push` / `advance_local_to`) to four
//! content-addressable methods ([`SyncTransport::head`],
//! [`SyncTransport::fetch_if_changed`], [`SyncTransport::put_conditional`])
//! plus the [`IsPreconditionFailed`] marker the orchestrator uses to
//! detect the conditional-PUT retry case without naming the concrete
//! transport error.
//!
//! The new shape is the lingua franca of "single-object remote storage
//! with versioned concurrency control" — it maps cleanly onto S3
//! (`ETag` + `If-Match` / `If-None-Match`), NFS (mtime + sidecar etag),
//! `WebDAV` (opaque lock tokens), and a future-reconsidered git transport
//! (commit hash + `force-with-lease`).
//!
//! Two implementors live alongside this trait:
//! - [`s3::S3Transport`] — the production impl (T3.3 / T3.4).
//! - `memory::MemoryTransport` — a test helper feature-gated behind
//!   `test-helpers` (T3.2; not exported at the public surface).
//!
//! [`IsPreconditionFailed`] is defined in [`crate::s3::error`] (where
//! [`crate::s3::S3Error`] also lives) to break what would otherwise be a
//! circular dependency between this module and the production impl; the
//! re-export here is the canonical path callers use.

#[cfg(any(test, feature = "test-helpers"))]
pub mod memory;
pub mod s3;

pub use crate::s3::error::IsPreconditionFailed;

/// Opaque, transport-defined version identifier for a remote object.
///
/// For [`s3::S3Transport`] this wraps the strong-ETag string a server
/// returned (already quote-stripped — see [`crate::s3::Etag`]); for a
/// Phase-4 `NfsTransport` it could wrap `(mtime, sha256)`; for `WebDAV`,
/// an opaque lock-token. The trait makes no assumption beyond:
///
/// - `==` defines version equality, and
/// - the transport is the sole interpreter of the inner bytes.
///
/// The orchestrator never inspects the inner string; it only compares
/// `ObjectVersion` values against the bookmark it persists in
/// `vaults.toml` (`last_synced_remote_etag`, design.md §2.3.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectVersion(
    /// The transport-defined version string.
    pub String,
);

/// A snapshot of the remote object: its bytes and the version they were at.
///
/// Returned by [`SyncTransport::fetch_if_changed`] when the remote has
/// advanced relative to the caller's `prev_version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectSnapshot {
    /// The transport's version identifier for these bytes.
    pub version: ObjectVersion,
    /// The raw remote bytes (an encrypted KDBX blob in the production path).
    pub bytes: Vec<u8>,
}

/// The transport-agnostic sync contract (FR-046; design.md §2.2.1).
///
/// **Implementor's promise:**
///
/// - [`head`](Self::head) is idempotent within a single instance and is
///   the cheapest way to learn the remote's current version (HEAD over
///   the wire for S3; no body transfer).
/// - [`fetch_if_changed`](Self::fetch_if_changed) given `Some(prev)` MUST
///   use a conditional-GET protocol primitive where one exists (S3:
///   `If-None-Match`) so that, when `prev` matches the remote's current
///   version, the method returns `Ok(None)` *without* transferring the
///   body. Given `None`, it MUST return the current snapshot
///   unconditionally — used by the orchestrator's merge-retry loop
///   after a 412 to fold in the new remote state.
/// - [`put_conditional`](Self::put_conditional) given `Some(prev)` MUST
///   be atomic compare-and-swap: succeed only if the remote's current
///   version equals `prev`; otherwise return an error for which
///   [`IsPreconditionFailed::is_precondition_failed`] returns `true`.
///   Given `None`, the PUT is unconditional — used only for the
///   first-ever upload to an empty key.
/// - All methods are blocking. The caller manages threading.
///
/// **Caller's promise:** single-threaded use of any given transport
/// instance. Two threads wishing to sync the same configured target must
/// either coordinate above this trait or hold separate instances.
///
/// The trait is deliberately *not* object-safe (the associated [`Error`](Self::Error)
/// type with its `IsPreconditionFailed` bound would force `Box<dyn …>`
/// gymnastics that aren't worth it). The orchestrator is generic over
/// `T: SyncTransport`; each impl picks its own error.
pub trait SyncTransport {
    /// Transport-specific error type. Mapped into [`crate::SyncError`] by
    /// the orchestrator via an `Into` bound. The
    /// [`IsPreconditionFailed`] bound lets the orchestrator branch on
    /// the retry-the-merge case without naming the concrete type.
    type Error: std::error::Error + Send + Sync + IsPreconditionFailed + 'static;

    /// HEAD the configured remote object: returns its current version, or
    /// `Ok(None)` when the object does not exist (first-ever sync to an
    /// empty location).
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] on network, auth, or protocol failure
    /// (anything other than 200 / 404 for an S3 backend).
    fn head(&mut self) -> Result<Option<ObjectVersion>, Self::Error>;

    /// GET the remote object iff its version differs from `prev_version`.
    ///
    /// When `prev_version` is `Some(v)` and the remote's current version
    /// equals `v`, returns `Ok(None)` — implementations MUST use a
    /// conditional-GET protocol primitive (S3: `If-None-Match`) so no
    /// body is transferred.
    ///
    /// When `prev_version` is `None`, returns the current snapshot
    /// unconditionally.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] on network, auth, or protocol failure.
    fn fetch_if_changed(
        &mut self,
        prev_version: Option<&ObjectVersion>,
    ) -> Result<Option<ObjectSnapshot>, Self::Error>;

    /// PUT `bytes` to the configured remote object.
    ///
    /// When `if_match` is `Some(v)`, succeeds only if the remote's current
    /// version equals `v`; otherwise returns an error for which
    /// [`IsPreconditionFailed::is_precondition_failed`] returns `true`.
    ///
    /// When `if_match` is `None`, the PUT is unconditional (used for the
    /// first-ever upload to an empty key).
    ///
    /// Returns the new [`ObjectVersion`] reported by the server.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] on network, auth, or protocol failure,
    /// including a precondition-failed variant
    /// (`is_precondition_failed() == true`) when `if_match` was supplied
    /// and the remote did not match.
    fn put_conditional(
        &mut self,
        bytes: &[u8],
        if_match: Option<&ObjectVersion>,
    ) -> Result<ObjectVersion, Self::Error>;
}
