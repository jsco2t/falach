// Same posture as `crate::s3::mod`: domain acronyms (KDBX, ETag, FR-046, etc.)
// dominate the doc comments here; backticking each one harms readability.
#![allow(clippy::doc_markdown)]

//! In-memory [`SyncTransport`] implementation for tests (T3.2).
//!
//! [`MemoryTransport`] is the test-only fixture US-043 (disjoint merge),
//! US-044 (collision merge), and US-046 (`SyncTransport` shape proof) drive
//! the merge engine through. It is ~50 LoC: one `Option<(ObjectVersion,
//! Vec<u8>)>` of remote state plus a monotonic counter that mints fresh
//! versions on every successful write.
//!
//! Feature-gated `test-helpers` so the type can be reused from integration
//! tests in sibling crates (e.g. `falach-cli` once Phase-5 wiring lands)
//! without leaking into production binaries.

use std::sync::atomic::{AtomicU64, Ordering};

use super::{ObjectSnapshot, ObjectVersion, SyncTransport};
use crate::s3::error::IsPreconditionFailed;

/// Errors returned by [`MemoryTransport`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MemoryTransportError {
    /// The remote object does not exist; surfaced by [`MemoryTransport::fetch_if_changed`]
    /// when called with `prev_version = None` against an empty transport.
    /// `head` itself returns `Ok(None)` for the same condition — this variant
    /// is only used when the caller asked unconditionally for a snapshot.
    #[error("memory transport: object not found")]
    NotFound,

    /// The conditional PUT's `if_match` did not match the current remote
    /// version. The trait's [`IsPreconditionFailed`] marker returns `true`
    /// for this variant; the orchestrator's retry loop catches it via the
    /// marker without naming the concrete enum.
    #[error("memory transport: precondition failed (concurrent write)")]
    PreconditionFailed,
}

impl IsPreconditionFailed for MemoryTransportError {
    fn is_precondition_failed(&self) -> bool {
        matches!(self, MemoryTransportError::PreconditionFailed)
    }
}

/// A named point in the orchestrator's merge sequence at which
/// [`MemoryTransport`] can deterministically panic, so the fault-injection
/// suite (T6.4) can assert the `.kdbx.bak` recovery invariant without
/// killing a real process.
///
/// The boundaries are expressed in terms of *which trait method the
/// orchestrator calls next*, because the orchestrator is generic over the
/// transport and drives every network step through these methods:
///
/// - [`FaultBoundary::AfterBakBeforeFetch`] — the orchestrator's `(true,
///   true)` merge path writes `.kdbx.bak` and then calls
///   [`SyncTransport::fetch_if_changed`]. Panicking at the *start* of
///   `fetch_if_changed` reproduces "process killed after the backup, before
///   any merge work": `.kdbx` is still the original, `.kdbx.bak` is its copy.
/// - [`FaultBoundary::AfterMergeBeforePut`] — after the merge + `vault.save`,
///   the orchestrator calls [`SyncTransport::put_conditional`]. Panicking at
///   the start of `put_conditional` reproduces "process killed after the
///   merged write, before the upload": `.kdbx` holds the merged state,
///   `.kdbx.bak` holds the pre-merge state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultBoundary {
    /// Panic when `fetch_if_changed` is next called.
    AfterBakBeforeFetch,
    /// Panic when `put_conditional` is next called.
    AfterMergeBeforePut,
}

/// In-memory [`SyncTransport`] for unit tests. Holds a single
/// `Option<(version, bytes)>` of remote state.
#[derive(Debug, Default)]
pub struct MemoryTransport {
    state: Option<(ObjectVersion, Vec<u8>)>,
    /// Monotonic counter that backs [`MemoryTransport::next_version`]; the
    /// resulting `ObjectVersion` is the counter's decimal string. Real S3
    /// ETags are hex-MD5; the test fixture only needs *some* string that
    /// changes monotonically.
    counter: AtomicU64,
    /// When set, panic at the named orchestrator boundary (T6.4).
    panic_after: Option<FaultBoundary>,
    /// When `true`, [`SyncTransport::head`] returns `Err(NotFound)` — which
    /// the orchestrator maps to [`crate::SyncError::RemoteUnreachable`].
    /// Lets US-045 drive the "remote unreachable" failure path without a
    /// network (the live-wire equivalent is MINIO-011's dead endpoint).
    fail_head: bool,
}

impl MemoryTransport {
    /// Construct an empty transport — `head()` returns `Ok(None)` until a
    /// `put_conditional(_, None)` seeds it.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Arrange for a panic at `boundary` the next time the orchestrator
    /// reaches it (T6.4 fault injection). See [`FaultBoundary`].
    pub fn set_panic_after(&mut self, boundary: FaultBoundary) {
        self.panic_after = Some(boundary);
    }

    /// Make [`SyncTransport::head`] fail with `NotFound` (→
    /// `SyncError::RemoteUnreachable`). Used by US-045.
    pub fn set_fail_head(&mut self, fail: bool) {
        self.fail_head = fail;
    }

    /// Mint a fresh version. Distinct from any prior return value within
    /// the same instance.
    fn next_version(&self) -> ObjectVersion {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        ObjectVersion(format!("memv-{n}"))
    }
}

impl SyncTransport for MemoryTransport {
    type Error = MemoryTransportError;

    fn head(&mut self) -> Result<Option<ObjectVersion>, Self::Error> {
        if self.fail_head {
            return Err(MemoryTransportError::NotFound);
        }
        Ok(self.state.as_ref().map(|(v, _)| v.clone()))
    }

    fn fetch_if_changed(
        &mut self,
        prev_version: Option<&ObjectVersion>,
    ) -> Result<Option<ObjectSnapshot>, Self::Error> {
        // Deliberate fault injection (T6.4), not an invariant check — a
        // `panic!` is the intent, so the manual-assert lint doesn't apply.
        #[allow(clippy::manual_assert)]
        if self.panic_after == Some(FaultBoundary::AfterBakBeforeFetch) {
            panic!("fault injection: AfterBakBeforeFetch");
        }
        match (&self.state, prev_version) {
            (None, _) => Err(MemoryTransportError::NotFound),
            (Some((current, _)), Some(prev)) if current == prev => Ok(None),
            (Some((current, bytes)), _) => Ok(Some(ObjectSnapshot {
                version: current.clone(),
                bytes: bytes.clone(),
            })),
        }
    }

    fn put_conditional(
        &mut self,
        bytes: &[u8],
        if_match: Option<&ObjectVersion>,
    ) -> Result<ObjectVersion, Self::Error> {
        // Deliberate fault injection (T6.4), not an invariant check.
        #[allow(clippy::manual_assert)]
        if self.panic_after == Some(FaultBoundary::AfterMergeBeforePut) {
            panic!("fault injection: AfterMergeBeforePut");
        }
        match (&self.state, if_match) {
            // `if_match = Some(_)` against an empty remote: there is no
            // current version to match, so the precondition cannot hold.
            (None, Some(_)) => Err(MemoryTransportError::PreconditionFailed),

            // Conditional path: succeed only if `if_match` matches current.
            (Some((current, _)), Some(prev)) if current != prev => {
                Err(MemoryTransportError::PreconditionFailed)
            }

            // Unconditional (first sync or explicit overwrite) or matched
            // conditional: install the new bytes + version.
            _ => {
                let new_version = self.next_version();
                self.state = Some((new_version.clone(), bytes.to_vec()));
                Ok(new_version)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- TC-MEM-001 ---------------------------------------------------------
    #[test]
    fn empty_transport_head_returns_none() {
        let mut t = MemoryTransport::new();
        assert_eq!(t.head().expect("head ok"), None);
    }

    // -- TC-MEM-002 ---------------------------------------------------------
    #[test]
    fn put_then_head_returns_version() {
        let mut t = MemoryTransport::new();
        let new_v = t
            .put_conditional(b"hello", None)
            .expect("first put succeeds");
        let head_v = t.head().expect("head ok").expect("some version after put");
        assert_eq!(head_v, new_v, "head returns the same version put returned");
    }

    // -- TC-MEM-003 ---------------------------------------------------------
    #[test]
    fn fetch_if_changed_with_matching_version_returns_none() {
        let mut t = MemoryTransport::new();
        let v = t.put_conditional(b"hello", None).expect("put");
        let result = t
            .fetch_if_changed(Some(&v))
            .expect("fetch with matching version is Ok");
        assert!(result.is_none(), "matching version → no snapshot transfer");
    }

    // -- TC-MEM-003b --------------------------------------------------------
    // Mirror of TC-MEM-003: when the caller's `prev_version` is stale the
    // transport DOES return the current snapshot. Without this case the
    // "matching → None" assertion above is half-tested.
    #[test]
    fn fetch_if_changed_with_stale_version_returns_snapshot() {
        let mut t = MemoryTransport::new();
        let v1 = t.put_conditional(b"v1", None).expect("put 1");
        let _v2 = t.put_conditional(b"v2", Some(&v1)).expect("put 2");
        let snapshot = t
            .fetch_if_changed(Some(&v1))
            .expect("fetch with stale version ok")
            .expect("stale version → snapshot present");
        assert_eq!(snapshot.bytes, b"v2");
    }

    // -- TC-MEM-004 ---------------------------------------------------------
    #[test]
    fn put_conditional_with_wrong_if_match_returns_precondition_failed() {
        let mut t = MemoryTransport::new();
        let _v = t.put_conditional(b"hello", None).expect("first put");
        let bogus = ObjectVersion("not-the-current-version".to_string());
        let err = t
            .put_conditional(b"world", Some(&bogus))
            .expect_err("bogus if-match must fail");
        assert!(matches!(err, MemoryTransportError::PreconditionFailed));
    }

    // -- TC-MEM-005 ---------------------------------------------------------
    #[test]
    fn put_conditional_with_none_overwrites_unconditionally() {
        let mut t = MemoryTransport::new();
        let v1 = t.put_conditional(b"v1", None).expect("first put");
        let v2 = t.put_conditional(b"v2", None).expect("overwrite");
        assert_ne!(v1, v2, "fresh version minted on every successful put");
        let head = t.head().expect("head").expect("some");
        assert_eq!(head, v2);
    }

    // -- TC-MEM-006 ---------------------------------------------------------
    #[test]
    fn is_precondition_failed_marker_implemented() {
        assert!(MemoryTransportError::PreconditionFailed.is_precondition_failed());
        assert!(!MemoryTransportError::NotFound.is_precondition_failed());
    }

    // -- TC-MEM-007 — set_fail_head drives the head() failure path ----------
    #[test]
    fn set_fail_head_makes_head_return_not_found() {
        let mut t = MemoryTransport::new();
        t.put_conditional(b"x", None).expect("seed");
        t.set_fail_head(true);
        let err = t.head().expect_err("fail_head must error");
        assert!(matches!(err, MemoryTransportError::NotFound));
    }

    // -- TC-MEM-008 — set_panic_after fires at the configured boundary ------
    #[test]
    fn set_panic_after_fetch_panics_on_fetch() {
        let caught = std::panic::catch_unwind(|| {
            let mut t = MemoryTransport::new();
            t.put_conditional(b"x", None).expect("seed");
            t.set_panic_after(FaultBoundary::AfterBakBeforeFetch);
            // This call must panic before touching state.
            let _ = t.fetch_if_changed(None);
        });
        assert!(
            caught.is_err(),
            "fetch_if_changed must panic at the boundary"
        );
    }
}
