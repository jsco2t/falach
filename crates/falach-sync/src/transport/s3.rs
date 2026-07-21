// Same posture as `crate::s3::mod`: domain acronyms (S3, AWS, ETag, SigV4,
// MinIO, KDBX, ADR-n, etc.) dominate the doc comments here; backticking
// every one degrades readability without catching real intra-doc-link
// bugs.
#![allow(clippy::doc_markdown)]

//! [`S3Transport`] — the production [`SyncTransport`] impl over the S3 wire
//! protocol (design.md §2.2.2; tasks T3.3 + T3.4).
//!
//! Translates the four trait methods into the corresponding
//! [`crate::s3::Client`] calls and caches the most-recent ETag in
//! [`S3Transport::cached_remote_version`].
//!
//! Generic over `B: S3ClientBackend` so unit tests can substitute a
//! `MockS3Client` (see `crate::s3::testing`); the production wiring
//! uses `crate::s3::Client<crate::s3::HttpClient>`.
//!
//! **What this module owns vs. the rest of the stack:**
//!
//! - Trait-shape adapter: maps `S3Error::NotFound` (HEAD 404) to
//!   `Ok(None)` and `S3Error::PreconditionFailed` (PUT 412) to a
//!   [`crate::s3::S3Error::PreconditionFailed`] whose [`IsPreconditionFailed`]
//!   marker is `true` — the orchestrator's retry path keys off the
//!   marker, not the concrete variant.
//! - Per-call ETag cache (`cached_remote_version`): the most-recent
//!   version observed by ANY of HEAD / GET / PUT, used as an in-process
//!   optimization. NOT the orchestrator's persistent sync bookmark —
//!   that lives in `SyncConfig::last_synced_remote_etag` (T5.1).
//!
//! What this module does *not* own:
//!
//! - The wire-level retry policy for 503s (lives in [`crate::s3::Client`]).
//! - The merge engine (lives in [`crate::merge`]).
//! - The four-state truth table (lives in the orchestrator, T5.2).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{IsPreconditionFailed, ObjectSnapshot, ObjectVersion, SyncTransport};
use crate::config::IfMatchSupport;
use crate::s3::client::{GetResult, S3ClientBackend};
use crate::s3::error::S3Error;

/// The literal `If-Match` value the sentinel-key probe sends. A fake-but-
/// well-formed 32-char hex string — unambiguously distinct from any real
/// MD5-shaped ETag a server could legitimately return (the probability of
/// the bucket's sentinel key happening to have this exact ETag is 2^-128;
/// the value comes from `follow-ups/open-items.md` OQ-8 resolution).
///
/// Empty-string `""` was rejected as alternative because RFC 7232 leaves
/// it undefined and some backends short-circuit on it before reaching the
/// conditional-PUT logic.
const PROBE_IF_MATCH: &str = "00000000000000000000000000000000";

/// Production [`SyncTransport`] over the S3 wire protocol.
///
/// Generic over the backend so tests inject a `MockS3Client` and production
/// uses [`crate::s3::Client`].
///
/// **Phase 3 mechanics:** T3.3 lands the basic four trait methods; T3.4
/// adds the sentinel-key probe and degraded-PUT path so the FR-047
/// graceful-degradation requirement holds against backends that silently
/// accept `If-Match` without enforcing it.
pub struct S3Transport<B: S3ClientBackend> {
    backend: B,
    bucket: String,
    key: String,
    /// The most-recent ETag observed by any of `head` / `fetch_if_changed`
    /// / `put_conditional`. In-process optimization only — the orchestrator
    /// holds the persistent bookmark in [`crate::config::SyncConfig`].
    cached_remote_version: Option<ObjectVersion>,
    /// In-memory copy of the per-backend `If-Match` enforcement
    /// classification. Initialized from [`crate::config::S3Config::if_match_supported`]
    /// at construction; updated by the probe; persisted back to
    /// `vaults.toml` via [`Self::on_if_match_change`] when set.
    if_match_supported: IfMatchSupport,
    /// Called whenever the transport classifies the backend via the probe,
    /// so the persistent `vaults.toml` cache can be updated. `None` is
    /// acceptable for tests that don't care about persistence.
    on_if_match_change: Option<Box<dyn Fn(IfMatchSupport)>>,
}

impl<B: S3ClientBackend> S3Transport<B> {
    /// Construct a transport over an [`S3ClientBackend`].
    ///
    /// Production callers pass [`crate::s3::Client`]; tests pass a
    /// `MockS3Client`. The `bucket` / `key` pair selects the single
    /// object this transport syncs against; a different vault uses a
    /// different `S3Transport` instance.
    ///
    /// Defaults `if_match_supported` to [`IfMatchSupport::Unknown`]: the
    /// first conditional PUT will run the sentinel-key probe before the
    /// real PUT. Production callers wishing to seed the classification
    /// from a `vaults.toml`-persisted value go through
    /// [`Self::with_if_match_state`].
    pub fn new(backend: B, bucket: String, key: String) -> Self {
        Self {
            backend,
            bucket,
            key,
            cached_remote_version: None,
            if_match_supported: IfMatchSupport::Unknown,
            on_if_match_change: None,
        }
    }

    /// Same as [`Self::new`] but seeds the `If-Match` classification +
    /// the persist-callback. The orchestrator constructs the transport
    /// this way so the probe runs at most once per backend across
    /// process restarts (the result is persisted to `vaults.toml`).
    pub fn with_if_match_state(
        backend: B,
        bucket: String,
        key: String,
        if_match_supported: IfMatchSupport,
        on_if_match_change: Box<dyn Fn(IfMatchSupport)>,
    ) -> Self {
        Self {
            backend,
            bucket,
            key,
            cached_remote_version: None,
            if_match_supported,
            on_if_match_change: Some(on_if_match_change),
        }
    }

    /// Returns the most-recent ETag this transport observed. Used by the
    /// transport's own internal flow (and exposed for testing); the
    /// orchestrator does not consume it.
    #[must_use]
    pub fn cached_remote_version(&self) -> Option<&ObjectVersion> {
        self.cached_remote_version.as_ref()
    }

    /// The current in-memory `If-Match` classification.
    #[must_use]
    pub fn if_match_supported(&self) -> IfMatchSupport {
        self.if_match_supported
    }

    fn set_cached_version(&mut self, version: ObjectVersion) {
        self.cached_remote_version = Some(version);
    }

    fn record_if_match_classification(&mut self, support: IfMatchSupport) {
        self.if_match_supported = support;
        if let Some(cb) = &self.on_if_match_change {
            cb(support);
        }
    }

    /// Run the sentinel-key probe. Per design.md ADR-5:
    ///
    /// 1. PUT a probe object at `<key>.falach-probe-<random-6-char-suffix>`
    ///    with a deliberately-bogus `If-Match` value.
    /// 2. Observe the response:
    ///    - The backend *rejected* the bogus precondition → it enforces
    ///      `If-Match` → record [`IfMatchSupport::Supported`]. Because the
    ///      probe key does not yet exist, an enforcing backend cannot match
    ///      the (bogus) ETag, so the rejection arrives as either `412
    ///      Precondition Failed` (AWS S3) *or* `404 No Such Key` (MinIO and
    ///      other backends that evaluate object existence first). Both are
    ///      "the precondition was enforced", so both map to `Supported`.
    ///      (Verified against MinIO `RELEASE.2025-09-07` by MINIO-006.)
    ///    - 2xx (a successful PUT) → backend silently accepted the bogus
    ///      header and created the object → record [`IfMatchSupport::Degraded`].
    ///    - any other error (auth, malformed, 5xx) → probe inconclusive;
    ///      leave the cache as `Unknown` and proceed.
    /// 3. DELETE the probe object regardless of the PUT outcome
    ///    (best-effort cleanup; orphan acceptable per the design's
    ///    operator-guide note).
    ///
    /// The probe is "best-effort": its own failures do NOT propagate to
    /// the caller — they leave the cache in `Unknown` so the next sync
    /// re-probes. Documented as part of the FR-047 graceful-degradation
    /// contract.
    fn probe_if_match_support(&mut self) {
        let probe_key = format!("{}.falach-probe-{}", self.key, probe_suffix());

        let probe_result = self.backend.put_object(
            &self.bucket,
            &probe_key,
            b"falach-probe",
            Some(PROBE_IF_MATCH),
        );

        let classification = match &probe_result {
            // Backend rejected the bogus precondition → it enforces If-Match.
            // 412 = AWS S3; 404 = MinIO et al. (object-existence checked
            // first). Both mean "Supported". See the doc comment + MINIO-006.
            Err(S3Error::PreconditionFailed | S3Error::NotFound) => Some(IfMatchSupport::Supported),
            // Backend silently accepted the bogus header and created the
            // object → it does NOT enforce If-Match.
            Ok(_) => Some(IfMatchSupport::Degraded),
            // Anything else (auth, malformed, 5xx) → inconclusive; leave
            // Unknown so the next sync re-probes.
            Err(_other) => None,
        };

        // Best-effort cleanup. We deliberately swallow any error here:
        // - If the PUT succeeded (Degraded path) the orphan-on-delete-fail
        //   case is documented in the operator guide.
        // - If the PUT failed (Supported path or inconclusive) the probe
        //   object likely does not exist; a 404 from DELETE is harmless.
        let _ = self.backend.delete_object(&self.bucket, &probe_key);

        if let Some(c) = classification {
            self.record_if_match_classification(c);
        }
    }
}

/// Mint a fresh 6-character probe-key suffix from the lowercase-alnum
/// alphabet. Uses wall-clock nanoseconds XOR'd with a process-local atomic
/// counter — uniqueness within the bucket is best-effort cleanup, not
/// crypto: collisions are tolerable (the orphan-cleanup is best-effort
/// regardless, and the next probe mints a new suffix).
fn probe_suffix() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    const ALPHABET: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    // `subsec_nanos()` is u32 — plenty of entropy when XOR'd with the
    // process-local counter, and side-steps the `u128 as u64` truncation
    // clippy lint that the full `as_nanos()` value would trigger.
    let nanos = u64::from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos()),
    );
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut seed = nanos
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(counter);
    let mut out = String::with_capacity(6);
    for _ in 0..6 {
        out.push(ALPHABET[(seed % 36) as usize] as char);
        seed /= 36;
    }
    out
}

impl<B: S3ClientBackend> SyncTransport for S3Transport<B> {
    type Error = S3Error;

    fn head(&mut self) -> Result<Option<ObjectVersion>, Self::Error> {
        match self.backend.head_object(&self.bucket, &self.key) {
            Ok(head) => {
                let version = ObjectVersion(head.etag.as_str().to_string());
                self.set_cached_version(version.clone());
                Ok(Some(version))
            }
            Err(S3Error::NotFound) => {
                // The remote is empty; do not pollute the cache with a stale
                // version from a prior call.
                self.cached_remote_version = None;
                Ok(None)
            }
            Err(other) => Err(other),
        }
    }

    fn fetch_if_changed(
        &mut self,
        prev_version: Option<&ObjectVersion>,
    ) -> Result<Option<ObjectSnapshot>, Self::Error> {
        let if_none_match = prev_version.map(|v| v.0.as_str());
        match self
            .backend
            .get_object(&self.bucket, &self.key, if_none_match)?
        {
            GetResult::NotModified => Ok(None),
            GetResult::Body { etag, body } => {
                let version = ObjectVersion(etag.as_str().to_string());
                self.set_cached_version(version.clone());
                Ok(Some(ObjectSnapshot {
                    version,
                    bytes: body,
                }))
            }
        }
    }

    fn put_conditional(
        &mut self,
        bytes: &[u8],
        if_match: Option<&ObjectVersion>,
    ) -> Result<ObjectVersion, Self::Error> {
        // Unconditional PUT (first-ever sync to an empty key): never
        // exercises the conditional path, so the probe + degraded paths
        // do not apply.
        let Some(prev) = if_match else {
            let put = self
                .backend
                .put_object(&self.bucket, &self.key, bytes, None)?;
            let new_version = ObjectVersion(put.etag.as_str().to_string());
            self.set_cached_version(new_version.clone());
            return Ok(new_version);
        };

        // Conditional path. If the backend's `If-Match` enforcement is
        // unknown, run the probe before the real PUT — even on probe
        // failure we proceed (the cache stays `Unknown` and the next
        // sync re-probes).
        if self.if_match_supported == IfMatchSupport::Unknown {
            self.probe_if_match_support();
        }

        match self.if_match_supported {
            // `Unknown` means the probe itself was inconclusive. Treat as
            // Supported for the immediate PUT (the worst case is a
            // backend that ignores `If-Match`, and the orchestrator's
            // post-PUT divergence check + `.kdbx.bak` still bound the
            // data-loss exposure). The next sync re-probes.
            IfMatchSupport::Supported | IfMatchSupport::Unknown => {
                let put = self.backend.put_object(
                    &self.bucket,
                    &self.key,
                    bytes,
                    Some(prev.0.as_str()),
                )?;
                let new_version = ObjectVersion(put.etag.as_str().to_string());
                self.set_cached_version(new_version.clone());
                Ok(new_version)
            }
            // Degraded path: the backend silently ignores `If-Match`, so
            // we have to PUT unconditionally and then HEAD + ETag-compare
            // to detect any racing writer. A mismatch surfaces as
            // [`S3Error::ConcurrentWriteDetected`], whose
            // [`IsPreconditionFailed`] marker is `true` — the
            // orchestrator's retry loop treats this identically to a 412
            // (refetch, remerge, retry). `.kdbx.bak` is the safety net
            // for the small race window the design accepts.
            IfMatchSupport::Degraded => {
                let put = self
                    .backend
                    .put_object(&self.bucket, &self.key, bytes, None)?;
                let put_etag = put.etag.as_str().to_string();
                let head = self.backend.head_object(&self.bucket, &self.key)?;
                if head.etag.as_str() != put_etag {
                    return Err(S3Error::ConcurrentWriteDetected);
                }
                let new_version = ObjectVersion(put_etag);
                self.set_cached_version(new_version.clone());
                Ok(new_version)
            }
        }
    }
}

// Make the type usable from `IsPreconditionFailed` consumers without the
// caller importing `crate::s3::S3Error` directly. Compile-time-only
// assertion that `S3Error: IsPreconditionFailed` (would fail to compile
// if the bound were violated by a future refactor).
const _: fn() = || {
    fn assert_marker<T: IsPreconditionFailed>() {}
    assert_marker::<S3Error>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s3::client::{HeadResult, PutResult};
    use crate::s3::etag::Etag;
    use crate::s3::testing::{MockS3Client, MockS3Request, MockS3Response};

    fn etag(s: &str) -> Etag {
        Etag(s.to_string())
    }

    /// Build a transport with `if_match_supported` pre-seeded to
    /// [`IfMatchSupport::Supported`] — i.e., the probe has already run
    /// for this backend (or never needs to). The T3.3 happy-path tests
    /// below use this to focus on the basic four-method shape; the T3.4
    /// probe tests use [`build_with_probe`] instead.
    fn transport(mock: MockS3Client) -> S3Transport<MockS3Client> {
        S3Transport::with_if_match_state(
            mock,
            "my-bucket".to_string(),
            "work.kdbx".to_string(),
            IfMatchSupport::Supported,
            Box::new(|_| {}),
        )
    }

    // -- TC-S3T-001 ---------------------------------------------------------
    #[test]
    fn head_returns_some_for_existing_object() {
        let mock = MockS3Client::new(vec![MockS3Response::Head(Ok(HeadResult {
            etag: etag("v1"),
        }))]);
        let mut t = transport(mock);
        let result = t.head().expect("head ok");
        assert_eq!(result, Some(ObjectVersion("v1".to_string())));
        assert_eq!(
            t.cached_remote_version(),
            Some(&ObjectVersion("v1".to_string())),
            "successful head populates the cache"
        );
    }

    // -- TC-S3T-002 ---------------------------------------------------------
    #[test]
    fn head_returns_none_for_missing_object() {
        let mock = MockS3Client::new(vec![MockS3Response::Head(Err(S3Error::NotFound))]);
        let mut t = transport(mock);
        let result = t.head().expect("head ok");
        assert_eq!(result, None);
        assert!(
            t.cached_remote_version().is_none(),
            "404 must NOT populate the cache"
        );
    }

    // -- TC-S3T-003 ---------------------------------------------------------
    #[test]
    fn fetch_if_changed_returns_none_on_304() {
        let mock = MockS3Client::new(vec![MockS3Response::Get(Ok(GetResult::NotModified))]);
        let mut t = transport(mock);
        let prev = ObjectVersion("v1".to_string());
        let result = t.fetch_if_changed(Some(&prev)).expect("fetch ok");
        assert!(result.is_none(), "304 NotModified → no snapshot");
    }

    // -- TC-S3T-004 ---------------------------------------------------------
    #[test]
    fn fetch_if_changed_returns_snapshot_on_changed() {
        let mock = MockS3Client::new(vec![MockS3Response::Get(Ok(GetResult::Body {
            etag: etag("v2"),
            body: b"new bytes".to_vec(),
        }))]);
        let mut t = transport(mock);
        let prev = ObjectVersion("v1".to_string());
        let snapshot = t
            .fetch_if_changed(Some(&prev))
            .expect("fetch ok")
            .expect("changed → snapshot");
        assert_eq!(snapshot.version.0, "v2");
        assert_eq!(snapshot.bytes, b"new bytes");
        assert_eq!(
            t.cached_remote_version().map(|v| v.0.as_str()),
            Some("v2"),
            "fetch populates the cache with the new version"
        );

        // The outgoing request must carry If-None-Match.
        let calls = t.backend.requests.borrow();
        let MockS3Request::Get { if_none_match, .. } = &calls[0] else {
            panic!("expected Get request, got {:?}", calls[0]);
        };
        assert_eq!(if_none_match.as_deref(), Some("v1"));
    }

    // -- TC-S3T-005 ---------------------------------------------------------
    #[test]
    fn fetch_if_changed_with_none_issues_unconditional_get() {
        let mock = MockS3Client::new(vec![MockS3Response::Get(Ok(GetResult::Body {
            etag: etag("v1"),
            body: b"bytes".to_vec(),
        }))]);
        let mut t = transport(mock);
        let snapshot = t
            .fetch_if_changed(None)
            .expect("fetch ok")
            .expect("snapshot");
        assert_eq!(snapshot.version.0, "v1");

        let calls = t.backend.requests.borrow();
        let MockS3Request::Get { if_none_match, .. } = &calls[0] else {
            panic!("expected Get request, got {:?}", calls[0]);
        };
        assert!(
            if_none_match.is_none(),
            "None prev_version → no If-None-Match header"
        );
    }

    // -- TC-S3T-006 ---------------------------------------------------------
    #[test]
    fn put_conditional_succeeds_with_if_match() {
        let mock = MockS3Client::new(vec![MockS3Response::Put(Ok(PutResult {
            etag: etag("v2"),
        }))]);
        let mut t = transport(mock);
        let prev = ObjectVersion("v1".to_string());
        let new_version = t
            .put_conditional(b"body", Some(&prev))
            .expect("PUT succeeds");
        assert_eq!(new_version.0, "v2");
        assert_eq!(
            t.cached_remote_version().map(|v| v.0.as_str()),
            Some("v2"),
            "successful PUT populates the cache with the new ETag"
        );

        let calls = t.backend.requests.borrow();
        let MockS3Request::Put {
            if_match,
            body,
            bucket,
            key,
        } = &calls[0]
        else {
            panic!("expected Put request, got {:?}", calls[0]);
        };
        assert_eq!(if_match.as_deref(), Some("v1"));
        assert_eq!(body, b"body");
        assert_eq!(bucket, "my-bucket");
        assert_eq!(key, "work.kdbx");
    }

    // -- TC-S3T-007 ---------------------------------------------------------
    #[test]
    fn put_conditional_precondition_failed_propagates() {
        let mock = MockS3Client::new(vec![MockS3Response::Put(Err(S3Error::PreconditionFailed))]);
        let mut t = transport(mock);
        let prev = ObjectVersion("v1".to_string());
        let err = t
            .put_conditional(b"body", Some(&prev))
            .expect_err("PUT should fail");
        assert!(err.is_precondition_failed());
    }

    // -- TC-S3T-007b --------------------------------------------------------
    // Mirror of TC-S3T-006: `if_match = None` issues an unconditional PUT.
    // Without this case the orchestrator's first-ever-sync path is untested
    // at the transport boundary.
    #[test]
    fn put_conditional_with_none_issues_unconditional_put() {
        let mock = MockS3Client::new(vec![MockS3Response::Put(Ok(PutResult {
            etag: etag("v1"),
        }))]);
        let mut t = transport(mock);
        let _ = t.put_conditional(b"body", None).expect("PUT ok");
        let calls = t.backend.requests.borrow();
        let MockS3Request::Put { if_match, .. } = &calls[0] else {
            panic!("expected Put");
        };
        assert!(
            if_match.is_none(),
            "None if_match → no If-Match header on the outgoing request"
        );
    }

    // -- Probe + degraded-path tests (T3.4) ---------------------------------

    /// Per-test builder: construct an `S3Transport` with a probe-classification
    /// callback that records the latest value into a shared cell. The cell
    /// lets each test assert what (if anything) was persisted by the probe.
    fn build_with_probe(
        mock: MockS3Client,
    ) -> (
        S3Transport<MockS3Client>,
        std::rc::Rc<std::cell::RefCell<Option<IfMatchSupport>>>,
    ) {
        let cell = std::rc::Rc::new(std::cell::RefCell::new(None::<IfMatchSupport>));
        let cell_for_cb = std::rc::Rc::clone(&cell);
        let t = S3Transport::with_if_match_state(
            mock,
            "my-bucket".to_string(),
            "work.kdbx".to_string(),
            IfMatchSupport::Unknown,
            Box::new(move |s| {
                *cell_for_cb.borrow_mut() = Some(s);
            }),
        );
        (t, cell)
    }

    // -- TC-S3T-008 ---------------------------------------------------------
    // Unknown backend + conditional PUT runs the probe before the real
    // PUT. Sequence-assert: PUT probe → DELETE probe → PUT real.
    #[test]
    fn put_conditional_runs_sentinel_probe_on_unknown_backend() {
        let mock = MockS3Client::new(vec![
            // Probe PUT: 412 → Supported classification.
            MockS3Response::Put(Err(S3Error::PreconditionFailed)),
            // Probe DELETE: success cleanup.
            MockS3Response::Delete(Ok(())),
            // Real PUT: succeeds.
            MockS3Response::Put(Ok(PutResult { etag: etag("v2") })),
        ]);
        let (mut t, _cell) = build_with_probe(mock);
        let prev = ObjectVersion("v1".to_string());
        let _ = t
            .put_conditional(b"real body", Some(&prev))
            .expect("real PUT ok");

        let calls = t.backend.requests.borrow();
        assert_eq!(
            calls.len(),
            3,
            "expected probe-PUT + probe-DELETE + real-PUT"
        );

        // Call 1: probe PUT to `<key>.falach-probe-<...>` with bogus
        // If-Match.
        let MockS3Request::Put {
            key: probe_put_key,
            if_match: probe_if_match,
            body: probe_body,
            ..
        } = &calls[0]
        else {
            panic!("call 0 should be a PUT, got {:?}", calls[0]);
        };
        assert!(
            probe_put_key.starts_with("work.kdbx.falach-probe-"),
            "probe key should be derived from configured key, got {probe_put_key}"
        );
        assert_eq!(probe_if_match.as_deref(), Some(PROBE_IF_MATCH));
        assert!(!probe_body.is_empty(), "probe PUT carries a sentinel body");

        // Call 2: probe DELETE for the same key. The DELETE must run
        // regardless of the probe PUT outcome — see R-T3.4-A.
        let MockS3Request::Delete {
            key: probe_del_key, ..
        } = &calls[1]
        else {
            panic!("call 1 should be a DELETE, got {:?}", calls[1]);
        };
        assert_eq!(
            probe_del_key, probe_put_key,
            "probe DELETE targets the same key"
        );

        // Call 3: real PUT to `work.kdbx` with the caller's If-Match.
        let MockS3Request::Put {
            key: real_key,
            if_match: real_if_match,
            body: real_body,
            ..
        } = &calls[2]
        else {
            panic!("call 2 should be the real PUT, got {:?}", calls[2]);
        };
        assert_eq!(real_key, "work.kdbx");
        assert_eq!(real_if_match.as_deref(), Some("v1"));
        assert_eq!(real_body, b"real body");
    }

    // -- TC-S3T-009 ---------------------------------------------------------
    #[test]
    fn probe_412_response_transitions_to_supported_and_caches() {
        let mock = MockS3Client::new(vec![
            MockS3Response::Put(Err(S3Error::PreconditionFailed)),
            MockS3Response::Delete(Ok(())),
            MockS3Response::Put(Ok(PutResult { etag: etag("v2") })),
        ]);
        let (mut t, cell) = build_with_probe(mock);
        let prev = ObjectVersion("v1".to_string());
        let _ = t.put_conditional(b"body", Some(&prev)).expect("PUT ok");

        assert_eq!(t.if_match_supported(), IfMatchSupport::Supported);
        assert_eq!(*cell.borrow(), Some(IfMatchSupport::Supported));
    }

    // -- TC-S3T-009b --------------------------------------------------------
    // A backend that returns 404 (not 412) when the bogus If-Match cannot
    // match the absent probe key is STILL enforcing the precondition →
    // Supported. This mirrors MinIO's live behaviour (MINIO-006): an
    // enforcing backend that checks object existence first rejects with
    // NoSuchKey rather than PreconditionFailed.
    #[test]
    fn probe_404_response_also_transitions_to_supported() {
        let mock = MockS3Client::new(vec![
            // Probe PUT: 404 NoSuchKey → enforcing backend → Supported.
            MockS3Response::Put(Err(S3Error::NotFound)),
            MockS3Response::Delete(Ok(())),
            // Real PUT succeeds.
            MockS3Response::Put(Ok(PutResult { etag: etag("v2") })),
        ]);
        let (mut t, cell) = build_with_probe(mock);
        let prev = ObjectVersion("v1".to_string());
        let _ = t.put_conditional(b"body", Some(&prev)).expect("PUT ok");
        assert_eq!(t.if_match_supported(), IfMatchSupport::Supported);
        assert_eq!(*cell.borrow(), Some(IfMatchSupport::Supported));
    }

    // -- TC-S3T-010 ---------------------------------------------------------
    #[test]
    fn probe_200_response_transitions_to_degraded_and_caches() {
        let mock = MockS3Client::new(vec![
            // Probe PUT: 200 silent-accept → Degraded.
            MockS3Response::Put(Ok(PutResult {
                etag: etag("probe-v1"),
            })),
            MockS3Response::Delete(Ok(())),
            // Real PUT on Degraded path is unconditional, then HEAD.
            MockS3Response::Put(Ok(PutResult { etag: etag("v2") })),
            MockS3Response::Head(Ok(HeadResult { etag: etag("v2") })),
        ]);
        let (mut t, cell) = build_with_probe(mock);
        let prev = ObjectVersion("v1".to_string());
        let _ = t.put_conditional(b"body", Some(&prev)).expect("PUT ok");

        assert_eq!(t.if_match_supported(), IfMatchSupport::Degraded);
        assert_eq!(*cell.borrow(), Some(IfMatchSupport::Degraded));
    }

    // -- TC-S3T-010b --------------------------------------------------------
    // Probe DELETE failure does NOT prevent classification or the real
    // PUT — DELETE is best-effort cleanup per ADR-5.
    #[test]
    fn probe_delete_failure_is_swallowed() {
        let mock = MockS3Client::new(vec![
            MockS3Response::Put(Err(S3Error::PreconditionFailed)),
            // DELETE fails — orphan probe object left behind; tolerated.
            MockS3Response::Delete(Err(S3Error::Unexpected {
                status: 500,
                reason: "delete failed".to_string(),
            })),
            // Real PUT still happens and succeeds.
            MockS3Response::Put(Ok(PutResult { etag: etag("v2") })),
        ]);
        let (mut t, _) = build_with_probe(mock);
        let prev = ObjectVersion("v1".to_string());
        let _ = t
            .put_conditional(b"body", Some(&prev))
            .expect("real PUT still succeeds despite DELETE failure");
        assert_eq!(t.if_match_supported(), IfMatchSupport::Supported);
    }

    // -- TC-S3T-011 ---------------------------------------------------------
    // Degraded backend: real PUT is unconditional + post-PUT HEAD + ETag
    // compare. Matching ETag → Ok.
    #[test]
    fn put_conditional_uses_degraded_path_on_degraded_backend() {
        let mock = MockS3Client::new(vec![
            // No probe — `if_match_supported` is seeded to Degraded.
            MockS3Response::Put(Ok(PutResult { etag: etag("v2") })),
            MockS3Response::Head(Ok(HeadResult { etag: etag("v2") })),
        ]);
        let cell = std::rc::Rc::new(std::cell::RefCell::new(None::<IfMatchSupport>));
        let cell_for_cb = std::rc::Rc::clone(&cell);
        let mut t = S3Transport::with_if_match_state(
            mock,
            "my-bucket".to_string(),
            "work.kdbx".to_string(),
            IfMatchSupport::Degraded,
            Box::new(move |s| *cell_for_cb.borrow_mut() = Some(s)),
        );

        let prev = ObjectVersion("v1".to_string());
        let new_v = t.put_conditional(b"body", Some(&prev)).expect("PUT ok");
        assert_eq!(new_v.0, "v2");

        let calls = t.backend.requests.borrow();
        assert_eq!(calls.len(), 2, "Degraded path is one PUT + one HEAD");
        let MockS3Request::Put { if_match, .. } = &calls[0] else {
            panic!("expected PUT");
        };
        assert!(
            if_match.is_none(),
            "Degraded backend → real PUT carries NO If-Match header"
        );
        assert!(matches!(calls[1], MockS3Request::Head { .. }));
    }

    // -- TC-S3T-011b --------------------------------------------------------
    // Mirror of TC-S3T-011: post-PUT HEAD reveals a different ETag → race
    // detected → `ConcurrentWriteDetected`; marker says retry.
    #[test]
    fn degraded_path_detects_concurrent_write_via_etag_mismatch() {
        let mock = MockS3Client::new(vec![
            MockS3Response::Put(Ok(PutResult { etag: etag("v2") })),
            // Someone else wrote between our PUT and our HEAD — ETag
            // differs from what we just got back from the PUT.
            MockS3Response::Head(Ok(HeadResult { etag: etag("v3") })),
        ]);
        let mut t = S3Transport::with_if_match_state(
            mock,
            "my-bucket".to_string(),
            "work.kdbx".to_string(),
            IfMatchSupport::Degraded,
            Box::new(|_| {}),
        );
        let prev = ObjectVersion("v1".to_string());
        let err = t
            .put_conditional(b"body", Some(&prev))
            .expect_err("HEAD/PUT mismatch must surface an error");
        assert!(matches!(err, S3Error::ConcurrentWriteDetected));
        assert!(
            err.is_precondition_failed(),
            "ConcurrentWriteDetected must trigger the orchestrator retry path"
        );
    }

    // -- TC-S3T-015 ---------------------------------------------------------
    #[test]
    fn cached_remote_version_updates_on_successful_put() {
        let mock = MockS3Client::new(vec![MockS3Response::Put(Ok(PutResult {
            etag: etag("v2"),
        }))]);
        let mut t = transport(mock);
        assert!(t.cached_remote_version().is_none());
        let prev = ObjectVersion("v1".to_string());
        let _ = t.put_conditional(b"body", Some(&prev)).expect("ok");
        assert_eq!(
            t.cached_remote_version().map(|v| v.0.as_str()),
            Some("v2"),
            "successful PUT updates the in-process ETag cache"
        );
    }

    // -- TC-S3T-016 ---------------------------------------------------------
    // The marker assertion is in `s3::error::tests`
    // (`precondition_failed_marker_returns_true_for_retry_signaling_variants`) —
    // re-checked here at the transport layer so a refactor that drops the
    // marker impl from the error type fails loudly at THIS test boundary,
    // not buried in the error suite.
    #[test]
    fn is_precondition_failed_marker_drives_orchestrator_retry() {
        let pf: S3Error = S3Error::PreconditionFailed;
        let cw: S3Error = S3Error::ConcurrentWriteDetected;
        let other: S3Error = S3Error::NotFound;
        assert!(pf.is_precondition_failed());
        assert!(cw.is_precondition_failed());
        assert!(!other.is_precondition_failed());
    }
}
