//! S3-wire-protocol-level errors and the `IsPreconditionFailed` marker.
//!
//! [`S3Error`] is the error type returned by every method on [`crate::s3::Client`]
//! and will be propagated up by the production `SyncTransport` impl that
//! lands in T3.3 (`crate::transport::s3::S3Transport` — does not exist yet;
//! kept here as a plain code-span, not an intra-doc-link). It maps HTTP
//! status codes + transport failures into named variants so the
//! orchestrator (T5.2) can branch on the failure mode without parsing
//! human-readable strings.
//!
//! [`IsPreconditionFailed`] is a marker trait the orchestrator uses to detect
//! the conditional-PUT retry case without knowing the concrete transport
//! error type (design.md §2.2.1 / ADR-3). It is defined here — not in
//! [`crate::transport`] — to break the otherwise-circular dependency between
//! the trait module and the production impl. [`crate::transport`] re-exports
//! it once T3.1 lands.

use crate::s3::etag::EtagError;
use crate::s3::http::HttpError;
use crate::s3::signer::SignerError;

/// Marker trait for transport errors that distinguish the conditional-PUT
/// precondition-failed case (HTTP 412 for S3).
///
/// Used by the orchestrator's retry loop (T5.2) to decide whether a
/// failed PUT should trigger a re-fetch + remerge or be surfaced as a
/// fatal error.
pub trait IsPreconditionFailed {
    /// Return `true` iff this error indicates an atomic-compare-and-swap
    /// precondition failed (S3: 412 Precondition Failed on a PUT with
    /// `If-Match`).
    fn is_precondition_failed(&self) -> bool;
}

/// Errors at the S3 wire-protocol layer.
///
/// Variants name the failure mode (auth, not-found, precondition, transport,
/// etc.) so the orchestrator can branch on them. No variant ever carries
/// secret material — request bodies, signing keys, and credential values
/// stay out of the error payload.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum S3Error {
    /// HTTP 404 — the object (or, for HEAD on a missing bucket+key, the key)
    /// does not exist on the remote.
    #[error("S3 object not found")]
    NotFound,

    /// HTTP 403 — authentication or authorization failed. Could be wrong
    /// credentials, an expired session token, a bucket policy denial, or a
    /// signature that the server rejected. The orchestrator does not attempt
    /// to disambiguate these (no useful retry exists).
    #[error("S3 authentication or authorization failed (HTTP 403)")]
    AuthFailed,

    /// HTTP 412 — the conditional PUT's `If-Match` precondition did not
    /// match the remote's current ETag. The orchestrator's retry loop (T5.2)
    /// catches this via [`IsPreconditionFailed::is_precondition_failed`] and
    /// re-fetches + remerges before retrying the PUT.
    #[error("S3 conditional PUT precondition failed (HTTP 412); remote advanced concurrently")]
    PreconditionFailed,

    /// HTTP 5xx after the documented retry policy was exhausted. The
    /// orchestrator surfaces this to the caller with a "retry sync later"
    /// recommendation.
    #[error("S3 endpoint unreachable after retries: {reason}")]
    RemoteUnreachable {
        /// Non-secret human-readable reason. The orchestrator's [`crate::SyncError`]
        /// wraps this into a `RemoteUnreachable { endpoint, source }`.
        reason: String,
    },

    /// The conditional-PUT operation is required for safe sync semantics, but
    /// the backend silently accepted an `If-Match` header without enforcing
    /// it (detected via the T3.4 sentinel-key probe). Surfaced when the
    /// caller has explicitly requested the conditional path with
    /// degradation disabled.
    #[error("S3 backend does not enforce conditional PUT (`If-Match` accepted but ignored)")]
    ConditionalPutNotSupported,

    /// The degraded-PUT path's post-PUT HEAD-and-compare detected a concurrent
    /// writer: the just-uploaded object's ETag differs from the one we
    /// observed immediately after our own PUT. Used only when
    /// `IfMatchSupport::Degraded` is the cached state — the backend doesn't
    /// enforce `If-Match`, so we PUT unconditionally, HEAD, and compare;
    /// a mismatch means somebody else PUT between us and the HEAD.
    ///
    /// The orchestrator (T5.2) treats this identically to
    /// [`Self::PreconditionFailed`]: refetch, remerge, retry. The two are
    /// kept distinct so the operator-facing error message can name the
    /// actual mechanism that detected the race.
    #[error("S3 concurrent write detected on degraded backend (post-PUT HEAD ETag mismatch)")]
    ConcurrentWriteDetected,

    /// The server returned a weak ETag (`W/"..."`) where a strong ETag was
    /// expected. Conditional-PUT semantics require strong ETags; we cannot
    /// safely treat a weak ETag as a version identifier.
    #[error("S3 returned a weak ETag where a strong ETag is required")]
    WeakEtag,

    /// Malformed ETag header (missing quotes, non-hex content where MD5-hex
    /// expected, etc.). Wraps [`EtagError`] for context.
    #[error("S3 returned a malformed ETag: {0}")]
    MalformedEtag(#[from] EtagError),

    /// SigV4 signing produced an error before the request could be sent.
    /// Examples: invalid region string, credentials with non-UTF-8 bytes,
    /// pathological header values.
    #[error("S3 request signing failed: {0}")]
    Signer(#[from] SignerError),

    /// Underlying HTTP-layer error (connection refused, DNS, TLS handshake,
    /// I/O timeout, etc.). Wraps [`HttpError`] for context.
    #[error("S3 HTTP transport error: {0}")]
    Http(#[from] HttpError),

    /// An unexpected response was received that doesn't map to any of the
    /// other variants. The variant carries the HTTP status and a short
    /// non-secret diagnostic; the response body is NOT included (it may
    /// contain object contents or other sensitive material).
    #[error("S3 returned unexpected status {status}: {reason}")]
    Unexpected {
        /// The HTTP status code that was received.
        status: u16,
        /// Short non-secret description of the unexpected condition.
        reason: String,
    },
}

impl IsPreconditionFailed for S3Error {
    fn is_precondition_failed(&self) -> bool {
        // Both variants describe "the remote advanced concurrently between
        // our last view and our write" and trigger the same orchestrator
        // response (refetch, remerge, retry). They are kept distinct in the
        // enum so the operator-facing message can name the actual detection
        // mechanism (412 vs. degraded HEAD-and-compare).
        matches!(
            self,
            S3Error::PreconditionFailed | S3Error::ConcurrentWriteDetected
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- TC-ERR-001 ---------------------------------------------------------
    #[test]
    fn precondition_failed_marker_returns_true_for_retry_signaling_variants() {
        // Both 412 (Supported backend) and degraded-path race (Degraded
        // backend) tell the orchestrator to refetch + remerge + retry.
        assert!(S3Error::PreconditionFailed.is_precondition_failed());
        assert!(S3Error::ConcurrentWriteDetected.is_precondition_failed());

        // Everything else is a hard failure — no retry available.
        assert!(!S3Error::NotFound.is_precondition_failed());
        assert!(!S3Error::AuthFailed.is_precondition_failed());
        assert!(!S3Error::WeakEtag.is_precondition_failed());
        assert!(!S3Error::ConditionalPutNotSupported.is_precondition_failed());
    }

    // -- TC-ERR-002 ---------------------------------------------------------
    // Display messages never carry secret material. Spot-check the
    // structurally-rich variants.
    #[test]
    fn display_messages_carry_no_secrets() {
        let unexpected = S3Error::Unexpected {
            status: 418,
            reason: "i am a teapot".to_string(),
        };
        let formatted = format!("{unexpected}");
        assert!(formatted.contains("418"));
        assert!(formatted.contains("teapot"));

        let unreachable = S3Error::RemoteUnreachable {
            reason: "dial tcp: connection refused".to_string(),
        };
        let formatted = format!("{unreachable}");
        assert!(formatted.contains("connection refused"));
    }
}
