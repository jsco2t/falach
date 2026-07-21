//! HTTP transport layer over `ureq` (design.md §2.2.5 / ADR-1).
//!
//! Thin wrapper around `ureq::Agent` configured for our TLS posture:
//! rustls with the ring provider, OS trust store via
//! `rustls-platform-verifier` (so no `webpki-roots` MPL dep).
//!
//! Exposes a minimal `(method, url, headers, body) -> response` surface
//! and a `HttpBackend` trait so the higher-level [`crate::s3::Client`] can
//! be tested against a `MockHttpClient` without any real I/O.

use std::time::Duration;

/// Upper bound on the wall-clock duration of a single S3 request,
/// end-to-end (DNS → connect → TLS → send → receive body).
///
/// **Why this exists (FU-SYNC-TIMEOUT):** the TUI's deferred-auto-lock
/// model (tui-skeleton design ADR-T4a) holds off an idle-fired lock until
/// the in-flight `sync_now` returns — the shipped `sync_now` has no cancel
/// hook. With no network timeout, a hung S3 connection would keep the
/// master key resident in memory **unbounded**, defeating FR-073's
/// auto-lock posture. A bounded global timeout caps that worst case.
///
/// **Honest limit (CLAUDE.md principle #5):** this bounds *per request*,
/// not the whole `sync_now` call — a sync may issue a small, bounded
/// number of requests (GET + conditional PUT, plus a HEAD on the
/// ETag-compare fallback path), so the residual zeroize-lag after an
/// idle-lock fires is at most a small multiple of this value, never
/// unbounded. A true `sync_now` cancellation hook (FU-SYNC-CANCEL) is a
/// separate, post-MVP enhancement.
///
/// The value is deliberately generous (tens of seconds) so slow links
/// don't see spurious sync failures; tune if real-world use shows it's
/// too tight or too loose.
const NETWORK_TIMEOUT: Duration = Duration::from_secs(60);

/// Upper bound on a response body read.
///
/// `ureq`'s bare `read_to_vec()` defaults to a 10 MiB cap — smaller than
/// a legal vault (attachments are a first-class entry type; the per-file
/// cap is 100 MiB, `falach_core::MAX_ATTACHMENT_BYTES_UPPER_BOUND`), so
/// a vault that PUT fine from one device could never be GET on another.
/// Sized to hold a maxed-out attachment plus generous vault overhead
/// while still bounding a malicious/misconfigured endpoint's response
/// (memory-exhaustion defense).
const MAX_RESPONSE_BODY_BYTES: u64 = 256 * 1024 * 1024;

/// HTTP-layer errors. These cover everything below the S3 protocol —
/// connection, DNS, TLS handshake, I/O timeout, malformed response — but
/// NOT HTTP status codes (4xx/5xx are returned as `Ok(HttpResponse)` with
/// `status` set; the caller decides whether they're errors).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HttpError {
    /// The URL could not be parsed by the HTTP client.
    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    /// A network-layer failure (connection refused, timeout, DNS, TLS handshake).
    #[error("network I/O failed: {0}")]
    Io(String),

    /// The HTTP request was successfully sent but the response could not
    /// be read in full (truncated body, decoding error, etc.).
    #[error("HTTP response read failed: {0}")]
    ResponseRead(String),

    /// `ureq::Agent` construction failed at the TLS-config stage.
    /// Surfaces only at `HttpClient::new`.
    #[error("HTTP client configuration failed: {0}")]
    Config(String),

    /// A non-network failure raised by `ureq` that doesn't map to any
    /// other variant. Carries the underlying error's `Display`
    /// representation only — never any response body.
    #[error("HTTP transport error: {0}")]
    Other(String),
}

/// One HTTP response: status, headers, and body.
///
/// Status is `u16` (not `http::StatusCode`) to avoid pulling the `http`
/// crate just for status decoding; the s3::Client matches on raw codes
/// (200/304/403/404/412/503/etc.).
///
/// Headers are stored as `Vec<(String, String)>` not `HashMap` because
/// S3 responses can contain multiple headers with the same name in
/// principle (though in practice we only care about `ETag`,
/// `Content-Length`, and a few `x-amz-*` ones, all of which are
/// single-valued in S3's responses).
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Headers received from the server. Header names are normalized to
    /// lowercase for consistent lookup.
    pub headers: Vec<(String, String)>,
    /// Response body bytes. For HEAD this is always empty (`ureq` returns
    /// an empty body even though one is technically allowed).
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Look up the first value for the given header name, case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(&lower))
            .map(|(_, v)| v.as_str())
    }
}

/// Pluggable HTTP backend trait. The production implementation is
/// [`HttpClient`] (over `ureq`); test code uses an in-tree mock that
/// records calls + injects canned responses.
///
/// **Visibility:** `pub` (re-exported from [`crate::s3`]) so the
/// [`crate::s3::Client`] generic bound `Client<H: HttpBackend>` resolves
/// in callers' generic-parameter slots, but `s3/mod.rs` documents that
/// nothing outside `falach-sync` should depend on `crate::s3::*`
/// directly. The trait is effectively internal-with-leaks; T3.x may
/// retighten to `pub(crate)` once the orchestrator is in place and the
/// generic bound moves entirely inside the crate.
pub trait HttpBackend {
    /// Send a single HTTP request. Returns the response on any HTTP
    /// status (4xx/5xx are `Ok` with `status` set); returns `Err` only
    /// for transport-layer failures (network, TLS, malformed URL).
    ///
    /// # Errors
    ///
    /// Returns [`HttpError`] on transport-layer failures.
    fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse, HttpError>;
}

/// Production HTTP client wrapping `ureq::Agent` configured with rustls
/// + platform-verifier.
pub struct HttpClient {
    agent: ureq::Agent,
}

impl HttpClient {
    /// Build a new HTTP client with the given User-Agent string
    /// (design.md ADR-7: `falach-sync/<crate-version>`).
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::Config`] when `ureq`'s TLS-config builder
    /// fails (in practice unreachable for our pinned 3.3.0).
    pub fn new(user_agent: &str) -> Result<Self, HttpError> {
        let tls_config = ureq::tls::TlsConfig::builder()
            .provider(ureq::tls::TlsProvider::Rustls)
            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
            .build();

        let agent = ureq::Agent::config_builder()
            .tls_config(tls_config)
            .user_agent(user_agent)
            .timeout_global(Some(NETWORK_TIMEOUT))
            .build()
            .new_agent();

        Ok(Self { agent })
    }
}

impl HttpBackend for HttpClient {
    fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse, HttpError> {
        // ureq 3.x exposes verb-specific builders rather than a generic
        // `request(method, url)`. Split bodyless verbs (GET/HEAD/DELETE)
        // from bodied ones (PUT/POST) so we can match the builder's
        // type-state (`WithoutBody` vs `WithBody`).
        let method_upper = method.to_ascii_uppercase();
        let response_result = match method_upper.as_str() {
            "GET" => {
                let mut req = self.agent.get(url);
                for (n, v) in headers {
                    req = req.header(n, v);
                }
                req.call()
            }
            "HEAD" => {
                let mut req = self.agent.head(url);
                for (n, v) in headers {
                    req = req.header(n, v);
                }
                req.call()
            }
            "DELETE" => {
                let mut req = self.agent.delete(url);
                for (n, v) in headers {
                    req = req.header(n, v);
                }
                req.call()
            }
            "PUT" => {
                let mut req = self.agent.put(url);
                for (n, v) in headers {
                    req = req.header(n, v);
                }
                if body.is_empty() {
                    req.send_empty()
                } else {
                    req.send(body)
                }
            }
            "POST" => {
                let mut req = self.agent.post(url);
                for (n, v) in headers {
                    req = req.header(n, v);
                }
                if body.is_empty() {
                    req.send_empty()
                } else {
                    req.send(body)
                }
            }
            other => {
                return Err(HttpError::InvalidUrl(format!(
                    "unsupported HTTP method: {other}"
                )));
            }
        };

        let mut response = match response_result {
            Ok(r) => r,
            Err(ureq::Error::StatusCode(code)) => {
                // ureq 3.x returns 4xx/5xx as `StatusCode` errors when the
                // default `http_status_as_error` config is on. The
                // higher-level s3::Client only branches on the code for
                // 4xx/5xx (response bodies on errors are XML diagnostics
                // we don't parse), so synthesize a body-less response.
                return Ok(HttpResponse {
                    status: code,
                    headers: Vec::new(),
                    body: Vec::new(),
                });
            }
            Err(ref e) => return Err(map_ureq_error(e)),
        };

        let status = response.status().as_u16();
        let response_headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.as_str().to_ascii_lowercase(), v.to_string()))
            })
            .collect();

        let body_bytes = response
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BODY_BYTES)
            .read_to_vec()
            .map_err(|e| HttpError::ResponseRead(e.to_string()))?;

        Ok(HttpResponse {
            status,
            headers: response_headers,
            body: body_bytes,
        })
    }
}

/// Map a `ureq::Error` into the appropriate `HttpError` variant. Keeps
/// the error-message conversions in one place.
fn map_ureq_error(e: &ureq::Error) -> HttpError {
    let message = e.to_string();
    match e {
        ureq::Error::BadUri(_) => HttpError::InvalidUrl(message),
        ureq::Error::Io(_)
        | ureq::Error::Timeout(_)
        | ureq::Error::HostNotFound
        | ureq::Error::ConnectionFailed => HttpError::Io(message),
        _ => HttpError::Other(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s3::testing::MockHttpClient;

    // -- TC-HTTP-001 --------------------------------------------------------
    #[test]
    fn http_client_constructs_with_platform_verifier_tls_config() {
        // Smoke test: the constructor doesn't panic and returns Ok. The
        // deeper guarantee — that webpki-roots is NOT in the dep tree —
        // is verified at T2.1 via `cargo tree | grep webpki`.
        let client = HttpClient::new("falach-sync/0.1.0");
        assert!(client.is_ok());
    }

    // -- TC-HTTP-001b (FU-SYNC-TIMEOUT) -------------------------------------
    #[test]
    fn http_client_agent_is_built_with_bounded_global_timeout() {
        // Regression guard for PMF-3 / FU-SYNC-TIMEOUT: the agent must carry
        // a bounded global network timeout so a hung sync cannot keep the
        // master key resident unbounded under the TUI's deferred-auto-lock
        // model (ADR-T4a). This fails if `.timeout_global(..)` is dropped
        // from the builder chain.
        let client = HttpClient::new("falach-sync/0.1.0").expect("client constructs");
        let configured = client.agent.config().timeouts().global;
        assert_eq!(
            configured,
            Some(NETWORK_TIMEOUT),
            "S3 agent must be built with the bounded NETWORK_TIMEOUT"
        );
    }

    // -- TC-HTTP-002 --------------------------------------------------------
    #[test]
    fn http_response_header_lookup_is_case_insensitive() {
        let response = HttpResponse {
            status: 200,
            headers: vec![
                ("etag".to_string(), "\"abc\"".to_string()),
                ("Content-Length".to_string(), "42".to_string()),
            ],
            body: Vec::new(),
        };
        assert_eq!(response.header("ETag"), Some("\"abc\""));
        assert_eq!(response.header("etag"), Some("\"abc\""));
        assert_eq!(response.header("content-length"), Some("42"));
        assert_eq!(response.header("Missing"), None);
    }

    // -- TC-HTTP-003 --------------------------------------------------------
    #[test]
    fn mock_http_client_records_calls_and_returns_canned_responses() {
        let canned = HttpResponse {
            status: 200,
            headers: vec![("etag".to_string(), "\"deadbeef\"".to_string())],
            body: b"hello".to_vec(),
        };
        let mock = MockHttpClient::new(vec![Ok(canned)]);

        let result = mock
            .request(
                "GET",
                "https://example.com/key",
                &[("authorization".to_string(), "sigv4...".to_string())],
                b"",
            )
            .expect("mock returns Ok");
        assert_eq!(result.status, 200);
        assert_eq!(result.body, b"hello");

        let calls = mock.requests.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "GET");
        assert_eq!(calls[0].1, "https://example.com/key");
        assert_eq!(calls[0].2[0].0, "authorization");
    }
}
