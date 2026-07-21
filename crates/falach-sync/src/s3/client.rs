//! High-level S3 client (design.md §2.2.3) — composes signer + HTTP +
//! endpoint into the four operations the transport needs:
//! `head_object`, `get_object`, `put_object`, `delete_object`.
//!
//! Maps HTTP status codes to [`crate::s3::S3Error`] variants. Implements
//! the documented 503 single-retry policy (one retry after 500ms; if the
//! second response is also 503, surface `RemoteUnreachable`).

use std::thread;
use std::time::{Duration, SystemTime};

use crate::s3::endpoint::EndpointBuilder;
use crate::s3::error::S3Error;
use crate::s3::etag::Etag;
use crate::s3::http::{HttpBackend, HttpResponse};
use crate::s3::signer::{ResolvedCredentials, Signer};

/// Pluggable S3-protocol-level backend. The production impl is [`Client`];
/// tests use an in-process mock that injects canned responses without
/// going through the signer + HTTP layers.
///
/// **Visibility:** `pub` (re-exported from [`crate::s3`]) — same posture
/// as [`crate::s3::HttpBackend`]; consumers outside `falach-sync` are
/// not expected to implement it. T3.x may retighten to `pub(crate)`
/// once the orchestrator is in place.
pub trait S3ClientBackend {
    /// HEAD the named object. `Ok(HeadResult)` on 200; standard error
    /// mappings (404 → `NotFound`, 403 → `AuthFailed`, etc.) otherwise.
    ///
    /// # Errors
    /// Returns [`S3Error`] for any non-200 response or transport failure.
    fn head_object(&self, bucket: &str, key: &str) -> Result<HeadResult, S3Error>;

    /// GET the named object. When `if_none_match` is `Some`, sets the
    /// header and translates a 304 response to `GetResult::NotModified`.
    ///
    /// # Errors
    /// Returns [`S3Error`] for any non-200/304 response or transport failure.
    fn get_object(
        &self,
        bucket: &str,
        key: &str,
        if_none_match: Option<&str>,
    ) -> Result<GetResult, S3Error>;

    /// PUT `bytes` at the named object key. When `if_match` is `Some`,
    /// sets the conditional header and translates 412 to
    /// `S3Error::PreconditionFailed`. Sets `x-amz-content-sha256` to the
    /// hex-SHA256 of `bytes` (already done by the signer; this method
    /// surfaces it explicitly for documentation).
    ///
    /// # Errors
    /// Returns [`S3Error`] for any non-200 response or transport failure.
    fn put_object(
        &self,
        bucket: &str,
        key: &str,
        bytes: &[u8],
        if_match: Option<&str>,
    ) -> Result<PutResult, S3Error>;

    /// DELETE the named object. `Ok(())` on 204 (or 200, depending on
    /// backend); `Err(S3Error::NotFound)` on 404.
    ///
    /// # Errors
    /// Returns [`S3Error`] for any non-204/200 response or transport failure.
    fn delete_object(&self, bucket: &str, key: &str) -> Result<(), S3Error>;
}

/// The result of a HEAD request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadResult {
    /// The object's current ETag.
    pub etag: Etag,
}

/// The result of a conditional GET.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetResult {
    /// `If-None-Match` matched the remote's current ETag — no body
    /// transferred. HTTP 304.
    NotModified,
    /// The object was fetched. HTTP 200.
    Body {
        /// The object's current ETag.
        etag: Etag,
        /// The object's bytes.
        body: Vec<u8>,
    },
}

/// The result of a PUT request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutResult {
    /// The ETag the server reported for the just-written object.
    pub etag: Etag,
}

/// Production S3 client wrapping a signer + an HTTP backend + an endpoint
/// builder.
///
/// Generic over the HTTP backend so tests can substitute
/// `MockHttpClient`. Production wires `HttpClient` (the `ureq` impl).
pub struct Client<H: HttpBackend> {
    http: H,
    signer: Signer,
    endpoint: EndpointBuilder,
    credentials: ResolvedCredentials,
    /// Delay between 503 retries. Production: 500ms. Tests inject 0 for
    /// determinism without flakiness.
    retry_delay: Duration,
}

impl<H: HttpBackend> Client<H> {
    /// Build a client from its constituent parts.
    pub fn new(
        http: H,
        signer: Signer,
        endpoint: EndpointBuilder,
        credentials: ResolvedCredentials,
    ) -> Self {
        Self {
            http,
            signer,
            endpoint,
            credentials,
            retry_delay: Duration::from_millis(500),
        }
    }

    /// Same as [`Self::new`] but with a custom retry delay (used by tests
    /// to keep them fast).
    #[doc(hidden)]
    pub fn with_retry_delay(
        http: H,
        signer: Signer,
        endpoint: EndpointBuilder,
        credentials: ResolvedCredentials,
        retry_delay: Duration,
    ) -> Self {
        Self {
            http,
            signer,
            endpoint,
            credentials,
            retry_delay,
        }
    }

    /// Send a single signed request, with a single 503 retry after
    /// [`Self::retry_delay`]. Used by every public method below.
    fn signed_request(
        &self,
        method: &str,
        url: &str,
        host: &str,
        path: &str,
        extra_headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse, S3Error> {
        let mut attempts = 0u8;
        loop {
            attempts += 1;
            // Build headers fresh on each attempt — the previous attempt's
            // Authorization is tied to its specific timestamp.
            let mut headers = Vec::with_capacity(extra_headers.len() + 4);
            headers.push(("host".to_string(), host.to_string()));
            if !body.is_empty() {
                headers.push(("content-length".to_string(), body.len().to_string()));
            }
            for (k, v) in extra_headers {
                headers.push((k.clone(), v.clone()));
            }

            self.signer
                .sign(
                    method,
                    path,
                    &[],
                    &mut headers,
                    body,
                    &self.credentials,
                    SystemTime::now(),
                )
                .map_err(S3Error::from)?;

            let response = self.http.request(method, url, &headers, body)?;
            if response.status == 503 && attempts == 1 {
                thread::sleep(self.retry_delay);
                continue;
            }
            return Ok(response);
        }
    }
}

impl<H: HttpBackend> S3ClientBackend for Client<H> {
    fn head_object(&self, bucket: &str, key: &str) -> Result<HeadResult, S3Error> {
        let url = self.endpoint.object_url(bucket, key);
        let host = self.endpoint.host_header(bucket);
        let path = path_for_request(&self.endpoint, bucket, key);

        let response = self.signed_request("HEAD", &url, &host, &path, &[], b"")?;
        match response.status {
            200 => {
                let etag = parse_etag(&response)?;
                Ok(HeadResult { etag })
            }
            404 => Err(S3Error::NotFound),
            403 => Err(S3Error::AuthFailed),
            503 => Err(remote_unreachable_after_retry()),
            status => Err(unexpected_status("HEAD", status)),
        }
    }

    fn get_object(
        &self,
        bucket: &str,
        key: &str,
        if_none_match: Option<&str>,
    ) -> Result<GetResult, S3Error> {
        let url = self.endpoint.object_url(bucket, key);
        let host = self.endpoint.host_header(bucket);
        let path = path_for_request(&self.endpoint, bucket, key);

        let mut extra = Vec::new();
        if let Some(etag) = if_none_match {
            extra.push(("if-none-match".to_string(), quote_etag(etag)));
        }

        let response = self.signed_request("GET", &url, &host, &path, &extra, b"")?;
        match response.status {
            200 => {
                let etag = parse_etag(&response)?;
                Ok(GetResult::Body {
                    etag,
                    body: response.body,
                })
            }
            304 => Ok(GetResult::NotModified),
            404 => Err(S3Error::NotFound),
            403 => Err(S3Error::AuthFailed),
            503 => Err(remote_unreachable_after_retry()),
            status => Err(unexpected_status("GET", status)),
        }
    }

    fn put_object(
        &self,
        bucket: &str,
        key: &str,
        bytes: &[u8],
        if_match: Option<&str>,
    ) -> Result<PutResult, S3Error> {
        let url = self.endpoint.object_url(bucket, key);
        let host = self.endpoint.host_header(bucket);
        let path = path_for_request(&self.endpoint, bucket, key);

        let mut extra = vec![(
            "content-type".to_string(),
            "application/octet-stream".to_string(),
        )];
        if let Some(etag) = if_match {
            extra.push(("if-match".to_string(), quote_etag(etag)));
        }

        let response = self.signed_request("PUT", &url, &host, &path, &extra, bytes)?;
        match response.status {
            200 => {
                let etag = parse_etag(&response)?;
                Ok(PutResult { etag })
            }
            412 => Err(S3Error::PreconditionFailed),
            403 => Err(S3Error::AuthFailed),
            404 => Err(S3Error::NotFound),
            503 => Err(remote_unreachable_after_retry()),
            status => Err(unexpected_status("PUT", status)),
        }
    }

    fn delete_object(&self, bucket: &str, key: &str) -> Result<(), S3Error> {
        let url = self.endpoint.object_url(bucket, key);
        let host = self.endpoint.host_header(bucket);
        let path = path_for_request(&self.endpoint, bucket, key);

        let response = self.signed_request("DELETE", &url, &host, &path, &[], b"")?;
        match response.status {
            200 | 204 => Ok(()),
            404 => Err(S3Error::NotFound),
            403 => Err(S3Error::AuthFailed),
            503 => Err(remote_unreachable_after_retry()),
            status => Err(unexpected_status("DELETE", status)),
        }
    }
}

/// The `S3Error` returned when a 5xx persists after the documented
/// single retry. Extracted as a helper so the same Display string lives
/// in exactly one place — a future "include retry count in the message"
/// extension only edits here.
fn remote_unreachable_after_retry() -> S3Error {
    S3Error::RemoteUnreachable {
        reason: "S3 503 Service Unavailable after retry".to_string(),
    }
}

/// The `S3Error::Unexpected` returned when a status code falls through
/// every named match arm. Extracted so the message format is uniform
/// across the four operations.
fn unexpected_status(method: &str, status: u16) -> S3Error {
    S3Error::Unexpected {
        status,
        reason: format!("{method} returned {status}"),
    }
}

/// Build the URI-path portion used by SigV4 canonical-request building.
/// For virtual-hosted addressing the path is just `/{key}`; for path-style
/// it's `/{bucket}/{key}`.
fn path_for_request(endpoint: &EndpointBuilder, bucket: &str, key: &str) -> String {
    let key = key.trim_start_matches('/');
    match endpoint.style {
        crate::s3::endpoint::AddressingStyle::VirtualHosted => format!("/{key}"),
        crate::s3::endpoint::AddressingStyle::PathStyle => format!("/{bucket}/{key}"),
    }
}

/// Parse the `ETag` response header into an [`Etag`].
fn parse_etag(response: &HttpResponse) -> Result<Etag, S3Error> {
    let raw = response.header("etag").ok_or_else(|| S3Error::Unexpected {
        status: response.status,
        reason: "response missing ETag header".to_string(),
    })?;
    Etag::parse(raw).map_err(S3Error::from)
}

/// Ensure the ETag is in quoted form for `If-Match` / `If-None-Match`
/// headers. Callers may pass either the raw inner form (`"abc123"` →
/// `abc123`) or already-quoted; we always emit quoted.
fn quote_etag(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        trimmed.to_string()
    } else {
        format!("\"{trimmed}\"")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s3::endpoint::EndpointConfig;
    use crate::s3::http::HttpResponse;
    use crate::s3::testing::MockHttpClient;

    fn test_credentials() -> ResolvedCredentials {
        ResolvedCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: None,
        }
    }

    fn build_client(mock: MockHttpClient) -> Client<MockHttpClient> {
        let endpoint = EndpointBuilder::from_config(&EndpointConfig {
            endpoint: Some("https://s3.us-east-1.amazonaws.com"),
            region: "us-east-1",
            bucket: "my-bucket",
            force_path_style: false,
        })
        .expect("endpoint build");
        Client::with_retry_delay(
            mock,
            Signer::new("us-east-1".to_string()),
            endpoint,
            test_credentials(),
            // Zero retry delay so 503-retry tests don't block.
            Duration::from_millis(0),
        )
    }

    fn ok_response(status: u16, etag: Option<&str>, body: &[u8]) -> HttpResponse {
        let mut headers = Vec::new();
        if let Some(e) = etag {
            headers.push(("etag".to_string(), format!("\"{e}\"")));
        }
        HttpResponse {
            status,
            headers,
            body: body.to_vec(),
        }
    }

    // -- TC-CLIENT-001 ------------------------------------------------------
    #[test]
    fn head_object_returns_etag_on_200() {
        let mock = MockHttpClient::new(vec![Ok(ok_response(200, Some("deadbeef"), &[]))]);
        let client = build_client(mock);
        let result = client
            .head_object("my-bucket", "work.kdbx")
            .expect("HEAD ok");
        assert_eq!(result.etag.as_str(), "deadbeef");
    }

    // -- TC-CLIENT-002 ------------------------------------------------------
    #[test]
    fn head_object_maps_404_to_not_found() {
        let mock = MockHttpClient::new(vec![Ok(ok_response(404, None, &[]))]);
        let client = build_client(mock);
        let err = client
            .head_object("my-bucket", "work.kdbx")
            .expect_err("404 returns error");
        assert!(matches!(err, S3Error::NotFound));
    }

    // -- TC-CLIENT-003 ------------------------------------------------------
    #[test]
    fn head_object_maps_403_to_auth_failed() {
        let mock = MockHttpClient::new(vec![Ok(ok_response(403, None, &[]))]);
        let client = build_client(mock);
        let err = client
            .head_object("my-bucket", "k")
            .expect_err("403 returns error");
        assert!(matches!(err, S3Error::AuthFailed));
    }

    // -- TC-CLIENT-004 ------------------------------------------------------
    #[test]
    fn get_object_returns_body_on_200() {
        let mock = MockHttpClient::new(vec![Ok(ok_response(200, Some("v1"), b"hello"))]);
        let client = build_client(mock);
        let result = client.get_object("my-bucket", "k", None).expect("GET ok");
        match result {
            GetResult::Body { etag, body } => {
                assert_eq!(etag.as_str(), "v1");
                assert_eq!(body, b"hello");
            }
            GetResult::NotModified => panic!("expected Body, got NotModified"),
        }
    }

    // -- TC-CLIENT-005 ------------------------------------------------------
    #[test]
    fn get_object_returns_not_modified_on_304() {
        let mock = MockHttpClient::new(vec![Ok(ok_response(304, None, &[]))]);
        let client = build_client(mock);
        let result = client
            .get_object("my-bucket", "k", Some("v1"))
            .expect("GET ok");
        assert!(matches!(result, GetResult::NotModified));
    }

    // -- TC-CLIENT-006 ------------------------------------------------------
    #[test]
    fn get_object_sends_if_none_match_header() {
        let mock = MockHttpClient::new(vec![Ok(ok_response(304, None, &[]))]);
        let client = build_client(mock);
        let _ = client
            .get_object("my-bucket", "k", Some("abc"))
            .expect("GET ok");

        let calls = client.http.requests.borrow();
        assert_eq!(calls.len(), 1);
        let hdrs = &calls[0].2;
        let if_none_match = hdrs
            .iter()
            .find(|(n, _)| n == "if-none-match")
            .map(|(_, v)| v.as_str());
        assert_eq!(if_none_match, Some("\"abc\""));
    }

    // -- TC-CLIENT-007 ------------------------------------------------------
    #[test]
    fn put_object_maps_412_to_precondition_failed() {
        let mock = MockHttpClient::new(vec![Ok(ok_response(412, None, &[]))]);
        let client = build_client(mock);
        let err = client
            .put_object("my-bucket", "k", b"body", Some("old-etag"))
            .expect_err("412 returns error");
        assert!(matches!(err, S3Error::PreconditionFailed));
    }

    // -- TC-CLIENT-008 ------------------------------------------------------
    #[test]
    fn put_object_sends_if_match_and_content_type_headers() {
        let mock = MockHttpClient::new(vec![Ok(ok_response(200, Some("new-v"), &[]))]);
        let client = build_client(mock);
        let _ = client
            .put_object("my-bucket", "k", b"body", Some("old-etag"))
            .expect("PUT ok");

        let calls = client.http.requests.borrow();
        let hdrs = &calls[0].2;
        assert!(hdrs
            .iter()
            .any(|(n, v)| n == "if-match" && v == "\"old-etag\""));
        assert!(hdrs
            .iter()
            .any(|(n, v)| n == "content-type" && v == "application/octet-stream"));
        // Signer adds x-amz-content-sha256 — verify it's present.
        assert!(hdrs.iter().any(|(n, _)| n == "x-amz-content-sha256"));
    }

    // -- TC-CLIENT-009 ------------------------------------------------------
    #[test]
    fn delete_object_accepts_204_and_200() {
        let mock = MockHttpClient::new(vec![Ok(ok_response(204, None, &[]))]);
        let client = build_client(mock);
        assert!(client.delete_object("my-bucket", "k").is_ok());

        let mock = MockHttpClient::new(vec![Ok(ok_response(200, None, &[]))]);
        let client = build_client(mock);
        assert!(client.delete_object("my-bucket", "k").is_ok());
    }

    // -- TC-CLIENT-010 ------------------------------------------------------
    #[test]
    fn five_oh_three_retries_once_then_succeeds() {
        let mock = MockHttpClient::new(vec![
            Ok(ok_response(503, None, &[])),
            Ok(ok_response(200, Some("v1"), &[])),
        ]);
        let client = build_client(mock);
        let result = client
            .head_object("my-bucket", "k")
            .expect("retry succeeds");
        assert_eq!(result.etag.as_str(), "v1");

        let calls = client.http.requests.borrow();
        assert_eq!(calls.len(), 2, "expected one retry");
    }

    // -- TC-CLIENT-011 ------------------------------------------------------
    #[test]
    fn five_oh_three_twice_surfaces_remote_unreachable() {
        let mock = MockHttpClient::new(vec![
            Ok(ok_response(503, None, &[])),
            Ok(ok_response(503, None, &[])),
        ]);
        let client = build_client(mock);
        let err = client
            .head_object("my-bucket", "k")
            .expect_err("two 503s exhaust retry");
        assert!(matches!(err, S3Error::RemoteUnreachable { .. }));
    }

    // -- TC-CLIENT-012 ------------------------------------------------------
    #[test]
    fn missing_etag_on_200_is_unexpected_error() {
        let mock = MockHttpClient::new(vec![Ok(ok_response(200, None, b"body"))]);
        let client = build_client(mock);
        let err = client
            .get_object("my-bucket", "k", None)
            .expect_err("missing ETag header is an error");
        match err {
            S3Error::Unexpected { status, reason } => {
                assert_eq!(status, 200);
                assert!(reason.contains("ETag"));
            }
            _ => panic!("expected Unexpected, got {err:?}"),
        }
    }

    // -- TC-CLIENT-013 ------------------------------------------------------
    #[test]
    fn quote_etag_idempotent_for_already_quoted_input() {
        assert_eq!(quote_etag("\"abc\""), "\"abc\"");
        assert_eq!(quote_etag("abc"), "\"abc\"");
        // Whitespace stripped.
        assert_eq!(quote_etag("  abc  "), "\"abc\"");
    }
}
