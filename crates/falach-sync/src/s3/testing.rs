//! Shared test helpers for the s3 wire-protocol layer.
//!
//! The contents are only compiled for `#[cfg(test)]` and are
//! `pub(crate)` — never appear on the public surface. Hoisted out of
//! the individual module test blocks so we don't carry two divergent
//! copies of [`MockHttpClient`] (one in `s3::http::tests`, one in
//! `s3::client::tests`).

#![cfg(test)]

use std::cell::RefCell;

use crate::s3::client::{GetResult, HeadResult, PutResult, S3ClientBackend};
use crate::s3::error::S3Error;
use crate::s3::http::{HttpBackend, HttpError, HttpResponse};

/// One recorded HTTP request: `(method, url, headers, body)`. Aliased
/// to keep `clippy::type_complexity` happy and make the purpose obvious
/// at call sites.
pub(crate) type RecordedRequest = (String, String, Vec<(String, String)>, Vec<u8>);

/// In-process mock [`HttpBackend`]. Records every call in `requests`
/// (publicly readable by tests) and returns canned responses from
/// `responses` in **FIFO order** — `MockHttpClient::new(vec![r1, r2])`
/// returns `r1` on the first call, `r2` on the second.
///
/// Implementation detail: internal storage is a `Vec` popped via
/// `Vec::pop`, so the constructor reverses the caller-supplied list to
/// make FIFO the actual behaviour. This makes the FIFO contract a
/// single-source-of-truth assertion verified by the multi-response
/// tests below.
pub(crate) struct MockHttpClient {
    responses: RefCell<Vec<Result<HttpResponse, HttpError>>>,
    pub(crate) requests: RefCell<Vec<RecordedRequest>>,
}

impl MockHttpClient {
    /// Construct a mock that returns the given responses in FIFO order.
    pub(crate) fn new(responses: Vec<Result<HttpResponse, HttpError>>) -> Self {
        let mut reversed = responses;
        reversed.reverse();
        Self {
            responses: RefCell::new(reversed),
            requests: RefCell::new(Vec::new()),
        }
    }
}

impl HttpBackend for MockHttpClient {
    fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse, HttpError> {
        self.requests.borrow_mut().push((
            method.to_string(),
            url.to_string(),
            headers.to_vec(),
            body.to_vec(),
        ));
        self.responses
            .borrow_mut()
            .pop()
            .unwrap_or_else(|| panic!("MockHttpClient: no canned response available"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_response(status: u16) -> HttpResponse {
        HttpResponse {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    // -- TC-MOCK-001 --------------------------------------------------------
    // The FIFO contract IS the reason this module exists. A regression here
    // would silently break every multi-response test in `s3::client::tests`
    // (the 503-retry suite). Verify directly with a 3-response sequence.
    #[test]
    fn mock_http_client_returns_responses_in_fifo_order() {
        let mock = MockHttpClient::new(vec![
            Ok(ok_response(200)),
            Ok(ok_response(404)),
            Ok(ok_response(500)),
        ]);
        let first = mock
            .request("GET", "https://example/a", &[], b"")
            .expect("first");
        let second = mock
            .request("GET", "https://example/b", &[], b"")
            .expect("second");
        let third = mock
            .request("GET", "https://example/c", &[], b"")
            .expect("third");

        assert_eq!(
            first.status, 200,
            "first canned response must be first served"
        );
        assert_eq!(second.status, 404);
        assert_eq!(third.status, 500);
    }

    // -- TC-MOCK-002 --------------------------------------------------------
    #[test]
    fn mock_http_client_records_call_details() {
        let mock = MockHttpClient::new(vec![Ok(ok_response(200))]);
        let headers = vec![("authorization".to_string(), "sigv4...".to_string())];
        let _ = mock
            .request("PUT", "https://example/key", &headers, b"body-bytes")
            .expect("ok");

        let calls = mock.requests.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "PUT");
        assert_eq!(calls[0].1, "https://example/key");
        assert_eq!(calls[0].2[0].0, "authorization");
        assert_eq!(calls[0].3, b"body-bytes");
    }

    // -- TC-MOCK-003 --------------------------------------------------------
    #[test]
    #[should_panic(expected = "no canned response available")]
    fn mock_http_client_panics_on_unexpected_call() {
        let mock = MockHttpClient::new(vec![]);
        let _ = mock.request("GET", "https://example", &[], b"");
    }
}

// ---------------------------------------------------------------------------
// MockS3Client — sequence-asserting mock at the S3ClientBackend boundary.
// Used by the transport tests (T3.3 / T3.4) so they can verify the order
// of HEAD / GET / PUT / DELETE calls (critical for the T3.4 probe path:
// PUT → DELETE must happen regardless of probe outcome) without exercising
// the signer + HTTP layers.
// ---------------------------------------------------------------------------

/// One recorded S3 protocol-level call. Mirrors the four operations on
/// [`S3ClientBackend`]; tests pattern-match on the variant to verify both
/// the type of call and its arguments.
///
/// The `bucket` and `key` fields on every variant are recorded even when
/// the current test set doesn't read them — the T3.4 probe tests need to
/// assert "the probe targeted `<key>.falach-probe-<suffix>`, not the real
/// key", which requires the field to be present. `#[allow(dead_code)]`
/// silences the dead-field warning until those tests land.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) enum MockS3Request {
    Head {
        bucket: String,
        key: String,
    },
    Get {
        bucket: String,
        key: String,
        if_none_match: Option<String>,
    },
    Put {
        bucket: String,
        key: String,
        body: Vec<u8>,
        if_match: Option<String>,
    },
    Delete {
        bucket: String,
        key: String,
    },
}

/// One canned response. Each variant matches the operation that will pop
/// it; calling `head_object` when the next response is a `Get(_)` panics.
/// This keeps test sequences honest about which call goes where.
pub(crate) enum MockS3Response {
    Head(Result<HeadResult, S3Error>),
    Get(Result<GetResult, S3Error>),
    Put(Result<PutResult, S3Error>),
    Delete(Result<(), S3Error>),
}

/// In-process mock [`S3ClientBackend`]. Records every call in
/// [`Self::requests`] and serves [`MockS3Response`]s in **FIFO order** —
/// matching [`MockHttpClient`]'s contract.
pub(crate) struct MockS3Client {
    responses: RefCell<Vec<MockS3Response>>,
    pub(crate) requests: RefCell<Vec<MockS3Request>>,
}

impl MockS3Client {
    /// Construct a mock that serves the given responses in FIFO order.
    pub(crate) fn new(responses: Vec<MockS3Response>) -> Self {
        let mut reversed = responses;
        reversed.reverse();
        Self {
            responses: RefCell::new(reversed),
            requests: RefCell::new(Vec::new()),
        }
    }

    /// Pop the next canned response; panic with a helpful message on
    /// underrun. Centralized so the four `S3ClientBackend` methods share
    /// one error path.
    fn next_response(&self, method: &'static str) -> MockS3Response {
        self.responses
            .borrow_mut()
            .pop()
            .unwrap_or_else(|| panic!("MockS3Client: no canned response available for {method}"))
    }
}

impl S3ClientBackend for MockS3Client {
    fn head_object(&self, bucket: &str, key: &str) -> Result<HeadResult, S3Error> {
        self.requests.borrow_mut().push(MockS3Request::Head {
            bucket: bucket.to_string(),
            key: key.to_string(),
        });
        match self.next_response("HEAD") {
            MockS3Response::Head(r) => r,
            other => panic!(
                "MockS3Client: expected HEAD response, got {} variant",
                other.variant_name()
            ),
        }
    }

    fn get_object(
        &self,
        bucket: &str,
        key: &str,
        if_none_match: Option<&str>,
    ) -> Result<GetResult, S3Error> {
        self.requests.borrow_mut().push(MockS3Request::Get {
            bucket: bucket.to_string(),
            key: key.to_string(),
            if_none_match: if_none_match.map(str::to_string),
        });
        match self.next_response("GET") {
            MockS3Response::Get(r) => r,
            other => panic!(
                "MockS3Client: expected GET response, got {} variant",
                other.variant_name()
            ),
        }
    }

    fn put_object(
        &self,
        bucket: &str,
        key: &str,
        bytes: &[u8],
        if_match: Option<&str>,
    ) -> Result<PutResult, S3Error> {
        self.requests.borrow_mut().push(MockS3Request::Put {
            bucket: bucket.to_string(),
            key: key.to_string(),
            body: bytes.to_vec(),
            if_match: if_match.map(str::to_string),
        });
        match self.next_response("PUT") {
            MockS3Response::Put(r) => r,
            other => panic!(
                "MockS3Client: expected PUT response, got {} variant",
                other.variant_name()
            ),
        }
    }

    fn delete_object(&self, bucket: &str, key: &str) -> Result<(), S3Error> {
        self.requests.borrow_mut().push(MockS3Request::Delete {
            bucket: bucket.to_string(),
            key: key.to_string(),
        });
        match self.next_response("DELETE") {
            MockS3Response::Delete(r) => r,
            other => panic!(
                "MockS3Client: expected DELETE response, got {} variant",
                other.variant_name()
            ),
        }
    }
}

impl MockS3Response {
    fn variant_name(&self) -> &'static str {
        match self {
            MockS3Response::Head(_) => "Head",
            MockS3Response::Get(_) => "Get",
            MockS3Response::Put(_) => "Put",
            MockS3Response::Delete(_) => "Delete",
        }
    }
}

#[cfg(test)]
mod mock_s3_tests {
    use super::*;
    use crate::s3::etag::Etag;

    fn etag(s: &str) -> Etag {
        Etag(s.to_string())
    }

    // -- TC-MOCK-S3-001 -----------------------------------------------------
    // The FIFO + per-method-variant contract IS the reason this mock
    // exists. A regression silently breaks the T3.4 probe-sequence tests.
    #[test]
    fn mock_s3_client_serves_responses_in_fifo_and_records_calls() {
        let mock = MockS3Client::new(vec![
            MockS3Response::Head(Ok(HeadResult { etag: etag("v1") })),
            MockS3Response::Put(Ok(PutResult { etag: etag("v2") })),
            MockS3Response::Delete(Ok(())),
        ]);

        let h = mock.head_object("b", "k").expect("head");
        assert_eq!(h.etag.as_str(), "v1");
        let p = mock.put_object("b", "k", b"body", Some("v1")).expect("put");
        assert_eq!(p.etag.as_str(), "v2");
        mock.delete_object("b", "k").expect("delete");

        let calls = mock.requests.borrow();
        assert_eq!(calls.len(), 3);
        assert!(matches!(calls[0], MockS3Request::Head { .. }));
        assert!(matches!(calls[1], MockS3Request::Put { .. }));
        assert!(matches!(calls[2], MockS3Request::Delete { .. }));
    }

    // -- TC-MOCK-S3-002 -----------------------------------------------------
    // Wrong-variant on a queued response is a test bug, not a production
    // condition; panic loudly so it's caught at write time rather than
    // misleading the assertion.
    #[test]
    #[should_panic(expected = "expected HEAD response, got Put variant")]
    fn mock_s3_client_panics_on_wrong_method_variant() {
        let mock = MockS3Client::new(vec![MockS3Response::Put(Ok(PutResult { etag: etag("v") }))]);
        let _ = mock.head_object("b", "k");
    }
}
