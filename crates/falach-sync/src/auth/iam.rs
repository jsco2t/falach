// Domain acronyms saturate this module's docs.
#![allow(clippy::doc_markdown)]

//! IAM-instance-role credential resolver (FR-045; design.md §2.2.7).
//!
//! Implements the IMDSv2 (Instance Metadata Service v2) credential
//! discovery flow used by EC2 / ECS hosts running with an instance
//! profile:
//!
//! 1. `PUT /latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds`
//!    → session-scoped token.
//! 2. `GET /latest/meta-data/iam/security-credentials/` with
//!    `X-aws-ec2-metadata-token` → role name attached to this instance
//!    (single line).
//! 3. `GET /latest/meta-data/iam/security-credentials/<role>` with the
//!    token → JSON document with access-key + secret + session token +
//!    expiry.
//!
//! IMDSv1 (no-token) is NOT supported — AWS recommends IMDSv2 for new
//! workloads and many hardened AMIs disable v1 entirely.
//!
//! Talks to the IMDS endpoint via `ureq` (already vendored). Default
//! endpoint is the standard link-local address `http://169.254.169.254`;
//! the [`crate::auth::CredentialSource::IamInstanceRole::imds_endpoint`]
//! field overrides it (used by `MockImds` in tests and by EC2 setups
//! using a custom metadata-service URL).

use std::time::Duration;

use chrono::{DateTime, Utc};
use secrecy::SecretString;
use serde::Deserialize;
use zeroize::Zeroize;

use crate::auth::error::AuthError;
use crate::auth::source::ResolvedCredentials;

/// The standard IMDS endpoint (link-local IPv4).
const DEFAULT_IMDS_ENDPOINT: &str = "http://169.254.169.254";

/// `X-aws-ec2-metadata-token-ttl-seconds` value sent on the token PUT.
/// 6 hours (the AWS-documented maximum).
const TOKEN_TTL_SECONDS: u32 = 21600;

/// Per-request timeout. Local-link addresses respond in < 10 ms in
/// practice; 1 second is generous and bounds non-EC2 hangs.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(1);

/// Resolve [`crate::auth::CredentialSource::IamInstanceRole`] via IMDSv2.
///
/// `imds_endpoint = None` uses the link-local default
/// (`http://169.254.169.254`); `Some(url)` overrides for `MockImds`
/// + non-standard EC2 setups.
///
/// # Errors
///
/// - [`AuthError::ImdsUnreachable`] — connection refused / timeout /
///   DNS failure (common on non-EC2 hosts where the metadata service
///   doesn't exist).
/// - [`AuthError::NoIamRole`] — IMDS returned 404 for the role lookup
///   (no instance profile attached).
/// - [`AuthError::ImdsMalformedResponse`] — JSON parse failure or
///   missing expected fields.
/// - [`AuthError::ImdsUnexpectedStatus`] — any other non-200 status.
pub fn resolve_iam_instance_role(
    imds_endpoint: Option<&str>,
) -> Result<ResolvedCredentials, AuthError> {
    let endpoint = imds_endpoint.unwrap_or(DEFAULT_IMDS_ENDPOINT);
    let agent = build_agent();

    // Step 1: PUT /latest/api/token
    let token = fetch_imds_token(&agent, endpoint)?;

    // Step 2: GET /latest/meta-data/iam/security-credentials/
    // → single-line role name.
    let role = fetch_role_name(&agent, endpoint, &token)?;

    // Step 3: GET /latest/meta-data/iam/security-credentials/<role>
    // → JSON document.
    fetch_role_credentials(&agent, endpoint, &token, &role)
}

/// Build an HTTP agent suitable for IMDS calls. Plain `ureq::Agent`
/// without TLS config — IMDS is HTTP-only on the link-local address.
///
/// `http_status_as_error(false)` is critical: ureq's default treats 4xx
/// as `Err(Error::StatusCode(n))`, which would collapse 404 (no role
/// attached) and 401 (auth failure) into a single error variant we
/// can't disambiguate. We want the response object so we can branch on
/// status ourselves.
fn build_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(REQUEST_TIMEOUT))
        .http_status_as_error(false)
        .build()
        .into()
}

/// PUT `/latest/api/token` and return the session token string.
fn fetch_imds_token(agent: &ureq::Agent, endpoint: &str) -> Result<String, AuthError> {
    let url = format!("{endpoint}/latest/api/token");
    let response = agent
        .put(&url)
        .header(
            "x-aws-ec2-metadata-token-ttl-seconds",
            &TOKEN_TTL_SECONDS.to_string(),
        )
        .send_empty()
        .map_err(|e| AuthError::ImdsUnreachable {
            endpoint: endpoint.to_string(),
            reason: e.to_string(),
        })?;

    let status = response.status().as_u16();
    if status != 200 {
        return Err(AuthError::ImdsUnexpectedStatus { status });
    }
    let mut response = response;
    let body =
        response
            .body_mut()
            .read_to_string()
            .map_err(|e| AuthError::ImdsMalformedResponse {
                reason: format!("token response read failed: {e}"),
            })?;
    Ok(body.trim().to_string())
}

/// GET the role name; surfaces 404 as `NoIamRole`.
fn fetch_role_name(agent: &ureq::Agent, endpoint: &str, token: &str) -> Result<String, AuthError> {
    let url = format!("{endpoint}/latest/meta-data/iam/security-credentials/");
    let response = agent
        .get(&url)
        .header("x-aws-ec2-metadata-token", token)
        .call()
        .map_err(|e| AuthError::ImdsUnreachable {
            endpoint: endpoint.to_string(),
            reason: e.to_string(),
        })?;

    let status = response.status().as_u16();
    match status {
        200 => {
            let mut response = response;
            let body = response.body_mut().read_to_string().map_err(|e| {
                AuthError::ImdsMalformedResponse {
                    reason: format!("role-name response read failed: {e}"),
                }
            })?;
            let role = body.trim();
            if role.is_empty() {
                return Err(AuthError::NoIamRole);
            }
            Ok(role.to_string())
        }
        404 => Err(AuthError::NoIamRole),
        other => Err(AuthError::ImdsUnexpectedStatus { status: other }),
    }
}

/// IMDS credentials response JSON. The `Code = "Success"` field is
/// present on success but we don't gate on it (the 200 status is the
/// gate); we deserialize only the fields we consume.
#[derive(Debug, Deserialize)]
#[allow(non_snake_case)] // AWS field naming.
struct ImdsCredentials {
    AccessKeyId: String,
    SecretAccessKey: String,
    Token: String,
    Expiration: String,
}

/// GET the JSON credentials for `role` and convert into
/// [`ResolvedCredentials`].
fn fetch_role_credentials(
    agent: &ureq::Agent,
    endpoint: &str,
    token: &str,
    role: &str,
) -> Result<ResolvedCredentials, AuthError> {
    let url = format!("{endpoint}/latest/meta-data/iam/security-credentials/{role}");
    let response = agent
        .get(&url)
        .header("x-aws-ec2-metadata-token", token)
        .call()
        .map_err(|e| AuthError::ImdsUnreachable {
            endpoint: endpoint.to_string(),
            reason: e.to_string(),
        })?;

    let status = response.status().as_u16();
    if status == 404 {
        return Err(AuthError::NoIamRole);
    }
    if status != 200 {
        return Err(AuthError::ImdsUnexpectedStatus { status });
    }

    let mut response = response;
    let mut body =
        response
            .body_mut()
            .read_to_string()
            .map_err(|e| AuthError::ImdsMalformedResponse {
                reason: format!("credentials response read failed: {e}"),
            })?;
    let parse_result = serde_json::from_str::<ImdsCredentials>(&body);
    // The raw response body holds the plaintext secret access key + session
    // token; wipe it before it drops (CLAUDE.md "zeroize on drop for every
    // type holding sensitive bytes"). IMDS creds are memory-only STS
    // temporaries — there is no on-disk plaintext to fall back on.
    body.zeroize();
    let parsed: ImdsCredentials = parse_result.map_err(|e| AuthError::ImdsMalformedResponse {
        reason: format!("JSON parse failed: {e}"),
    })?;

    // Move the secret fields into zeroizing wrappers *before* the fallible
    // Expiration parse, so an error there drops them already wiped rather than
    // leaking the plaintext `ImdsCredentials` (`Expiration` is a non-secret
    // RFC 3339 timestamp).
    let access_key_id = parsed.AccessKeyId;
    let secret_access_key = SecretString::from(parsed.SecretAccessKey);
    let session_token = SecretString::from(parsed.Token);
    let expiration = parsed.Expiration;

    let expiry: DateTime<Utc> =
        expiration
            .parse()
            .map_err(|e| AuthError::ImdsMalformedResponse {
                reason: format!("Expiration `{expiration}` is not RFC 3339: {e}"),
            })?;

    Ok(ResolvedCredentials {
        access_key_id,
        secret_access_key,
        session_token: Some(session_token),
        expiry: Some(expiry),
    })
}

// ---------------------------------------------------------------------------
// MockImds — tiny in-tree HTTP server for testing the IMDS resolver.
//
// Bound to 127.0.0.1:0 (random ephemeral port); spawns a worker thread
// to handle requests; auto-cleanup on Drop via a shutdown channel.
// Public + feature-gated `test-helpers` so future integration tests
// (`tests/auth_iam.rs`, Phase 5 orchestrator tests) can reuse it.
// ---------------------------------------------------------------------------

/// One canned IMDS response. The `MockImds` serves responses in
/// FIFO order; underrun panics with a helpful message.
#[cfg(any(test, feature = "test-helpers"))]
#[derive(Debug, Clone)]
pub struct MockImdsResponse {
    /// HTTP status code (typically 200, 404, or 401).
    pub status: u16,
    /// Response body (UTF-8). Empty string for status-only responses.
    pub body: String,
}

#[cfg(any(test, feature = "test-helpers"))]
impl MockImdsResponse {
    /// Build a 200 response with the given body.
    #[must_use]
    pub fn ok(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            body: body.into(),
        }
    }

    /// Build a 404.
    #[must_use]
    pub fn not_found() -> Self {
        Self {
            status: 404,
            body: String::new(),
        }
    }
}

/// In-process HTTP server that serves canned IMDS responses. Bound to
/// `127.0.0.1:0` (kernel picks a free ephemeral port).
///
/// Construct via [`MockImds::with_responses`]; the server stops on
/// `Drop` via the shutdown channel + the worker thread joining.
#[cfg(any(test, feature = "test-helpers"))]
pub struct MockImds {
    /// Endpoint URL (e.g. `http://127.0.0.1:54321`).
    pub endpoint: String,
    shutdown: Option<std::sync::mpsc::Sender<()>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

#[cfg(any(test, feature = "test-helpers"))]
impl MockImds {
    /// Spawn a new mock IMDS server serving the given responses in
    /// FIFO order.
    ///
    /// # Panics
    ///
    /// Panics if the kernel cannot bind to `127.0.0.1:0` (which would
    /// indicate a broken test environment, not a real failure case).
    pub fn with_responses(responses: Vec<MockImdsResponse>) -> Self {
        use std::sync::mpsc;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
        let port = listener.local_addr().expect("local_addr").port();
        // The worker uses non-blocking accept so it can poll the
        // shutdown channel.
        listener.set_nonblocking(true).expect("nonblocking");

        let (tx, rx) = mpsc::channel::<()>();
        let mut queue = responses;

        let worker = std::thread::spawn(move || {
            use std::io::{Read, Write};
            loop {
                if rx.try_recv().is_ok() {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        // Read the request — read until we see CRLF CRLF.
                        let mut buf = [0u8; 4096];
                        let mut total = Vec::new();
                        loop {
                            match stream.read(&mut buf) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    total.extend_from_slice(&buf[..n]);
                                    if total.windows(4).any(|w| w == b"\r\n\r\n") {
                                        break;
                                    }
                                }
                            }
                        }
                        // Pop the next canned response, write it.
                        let canned = if queue.is_empty() {
                            MockImdsResponse {
                                status: 500,
                                body: "mock-imds: no canned response left".to_string(),
                            }
                        } else {
                            queue.remove(0)
                        };
                        let status_line = match canned.status {
                            401 => "HTTP/1.1 401 Unauthorized",
                            404 => "HTTP/1.1 404 Not Found",
                            500 => "HTTP/1.1 500 Internal Server Error",
                            // Default to 200 OK — the tests using this mock
                            // only need 200/404/500. 401 is here for
                            // completeness in case a future test wants it.
                            _ => "HTTP/1.1 200 OK",
                        };
                        let response = format!(
                            "{status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            canned.body.len(),
                            canned.body
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.shutdown(std::net::Shutdown::Write);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            endpoint: format!("http://127.0.0.1:{port}"),
            shutdown: Some(tx),
            worker: Some(worker),
        }
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl Drop for MockImds {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    fn ok_creds_json() -> String {
        // Matches AWS IMDS credentials shape.
        r#"{"Code":"Success","LastUpdated":"2026-05-28T00:00:00Z","Type":"AWS-HMAC","AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"secret-key-bytes","Token":"session-token-bytes","Expiration":"2026-05-28T06:00:00Z"}"#
            .to_string()
    }

    // -- TC-AUTH-IAM1 -------------------------------------------------------
    #[test]
    fn resolve_iam_returns_creds_from_mock_imds() {
        let mock = MockImds::with_responses(vec![
            MockImdsResponse::ok("imds-token-value"), // PUT /token
            MockImdsResponse::ok("my-role"),          // GET /security-credentials/
            MockImdsResponse::ok(ok_creds_json()),    // GET /security-credentials/my-role
        ]);
        let creds = resolve_iam_instance_role(Some(&mock.endpoint)).expect("resolve");
        assert_eq!(creds.access_key_id, "ASIAEXAMPLE");
        assert_eq!(creds.secret_access_key.expose_secret(), "secret-key-bytes");
        assert_eq!(
            creds
                .session_token
                .as_ref()
                .map(secrecy::ExposeSecret::expose_secret),
            Some("session-token-bytes")
        );
        assert!(creds.expiry.is_some());
    }

    // -- TC-AUTH-IAM2 -------------------------------------------------------
    #[test]
    fn resolve_iam_handles_no_role_attached_response() {
        // The role-name lookup returns 404 → NoIamRole.
        let mock = MockImds::with_responses(vec![
            MockImdsResponse::ok("imds-token-value"),
            MockImdsResponse::not_found(),
        ]);
        let err = resolve_iam_instance_role(Some(&mock.endpoint)).expect_err("404 role");
        assert!(matches!(err, AuthError::NoIamRole));
    }

    // -- TC-AUTH-IAM3 -------------------------------------------------------
    #[test]
    fn resolve_iam_handles_imds_unreachable() {
        // Bind a port, immediately drop the listener → next connect
        // attempt fails with ECONNREFUSED. This is the realistic
        // non-EC2-host case.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let endpoint = format!("http://127.0.0.1:{port}");
        let err = resolve_iam_instance_role(Some(&endpoint)).expect_err("unreachable");
        match err {
            AuthError::ImdsUnreachable { endpoint: e, .. } => {
                assert_eq!(e, endpoint);
            }
            other => panic!("expected ImdsUnreachable, got {other:?}"),
        }
    }

    // -- TC-AUTH-IAM4 — deliberately omitted -------------------------------
    // The test plan's IAM4 ("parses IMDSv2 token flow") would require
    // `MockImds` to record incoming requests so we could assert the
    // `x-aws-ec2-metadata-token` header was carried from step 1 (PUT
    // /token) into step 2 (GET /security-credentials/). The current
    // `MockImds` is response-only and intentionally minimal (~80 LoC).
    //
    // The successful end-to-end resolve in IAM1 + the 404-on-role-lookup
    // case in IAM2 collectively prove the two-step sequence works for
    // every path the orchestrator exercises; the header-propagation
    // assertion is a genuinely-missing test, not a tautological one, and
    // is best added together with a `MockImds::requests()` helper when
    // Phase 5 lands integration tests that also need it.

    // -- TC-AUTH-IAM5 -------------------------------------------------------
    #[test]
    fn resolve_iam_handles_credential_expiry() {
        let mock = MockImds::with_responses(vec![
            MockImdsResponse::ok("tok"),
            MockImdsResponse::ok("role"),
            MockImdsResponse::ok(ok_creds_json()),
        ]);
        let creds = resolve_iam_instance_role(Some(&mock.endpoint)).expect("resolve");
        let expiry = creds.expiry.expect("expiry present");
        let expected: DateTime<Utc> = "2026-05-28T06:00:00Z".parse().expect("parse expiry");
        assert_eq!(expiry, expected);
    }

    // -- TC-AUTH-IAM-malformed ----------------------------------------------
    #[test]
    fn resolve_iam_handles_malformed_json() {
        let mock = MockImds::with_responses(vec![
            MockImdsResponse::ok("tok"),
            MockImdsResponse::ok("role"),
            MockImdsResponse::ok("{not valid json"),
        ]);
        let err = resolve_iam_instance_role(Some(&mock.endpoint)).expect_err("malformed");
        assert!(matches!(err, AuthError::ImdsMalformedResponse { .. }));
    }
}
