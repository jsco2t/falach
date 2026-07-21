//! AWS Signature Version 4 signing (design.md §2.2.4 / ADR-1).
//!
//! Hand-rolled implementation of the SigV4 algorithm against the published
//! AWS spec. Validated against AWS's `aws-sig-v4-test-suite` corpus
//! (`crates/falach-sync/tests/data/aws_sigv4_vectors/` — vendored at the
//! commit hash documented in
//! `crates/falach-sync/tests/data/AWS_SIGV4_VECTORS_SOURCE.md`) via the CI
//! gate `tests/sigv4_aws_test_vectors.rs`.
//!
//! # Algorithm
//!
//! Given an HTTP request (method, URI path, query string, headers, body)
//! plus `(access_key, secret_key, [session_token])` and a target region:
//!
//! 1. Build the **canonical request**:
//!    ```text
//!    METHOD\n
//!    canonical-URI\n
//!    canonical-query-string\n
//!    canonical-headers\n
//!    signed-headers\n
//!    hex-SHA256(payload)
//!    ```
//! 2. Build the **string-to-sign**:
//!    ```text
//!    AWS4-HMAC-SHA256\n
//!    <ISO8601 basic date>\n
//!    <credential-scope>\n
//!    hex-SHA256(canonical-request)
//!    ```
//!    where `credential-scope = YYYYMMDD/<region>/s3/aws4_request`.
//! 3. Derive the **signing key**:
//!    ```text
//!    kDate    = HMAC-SHA256("AWS4" + secret, YYYYMMDD)
//!    kRegion  = HMAC-SHA256(kDate, region)
//!    kService = HMAC-SHA256(kRegion, "s3")
//!    kSigning = HMAC-SHA256(kService, "aws4_request")
//!    ```
//! 4. **Signature**: `hex(HMAC-SHA256(kSigning, string-to-sign))`.
//! 5. **Authorization header**:
//!    `AWS4-HMAC-SHA256 Credential=<key>/<scope>, SignedHeaders=<list>, Signature=<sig>`.
//!
//! # Edge cases (validated by the test corpus)
//!
//! - Empty payload uses `hex(SHA256(""))`, **not** the literal
//!   `UNSIGNED-PAYLOAD`. We always send an explicit hash; it's the
//!   strictest mode and the one MinIO requires.
//! - URI path components are encoded per RFC 3986 unreserved set; `/`
//!   characters in the path are NOT encoded.
//! - Query string parameters are sorted by key (then value); both keys and
//!   values are percent-encoded; `=` separates and `&` joins.
//! - Header names are lowercased and trimmed; values have leading/trailing
//!   whitespace stripped and runs of internal whitespace collapsed to a
//!   single space (but only outside quoted strings, which we don't emit).
//! - The signed-headers list is the semicolon-joined sorted set of header
//!   names that participated in the signature.

use std::time::SystemTime;

use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

/// The default AWS service identifier. S3 is what Phase 0 actually signs
/// against; the field is configurable on [`Signer::with_service`] so the
/// AWS published test corpus (which uses the placeholder service name
/// `"service"`) can drive the same signer code.
const DEFAULT_SERVICE: &str = "s3";

/// Suffix of the credential scope; an AWS constant.
const TERMINATOR: &str = "aws4_request";

/// The SigV4 algorithm identifier used in both the `Authorization` header
/// and the string-to-sign.
const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// AWS resolved credentials for SigV4 signing.
///
/// The secret access key is held as a `String` for ergonomics but the type
/// is `Zeroize` + `ZeroizeOnDrop` so the underlying buffer is scrubbed on
/// drop (per CLAUDE.md memory-hygiene rules). Cloning intentionally
/// requires explicit handling — copies survive only as long as their
/// owning scope.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ResolvedCredentials {
    /// Public access-key identifier (e.g. `AKIA...`). Not secret per AWS.
    pub access_key_id: String,
    /// Secret access key. Held with `ZeroizeOnDrop` to scrub on free.
    pub secret_access_key: String,
    /// Optional session token for temporary credentials (STS, IAM-role).
    /// `None` for static long-lived credentials.
    pub session_token: Option<String>,
}

impl std::fmt::Debug for ResolvedCredentials {
    /// Never expose the secret_access_key in Debug output. The access_key_id
    /// is documented-non-secret per AWS posture; the secret + token are
    /// masked.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Errors that prevent a SigV4 signature from being produced.
///
/// These are signing-time failures (bad input data). HTTP-level failures
/// (connection, 4xx/5xx responses) are NOT signer errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignerError {
    /// The provided `SystemTime` is outside the representable
    /// `chrono::DateTime<Utc>` range (pre-`UNIX_EPOCH`, second-count
    /// overflows `i64`, or `chrono::DateTime::from_timestamp` rejects).
    /// In practice unreachable for any clock-derived `SystemTime`.
    #[error("SigV4 timestamp out of range: {0}")]
    TimestampOutOfRange(String),
}

/// AWS Signature Version 4 signer for S3.
///
/// Stateless aside from `(region, service)`; construct once per
/// (endpoint, region) tuple and call [`Signer::sign`] for every request.
#[derive(Debug, Clone)]
pub struct Signer {
    region: String,
    service: String,
}

impl Signer {
    /// Build a signer for the given AWS region (e.g. `us-east-1`) with
    /// the S3 service identifier.
    ///
    /// The region is part of the credential scope and the signing-key
    /// derivation; if the wrong region is used the server returns
    /// `SignatureDoesNotMatch`. We do NOT validate the region string here
    /// — AWS accepts arbitrary regional identifiers and S3-compatible
    /// backends may use non-AWS region names (e.g. MinIO often uses
    /// `us-east-1` by convention, but Cloudflare R2 uses `auto`).
    #[must_use]
    pub fn new(region: String) -> Self {
        Self {
            region,
            service: DEFAULT_SERVICE.to_string(),
        }
    }

    /// Build a signer with a non-default service identifier. Used only by
    /// the AWS test-vector corpus runner (the corpus uses `"service"` as
    /// a placeholder service name); production code paths use
    /// [`Signer::new`].
    #[doc(hidden)]
    #[must_use]
    pub fn with_service(region: String, service: String) -> Self {
        Self { region, service }
    }

    /// Sign an HTTP request, mutating `headers` in place to add the
    /// `Authorization`, `x-amz-date`, `x-amz-content-sha256`, and (if
    /// `credentials.session_token.is_some()`) `x-amz-security-token` headers.
    ///
    /// Inputs:
    /// - `method`: HTTP method in uppercase (`"PUT"`, `"GET"`, `"HEAD"`,
    ///   `"DELETE"`).
    /// - `uri_path`: the path component of the request URI (e.g.
    ///   `/my-bucket/my-key`); must already be percent-encoded for transport
    ///   per RFC 3986. SigV4 will re-encode this for the canonical request
    ///   per its own rules (which match RFC 3986 unreserved-set encoding,
    ///   preserving `/`).
    /// - `query`: query parameters as `(key, value)` pairs; both unencoded.
    /// - `headers`: mutable `(name, value)` list. The caller MUST include the
    ///   `host` header (and `content-length` if the body is non-empty) before
    ///   calling sign, and MUST NOT include any of the four headers the signer
    ///   manages (`x-amz-date`, `x-amz-content-sha256`,
    ///   `x-amz-security-token`, `authorization`) — pre-populating any of
    ///   them would produce a comma-joined value via SigV4's
    ///   duplicate-header rules and silently break the signature. A
    ///   `debug_assert!` inside the function panics on violations in dev
    ///   builds; release builds run the silently-broken path so callers
    ///   that take the prohibition seriously pay no runtime cost.
    /// - `body`: the raw request body bytes.
    /// - `credentials`: resolved AWS credentials.
    /// - `now`: the signing instant (separately injected for deterministic
    ///   tests; production passes `SystemTime::now()`).
    ///
    /// # Errors
    ///
    /// Returns [`SignerError`] when the input cannot be processed
    /// (currently only timestamp formatting failures — in practice
    /// unreachable for valid `SystemTime`s).
    #[allow(clippy::too_many_arguments)] // SigV4 needs all of these inputs by definition.
    pub fn sign(
        &self,
        method: &str,
        uri_path: &str,
        query: &[(String, String)],
        headers: &mut Vec<(String, String)>,
        body: &[u8],
        credentials: &ResolvedCredentials,
        now: SystemTime,
    ) -> Result<(), SignerError> {
        // 0. Defensive: the caller MUST NOT have pre-populated any of the
        //    four headers we manage. A caller-supplied `x-amz-content-sha256`
        //    that disagreed with the actual body would be silently
        //    comma-joined into the canonical headers and the request would
        //    fail with `SignatureDoesNotMatch` — debugging that from
        //    server-side telemetry is brutal. Dev builds fail loudly here;
        //    release builds run the broken path (zero-cost in production).
        debug_assert!(
            !headers
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case("x-amz-date")
                    || n.eq_ignore_ascii_case("x-amz-content-sha256")
                    || n.eq_ignore_ascii_case("x-amz-security-token")
                    || n.eq_ignore_ascii_case("authorization")),
            "Signer::sign: caller pre-populated a signer-managed header \
             (x-amz-date / x-amz-content-sha256 / x-amz-security-token / \
             authorization). See the sign() doc-comment."
        );

        // 1. Compute the payload hash. We always send an explicit hex hash —
        //    the strictest mode, and the only one all S3-compatible backends
        //    universally accept. `UNSIGNED-PAYLOAD` is an AWS-only shortcut
        //    we deliberately avoid.
        let payload_hash = hex_sha256(body);

        // 2. Format the timestamps. AWS uses ISO8601 basic form
        //    (`YYYYMMDDTHHMMSSZ`) for `x-amz-date`, and `YYYYMMDD` for the
        //    credential scope.
        let dt: DateTime<Utc> = systemtime_to_utc(now).ok_or_else(|| {
            SignerError::TimestampOutOfRange("SystemTime out of range".to_string())
        })?;
        let amz_date = dt.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = dt.format("%Y%m%d").to_string();

        // 3. Add the canonical pre-signing headers. ORDER MATTERS for
        //    deterministic output across re-signing the same request: caller
        //    headers come first, then our SigV4-injected ones.
        headers.push(("x-amz-date".to_string(), amz_date.clone()));
        headers.push(("x-amz-content-sha256".to_string(), payload_hash.clone()));
        if let Some(token) = &credentials.session_token {
            headers.push(("x-amz-security-token".to_string(), token.clone()));
        }

        // 4. Build the canonical request and signature.
        let credential_scope =
            format!("{date_stamp}/{}/{}/{TERMINATOR}", self.region, self.service);

        let (canonical_request, signed_headers) =
            build_canonical_request(method, uri_path, query, headers, &payload_hash);

        let string_to_sign = format!(
            "{ALGORITHM}\n{amz_date}\n{credential_scope}\n{}",
            hex_sha256(canonical_request.as_bytes())
        );

        let signing_key = derive_signing_key(
            &credentials.secret_access_key,
            &date_stamp,
            &self.region,
            &self.service,
        );

        let signature = hex::encode(*hmac_sha256(&*signing_key, string_to_sign.as_bytes()));

        // 5. Add the Authorization header.
        let authorization = format!(
            "{ALGORITHM} Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            credentials.access_key_id
        );
        headers.push(("authorization".to_string(), authorization));

        Ok(())
    }

    /// Build *just* the canonical request + string-to-sign without mutating
    /// headers, for use by the AWS test-vector runner. The runner asserts
    /// the intermediate strings match AWS's published expected outputs
    /// before reaching the final-signature stage.
    ///
    /// `signing_dt` must be a chrono `DateTime<Utc>` so the runner can
    /// inject the corpus's specific timestamp.
    ///
    /// Returns `(canonical_request, string_to_sign, signature_hex)`.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)] // mirrors `sign` plus a timestamp injection.
    pub fn debug_sign_components(
        &self,
        method: &str,
        uri_path: &str,
        query: &[(String, String)],
        headers: &[(String, String)],
        body: &[u8],
        credentials: &ResolvedCredentials,
        signing_dt: DateTime<Utc>,
    ) -> (String, String, String) {
        let payload_hash = hex_sha256(body);
        let amz_date = signing_dt.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = signing_dt.format("%Y%m%d").to_string();
        let credential_scope =
            format!("{date_stamp}/{}/{}/{TERMINATOR}", self.region, self.service);

        let (canonical_request, _signed_headers) =
            build_canonical_request(method, uri_path, query, headers, &payload_hash);

        let string_to_sign = format!(
            "{ALGORITHM}\n{amz_date}\n{credential_scope}\n{}",
            hex_sha256(canonical_request.as_bytes())
        );

        let signing_key = derive_signing_key(
            &credentials.secret_access_key,
            &date_stamp,
            &self.region,
            &self.service,
        );
        let signature = hex::encode(*hmac_sha256(&*signing_key, string_to_sign.as_bytes()));

        (canonical_request, string_to_sign, signature)
    }
}

/// Construct the canonical request string + signed-headers list per the
/// SigV4 spec.
fn build_canonical_request(
    method: &str,
    uri_path: &str,
    query: &[(String, String)],
    headers: &[(String, String)],
    payload_hash: &str,
) -> (String, String) {
    let canonical_method = method.to_ascii_uppercase();
    let canonical_uri = canonical_uri(uri_path);
    let canonical_query = canonical_query_string(query);
    let (canonical_headers, signed_headers) = canonical_headers_and_signed(headers);

    let canonical_request = format!(
        "{canonical_method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );

    (canonical_request, signed_headers)
}

/// RFC 3986 unreserved-set percent-encoding of the path component. SigV4
/// requires the `/` separator to be PRESERVED (i.e. NOT percent-encoded),
/// and existing `%XX` escape sequences in the input ALSO preserved
/// (i.e. `%` is treated as if it were unreserved). Every other byte
/// outside the unreserved set is encoded as `%XX`.
///
/// The `%` preservation matches the AWS SigV4 reference implementation's
/// behavior on the `get-space-normalized` / `get-space-unnormalized` test
/// vectors and matches the standard S3 convention that S3 keys with `%`
/// in them are pre-encoded by the caller (a literal `%` in a key is
/// transmitted as `%25`).
fn canonical_uri(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    let mut out = String::with_capacity(path.len());
    for b in path.bytes() {
        if is_unreserved(b) || b == b'/' || b == b'%' {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(hex_upper(b >> 4));
            out.push(hex_upper(b & 0x0F));
        }
    }
    out
}

/// Canonical query string: parameters sorted by key (then value); both
/// keys and values percent-encoded per RFC 3986 unreserved set; `=`
/// separates k=v pairs; `&` joins pairs. Empty query → empty string.
fn canonical_query_string(query: &[(String, String)]) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut encoded: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (percent_encode(k), percent_encode(v)))
        .collect();
    encoded.sort();

    encoded
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Canonical headers + signed-headers list.
///
/// Each header name is lowercased and trimmed; each value has surrounding
/// whitespace stripped and runs of internal whitespace collapsed to a
/// single space. When multiple headers share the same name
/// (case-insensitively), their values are combined into a single
/// comma-joined value in *input order* (RFC 7230 §3.2.2 / SigV4 spec).
/// The combined headers are then sorted by name.
///
/// Returns the canonical-headers block (one `name:value\n` per header,
/// with a trailing newline after the final entry) and the
/// signed-headers list (semicolon-joined names, each appearing once).
fn canonical_headers_and_signed(headers: &[(String, String)]) -> (String, String) {
    // First pass: normalize names + values; preserve input order for
    // values that share a name.
    let normalized: Vec<(String, String)> = headers
        .iter()
        .map(|(name, value)| {
            (
                name.trim().to_ascii_lowercase(),
                normalize_header_value(value),
            )
        })
        .collect();

    // Second pass: group same-name values into comma-joined entries.
    // Using a Vec rather than a HashMap so input order is preserved for
    // values within the same name (matches the AWS get-header-value-order
    // test fixture).
    let mut grouped: Vec<(String, Vec<String>)> = Vec::new();
    for (name, value) in normalized {
        if let Some(entry) = grouped.iter_mut().find(|(n, _)| n == &name) {
            entry.1.push(value);
        } else {
            grouped.push((name, vec![value]));
        }
    }

    // Sort by name.
    grouped.sort_by(|a, b| a.0.cmp(&b.0));

    let mut canonical_headers = String::new();
    for (n, vs) in &grouped {
        canonical_headers.push_str(n);
        canonical_headers.push(':');
        canonical_headers.push_str(&vs.join(","));
        canonical_headers.push('\n');
    }

    let signed_headers = grouped
        .iter()
        .map(|(n, _)| n.as_str())
        .collect::<Vec<_>>()
        .join(";");

    (canonical_headers, signed_headers)
}

/// Normalize a header value: trim leading/trailing whitespace, collapse
/// internal runs of whitespace to a single space. Per RFC 7230 / SigV4
/// canonicalization rules.
fn normalize_header_value(value: &str) -> String {
    let trimmed = value.trim();
    let mut out = String::with_capacity(trimmed.len());
    let mut prev_was_space = false;
    for ch in trimmed.chars() {
        if ch == ' ' || ch == '\t' {
            if !prev_was_space {
                out.push(' ');
                prev_was_space = true;
            }
        } else {
            out.push(ch);
            prev_was_space = false;
        }
    }
    out
}

/// Percent-encode per RFC 3986 unreserved set (used for query string keys
/// + values). Unlike [`canonical_uri`], this encodes `/` as well.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if is_unreserved(b) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(hex_upper(b >> 4));
            out.push(hex_upper(b & 0x0F));
        }
    }
    out
}

/// Is `b` in the RFC 3986 unreserved set?
/// `unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"`
const fn is_unreserved(b: u8) -> bool {
    matches!(b,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~')
}

/// Hex digit (uppercase) for a nibble. Caller MUST pass `n < 16`; the
/// `& 0xF` mask defends against accidental violation by silently masking
/// to the low 4 bits rather than emitting a corrupt `?` placeholder
/// (the previous design's `_ => '?'` arm was unreachable in practice but
/// would have silently corrupted output if a future caller misused it).
const fn hex_upper(n: u8) -> char {
    const TABLE: &[u8; 16] = b"0123456789ABCDEF";
    TABLE[(n & 0xF) as usize] as char
}

/// SHA-256 over `bytes`, returned as a lowercase hex string.
fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// HMAC-SHA256 over `data`, keyed by `key`. Returns the raw 32-byte MAC
/// wrapped in [`Zeroizing`] so it is scrubbed on drop — required by
/// CLAUDE.md ("Zeroize on drop for derived keys").
///
/// Documented residual: the `GenericArray` returned by `Hmac::finalize`
/// does not implement `Zeroize`, so the MAC bytes briefly exist on the
/// stack frame of this function before being copied into the returned
/// `Zeroizing<[u8; 32]>`. The residual stack copy is overwritten by
/// subsequent frames and is the same posture `aws-sigv4` ships with;
/// CLAUDE.md's "no cosmic-ray paranoia (Rowhammer, cold-boot DMA) — out
/// of scope" engineering principle covers this gap explicitly.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&result);
    out
}

/// Derive the SigV4 signing key per the AWS spec. Returns the key wrapped
/// in [`Zeroizing`] so the caller propagates the zero-on-drop guarantee.
///
/// `kSecret  = "AWS4" + secret_access_key`
/// `kDate    = HMAC-SHA256(kSecret, date_stamp_YYYYMMDD)`
/// `kRegion  = HMAC-SHA256(kDate, region)`
/// `kService = HMAC-SHA256(kRegion, service)`
/// `kSigning = HMAC-SHA256(kService, "aws4_request")`
///
/// All intermediate derived keys (`kDate`, `kRegion`, `kService`) are
/// also wrapped in `Zeroizing` so they scrub on drop at end-of-function.
fn derive_signing_key(
    secret: &str,
    date_stamp: &str,
    region: &str,
    service: &str,
) -> Zeroizing<[u8; 32]> {
    // `kSecret = "AWS4" + secret`. `String::with_capacity` pre-allocates so
    // the `push_str` calls below cannot trigger a reallocation that would
    // leave the original buffer un-scrubbed.
    let mut k_secret = String::with_capacity(4 + secret.len());
    k_secret.push_str("AWS4");
    k_secret.push_str(secret);

    let k_date = hmac_sha256(k_secret.as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&*k_date, region.as_bytes());
    let k_service = hmac_sha256(&*k_region, service.as_bytes());
    let k_signing = hmac_sha256(&*k_service, TERMINATOR.as_bytes());

    // Explicitly scrub the kSecret String before drop. The derived
    // intermediates (k_date / k_region / k_service) are already
    // `Zeroizing` and will scrub when this function returns.
    k_secret.zeroize();

    k_signing
}

/// Convert `SystemTime` → `chrono::DateTime<Utc>`. Returns `None` if the
/// instant is outside chrono's representable range (essentially the year
/// 0–9999 window), which is unreachable in practice for any clock-derived
/// `SystemTime`.
fn systemtime_to_utc(t: SystemTime) -> Option<DateTime<Utc>> {
    let duration = t.duration_since(SystemTime::UNIX_EPOCH).ok()?;
    let secs = i64::try_from(duration.as_secs()).ok()?;
    let nanos = duration.subsec_nanos();
    DateTime::<Utc>::from_timestamp(secs, nanos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    // The AWS-published reference example. These values are pinned in the
    // SigV4 docs: https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
    //
    // Using them in unit tests gives us a fast smoke signal independent
    // of the larger corpus runner.
    const TEST_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
    const TEST_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const TEST_REGION: &str = "us-east-1";

    fn fixed_credentials() -> ResolvedCredentials {
        ResolvedCredentials {
            access_key_id: TEST_ACCESS_KEY.to_string(),
            secret_access_key: TEST_SECRET_KEY.to_string(),
            session_token: None,
        }
    }

    fn fixed_signing_time() -> DateTime<Utc> {
        // 2013-05-24T00:00:00Z — the timestamp AWS uses in its published
        // worked examples.
        Utc.with_ymd_and_hms(2013, 5, 24, 0, 0, 0).unwrap()
    }

    // -- TC-SIG-001 ---------------------------------------------------------
    #[test]
    fn unreserved_set_matches_rfc3986() {
        for b in 0u8..=127 {
            let expected = matches!(b,
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~');
            assert_eq!(
                is_unreserved(b),
                expected,
                "is_unreserved({}) mismatch",
                b as char
            );
        }
    }

    // -- TC-SIG-002 ---------------------------------------------------------
    #[test]
    fn canonical_uri_preserves_slash_separator() {
        assert_eq!(canonical_uri("/"), "/");
        assert_eq!(canonical_uri("/foo/bar"), "/foo/bar");
        assert_eq!(canonical_uri("/foo bar"), "/foo%20bar");
        // Empty path is normalized to "/".
        assert_eq!(canonical_uri(""), "/");
    }

    // -- TC-SIG-003 ---------------------------------------------------------
    #[test]
    fn canonical_uri_encodes_non_unreserved_bytes() {
        assert_eq!(canonical_uri("/key with spaces"), "/key%20with%20spaces");
        // Multi-byte UTF-8 codepoint (é = 0xC3 0xA9) is encoded byte-by-byte.
        assert_eq!(canonical_uri("/café"), "/caf%C3%A9");
    }

    // -- TC-SIG-004 ---------------------------------------------------------
    #[test]
    fn canonical_query_string_sorts_and_encodes() {
        let q = vec![
            ("b".to_string(), "2".to_string()),
            ("a".to_string(), "1".to_string()),
            ("a".to_string(), "0".to_string()),
        ];
        // Sort by key, then value, ascending.
        assert_eq!(canonical_query_string(&q), "a=0&a=1&b=2");
    }

    // -- TC-SIG-005 ---------------------------------------------------------
    #[test]
    fn canonical_query_string_encodes_both_keys_and_values() {
        let q = vec![("foo bar".to_string(), "baz qux".to_string())];
        assert_eq!(canonical_query_string(&q), "foo%20bar=baz%20qux");
    }

    // -- TC-SIG-006 ---------------------------------------------------------
    #[test]
    fn canonical_query_string_empty_is_empty() {
        assert_eq!(canonical_query_string(&[]), "");
    }

    // -- TC-SIG-007 ---------------------------------------------------------
    #[test]
    fn canonical_headers_lowercases_and_sorts() {
        let h = vec![
            ("X-Amz-Date".to_string(), "20130524T000000Z".to_string()),
            (
                "Host".to_string(),
                "examplebucket.s3.amazonaws.com".to_string(),
            ),
        ];
        let (canonical, signed) = canonical_headers_and_signed(&h);
        assert!(canonical.starts_with("host:examplebucket.s3.amazonaws.com\n"));
        assert!(canonical.contains("x-amz-date:20130524T000000Z\n"));
        assert_eq!(signed, "host;x-amz-date");
    }

    // -- TC-SIG-008 ---------------------------------------------------------
    #[test]
    fn header_value_normalization_collapses_whitespace() {
        // Leading + trailing whitespace stripped.
        assert_eq!(normalize_header_value("  hello  "), "hello");
        // Internal runs of whitespace collapsed to single space.
        assert_eq!(normalize_header_value("foo   bar"), "foo bar");
        assert_eq!(normalize_header_value("foo\t\tbar"), "foo bar");
        // Single space preserved.
        assert_eq!(normalize_header_value("foo bar"), "foo bar");
    }

    // -- TC-SIG-009 ---------------------------------------------------------
    #[test]
    fn hex_sha256_of_empty_payload_matches_aws_constant() {
        // AWS hard-codes this hash for the "empty payload" case. We always
        // compute it explicitly; this assertion is the safety net that
        // catches any future drift in the sha2 dep.
        assert_eq!(
            hex_sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // -- TC-SIG-010 ---------------------------------------------------------
    // AWS published reference: GET / on examplebucket.s3.amazonaws.com.
    // Source: https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
    #[test]
    fn signing_key_derivation_matches_aws_reference() {
        let signing_key =
            derive_signing_key(TEST_SECRET_KEY, "20130524", TEST_REGION, DEFAULT_SERVICE);
        // The hex-encoded kSigning AWS publishes for this date+region+service.
        let expected = "dbb893acc010964918f1fd433add87c70e8b0db6be30c1fbeafefa5ec6ba8378";
        assert_eq!(hex::encode(signing_key), expected);
    }

    // -- TC-SIG-011 ---------------------------------------------------------
    // AWS published reference: HEAD / on examplebucket.s3.amazonaws.com,
    // 2013-05-24T00:00:00Z, anonymous payload-hash form.
    #[test]
    fn debug_sign_components_match_aws_reference_get_object() {
        let signer = Signer::new(TEST_REGION.to_string());
        let credentials = fixed_credentials();
        let signing_dt = fixed_signing_time();
        let headers = vec![
            (
                "Host".to_string(),
                "examplebucket.s3.amazonaws.com".to_string(),
            ),
            ("Range".to_string(), "bytes=0-9".to_string()),
            (
                "x-amz-content-sha256".to_string(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            ),
            ("x-amz-date".to_string(), "20130524T000000Z".to_string()),
        ];
        let (canonical, _string_to_sign, signature) = signer.debug_sign_components(
            "GET",
            "/test.txt",
            &[],
            &headers,
            b"",
            &credentials,
            signing_dt,
        );

        // Canonical request for this example (AWS published).
        let expected_canonical = "GET\n\
/test.txt\n\
\n\
host:examplebucket.s3.amazonaws.com\n\
range:bytes=0-9\n\
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
x-amz-date:20130524T000000Z\n\
\n\
host;range;x-amz-content-sha256;x-amz-date\n\
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        assert_eq!(canonical, expected_canonical);
        // AWS published signature for the GET-with-range example.
        assert_eq!(
            signature,
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    // -- TC-SIG-012 ---------------------------------------------------------
    #[test]
    fn sign_mutates_headers_to_add_authorization_and_amz_date() {
        let signer = Signer::new(TEST_REGION.to_string());
        let credentials = fixed_credentials();
        let mut headers = vec![(
            "host".to_string(),
            "examplebucket.s3.amazonaws.com".to_string(),
        )];
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_369_353_600); // 2013-05-24

        signer
            .sign("GET", "/", &[], &mut headers, b"", &credentials, now)
            .expect("sign succeeds");

        let names: Vec<&str> = headers.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"x-amz-date"));
        assert!(names.contains(&"x-amz-content-sha256"));
        assert!(names.contains(&"authorization"));
        // Session token NOT added for static creds.
        assert!(!names.contains(&"x-amz-security-token"));

        let auth = headers
            .iter()
            .find(|(n, _)| n == "authorization")
            .map(|(_, v)| v.as_str())
            .unwrap();
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/"));
        assert!(auth.contains("SignedHeaders="));
        assert!(auth.contains("Signature="));
    }

    // -- TC-SIG-013 ---------------------------------------------------------
    #[test]
    fn sign_adds_security_token_header_for_session_credentials() {
        let signer = Signer::new(TEST_REGION.to_string());
        let credentials = ResolvedCredentials {
            access_key_id: TEST_ACCESS_KEY.to_string(),
            secret_access_key: TEST_SECRET_KEY.to_string(),
            session_token: Some("FwoGZXIvYXdz...".to_string()),
        };
        let mut headers = vec![("host".to_string(), "example.com".to_string())];
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_369_353_600);

        signer
            .sign("GET", "/", &[], &mut headers, b"", &credentials, now)
            .expect("sign succeeds");

        let token = headers
            .iter()
            .find(|(n, _)| n == "x-amz-security-token")
            .map(|(_, v)| v.as_str());
        assert_eq!(token, Some("FwoGZXIvYXdz..."));
    }

    // -- TC-SIG-014 ---------------------------------------------------------
    #[test]
    fn debug_redacts_secret_access_key_and_session_token() {
        let creds = ResolvedCredentials {
            access_key_id: "AKIA-public".to_string(),
            secret_access_key: "SUPER-SECRET-KEY-VALUE".to_string(),
            session_token: Some("SUPER-SECRET-SESSION-TOKEN".to_string()),
        };
        let formatted = format!("{creds:?}");
        // The access_key_id is documented-non-secret per AWS posture.
        assert!(formatted.contains("AKIA-public"));
        // The secret values must NOT appear in Debug output.
        assert!(!formatted.contains("SUPER-SECRET-KEY-VALUE"));
        assert!(!formatted.contains("SUPER-SECRET-SESSION-TOKEN"));
        assert!(formatted.contains("<redacted>"));
    }
}
