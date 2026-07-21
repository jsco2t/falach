// See `crates/falach-sync/src/s3/mod.rs` for the rationale on allowing
// `clippy::doc_markdown` in the s3 wire-protocol layer.
#![allow(clippy::doc_markdown)]

//! AWS-published SigV4 test corpus runner (T2.2 / TC-VEC-CORPUS).
//!
//! Walks every test directory under
//! `tests/data/aws_sigv4_vectors/` and verifies that
//! [`falach_sync::s3::signer::Signer`] produces canonical-request and
//! signature outputs matching the upstream-published expected values.
//!
//! See `tests/data/AWS_SIGV4_VECTORS_SOURCE.md` for source provenance,
//! the vendoring procedure, and the rationale for skipped tests.
//!
//! # CI gate
//!
//! `make test-sigv4` invokes only this test file. The CI workflow runs it
//! independently of the broader unit-test suite so a SigV4 encoding bug
//! produces a fast, well-isolated failure signal.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use falach_sync::s3::signer::{ResolvedCredentials, Signer};

/// The set of test directories we deliberately skip, with one-line
/// rationales. Any directory present in the corpus but NOT in this list
/// must be processed by the runner — surfacing new tests as deliberate
/// reviewer decisions.
const SKIPPED_TESTS: &[(&str, &str)] = &[
    // Path-normalization tests. Falach does not collapse `..` or `.`
    // path components because S3 keys can legitimately contain them.
    (
        "get-relative-normalized",
        "path normalization not supported",
    ),
    (
        "get-relative-relative-normalized",
        "path normalization not supported",
    ),
    (
        "get-relative-relative-unnormalized",
        "path normalization not supported",
    ),
    (
        "get-relative-unnormalized",
        "path normalization not supported",
    ),
    (
        "get-slash-dot-slash-normalized",
        "path normalization not supported",
    ),
    (
        "get-slash-dot-slash-unnormalized",
        "path normalization not supported",
    ),
    (
        "get-slash-pointless-dot-normalized",
        "path normalization not supported",
    ),
    (
        "get-slash-pointless-dot-unnormalized",
        "path normalization not supported",
    ),
    // The `get-slashes-*` and `get-slash-normalized`/`unnormalized` tests
    // collapse runs of slashes; same rationale.
    ("get-slashes-normalized", "path normalization not supported"),
    (
        "get-slashes-unnormalized",
        "path normalization not supported",
    ),
    ("get-slash-normalized", "path normalization not supported"),
    ("get-slash-unnormalized", "path normalization not supported"),
    // Double-encoded-path tests assume the SDK decodes the input path
    // before re-encoding. We pass the path through verbatim.
    (
        "double-encode-path",
        "double-encoding decode/re-encode not supported",
    ),
    (
        "double-url-encode",
        "double-encoding decode/re-encode not supported",
    ),
    // Header-value-multiline tests assume the SDK reads multi-line header
    // values (LWS continuation lines per RFC 7230 §3.2.4). HTTP/1.1
    // deprecated this; we don't emit multi-line headers and the AWS SDK
    // tests them only against synthetic input.
    (
        "get-header-value-multiline",
        "multi-line header LWS continuation not supported",
    ),
    // POST with `sign_body: false` produces `UNSIGNED-PAYLOAD` as the
    // body hash. We always sign the body with explicit hex-SHA256 — the
    // strictest mode and the one MinIO requires.
    (
        "post-vanilla",
        "POST with sign_body=false (UNSIGNED-PAYLOAD) not supported",
    ),
    (
        "post-vanilla-query",
        "POST with sign_body=false (UNSIGNED-PAYLOAD) not supported",
    ),
    (
        "post-vanilla-empty-query-value",
        "POST with sign_body=false (UNSIGNED-PAYLOAD) not supported",
    ),
    (
        "post-header-key-case",
        "POST with sign_body=false (UNSIGNED-PAYLOAD) not supported",
    ),
    (
        "post-header-key-sort",
        "POST with sign_body=false (UNSIGNED-PAYLOAD) not supported",
    ),
    (
        "post-header-value-case",
        "POST with sign_body=false (UNSIGNED-PAYLOAD) not supported",
    ),
    (
        "post-sts-header-after",
        "POST with sign_body=false (UNSIGNED-PAYLOAD) not supported",
    ),
    (
        "post-sts-header-before",
        "POST with sign_body=false (UNSIGNED-PAYLOAD) not supported",
    ),
    (
        "post-x-www-form-urlencoded",
        "POST with sign_body=false (UNSIGNED-PAYLOAD) not supported",
    ),
    (
        "post-x-www-form-urlencoded-parameters",
        "POST with sign_body=false (UNSIGNED-PAYLOAD) not supported",
    ),
];

/// A single test case parsed from a corpus directory.
struct VectorTest {
    name: String,
    /// Parsed from `request.txt`.
    method: String,
    path: String,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// Parsed from `context.json`.
    credentials: ResolvedCredentials,
    region: String,
    service: String,
    timestamp: DateTime<Utc>,
    /// Expected outputs (with trailing newlines stripped).
    expected_canonical: String,
    expected_signature: String,
}

/// Tighten this as the applicable-test count grows. Bumping the lower
/// bound is the documented signal that a re-vendoring of the corpus
/// altered the applicable set (see AWS_SIGV4_VECTORS_SOURCE.md vendoring
/// procedure). A botched vendor that dropped most of the tree would
/// satisfy a looser `>= 5` and silently weaken the CI gate.
const MIN_APPLICABLE: usize = 15;

#[test]
fn aws_published_sigv4_corpus_matches_our_signer() {
    let corpus_dir = corpus_root();
    let mut applicable = 0;
    let mut skipped = 0;
    let mut failures: Vec<String> = Vec::new();
    let mut unknown_dirs: Vec<String> = Vec::new();

    let entries: Vec<_> = fs::read_dir(&corpus_dir)
        .expect(
            "corpus directory missing; see crates/falach-sync/tests/data/\
             AWS_SIGV4_VECTORS_SOURCE.md or run `tools/dev/fetch-sigv4-corpus.sh` \
             to re-vendor the AWS SigV4 published test vectors",
        )
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .collect();

    assert!(
        !entries.is_empty(),
        "corpus directory is empty — see tests/data/AWS_SIGV4_VECTORS_SOURCE.md"
    );

    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .expect("test directory name is UTF-8");
        if let Some((_, reason)) = SKIPPED_TESTS.iter().find(|(n, _)| *n == name) {
            skipped += 1;
            eprintln!("SKIP {name}: {reason}");
            continue;
        }

        let test = match load_test(&entry.path(), &name) {
            Ok(t) => t,
            Err(err) => {
                // A missing file usually means this directory wasn't in
                // the vendored set (corpus has tests we didn't fetch).
                // That's distinct from a skip — surface it for review.
                unknown_dirs.push(format!("{name}: {err}"));
                continue;
            }
        };

        applicable += 1;
        if let Err(msg) = run_test(&test) {
            failures.push(format!("{name}: {msg}"));
        }
    }

    eprintln!(
        "AWS SigV4 corpus: {applicable} ran, {skipped} skipped, {} failed, {} unknown",
        failures.len(),
        unknown_dirs.len()
    );

    assert!(
        unknown_dirs.is_empty(),
        "corpus directories present but not vendored or classified:\n  {}\n\
            update SKIPPED_TESTS or re-run the fetch script to add them.",
        unknown_dirs.join("\n  ")
    );

    assert!(
        failures.is_empty(),
        "SigV4 corpus failures ({} of {applicable} applicable):\n  {}",
        failures.len(),
        failures.join("\n  ")
    );

    assert!(
        applicable >= MIN_APPLICABLE,
        "expected at least {MIN_APPLICABLE} applicable corpus tests; got {applicable}. \
         If you intentionally re-vendored against a corpus with a smaller applicable \
         set, lower MIN_APPLICABLE and document the rationale in \
         crates/falach-sync/tests/data/AWS_SIGV4_VECTORS_SOURCE.md."
    );
}

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("aws_sigv4_vectors")
}

fn load_test(dir: &Path, name: &str) -> Result<VectorTest, String> {
    let request_raw =
        fs::read_to_string(dir.join("request.txt")).map_err(|e| format!("request.txt: {e}"))?;
    let context_raw =
        fs::read_to_string(dir.join("context.json")).map_err(|e| format!("context.json: {e}"))?;
    let expected_canonical = fs::read_to_string(dir.join("header-canonical-request.txt"))
        .map_err(|e| format!("header-canonical-request.txt: {e}"))?
        .trim_end()
        .to_string();
    let expected_signature = fs::read_to_string(dir.join("header-signature.txt"))
        .map_err(|e| format!("header-signature.txt: {e}"))?
        .trim()
        .to_string();

    let context = parse_context(&context_raw).map_err(|e| format!("context.json: {e}"))?;
    let (method, path, query, headers, body) =
        parse_request(&request_raw).map_err(|e| format!("request.txt: {e}"))?;

    Ok(VectorTest {
        name: name.to_string(),
        method,
        path,
        query,
        headers,
        body,
        credentials: context.credentials,
        region: context.region,
        service: context.service,
        timestamp: context.timestamp,
        expected_canonical,
        expected_signature,
    })
}

struct Context {
    credentials: ResolvedCredentials,
    region: String,
    service: String,
    timestamp: DateTime<Utc>,
}

/// Hand-rolled minimal JSON parser for the test corpus's `context.json`
/// files. Avoids adding `serde_json` as a falach-sync dev-dep just for
/// this one runner; the corpus's JSON is shape-stable.
fn parse_context(src: &str) -> Result<Context, String> {
    let access_key_id = extract_string(src, "access_key_id")?;
    let secret_access_key = extract_string(src, "secret_access_key")?;
    let session_token = extract_string(src, "token").ok();
    let region = extract_string(src, "region")?;
    let service = extract_string(src, "service")?;
    let timestamp_str = extract_string(src, "timestamp")?;

    let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
        .map_err(|e| format!("bad timestamp `{timestamp_str}`: {e}"))?
        .with_timezone(&Utc);

    Ok(Context {
        credentials: ResolvedCredentials {
            access_key_id,
            secret_access_key,
            session_token,
        },
        region,
        service,
        timestamp,
    })
}

/// Extract a `"field": "value"` pair's value from a flat JSON object.
/// Returns `Err` if the field is missing; `Err(...)` from `.ok()` callers
/// signals "field not present".
fn extract_string(src: &str, field: &str) -> Result<String, String> {
    let needle = format!("\"{field}\"");
    let idx = src
        .find(&needle)
        .ok_or_else(|| format!("missing {field}"))?;
    let after_field = &src[idx + needle.len()..];
    // Skip whitespace + colon + whitespace, then expect a quoted string.
    let after_colon = after_field
        .trim_start()
        .strip_prefix(':')
        .ok_or_else(|| format!("missing colon after {field}"))?;
    let after_open = after_colon
        .trim_start()
        .strip_prefix('"')
        .ok_or_else(|| format!("expected string value for {field}"))?;
    let end = after_open
        .find('"')
        .ok_or_else(|| format!("unterminated string for {field}"))?;
    Ok(after_open[..end].to_string())
}

/// Parse an HTTP/1.1 request from the AWS corpus's `request.txt` format.
///
/// Returns `(method, path, query, headers, body)`.
#[allow(clippy::type_complexity)]
fn parse_request(
    src: &str,
) -> Result<
    (
        String,
        String,
        Vec<(String, String)>,
        Vec<(String, String)>,
        Vec<u8>,
    ),
    String,
> {
    // Split request from body at the first empty line.
    let (head, body) = match src.split_once("\r\n\r\n") {
        Some((h, b)) => (h, b),
        None => match src.split_once("\n\n") {
            Some((h, b)) => (h, b),
            None => (src, ""),
        },
    };

    let mut lines = head
        .split('\n')
        .map(|s| s.trim_end_matches('\r'))
        .filter(|s| !s.is_empty());

    let request_line = lines.next().ok_or("empty request")?;
    // Request line format: `<METHOD> <URI> HTTP/<version>`. URI may
    // contain literal spaces (the AWS corpus tests this edge case), so
    // split on the FIRST space (after method) and the LAST ` HTTP/`
    // sequence rather than naively splitting whitespace.
    let first_space = request_line
        .find(' ')
        .ok_or("malformed request line: no spaces")?;
    let method = request_line[..first_space].to_string();
    let after_method = &request_line[first_space + 1..];
    let http_marker = after_method
        .rfind(" HTTP/")
        .ok_or("malformed request line: no HTTP/ marker")?;
    let raw_uri = &after_method[..http_marker];

    let (path, query) = split_path_query(raw_uri);

    let mut headers = Vec::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| format!("malformed header line `{line}`: missing colon"))?;
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }

    Ok((method, path, query, headers, body.as_bytes().to_vec()))
}

/// Split `/path?key=value&key2=value2` into `("/path", [(key, value), ...])`.
fn split_path_query(uri: &str) -> (String, Vec<(String, String)>) {
    let (path, query_str) = uri.split_once('?').unwrap_or((uri, ""));
    let mut query = Vec::new();
    if !query_str.is_empty() {
        for pair in query_str.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            query.push((url_decode(k), url_decode(v)));
        }
    }
    (path.to_string(), query)
}

/// Minimal RFC 3986 percent-decoder. Decodes `%XX` byte sequences;
/// passes other characters through.
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn run_test(test: &VectorTest) -> Result<(), String> {
    // Pre-build the headers list with the SigV4-injected `x-amz-date`,
    // `x-amz-content-sha256`, and optional `x-amz-security-token` BEFORE
    // calling debug_sign_components — that helper expects the full
    // signed-headers set as input (it doesn't mutate headers like
    // Signer::sign does).
    let amz_date = test.timestamp.format("%Y%m%dT%H%M%SZ").to_string();
    let payload_hash = hex_sha256(&test.body);

    let mut headers: Vec<(String, String)> = test.headers.clone();
    headers.push(("x-amz-date".to_string(), amz_date));
    if let Some(token) = &test.credentials.session_token {
        headers.push(("x-amz-security-token".to_string(), token.clone()));
    }

    // The AWS corpus's canonical-request expects the `x-amz-content-sha256`
    // header ONLY when the test's expected canonical-request includes it.
    // The vendored corpus's `service: "service"` tests don't include the
    // header in the expected output (it's an S3-specific convention).
    // Add it ONLY when the expected canonical-request mentions it.
    let needs_content_sha256 = test.expected_canonical.contains("x-amz-content-sha256");
    if needs_content_sha256 {
        headers.push(("x-amz-content-sha256".to_string(), payload_hash));
    }

    let signer = Signer::with_service(test.region.clone(), test.service.clone());
    let (canonical_request, _string_to_sign, signature) = signer.debug_sign_components(
        &test.method,
        &test.path,
        &test.query,
        &headers,
        &test.body,
        &test.credentials,
        test.timestamp,
    );

    if canonical_request != test.expected_canonical {
        return Err(format!(
            "canonical-request mismatch\n  expected: {:?}\n  got: {:?}",
            test.expected_canonical, canonical_request
        ));
    }
    if signature != test.expected_signature {
        return Err(format!(
            "signature mismatch (expected {}, got {}) for test {}",
            test.expected_signature, signature, test.name
        ));
    }

    Ok(())
}

fn hex_sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}
