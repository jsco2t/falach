# AWS SigV4 Test Vectors — Source and Vendoring Procedure

The `aws_sigv4_vectors/` subdirectory contains the AWS-published SigV4
test corpus, used by `tests/sigv4_aws_test_vectors.rs` as the CI gate
for `crates/falach-sync/src/s3/signer.rs`.

## Source

- **Upstream repo:** [awslabs/aws-sdk-rust](https://github.com/awslabs/aws-sdk-rust)
- **Path in upstream:** `sdk/aws-sigv4/aws-signing-test-suite/v4/`
- **Vendored at commit:** `d494917f241247c9d5848455352181fde0965c8b` (main, 2026-05-28)
- **License:** Apache-2.0 (matches the rest of `aws-sdk-rust`; permissive,
  on the deny.toml allowlist)

## Directory layout

Each test case is a directory named after the scenario it covers
(`get-vanilla`, `get-utf8`, `post-x-www-form-urlencoded`, etc.). Each
directory contains:

- `context.json` — credentials, region, service, signing-timestamp, and
  flags (`normalize`, `sign_body`).
- `request.txt` — the raw HTTP/1.1 request input.
- `header-canonical-request.txt` — expected canonical-request string.
- `header-string-to-sign.txt` — expected string-to-sign.
- `header-signature.txt` — expected hex signature.
- `header-signed-request.txt` — expected fully-signed request.
- `query-*.txt` — analogous files for **query-string signing** (presigned
  URLs). **NOT vendored** because Falach does not use presigned URLs
  (design.md §1.3 explicitly defers them); only the `header-*` files are
  fetched.

## Vendoring procedure

To re-vendor against a new upstream commit:

1. Look up the latest commit hash on `awslabs/aws-sdk-rust`'s `main`
   branch (e.g. via `https://api.github.com/repos/awslabs/aws-sdk-rust/branches/main`).
2. Run `bash tools/dev/fetch-sigv4-corpus.sh <COMMIT_HASH>` from the repo
   root. (No argument defaults to `main`; passing the explicit hash is
   the recommended workflow because the **Vendored at commit** line
   below must be updated to match.)
3. Diff the resulting `aws_sigv4_vectors/` tree against the previous one;
   investigate any unexpected changes before committing.
4. Update the **Vendored at commit** field in this file.
5. Re-run `make test-sigv4` to verify our signer still matches the new
   corpus.

The fetch script ([`tools/dev/fetch-sigv4-corpus.sh`](../../../../tools/dev/fetch-sigv4-corpus.sh))
is the canonical source of the test-directory list and the per-test file
list. Refer to that script for the exact `TESTS=( ... )` and `FILES=( ... )`
arrays; this doc intentionally does not duplicate them so the two never
drift.

## Tests we run vs. tests we skip

Of the 40 v4 corpus directories, the runner exercises ~15 — the rest
are skipped because they require features Falach does not implement.
The authoritative list with per-directory rationale lives in the
`SKIPPED_TESTS` constant of
`crates/falach-sync/tests/sigv4_aws_test_vectors.rs`; the categories
are:

- **Path normalization** (`get-relative-*`, `get-slash-dot-slash-*`,
  `get-slash-pointless-dot-*`, `get-slashes-*`, `get-slash-*`) —
  Falach deliberately does NOT normalize URI paths. S3 keys can
  legitimately contain `..` or `.` as literal characters; collapsing
  them would corrupt object keys.
- **Path-component decoding before re-encoding** (`double-encode-path`,
  `double-url-encode`) — same rationale; we pass the path through to
  the canonical-request encoder verbatim and let it RFC-3986-encode
  any non-unreserved bytes.
- **Multi-line header LWS continuation** (`get-header-value-multiline`)
  — RFC 7230 §3.2.4 deprecated header-folding via leading whitespace
  on continuation lines; we don't emit it and AWS SDKs only test
  against synthetic input.
- **`UNSIGNED-PAYLOAD` mode** (the `post-*` family — `post-vanilla`,
  `post-vanilla-query`, `post-vanilla-empty-query-value`,
  `post-header-key-case`, `post-header-key-sort`,
  `post-header-value-case`, `post-sts-header-after`,
  `post-sts-header-before`, `post-x-www-form-urlencoded`,
  `post-x-www-form-urlencoded-parameters`) — these tests run with
  `context.json` `sign_body: false`, which produces the literal
  `UNSIGNED-PAYLOAD` body-hash sentinel. We always sign the body
  explicitly with hex-SHA256 — the strictest mode and the only mode
  all S3-compatible backends universally accept (in particular
  MinIO's SigV4 parser requires it).
- **Query-string signing** (`query-*.txt` files inside each test
  directory) — we don't use presigned URLs in Phase 0; the
  vendoring script does not fetch these files.

The runner asserts that the count of *unknown* directories (present
in the corpus but neither matched by the runner's logic nor listed in
`SKIPPED_TESTS`) is zero — so if a new directory appears in a future
upstream commit, the runner fails loudly and the maintainer
classifies it explicitly.
