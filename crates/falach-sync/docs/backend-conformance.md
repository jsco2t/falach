# S3-compatible backend conformance matrix

Falach's sync transport targets the **lowest-common-denominator S3 wire
subset** (FR-047): SigV4 auth; single-object `PUT` / `GET` / `HEAD` /
`DELETE`; virtual-hosted *and* path-style addressing; `If-None-Match` on GET;
`If-Match` on PUT (with graceful degradation where unsupported); ETag as the
content version. This document records which backends are *verified*, which
are *best-effort documented*, and any known issues.

Verification status is one of:

- **CI** — exercised on every PR by `make test-s3-integration` against the
  pinned MinIO container (see `tools/sync-tests/fixtures/MINIO_VERSION.md`).
- **Release** — manually verified at release time against a real account.
- **Best-effort** — documented from vendor docs / community reports; not yet
  run by the maintainers. Contributions welcome.

## Matrix

| Feature | AWS S3 | MinIO | Cloudflare R2 | Backblaze B2 (S3) | Wasabi | Garage | SeaweedFS |
| ------- | ------ | ----- | ------------- | ----------------- | ------ | ------ | --------- |
| SigV4 authentication | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Virtual-hosted addressing | ✓ | ✓ | ✓ | ✓ | ✓ | depends | depends |
| Path-style addressing | ✓ (deprecating) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Single-PUT (≤ 5 GB) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| GET with `If-None-Match` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| PUT with `If-Match` (conditional PUT) | ✓ (2024-11+) | ✓ | ✓ | partial | partial | verify | verify |
| ETag = MD5-hex for single-PUT | ✓ | ✓ | ✓ | mostly | ✓ | ✓ | verify |
| **Verification status** | **Release** | **CI** | Best-effort | Best-effort | Best-effort | Best-effort | Best-effort |

Legend: ✓ supported · *partial* known-incomplete · *depends* deployment-specific
· *verify* unconfirmed (conformance-test target) · *mostly* generally true with
edge cases.

## Notes per backend

### AWS S3 — verified at release

The permissive reference implementation. AWS's SigV4 parser tolerates some
canonical-request encoding sloppiness that stricter backends reject, so AWS
passing is *necessary but not sufficient* — MinIO is the strict gate. `If-Match`
on `PutObject` became generally available 2024-11; older SDKs/regions without
it fall through to the FR-047 degraded path. Not run in PR CI (a real account
is paid; OQ-3 resolution: manual at release only).

### MinIO — verified in CI (strict gate)

The strict SigV4 implementation; rejects encoding bugs AWS silently accepts.
This is the PR-CI backend (`integration-s3` job). One verified-by-test nuance:
a `PUT` with a bogus `If-Match` against a **non-existent** key returns **404
No Such Key** (not 412) — MinIO checks object existence before the
precondition. The sentinel-key probe (ADR-5) treats *any* rejection (404 or
412) as "enforces `If-Match`" → `Supported` (see `transport::s3` +
MINIO-006 / TC-S3T-009b).

### Cloudflare R2 — best-effort

Supports SigV4, both addressing styles, and conditional writes per Cloudflare's
S3-compatibility docs. Not yet maintainer-verified.

### Backblaze B2 (S3-compatible endpoint) — best-effort

Core PUT/GET/HEAD/DELETE + SigV4 work. `If-Match` support has historically been
partial; if the sentinel probe classifies B2 as `Degraded`, Falach uses the
read-then-PUT-then-HEAD-compare path and relies on `.kdbx.bak` for the small
race window.

### Wasabi — best-effort

S3-compatible; `If-Match` support reported partial. Same degraded-path note as
B2.

### Garage / SeaweedFS (self-hosted) — best-effort

Both implement the core subset and path-style addressing (the sensible default
for self-hosted). Virtual-hosted addressing and `If-Match` enforcement are
deployment- and version-dependent — set `path_style = true` and let the probe
classify `If-Match`. Marked *verify* pending a maintainer or community run.

## Extending this matrix

Run the integration suite against your backend by pointing the
`FALACH_MINIO_*` env vars at it (any SigV4 endpoint works, not just MinIO) and
running `make test-s3-integration`. Record the results — especially the
`If-Match` PUT and ETag-format rows — and open a PR updating the row.
