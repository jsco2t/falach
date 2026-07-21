# Pinned MinIO version

The s3-sync integration tests run against a **pinned** MinIO container image
— never `:latest`. Pinning keeps the per-backend conformance baseline
(`crates/falach-sync/docs/backend-conformance.md`) reproducible and stops a
silent upstream behaviour change (SigV4 strictness, `If-Match` semantics,
ETag format) from turning a green CI run red without a corresponding commit.

| Field | Value |
| ----- | ----- |
| Image | `minio/minio:RELEASE.2025-09-07T16-13-09Z` |
| `mc` (client) | `RELEASE.2025-08-13T08-35-41Z` or newer (used only to create buckets) |
| Pinned on | 2026-05-29 (s3-sync T6.1) |
| Resolves OQ-2 | follow-ups/open-items.md |

The tag is referenced in:

- `tools/sync-tests/fixtures/start_minio.sh` (`MINIO_IMAGE`)
- `.github/workflows/ci.yml` (the `integration-s3` job's service image)

## Upgrade procedure

1. Pick the new tag from <https://hub.docker.com/r/minio/minio/tags> (use the
   `RELEASE.<date>` form, not `:latest`).
2. Update `MINIO_IMAGE` in `start_minio.sh` **and** the image in
   `.github/workflows/ci.yml` — they must match.
3. Update the table above (Image + Pinned-on date).
4. Run `make minio-up && make test-s3-integration && make minio-down`
   locally; all MINIO-* tests must stay green.
5. Re-check the conformance matrix doc — if the new release changes a
   capability (e.g. enables `If-Match` where a prior release degraded),
   update the MinIO column there.
