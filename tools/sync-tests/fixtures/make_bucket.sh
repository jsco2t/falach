#!/usr/bin/env bash
# make_bucket.sh <bucket-name> — create a fresh bucket in the running MinIO.
#
# Idempotent: creating an existing bucket is treated as success (mc's
# `--ignore-existing` flag). Uses the MinIO client `mc`; reads the
# endpoint + credentials from the env file start_minio.sh wrote (or from
# the FALACH_MINIO_* env vars if already exported).
#
# Why mc and not our own S3 client: bootstrapping the bucket with the very
# code under test would be circular (a signer bug could mask a signer bug).
# `mc` is an independent, AWS-compatible implementation. See
# 06-minio-and-conformance.md T6.1 technical notes.
#
# Usage:
#   tools/sync-tests/fixtures/make_bucket.sh my-bucket
set -euo pipefail

if [ "$#" -ne 1 ]; then
	echo "usage: make_bucket.sh <bucket-name>" >&2
	exit 2
fi
BUCKET="$1"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.minio-env"

# Pick up endpoint + credentials: prefer already-exported env, else source
# the file start_minio.sh generated.
if [ -z "${FALACH_MINIO_ENDPOINT:-}" ] && [ -f "$ENV_FILE" ]; then
	# shellcheck disable=SC1090
	. "$ENV_FILE"
fi
: "${FALACH_MINIO_ENDPOINT:?run start_minio.sh first (FALACH_MINIO_ENDPOINT unset)}"
: "${FALACH_MINIO_ACCESS_KEY:?FALACH_MINIO_ACCESS_KEY unset}"
: "${FALACH_MINIO_SECRET_KEY:?FALACH_MINIO_SECRET_KEY unset}"

if ! command -v mc >/dev/null 2>&1; then
	echo "make_bucket.sh: 'mc' (MinIO client) not found on PATH." >&2
	echo "  Install it: https://min.io/docs/minio/linux/reference/minio-mc.html" >&2
	exit 1
fi

# A private alias name so we don't clobber the developer's own mc config.
ALIAS="falach-test"
mc alias set "$ALIAS" "$FALACH_MINIO_ENDPOINT" \
	"$FALACH_MINIO_ACCESS_KEY" "$FALACH_MINIO_SECRET_KEY" >/dev/null

# `--ignore-existing` makes re-creation a no-op success.
mc mb --ignore-existing "${ALIAS}/${BUCKET}" >/dev/null
echo "make_bucket.sh: bucket '${BUCKET}' ready."
