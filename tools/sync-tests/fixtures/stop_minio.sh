#!/usr/bin/env bash
# stop_minio.sh — tear down the MinIO container started by start_minio.sh.
#
# Stops and removes the container and deletes the generated env file.
# Safe to run when nothing is running (no-ops).
#
# Usage:
#   tools/sync-tests/fixtures/stop_minio.sh
set -euo pipefail

CONTAINER="falach-minio"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.minio-env"

if command -v docker >/dev/null 2>&1; then
	ENGINE="docker"
elif command -v podman >/dev/null 2>&1; then
	ENGINE="podman"
else
	echo "stop_minio.sh: neither docker nor podman found on PATH" >&2
	exit 0
fi

"$ENGINE" rm -f "$CONTAINER" >/dev/null 2>&1 && \
	echo "stop_minio.sh: removed container '$CONTAINER'." || \
	echo "stop_minio.sh: no container '$CONTAINER' to remove."

rm -f "$ENV_FILE"
