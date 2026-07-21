#!/bin/bash
#
# Re-vendor the AWS SigV4 published test corpus into
# `crates/falach-sync/tests/data/aws_sigv4_vectors/`. Required reading
# before running: `crates/falach-sync/tests/data/AWS_SIGV4_VECTORS_SOURCE.md`.
#
# Usage: bash tools/dev/fetch-sigv4-corpus.sh [COMMIT]
#
# COMMIT defaults to `main`. To pin against a specific upstream snapshot
# (recommended for landing in CI), pass the commit hash explicitly and
# update AWS_SIGV4_VECTORS_SOURCE.md's "Vendored at commit" line.
#
# Requires: bash, curl, network access to raw.githubusercontent.com.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
COMMIT="${1:-main}"
BASE="https://raw.githubusercontent.com/awslabs/aws-sdk-rust/${COMMIT}/sdk/aws-sigv4/aws-signing-test-suite/v4"
DEST="${REPO_ROOT}/crates/falach-sync/tests/data/aws_sigv4_vectors"

# The 40 v4 test directories (from the upstream GitHub API listing).
TESTS=(
    double-encode-path
    double-url-encode
    get-header-key-duplicate
    get-header-value-multiline
    get-header-value-order
    get-header-value-trim
    get-relative-normalized
    get-relative-relative-normalized
    get-relative-relative-unnormalized
    get-relative-unnormalized
    get-slash-dot-slash-normalized
    get-slash-dot-slash-unnormalized
    get-slash-normalized
    get-slash-pointless-dot-normalized
    get-slash-pointless-dot-unnormalized
    get-slash-unnormalized
    get-slashes-normalized
    get-slashes-unnormalized
    get-space-normalized
    get-space-unnormalized
    get-unreserved
    get-utf8
    get-vanilla-empty-query-key
    get-vanilla-query-order-encoded
    get-vanilla-query-order-key-case
    get-vanilla-query-unreserved
    get-vanilla-query
    get-vanilla-utf8-query
    get-vanilla-with-session-token
    get-vanilla
    post-header-key-case
    post-header-key-sort
    post-header-value-case
    post-sts-header-after
    post-sts-header-before
    post-vanilla-empty-query-value
    post-vanilla-query
    post-vanilla
    post-x-www-form-urlencoded-parameters
    post-x-www-form-urlencoded
)

# Files we want from each test directory. We deliberately skip the
# `query-*.txt` variants because Phase 0 does not support presigned-URL
# (query-string) signing — only header signing (design.md §1.3).
FILES=(
    context.json
    request.txt
    header-canonical-request.txt
    header-string-to-sign.txt
    header-signature.txt
    header-signed-request.txt
)

mkdir -p "$DEST"
count=0
missing_warnings=0
for test in "${TESTS[@]}"; do
    mkdir -p "$DEST/$test"
    for file in "${FILES[@]}"; do
        url="$BASE/$test/$file"
        out="$DEST/$test/$file"
        if curl -sf "$url" -o "$out"; then
            count=$((count + 1))
        else
            # curl -sf does not write the output file on HTTP failure, but
            # might have left an empty stub from a network error — clean
            # it up explicitly.
            rm -f "$out"
            echo "warn: $test/$file not present upstream" >&2
            missing_warnings=$((missing_warnings + 1))
        fi
    done
done

echo "Downloaded $count files across ${#TESTS[@]} test directories."
if [ "$missing_warnings" -gt 0 ]; then
    echo "($missing_warnings expected misses — see AWS_SIGV4_VECTORS_SOURCE.md.)" >&2
fi
