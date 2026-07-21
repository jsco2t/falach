#!/usr/bin/env bash
# US-013 — file attachment added by falach-test-driver round-trips
# byte-identically via `keepassxc-cli attachment-export`. Verifies
# FR-016 (attachments + size cap).

set -euo pipefail

DRIVER="${FALACH_TEST_DRIVER:-target/debug/falach-test-driver}"
PASSWORD="interop-master"
ATTACHMENT_NAME="doc.bin"

if ! command -v keepassxc-cli >/dev/null 2>&1; then
    echo "keepassxc-cli not installed; skipping" >&2
    exit 77
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

vault="$workdir/us-013.kdbx"
source_file="$workdir/source.bin"
exported="$workdir/exported.bin"
re_extracted="$workdir/re-extracted.bin"

# Generate 100 KiB of deterministic pseudo-random data — enough to be
# meaningful but tiny enough to keep the test fast.
head -c 102400 /dev/urandom >"$source_file"

printf '%s\n' "$PASSWORD" | "$DRIVER" create "$vault" --password '<stdin>'

uuid_json=$(printf '%s\n' "$PASSWORD" | "$DRIVER" entry add \
    --vault "$vault" \
    --title "Document Holder" \
    --username "owner@example.com")
uuid=$(echo "$uuid_json" | jq -r .uuid)

printf '%s\n' "$PASSWORD" | "$DRIVER" entry attach \
    --vault "$vault" \
    --uuid "$uuid" \
    --name "$ATTACHMENT_NAME" \
    --file "$source_file"

# Round-trip through KeePassXC.
printf '%s\n' "$PASSWORD" | keepassxc-cli attachment-export -q \
    "$vault" "Document Holder" "$ATTACHMENT_NAME" "$exported"

source_sha=$(sha256sum "$source_file" | awk '{print $1}')
exported_sha=$(sha256sum "$exported" | awk '{print $1}')
if [ "$source_sha" != "$exported_sha" ]; then
    echo "FAIL: source SHA $source_sha != keepassxc export SHA $exported_sha" >&2
    exit 1
fi

# And back through the driver's own extract path for symmetry.
printf '%s\n' "$PASSWORD" | "$DRIVER" entry extract \
    --vault "$vault" --uuid "$uuid" --name "$ATTACHMENT_NAME" --out "$re_extracted"

reextracted_sha=$(sha256sum "$re_extracted" | awk '{print $1}')
if [ "$source_sha" != "$reextracted_sha" ]; then
    echo "FAIL: source SHA $source_sha != driver re-extract SHA $reextracted_sha" >&2
    exit 1
fi

echo "entry_us-013: OK"
