#!/usr/bin/env bash
# US-010 — credential entry created by falach-test-driver round-trips
# through `keepassxc-cli show`. Verifies FR-010 (CRUD) and FR-NFR-009
# (KDBX interop) at the entry-management level.

set -euo pipefail

DRIVER="${FALACH_TEST_DRIVER:-target/debug/falach-test-driver}"
PASSWORD="interop-master"
ENTRY_PASSWORD="entry-secret-010"

if ! command -v keepassxc-cli >/dev/null 2>&1; then
    echo "keepassxc-cli not installed; skipping" >&2
    exit 77
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

vault="$workdir/us-010.kdbx"

printf '%s\n' "$PASSWORD" | "$DRIVER" create "$vault" --password '<stdin>'

uuid_json=$(printf '%s\n' "$PASSWORD" | "$DRIVER" entry add \
    --vault "$vault" \
    --title "Example Site" \
    --username "me@example.com" \
    --password "$ENTRY_PASSWORD" \
    --url "https://example.test/login" \
    --notes "interop credential")

# Ensure JSON is well-formed and yields a UUID. jq exits non-zero on
# malformed input — that's the assertion.
echo "$uuid_json" | jq -e '.uuid | type == "string"' >/dev/null

shown="$workdir/show.txt"
printf '%s\n' "$PASSWORD" | keepassxc-cli show -q -s \
    -a Title -a UserName -a Password -a URL -a Notes \
    "$vault" "Example Site" >"$shown"

expected="$workdir/expected.txt"
cat >"$expected" <<EOF_EXPECTED
Example Site
me@example.com
$ENTRY_PASSWORD
https://example.test/login
interop credential
EOF_EXPECTED

diff -u "$expected" "$shown"

echo "entry_us-010: OK"
