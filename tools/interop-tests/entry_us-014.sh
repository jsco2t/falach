#!/usr/bin/env bash
# US-014 — editing an entry preserves the prior version as a KDBX
# history entry, and KeePassXC sees the history. Verifies FR-012
# (KDBX history per entry).

set -euo pipefail

DRIVER="${FALACH_TEST_DRIVER:-target/debug/falach-test-driver}"
PASSWORD="interop-master"
OLD_PASSWORD="rotated-out"
NEW_PASSWORD="current-secret"

if ! command -v keepassxc-cli >/dev/null 2>&1; then
    echo "keepassxc-cli not installed; skipping" >&2
    exit 77
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

vault="$workdir/us-014.kdbx"

printf '%s\n' "$PASSWORD" | "$DRIVER" create "$vault" --password '<stdin>'

uuid_json=$(printf '%s\n' "$PASSWORD" | "$DRIVER" entry add \
    --vault "$vault" \
    --title "Rotated" \
    --username "alice" \
    --password "$OLD_PASSWORD")
uuid=$(echo "$uuid_json" | jq -r .uuid)

# Rotate the password — this is the edit that should land in history.
printf '%s\n' "$PASSWORD" | "$DRIVER" entry update \
    --vault "$vault" --uuid "$uuid" --password "$NEW_PASSWORD"

# Driver-side: history_len must be 1.
history_len=$(printf '%s\n' "$PASSWORD" | "$DRIVER" entry get \
    --vault "$vault" --uuid "$uuid" | jq -r .history_len)
if [ "$history_len" != "1" ]; then
    echo "FAIL: history_len was '$history_len'; expected '1'" >&2
    exit 1
fi

# Current password is the new one.
current=$(printf '%s\n' "$PASSWORD" | keepassxc-cli show -q -s -a Password \
    "$vault" "Rotated")
if [ "$current" != "$NEW_PASSWORD" ]; then
    echo "FAIL: keepassxc-cli current password '$current' != expected '$NEW_PASSWORD'" >&2
    exit 1
fi

# KeePassXC exports XML that includes the History entries. Cross-check
# that the old password text is present somewhere in the exported XML —
# robust against minor formatting drift across KeePassXC versions.
exported_xml="$workdir/export.xml"
printf '%s\n' "$PASSWORD" | keepassxc-cli export -q -f xml "$vault" >"$exported_xml"

if ! grep -F "$OLD_PASSWORD" "$exported_xml" >/dev/null; then
    echo "FAIL: prior password '$OLD_PASSWORD' missing from KeePassXC XML export (history not preserved)" >&2
    exit 1
fi

echo "entry_us-014: OK"
