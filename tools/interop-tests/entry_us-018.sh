#!/usr/bin/env bash
# US-018 — entry expiration metadata round-trips through KeePassXC.
# Verifies FR-017 (expiration metadata).
#
# Note on KeePassXC interop surface: `keepassxc-cli show` does not
# surface `Times.Expires` in its default output, so we cross-check via
# `keepassxc-cli export -f xml`, which is the documented stable
# interchange format and includes the full Times block. We assert the
# entry's <Expires>True</Expires> tag appears in the XML and the root
# group's stays False.

set -euo pipefail

DRIVER="${FALACH_TEST_DRIVER:-target/debug/falach-test-driver}"
PASSWORD="interop-master"

if ! command -v keepassxc-cli >/dev/null 2>&1; then
    echo "keepassxc-cli not installed; skipping" >&2
    exit 77
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

vault="$workdir/us-018.kdbx"

printf '%s\n' "$PASSWORD" | "$DRIVER" create "$vault" --password '<stdin>'

uuid_json=$(printf '%s\n' "$PASSWORD" | "$DRIVER" entry add \
    --vault "$vault" \
    --title "ExpiredEntry" \
    --username "alice")
uuid=$(echo "$uuid_json" | jq -r .uuid)

# Set expiration to a fixed past timestamp — driver-side `is_expired(now)`
# will return true for any later time.
printf '%s\n' "$PASSWORD" | "$DRIVER" entry expire \
    --vault "$vault" --uuid "$uuid" --when "2020-01-01T00:00:00Z"

# Driver-side: `entry get` surfaces the `expires` field as RFC3339.
expires_rfc=$(printf '%s\n' "$PASSWORD" | "$DRIVER" entry get \
    --vault "$vault" --uuid "$uuid" | jq -r '.expires // empty')
if [ -z "$expires_rfc" ]; then
    echo "FAIL: driver did not surface expires field" >&2
    exit 1
fi

# KeePassXC interop: XML export must contain exactly one
# <Expires>True</Expires> (our entry; the root group is False).
xml="$workdir/export.xml"
printf '%s\n' "$PASSWORD" | keepassxc-cli export -q -f xml "$vault" >"$xml"

true_count=$(grep -c '<Expires>True</Expires>' "$xml")
if [ "$true_count" -ne 1 ]; then
    echo "FAIL: expected exactly 1 <Expires>True</Expires> in KeePassXC XML; got $true_count" >&2
    exit 1
fi

# Confirm the True one is for our entry by checking it appears in the
# Times block of an entry titled ExpiredEntry.
if ! python3 - "$xml" <<'PY'
import sys
import xml.etree.ElementTree as ET
tree = ET.parse(sys.argv[1])
for entry in tree.iter("Entry"):
    title = None
    for s in entry.findall("String"):
        key = s.findtext("Key")
        if key == "Title":
            title = s.findtext("Value")
            break
    if title != "ExpiredEntry":
        continue
    times = entry.find("Times")
    expires = times.findtext("Expires") if times is not None else None
    if expires == "True":
        sys.exit(0)
sys.exit(1)
PY
then
    echo "FAIL: KeePassXC XML does not show <Expires>True</Expires> for the ExpiredEntry entry" >&2
    exit 1
fi

echo "entry_us-018: OK"
