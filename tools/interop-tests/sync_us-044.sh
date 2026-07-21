#!/usr/bin/env sh
# sync_us-044.sh — KeePassXC interop for the US-044 collision merge
# (s3-sync T6.3 / impl plan §8.4.4).
#
# The Rust suite proves the merge engine + orchestrator produce the right
# in-memory result (us_044_collision_merge.rs, MINIO-010). This script closes
# the NFR-009 loop: a *merged* Falach vault must round-trip through a
# standards-compliant KeePassXC, with the collision loser preserved as a
# history entry that KeePassXC can read.
#
# `merge-interop-driver` writes a merged vault whose one entry has current
# title "winner" and a history entry titled "loser". We export it to XML with
# keepassxc-cli (the export includes <History> entries) and assert both are
# present.
set -eu

DRIVER="${FALACH_SYNC_MERGE_DRIVER:-target/debug/merge-interop-driver}"
PASSWORD="interop-master"

command -v keepassxc-cli >/dev/null 2>&1 || {
    echo "keepassxc-cli is required" >&2
    exit 1
}
[ -x "$DRIVER" ] || {
    echo "merge driver not built at $DRIVER — run via \`make test-sync-interop\`" >&2
    exit 1
}

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

vault="$workdir/merged.kdbx"
xml="$workdir/merged.xml"

# Produce the merged vault (password on stdin — never the command line).
printf '%s\n' "$PASSWORD" | "$DRIVER" "$vault" >/dev/null

# KeePassXC must be able to open + export the merged vault. The XML export
# includes history entries, so both the winner (current) and the loser
# (history) titles must appear.
printf '%s\n' "$PASSWORD" | keepassxc-cli export -q -f xml "$vault" >"$xml"

grep -F "winner" "$xml" >/dev/null || {
    echo "FAIL: merged current value 'winner' not readable by KeePassXC" >&2
    exit 1
}
grep -F "loser" "$xml" >/dev/null || {
    echo "FAIL: collision loser 'loser' not preserved in history (NFR-009 / FR-043)" >&2
    exit 1
}

echo "sync_us-044 KeePassXC interop OK (winner current + loser in history)"
