#!/usr/bin/env sh
set -eu

DRIVER="${FALACH_TEST_DRIVER:-target/debug/falach-test-driver}"
PASSWORD="interop-master"
ENTRY_PASSWORD="entry-secret"

command -v keepassxc-cli >/dev/null 2>&1 || {
    echo "keepassxc-cli is required" >&2
    exit 1
}

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

vault="$workdir/kpxc-created.kdbx"
dump="$workdir/dump.json"

printf '%s\n%s\n' "$PASSWORD" "$PASSWORD" |
    keepassxc-cli db-create -q --set-password "$vault" >/dev/null
printf '%s\n%s\n%s\n' "$PASSWORD" "$ENTRY_PASSWORD" "$ENTRY_PASSWORD" |
    keepassxc-cli add -q -u "alice@example.com" -p "$vault" "KeePassXC Entry" >/dev/null

printf '%s\n' "$PASSWORD" | "$DRIVER" dump "$vault" --password '<stdin>' >"$dump"

grep -F '"title": "KeePassXC Entry"' "$dump" >/dev/null
grep -F '"username": "alice@example.com"' "$dump" >/dev/null
grep -F '"password": "entry-secret"' "$dump" >/dev/null
