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

vault="$workdir/rust-created.kdbx"

printf '%s\n' "$PASSWORD" | "$DRIVER" create "$vault" --password '<stdin>'
printf '%s\n' "$PASSWORD" | "$DRIVER" add-entry "$vault" \
    --title "Example Site" \
    --username "me@example.com" \
    --password "$ENTRY_PASSWORD"

shown="$workdir/show.txt"
printf '%s\n' "$PASSWORD" | keepassxc-cli show -q -s \
    -a Title -a UserName -a Password \
    "$vault" "Example Site" >"$shown"

expected="$workdir/expected.txt"
cat >"$expected" <<EOF_EXPECTED
Example Site
me@example.com
$ENTRY_PASSWORD
EOF_EXPECTED

diff -u "$expected" "$shown"
