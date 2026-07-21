#!/usr/bin/env sh
set -eu

DRIVER="${FALACH_TEST_DRIVER:-target/debug/falach-test-driver}"
PASSWORD="interop-master"

command -v keepassxc-cli >/dev/null 2>&1 || {
    echo "keepassxc-cli is required" >&2
    exit 1
}

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

vault="$workdir/round-trip.kdbx"
dump="$workdir/final.json"
baseline_xml="$workdir/baseline.xml"
final_xml="$workdir/final.xml"

printf '%s\n' "$PASSWORD" | "$DRIVER" create "$vault" --password '<stdin>'

i=1
while [ "$i" -le 5 ]; do
    printf '%s\n' "$PASSWORD" | "$DRIVER" add-entry "$vault" \
        --title "Rust Entry $i" \
        --username "rust-$i@example.com" \
        --password "rust-secret-$i"

    printf '%s\n%s\n%s\n' "$PASSWORD" "kpxc-secret-$i" "kpxc-secret-$i" |
        keepassxc-cli add -q -u "kpxc-$i@example.com" -p "$vault" "KeePassXC Entry $i" >/dev/null
    i=$((i + 1))
done

printf '%s\n' "$PASSWORD" | "$DRIVER" add-entry "$vault" \
    --title "Final Falach Save" \
    --username "final-falach@example.com" \
    --password "final-falach-secret"

printf '%s\n' "$PASSWORD" | keepassxc-cli export -q -f xml "$vault" >"$baseline_xml"

i=1
while [ "$i" -le 5 ]; do
    printf '%s\n' "$PASSWORD" | "$DRIVER" dump "$vault" --password '<stdin>' >/dev/null
    "$DRIVER" change-pw "$vault" >/dev/null 2>&1 <<EOF_CHANGE
$PASSWORD
$PASSWORD
EOF_CHANGE
    i=$((i + 1))
done

printf '%s\n' "$PASSWORD" | keepassxc-cli export -q -f xml "$vault" >"$final_xml"
tools/interop-tests/lib/kpxc-diff.py "$baseline_xml" "$final_xml"

printf '%s\n' "$PASSWORD" | "$DRIVER" dump "$vault" --password '<stdin>' >"$dump"

i=1
while [ "$i" -le 5 ]; do
    grep -F "\"title\": \"Rust Entry $i\"" "$dump" >/dev/null
    grep -F "\"username\": \"rust-$i@example.com\"" "$dump" >/dev/null
    grep -F "\"password\": \"rust-secret-$i\"" "$dump" >/dev/null
    grep -F "\"title\": \"KeePassXC Entry $i\"" "$dump" >/dev/null
    grep -F "\"username\": \"kpxc-$i@example.com\"" "$dump" >/dev/null
    grep -F "\"password\": \"kpxc-secret-$i\"" "$dump" >/dev/null
    i=$((i + 1))
done
grep -F '"title": "Final Falach Save"' "$dump" >/dev/null
grep -F '"username": "final-falach@example.com"' "$dump" >/dev/null
grep -F '"password": "final-falach-secret"' "$dump" >/dev/null
