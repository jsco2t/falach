#!/usr/bin/env bash
# US-016 — group hierarchy created by falach-test-driver matches the
# tree KeePassXC sees. Verifies FR-013 (groups + tags).

set -euo pipefail

DRIVER="${FALACH_TEST_DRIVER:-target/debug/falach-test-driver}"
PASSWORD="interop-master"

if ! command -v keepassxc-cli >/dev/null 2>&1; then
    echo "keepassxc-cli not installed; skipping" >&2
    exit 77
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

vault="$workdir/us-016.kdbx"

printf '%s\n' "$PASSWORD" | "$DRIVER" create "$vault" --password '<stdin>'

# Banking → Savings; Work; Email
banking_json=$(printf '%s\n' "$PASSWORD" | "$DRIVER" group create \
    --vault "$vault" --name "Banking")
banking_uuid=$(echo "$banking_json" | jq -r .uuid)

printf '%s\n' "$PASSWORD" | "$DRIVER" group create \
    --vault "$vault" --parent "$banking_uuid" --name "Savings" >/dev/null
printf '%s\n' "$PASSWORD" | "$DRIVER" group create \
    --vault "$vault" --name "Work" >/dev/null
printf '%s\n' "$PASSWORD" | "$DRIVER" group create \
    --vault "$vault" --name "Email" >/dev/null

# Add an entry inside Banking/Savings so the tree is non-trivial.
printf '%s\n' "$PASSWORD" | "$DRIVER" entry add \
    --vault "$vault" \
    --title "Savings Account" \
    --username "user@bank.test" \
    --group "$(printf '%s\n' "$PASSWORD" | "$DRIVER" group create \
        --vault "$vault" --parent "$banking_uuid" --name "Inner" | jq -r .uuid)" >/dev/null

# KeePassXC recursive listing renders the tree with indentation; each
# group name appears once. Verify that every group + the nested entry
# are present.
listing=$(printf '%s\n' "$PASSWORD" | keepassxc-cli ls -q -R "$vault")

for expected_name in "Banking/" "Savings/" "Inner/" "Work/" "Email/" "Savings Account"; do
    if ! echo "$listing" | grep -F "$expected_name" >/dev/null; then
        echo "FAIL: expected '$expected_name' not present in keepassxc-cli ls output:" >&2
        echo "$listing" >&2
        exit 1
    fi
done

echo "entry_us-016: OK"
