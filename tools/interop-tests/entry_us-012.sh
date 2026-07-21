#!/usr/bin/env bash
# US-012 — TOTP entry round-trips and the generated code matches both
# `oathtool` (deterministic ground truth, optional) and
# `keepassxc-cli show -t` (interop ground truth). Verifies FR-015 (TOTP
# generation per RFC 6238) and the otpauth URI interop convention.

set -euo pipefail

DRIVER="${FALACH_TEST_DRIVER:-target/debug/falach-test-driver}"
PASSWORD="interop-master"
# RFC 6238 Appendix B test secret: ASCII "12345678901234567890" base32-encoded.
RFC_SECRET_BASE32="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
OTPAUTH_URI="otpauth://totp/Example?secret=${RFC_SECRET_BASE32}&algorithm=SHA1&digits=8&period=30"
# A fixed point in time so the test does not race the 30-second window.
FIXED_TIME=59
EXPECTED_CODE_AT_59="94287082"

if ! command -v keepassxc-cli >/dev/null 2>&1; then
    echo "keepassxc-cli not installed; skipping" >&2
    exit 77
fi

if ! command -v oathtool >/dev/null 2>&1; then
    echo "WARN: oathtool not installed; oathtool cross-check skipped" >&2
    have_oathtool=0
else
    have_oathtool=1
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

vault="$workdir/us-012.kdbx"

printf '%s\n' "$PASSWORD" | "$DRIVER" create "$vault" --password '<stdin>'

uuid_json=$(printf '%s\n' "$PASSWORD" | "$DRIVER" entry add-totp \
    --vault "$vault" \
    --title "Example" \
    --otpauth "$OTPAUTH_URI")
uuid=$(echo "$uuid_json" | jq -r .uuid)

# 1. Test driver --at FIXED_TIME — deterministic; the RFC 6238 vector.
driver_out=$(printf '%s\n' "$PASSWORD" | "$DRIVER" entry totp \
    --vault "$vault" --uuid "$uuid" --at "$FIXED_TIME")
driver_code=$(echo "$driver_out" | jq -r .code)
if [ "$driver_code" != "$EXPECTED_CODE_AT_59" ]; then
    echo "FAIL: driver code at t=$FIXED_TIME was '$driver_code'; expected '$EXPECTED_CODE_AT_59'" >&2
    exit 1
fi

# 2. oathtool cross-check (optional — degrades to warning if missing).
if [ "$have_oathtool" -eq 1 ]; then
    oath_code=$(oathtool --base32 --totp -d 8 -N "@$FIXED_TIME" "$RFC_SECRET_BASE32")
    if [ "$oath_code" != "$EXPECTED_CODE_AT_59" ]; then
        echo "FAIL: oathtool at t=$FIXED_TIME was '$oath_code'; expected '$EXPECTED_CODE_AT_59'" >&2
        exit 1
    fi
fi

# 3. KeePassXC cross-check uses the live system clock — race-tolerant.
#    Capture `now`, ask both falach and KeePassXC for the live code, and
#    accept either the current or next-second window to absorb a boundary.
now=$(date +%s)
next=$((now + 1))
falach_now=$(printf '%s\n' "$PASSWORD" | "$DRIVER" entry totp \
    --vault "$vault" --uuid "$uuid" --at "$now" | jq -r .code)
falach_next=$(printf '%s\n' "$PASSWORD" | "$DRIVER" entry totp \
    --vault "$vault" --uuid "$uuid" --at "$next" | jq -r .code)
kpxc_code=$(printf '%s\n' "$PASSWORD" | keepassxc-cli show -q -t "$vault" "Example")

if [ "$kpxc_code" != "$falach_now" ] && [ "$kpxc_code" != "$falach_next" ]; then
    echo "FAIL: keepassxc-cli code '$kpxc_code' matches neither falach@now ('$falach_now') nor falach@next ('$falach_next')" >&2
    exit 1
fi

echo "entry_us-012: OK"
