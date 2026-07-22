#!/usr/bin/env bash
# bench_search_gate.sh — NFR-002 gate.
#
# Runs the entry-search benchmark and exits non-zero if the selected
# statistic exceeds the budget:
#   - p99 (default): strict NFR-002 gate for controlled reference hardware.
#   - median: stable regression gate for noisy hosted CI runners.
#
# Budget:
#   - Local p99: 50ms (the NFR-002 requirement).
#   - Hosted CI median: 75ms (50% headroom for hardware variance).
# Override with `BUDGET_MS=<n>` or select `BENCH_STAT=p99|median`. CI p99
# reporting remains relative to `P99_REFERENCE_MS` (50ms by default).
#
# The benchmark harness (`crates/falach-core/benches/bench_search.rs`)
# emits plain `KEY=VALUE` lines:
#   bench_search_5k_median_ms=3.27
#   bench_search_5k_p99_ms=4.48
# In median mode, p99 remains visible as an informational value or warning.

set -euo pipefail

BUDGET_MS="${BUDGET_MS:-50}"
BENCH_STAT="${BENCH_STAT:-p99}"
P99_REFERENCE_MS="${P99_REFERENCE_MS:-50}"

case "$BENCH_STAT" in
    p99 | median) ;;
    *)
        echo "bench_search_gate: BENCH_STAT must be 'p99' or 'median'" >&2
        exit 2
        ;;
esac

cd "$(dirname "$0")/../.."

output=$(cargo bench -p falach-core --bench bench_search --offline --locked 2>&1 | tail -22)

extract() {
    local prefix="$1"
    local stat="$2"
    echo "$output" | awk -F= -v key="${prefix}_${stat}_ms" '$1 == key {print $2}' | tail -1
}

substring_value=$(extract "bench_search_5k" "$BENCH_STAT")
wildcard_value=$(extract "bench_search_5k_wildcard" "$BENCH_STAT")
fuzzy_value=$(extract "bench_search_5k_fuzzy" "$BENCH_STAT")
matcher_value=$(extract "bench_fuzzy_matcher_5k" "$BENCH_STAT")

substring_p99=$(extract "bench_search_5k" "p99")
wildcard_p99=$(extract "bench_search_5k_wildcard" "p99")
fuzzy_p99=$(extract "bench_search_5k_fuzzy" "p99")
matcher_p99=$(extract "bench_fuzzy_matcher_5k" "p99")

if [ -z "$substring_value" ] || [ -z "$wildcard_value" ] || [ -z "$fuzzy_value" ] || [ -z "$matcher_value" ] ||
    [ -z "$substring_p99" ] || [ -z "$wildcard_p99" ] || [ -z "$fuzzy_p99" ] || [ -z "$matcher_p99" ]; then
    echo "bench_search_gate: failed to parse benchmark output" >&2
    echo "$output" >&2
    exit 2
fi

# Dual threshold for fuzzy (OQ-2): a soft WARNING at 10ms flags a matcher
# slowdown early; the end-to-end fuzzy search has the hard NFR-002 budget.
FUZZY_WARN_MS="${FUZZY_WARN_MS:-10}"

# Float comparison via awk — bash arithmetic only handles integers.
check() {
    local label="$1"
    local value="$2"
    awk -v v="$value" -v b="$BUDGET_MS" -v label="$label" -v stat="$BENCH_STAT" '
        BEGIN {
            if (v > b) {
                printf "FAIL: %s %s %.2fms > budget %sms\n", label, stat, v, b > "/dev/stderr"
                exit 1
            }
            printf "OK:   %s %s %.2fms (budget %sms)\n", label, stat, v, b
            exit 0
        }
    '
}

# A non-fatal soft-threshold notice (does not affect exit status).
warn() {
    local label="$1"
    local value="$2"
    local warn_ms="$3"
    local stat="${4:-$BENCH_STAT}"
    awk -v v="$value" -v w="$warn_ms" -v label="$label" -v stat="$stat" '
        BEGIN {
            if (v > w) {
                printf "WARNING: %s %s %.2fms > soft threshold %sms\n", label, stat, v, w > "/dev/stderr"
            }
        }
    '
}

# Hosted CI gates on the median, but always reports p99 so tail latency remains
# visible without making a noisy-neighbour spike fail the build.
report_p99() {
    local label="$1"
    local value="$2"
    local threshold="$3"
    awk -v v="$value" -v t="$threshold" -v label="$label" '
        BEGIN {
            if (v > t) {
                printf "WARNING: %s p99 %.2fms > reference threshold %sms\n", label, v, t > "/dev/stderr"
            } else {
                printf "INFO: %s p99 %.2fms (reference threshold %sms)\n", label, v, t
            }
        }
    '
}

# Run all checks; only exit non-zero at the end so the developer sees every
# number in the failure log.
status=0
check "substring" "$substring_value" || status=$?
check "wildcard " "$wildcard_value"  || status=$?
warn  "matcher  " "$matcher_value" "$FUZZY_WARN_MS"
check "fuzzy    " "$fuzzy_value"      || status=$?

if [ "$BENCH_STAT" = "median" ]; then
    report_p99 "substring" "$substring_p99" "$P99_REFERENCE_MS"
    report_p99 "wildcard " "$wildcard_p99" "$P99_REFERENCE_MS"
    report_p99 "matcher  " "$matcher_p99" "$FUZZY_WARN_MS"
    report_p99 "fuzzy    " "$fuzzy_p99" "$P99_REFERENCE_MS"
fi

exit "$status"
