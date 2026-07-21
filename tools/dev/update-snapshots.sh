#!/usr/bin/env bash
# update-snapshots.sh — Generate or update falach-tui snapshot golden files.
#
# Runs the snapshot tests with `FALACH_UPDATE_SNAPSHOTS=1` so that any
# missing or stale golden files under `crates/falach-tui/tests/snapshots/`
# are created / rewritten.  This is the companion to `make test` which
# compares against committed goldens and fails on mismatch.
#
# Usage:
#   ./tools/dev/update-snapshots.sh          # create/update all goldens
#   ./tools/dev/update-snapshots.sh --check  # dry-run: report what would change
#
# Exit codes:
#   0 — all goldens present and up to date (or created successfully)
#   1 — test failure (mismatch or other error)
#   2 — usage error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SNAPSHOT_DIR="$REPO_ROOT/crates/falach-tui/tests/snapshots"

usage() {
    cat >&2 <<EOF
Usage: $(basename "$0") [--check]

Generate or update falach-tui snapshot golden files.

Options:
  --check   Dry-run: compare current test output against existing goldens and
            report which files are missing or would change (exit 1 on diff).
            Does NOT modify any files.
  --help    Show this help message.

Without --check, runs the snapshot tests with FALACH_UPDATE_SNAPSHOTS=1,
which creates any missing golden files and overwrites stale ones.
EOF
    exit "${2:-0}"
}

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

if [[ "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

if [[ ! -d "$SNAPSHOT_DIR" ]]; then
    echo "ERROR: snapshot directory not found: $SNAPSHOT_DIR" >&2
    echo "This script must be run from the repository root." >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Dry-run mode: detect missing/stale goldens without modifying anything
# ---------------------------------------------------------------------------

if [[ "${1:-}" == "--check" ]]; then
    echo "=== Snapshot golden file check ==="
    echo ""

    # Run the snapshot tests normally (update mode off).  Capture stdout/stderr
    # to detect which tests fail due to missing or mismatched goldens.
    cd "$REPO_ROOT"
    CARGO_STATUS=0
    OUTPUT=$(cargo test -p falach-tui --offline --locked snapshot_tests 2>&1) || CARGO_STATUS=$?

    # Parse test names that failed.
    MISSING=()
    STALE=()

    while IFS= read -r line; do
        if [[ "$line" == *"missing snapshot golden"* ]]; then
            # Extract the golden name from the error message.
            # Pattern: missing snapshot golden `name` at ...
            # Use awk with backtick as delimiter to extract the name.
            name=$(echo "$line" | awk -F'`' '{print $2}')
            if [[ -n "$name" ]]; then
                MISSING+=("$name")
            fi
        elif [[ "$line" == *"snapshot mismatch"* ]]; then
            # Extract the golden name from the mismatch message.
            # Pattern: --- snapshot mismatch: name ---
            name=$(echo "$line" | sed -n 's/.*snapshot mismatch: \(.*\) ---/\1/p')
            if [[ -n "$name" ]]; then
                STALE+=("$name")
            fi
        fi
    done <<< "$OUTPUT"

    if [[ ${#MISSING[@]} -eq 0 && ${#STALE[@]} -eq 0 ]]; then
        # No recognized snapshot problem. If cargo itself failed, it's something
        # this parser doesn't understand (compile error, render panic, or a
        # changed harness message) — surface it instead of reporting a false pass.
        if [[ $CARGO_STATUS -ne 0 ]]; then
            echo "ERROR: snapshot tests failed for an unrecognized reason (cargo exit $CARGO_STATUS)." >&2
            echo "$OUTPUT" >&2
            exit 1
        fi
        echo "All snapshot goldens are present and up to date."
        echo ""
        echo "Files in $SNAPSHOT_DIR:"
        ls -1 "$SNAPSHOT_DIR" 2>/dev/null | sed 's/^/  /'
        exit 0
    fi

    echo "Issues found:"
    if [[ ${#MISSING[@]} -gt 0 ]]; then
        echo "  Missing goldens (${#MISSING[@]}):"
        for name in "${MISSING[@]}"; do
            echo "    - ${name}.txt"
        done
        echo ""
    fi
    if [[ ${#STALE[@]} -gt 0 ]]; then
        echo "  Stale goldens (${#STALE[@]}):"
        for name in "${STALE[@]}"; do
            echo "    - ${name}.txt"
        done
        echo ""
    fi

    echo "Run '$(basename "$0")' (without --check) to create/update these files."
    echo "Then review the diff before committing."
    exit 1
fi

# ---------------------------------------------------------------------------
# Normal mode: create/update all goldens
# ---------------------------------------------------------------------------

echo "=== Updating snapshot golden files ==="
echo ""
echo "Snapshot directory: $SNAPSHOT_DIR"
echo ""

# Record existing files before the run.
EXISTING_BEFORE=()
if [[ -d "$SNAPSHOT_DIR" ]]; then
    while IFS= read -r f; do
        EXISTING_BEFORE+=("$f")
    done < <(ls -1 "$SNAPSHOT_DIR" 2>/dev/null || true)
fi

cd "$REPO_ROOT"

# Run snapshot tests with update mode enabled.
if ! FALACH_UPDATE_SNAPSHOTS=1 cargo test -p falach-tui --offline --locked snapshot_tests; then
    echo ""
    echo "ERROR: snapshot tests failed. Check the output above." >&2
    exit 1
fi

# Record files after the run.
EXISTING_AFTER=()
if [[ -d "$SNAPSHOT_DIR" ]]; then
    while IFS= read -r f; do
        EXISTING_AFTER+=("$f")
    done < <(ls -1 "$SNAPSHOT_DIR" 2>/dev/null || true)
fi

# Determine which files were created or updated.
CREATED=()
UPDATED=()

for f in "${EXISTING_AFTER[@]}"; do
    if [[ ! " ${EXISTING_BEFORE[*]} " =~ " $f " ]]; then
        CREATED+=("$f")
    else
        UPDATED+=("$f")
    fi
done

echo "Done."
echo ""
if [[ ${#CREATED[@]} -gt 0 ]]; then
    echo "Created (${#CREATED[@]}):"
    for f in "${CREATED[@]}"; do
        echo "  + $f"
    done
    echo ""
fi
if [[ ${#UPDATED[@]} -gt 0 ]]; then
    echo "Updated (${#UPDATED[@]}):"
    for f in "${UPDATED[@]}"; do
        echo "  ~ $f"
    done
    echo ""
fi
if [[ ${#CREATED[@]} -eq 0 && ${#UPDATED[@]} -eq 0 ]]; then
    echo "No changes — all goldens were already up to date."
    echo ""
fi

echo "Next steps:"
echo "  1. Review the changes: git diff crates/falach-tui/tests/snapshots/"
echo "  2. Commit the updated goldens if the changes look correct."
echo ""
