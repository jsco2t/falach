# Falach — Makefile
#
# This is the canonical build / test / lint interface for the project.
# Every developer-facing workflow has a target here so that local runs
# and CI run identical commands. Raw `cargo` invocations are reserved
# for ad-hoc exploration; anything that's part of the project's normal
# loop lives here.
#
# Run `make help` (or `make` alone) to list every target.
#
# All builds are offline against the vendored dependency tree. The
# project's `.cargo/config.toml` already enforces `[net] offline = true`;
# the explicit `--offline --locked` flags below are belt-and-suspenders
# so the intent is visible at the call site.

CARGO          := cargo
CARGO_FLAGS    := --workspace --offline --locked
CLIPPY_FLAGS   := --workspace --all-targets --offline --locked -- -D warnings

# Host OS — used to pick the platform-appropriate OS-event source test
# (logind on Linux, IOKit on macOS); the wrong-platform feature won't
# even resolve (`logind`→`zbus` is Linux-target-only; `iokit`→`objc2`
# is macOS-target-only), so `test-os-events` must not invoke both.
UNAME_S        := $(shell uname -s)

# `make` with no args shows the help screen — friendlier for first-run.
# Devs who know what they want type `make build`, `make test`, `make check`.
.DEFAULT_GOAL := help

.PHONY: help toolchain build test test-ignored test-all test-update-snapshots test-clipboard test-os-events \
        test-sigv4 minio-up minio-down test-s3-integration interop-sync \
        fmt fmt-check lint lint-fix check-feature-gates \
        check verify interop interop-entry bench bench-search bench-search-gate \
        vendor deny audit doc clean completions completions-check run-tui \
        snapshots-check

help:  ## Show this help.
	@awk 'BEGIN {FS = ":.*##"; print "Usage: make <target>\n\nTargets:"} /^[a-zA-Z_-]+:.*##/ {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ---------------------------------------------------------------------------
# One-time environment setup — run this first on a fresh machine.
# ---------------------------------------------------------------------------

toolchain:  ## Install all dev tooling (Rust toolchain, keepassxc-cli, cargo-deny/audit). Run first on a new machine.
	# Cross-platform bootstrap (Linux + macOS). Idempotent — re-running
	# skips already-installed tools. Tool versions are pinned to match CI
	# (.github/workflows/ci.yml). After this, `make check` works offline.
	# Invoked directly (not via `sh`) so its bash shebang is honoured —
	# the script uses `set -o pipefail`, which POSIX `sh`/dash lacks.
	tools/dev/install-toolchain.sh

# ---------------------------------------------------------------------------
# Core developer loop — these match CI exactly.
# ---------------------------------------------------------------------------

build:  ## Build the workspace (offline, vendored).
	$(CARGO) build $(CARGO_FLAGS)

run-tui:  ## Launch the interactive terminal UI (falach-tui).
	$(CARGO) run -p falach-tui --offline --locked

check-macos:  ## Type-check falach-security against macOS targets (Level-1 cross-compile gate; no link, no SDK).
	# `cargo check` does macro expansion + type/borrow checking but
	# does NOT invoke the linker, so the absence of Apple frameworks
	# (IOKit, AppKit, Foundation) on Linux does not block this gate.
	# Catches the realistic refactor-breakage class for Phase 5 T5.2's
	# `os_events/macos.rs`: trait-impl drift, signature changes,
	# `objc2` macro errors, missing-arm matches. Does NOT catch
	# wrong-extern-symbol-name or behavioural bugs — for those you
	# need a real macOS host (see CONTRIBUTING.md "macOS verification").
	#
	# `--features iokit` is passed so `os_events/macos.rs` actually
	# compiles under this gate (default features `#[cfg]` it out, which
	# would make the "catches macos.rs drift" claim above hollow). The
	# `iokit` feature only pulls the `objc2` ecosystem, all macOS-target
	# deps already in the vendored tree, so it resolves `--offline`.
	# `--all-features` is intentionally NOT used: it would also flip on
	# `logind`, whose `zbus` dep is Linux-target-only and would fail to
	# resolve for an apple-darwin target.
	$(CARGO) check --target aarch64-apple-darwin --offline --locked -p falach-security --features iokit
	$(CARGO) check --target x86_64-apple-darwin  --offline --locked -p falach-security --features iokit

check-feature-gates:  ## Type-check feature-gated test suites the runtime CI sweeps never compile (clipboard, OS-event helpers).
	# Compile-only drift gate. The display-dependent clipboard suites
	# (`clipboard-tests`) and the OS-event helper binaries are excluded
	# from every runtime CI sweep by design — but without this gate they
	# are never even *compiled* in CI, so an API refactor of
	# `falach_security::Clipboard` or the CLI's `--copy` path could
	# silently break them. `cargo check --tests` compiles the gated test
	# targets without running them (no display needed).
	$(CARGO) check -p falach-security --offline --locked --features clipboard-tests --tests
	$(CARGO) check -p falach-cli --offline --locked --features clipboard-tests --tests
ifeq ($(UNAME_S),Darwin)
	# iokit compiles natively here; logind's zbus tree is Linux-only.
	$(CARGO) check -p falach-security --offline --locked --features test-binaries,iokit --tests
else
	$(CARGO) check -p falach-security --offline --locked --features test-binaries,logind --tests
endif

test:  ## Run default-parallel tests (offline, vendored).
	$(CARGO) test $(CARGO_FLAGS)

test-ignored:  ## Run #[ignore]d tests serially (env-mutating + signal-handler tests, etc).
	# `--features test-binaries` enables falach-security's `sigstop_helper`
	# test binary, needed by `tests/us_052_sigstop_lock.rs`. Other workspace
	# members don't define the feature; cargo silently no-ops on them.
	# NOT enabled here: `minio-tests` (live-wire S3 cases needing `make
	# minio-up`) and `clipboard-tests` (real-display cases) — both stay
	# `cfg`/feature-gated out of this blanket sweep and run only via their
	# dedicated targets (`test-s3-integration`, `test-clipboard`).
	$(CARGO) test $(CARGO_FLAGS) --features test-binaries -- --ignored --test-threads=1

test-all: test test-ignored  ## Run both default and #[ignore]d tests.

test-update-snapshots:  ## Regenerate the falach-tui snapshot golden files (tui-skeleton T3.5).
	# Re-renders the Secrets-tab tree/detail snapshots and rewrites the golden
	# files under crates/falach-tui/tests/snapshots/. This is the only target
	# that mutates them — review the diff before committing. Normal `make test`
	# compares against the committed goldens and never rewrites. Delegates to the
	# same script as `snapshots-check` so the regenerate and dry-run paths share
	# one implementation.
	$(CURDIR)/tools/dev/update-snapshots.sh

snapshots-check:  ## Check for missing or stale snapshot golden files (dry-run).
	# Reports which golden files are missing or would change without modifying
	# anything. Exit code 1 means issues found; 0 means all goldens are up to date.
	$(CURDIR)/tools/dev/update-snapshots.sh --check

test-clipboard:  ## Run clipboard tests across falach-security + falach-cli (requires real display; wrap in xvfb-run on CI).
	# Spans two crates: the security crate's US-053 auto-clear cases and
	# the CLI's `entry get --copy` hand-off. Both files are gated behind
	# each crate's `clipboard-tests` feature so they stay out of the
	# blanket `make test-ignored` sweep; this target is the only one that
	# enables the feature. They drive the real system clipboard, so they
	# need a usable display/pasteboard (xvfb on Linux CI).
	$(CARGO) test -p falach-security --offline --locked --features clipboard-tests --test us_053_clipboard_autoclear -- --ignored --test-threads=1
	$(CARGO) test -p falach-cli --offline --locked --features clipboard-tests --test cli_clipboard_handoff -- --ignored --test-threads=1

test-sigv4:  ## Run the AWS SigV4 published test-vector corpus runner (s3-sync T2.2; fast CI gate).
	# Runs ONLY `tests/sigv4_aws_test_vectors.rs`, the corpus runner that
	# asserts our hand-rolled SigV4 signer (crates/falach-sync/src/s3/signer.rs)
	# matches the AWS-published expected outputs across ~15 applicable
	# test vectors. Fast (<1s); independent of the broader unit-test
	# suite so a SigV4 encoding bug produces a well-isolated failure
	# signal. The corpus is vendored at
	# crates/falach-sync/tests/data/aws_sigv4_vectors/ — see the
	# AWS_SIGV4_VECTORS_SOURCE.md doc there for the upstream provenance.
	$(CARGO) test -p falach-sync --offline --locked --test sigv4_aws_test_vectors

# Heavier merge-engine property sweep. The properties run at 256 cases under
# the blanket `make test`; this target raises the count for a deeper sweep
# (PRD §11 Risk #2 / impl-plan §8). Override the iteration count via
# PROPTEST_CASES (e.g. `make test-merge-properties PROPTEST_CASES=10000`).
PROPTEST_CASES ?= 4096
test-merge-properties:  ## Run the merge-engine property tests with a heavier case count (PROPTEST_CASES, default 4096).
	PROPTEST_CASES=$(PROPTEST_CASES) $(CARGO) test -p falach-sync --offline --locked --test merge_property_tests

# ---------------------------------------------------------------------------
# S3 sync live-wire integration (s3-sync T6.1/T6.2) — needs Docker + mc.
# The MINIO-* tests are #[ignore]-gated so the default `make test` skips
# them; this is the only path that runs them. See
# tools/sync-tests/README.md for the local + CI workflow.
# ---------------------------------------------------------------------------

minio-up:  ## Start the pinned MinIO container for s3-sync integration tests (requires Docker/Podman).
	tools/sync-tests/fixtures/start_minio.sh

minio-down:  ## Stop + remove the MinIO container started by `make minio-up`.
	tools/sync-tests/fixtures/stop_minio.sh

test-s3-integration:  ## Run the #[ignore]-gated MinIO live-wire tests (run `make minio-up` first).
	# Sources the endpoint + test credentials start_minio.sh wrote, then
	# runs ONLY the minio_integration test binary's #[ignore]-gated cases.
	# `--features minio-tests` compiles that binary in the first place: it is
	# `#![cfg(feature = "minio-tests")]`-gated so the blanket `make test-ignored`
	# sweep (non-MinIO `vault-core` CI job) never builds or runs these live-wire
	# cases. This target — the MinIO-provisioned `integration-s3` job — is the
	# only path that turns them on.
	# Serial (`--test-threads=1`): the cases share one container, and
	# `make_bucket.sh` reuses a single `mc` alias, so concurrent bucket
	# setup could race. Each case still uses a uniquely-suffixed bucket.
	@if [ ! -f tools/sync-tests/fixtures/.minio-env ]; then \
		echo "error: MinIO not running — run \`make minio-up\` first." >&2; \
		exit 1; \
	fi
	. tools/sync-tests/fixtures/.minio-env && \
		$(CARGO) test -p falach-sync --offline --locked --features minio-tests --test minio_integration -- --ignored --test-threads=1
	# The CLI's own live-wire happy-path (spawns the built binary against the
	# same MinIO): `cli-sync-wiring` T3.2's `#![cfg(feature = "minio-tests")]`
	# + `#[ignore]` case. Kept under this one target so all live-wire S3 cases
	# run via a single command (per plan §7.4).
	. tools/sync-tests/fixtures/.minio-env && \
		$(CARGO) test -p falach-cli --offline --locked --features minio-tests --test cli_sync_minio -- --ignored --test-threads=1

test-os-events:  ## Run falach-security OS-event integration tests (Phase 5: logind on Linux, IOKit on macOS).
	# Picks the host-appropriate source test. Both files are
	# `#[ignore]`d so the default `make test` skips them.
	#
	# Linux: `--features test-binaries,logind` enables the
	# `logind_helper` binary and compiles `os_events/logind.rs` + its
	# `zbus` dep tree. Requires a logind-enabled host + `dbus-send` +
	# `busctl` to drive the signals from outside the helper.
	#
	# macOS: `--features test-binaries,iokit` enables the `iokit_helper`
	# binary and compiles `os_events/macos.rs` + its `objc2` dep tree.
	# The cases are manual (a human triggers sleep / screen lock); they
	# print `INSTRUCTION:` lines and wait. GitHub-hosted macOS runners
	# have no interactive session, so CI skips them.
	#
	# `--test <name>` selects only the post-MVP file so neither the
	# clipboard nor SIGTSTP integration tests run here.
ifeq ($(UNAME_S),Darwin)
	# First the automated `os_events::macos` lib unit tests (incl. the
	# T5.0 clean-shutdown contract test, which registers real observers
	# and pumps a real CFRunLoop) — they pass without interaction. Then
	# the manual integration cases that need a human to trigger sleep /
	# screen lock.
	$(CARGO) test -p falach-security --offline --locked --features iokit --lib os_events::macos -- --ignored --test-threads=1
	$(CARGO) test -p falach-security --offline --locked --features test-binaries,iokit --test us_052_post_mvp_iokit -- --ignored --test-threads=1
else
	$(CARGO) test -p falach-security --offline --locked --features test-binaries,logind --test us_052_post_mvp_logind -- --ignored --test-threads=1
endif

fmt:  ## Auto-format the workspace.
	$(CARGO) fmt --all

fmt-check:  ## Verify formatting without modifying files (CI gate).
	$(CARGO) fmt --all --check

lint:  ## Run clippy with `-D warnings` (CI gate).
	$(CARGO) clippy $(CLIPPY_FLAGS)

lint-fix:  ## Apply clippy auto-fixes where safe.
	$(CARGO) clippy --workspace --all-targets --offline --locked --fix --allow-dirty

# ---------------------------------------------------------------------------
# Full local CI gate — run before pushing.
# ---------------------------------------------------------------------------

check: fmt-check lint build test check-macos check-feature-gates  ## fmt-check + lint + build + test + macOS/feature-gate type-checks (the CI gate).

verify: check test-ignored doc deny audit interop interop-entry interop-sync  ## Run the full core verification gate.

interop:  ## Run vault-core KeePassXC interop shell tests (requires keepassxc-cli).
	$(CARGO) build -p falach-core --bin falach-test-driver --offline --locked
	FALACH_TEST_DRIVER=target/debug/falach-test-driver sh tools/interop-tests/us_090_rust_to_kpxc.sh
	FALACH_TEST_DRIVER=target/debug/falach-test-driver sh tools/interop-tests/us_091_kpxc_to_rust.sh
	FALACH_TEST_DRIVER=target/debug/falach-test-driver sh tools/interop-tests/us_092_round_trip.sh

interop-sync:  ## Run the s3-sync KeePassXC merge-interop test (US-044; requires keepassxc-cli).
	# Builds the test-only merge driver (gated behind `test-helpers` via
	# required-features, so `make build` never compiles it), then runs the
	# shell harness that opens the merged vault in keepassxc-cli and asserts
	# the collision loser survives as a history entry (NFR-009 / FR-043).
	$(CARGO) build -p falach-sync --bin merge-interop-driver --features test-helpers --offline --locked
	FALACH_SYNC_MERGE_DRIVER=target/debug/merge-interop-driver sh tools/interop-tests/sync_us-044.sh

interop-entry:  ## Run entry-management KeePassXC interop shell tests (requires keepassxc-cli; oathtool optional).
	$(CARGO) build -p falach-core --bin falach-test-driver --offline --locked
	@for script in tools/interop-tests/entry_us-010.sh \
	               tools/interop-tests/entry_us-012.sh \
	               tools/interop-tests/entry_us-013.sh \
	               tools/interop-tests/entry_us-014.sh \
	               tools/interop-tests/entry_us-016.sh \
	               tools/interop-tests/entry_us-018.sh; do \
		echo "==> $$script"; \
		FALACH_TEST_DRIVER=target/debug/falach-test-driver "$$script" || exit $$?; \
	done

bench:  ## Run informational benchmarks.
	$(CARGO) bench -p falach-core --bench vault_open --offline --locked

bench-search:  ## Run the informational entry-search benchmark.
	$(CARGO) bench -p falach-core --bench bench_search --offline --locked

bench-search-gate:  ## NFR-002 gate: fail if entry-search exceeds the latency budget (BUDGET_MS overridable; fuzzy also warns above FUZZY_WARN_MS).
	tools/bench/bench_search_gate.sh

# ---------------------------------------------------------------------------
# Supply-chain and docs.
# ---------------------------------------------------------------------------

deny:  ## Run cargo-deny license + advisory + ban checks (requires cargo-deny installed).
	$(CARGO) deny check

audit:  ## Run cargo-audit against RustSec advisories (requires cargo-audit installed).
	$(CARGO) audit

doc:  ## Generate API docs locally.
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --no-deps --offline

# ---------------------------------------------------------------------------
# Shell completions (FR-064) — re-generated by `make completions`, checked
# into shell-completions/ for packaging + the CI drift gate.
# ---------------------------------------------------------------------------

completions:  ## Re-generate shell-completions/falach.{bash,fish} + _falach.
	$(CARGO) run --example gen_completions -p falach-cli --offline --locked

completions-check: completions  ## Re-generate completions and fail the build if shell-completions/ drifted (CI gate).
	@drift="$$(git status --porcelain -- shell-completions/)"; \
	if [ -n "$$drift" ]; then \
		echo "error: shell-completions/ drifted. Run \`make completions\` and commit the result." >&2; \
		echo "$$drift" >&2; \
		git --no-pager diff -- shell-completions/ >&2; \
		exit 1; \
	fi

# ---------------------------------------------------------------------------
# Dependency vendoring — the only target that needs network access.
# See CONTRIBUTING.md "Adding a dependency" for the full 5-step workflow.
# ---------------------------------------------------------------------------

vendor:  ## Re-vendor dependencies into vendor/. REQUIRES NETWORK ACCESS.
	CARGO_NET_OFFLINE=false $(CARGO) vendor

# ---------------------------------------------------------------------------
# Housekeeping.
# ---------------------------------------------------------------------------

clean:  ## Remove build artifacts (target/).
	$(CARGO) clean
