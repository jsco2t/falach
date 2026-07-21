# Falach

Falach (Scottish Gaelic: "hidden, concealed", pronounced FAH-luhkh) is an offline-first secrets manager built on a Rust core with thin cross-platform UIs. Vaults are stored in the KDBX (KeePass) format via the `keepass-rs` crate, so every Falach vault is directly interoperable with KeePassXC, KeeWeb, KeePass2, and mobile KDBX clients. Default sync transport is S3-compatible object storage (PRD §6.5 v1.1), with in-app three-way merge at the entry level.

**License:** MIT. **Status:** Greenfield (Phase 0 in progress).

## Planning docs (authoritative)

Engineering plans live outside this repo in the project notebook. Read these when scoping work — do not duplicate them here.

- **PRD:** `$HOME/Developer/sources/personal/notebook/projects/falach/prd.md` — the product spec; section IDs (FR-xxx, NFR-xxx) are referenced throughout the plans.
- **Project index:** `$HOME/Developer/sources/personal/notebook/projects/falach/index.md`
- **Verifications (user scenarios):** `…/falach/verifications/` — every Must-Have FR maps to a US-xxx scenario.
- **Knowledge base:** `…/falach/kb/` — KDBX format, three-way merge algorithm, memory hygiene, supply-chain policy, library notes.
- **Features:** `…/falach/features/<slug>/` — per-feature implementation plan, design, task plan, follow-ups. First feature: `features/vault-core/`.

When implementing a feature, the corresponding `plans/implementation-plan.md` and `plans/design.md` are the source of truth for that feature's scope and architecture.

## Architecture posture

- **Rust core, thin UIs.** All business logic and crypto live in the Rust core library. CLI and TUI are presentation layers over the same core. Future Flutter UIs (Phase 1+) bind to the same core via FFI. No UI-layer logic leaks into the core.
- **TUI is the reference UX.** Every feature lands in the TUI with full keyboard parity before any GUI work begins. CLI provides one-shot scriptable access to every core operation.
- **Offline-first.** Every feature works without network. Sync is opt-in and operates on top of the offline core — never a precondition.
- **Sync trait abstraction.** Phase 0 sync is **S3-compatible object storage** per PRD §6.5 v1.1 (2026-05-27 — replaces the originally-planned git transport, which was abandoned mid-implementation; see notebook `features/archive/sync-git/` and PRD §C decision #17). Later transports (NFS, Samba, WebDAV, possibly a reconsidered git transport) implement the same `SyncTransport` trait. CRUD and merge logic stay transport-agnostic. The gix-based scaffolding and its vendored deps were removed in `features/s3-sync/` T1; the S3 transport (hand-rolled SigV4 + `ureq`, design.md ADR-1) lands across `features/s3-sync/` Phases 2–6.

## Engineering principles

1. **KDBX interop is a product promise, not an implementation detail.** A Falach vault must round-trip through KeePassXC (≥2.7) with zero observable data loss. Any custom data written into a vault must be readable by a standards-compliant KDBX client. Round-trip CI tests gate every change to the vault layer.
2. **Test-forward.** Every Must-Have FR has at least one automated test AND one user-scenario verification in `notebook/.../verifications/`. The coverage matrix is a CI gate. Property-based / fuzz tests for the merge engine and fault-injection tests for atomic writes are first-class deliverables, not nice-to-haves.
3. **Simplicity over cleverness.** Prefer obvious code, narrow abstractions, and well-trodden patterns. Don't introduce generality for hypothetical future requirements. Three similar lines beats a premature abstraction.
4. **No data loss, ever.** During sync conflicts, the loser is preserved as a KDBX history entry under the same UUID. Atomic writes (write-then-rename) ensure a crash never leaves a corrupted vault. Pre-merge state is kept as `.kdbx.bak`.
5. **Honest about limits.** Document platform limitations (encrypted swap, `mlock` quotas, OS lock-event reliability) rather than papering over them. Cosmic-ray paranoia (Rowhammer, cold-boot DMA) is explicitly out of scope.
6. **Limited External Dependencies** Only add external dependencies when it is very clear they solve a major gap in functionality. For minor features it's worth evaluating writing the code directly in the repo (vs adding N more dependencies).

## Security rules (non-negotiable)

- **Zeroize on drop** for every type holding sensitive bytes (master keys, derived keys, entry passwords, master-password input buffers). Use `zeroize::ZeroizeOnDrop`.
- **`mlock` the master key** where the platform supports it (best-effort; quotas are small, so don't lock everything).
- **No plaintext to disk, ever.** The unlocked KDBX is never serialized in plaintext. Never log entry contents. Never include secret material in error messages.
- **Master password collection: secure stdin prompt only.** Never accept on the command line, never accept as an env var (leaks via shell history / `ps`).
- **No master-password recovery.** Warn at vault creation; there is no escrow, backdoor, or recovery service.
- **Atomic writes.** Always write to a sibling temp file and `rename(2)`. Never truncate the live vault.
- **Advisory file locking** coordinates concurrent CLI/TUI/agent processes. Concurrent reads OK; writes serialized.
- **Disable core dumps** for the agent and TUI (`setrlimit(RLIMIT_CORE, 0)`).
- **No telemetry, no analytics, no crash reporting, no update checks.** The only network calls are user-configured sync.
- **No hand-rolled crypto.** Cryptography comes from `keepass-rs` and the RustCrypto family (Argon2, AES, HMAC, SHA). KDBX4 KDF is Argon2id, tuned to ~1s on target hardware.
- **CSPRNG only.** Password generation uses `OsRng` from `rand`.

## Supply chain rules (non-negotiable)

- **Minimize external dependencies — actively.** This is the first and most important supply-chain rule, restated from engineering principle #6. Every new direct dependency drags transitives, expands the license-audit and security-review surface, increases the vendored tree, and adds versions that go stale. **Before adding a dep, evaluate whether the functionality could be written directly in the repo** (the SigV4 signer in `features/s3-sync/` is a worked example — ~400 LoC of in-repo code avoided ~60 transitive crates from the `aws-sigv4` ecosystem). Hand-rolling a small well-specified algorithm is almost always preferable to importing a feature-rich library that solves a hundred problems we don't have. If a dep is genuinely needed, prefer the narrowest crate that solves only our problem.
- **Permissive licenses only:** MIT, Apache-2.0, BSD-2/3-Clause, ISC, Zlib, Unlicense, CC0-1.0, Unicode-3.0, Unicode-DFS-2016.
- **Forbidden:** GPL-2.0, GPL-3.0, LGPL-2.1/3.0, AGPL-3.0, SSPL, Commons Clause, anything copyleft. **GPL-with-linking-exception is also forbidden** (e.g., libgit2 — the ambiguity isn't worth it; `git2` / `libgit2-sys` are explicitly banned in `deny.toml`).
- **Pinned exact versions.** `Cargo.lock` is the source of truth and is committed.
- **Vendored dependency tree.** All crates vendored at `vendor/` via `cargo vendor`. Builds run `--offline` / `CARGO_NET_OFFLINE=true`.
- **Off-target vendored sources are unavoidable; budget for them.** `Cargo.lock` is target-agnostic by design — the resolver records every platform-conditional dep across every triple a transitive could ever reach (Windows, Android, wasm32, etc.) so the lockfile is reproducible across hosts. Cargo's source-replacement (`replace-with = "vendored-sources"`) then validates the *entire* lockfile against `vendor/` at resolution time, so every locked package must exist on disk even if rustc will never compile it for our Phase-0 triples (macOS aarch64/x86_64, Linux x86_64/aarch64). The cost is disk space — `vendor/` currently carries ~90 directories of Windows / Android / wasm sources that rustc skips via `#[cfg(target_os = ...)]`. The supply-chain audit (`cargo deny`) sees through this via `deny.toml`'s `targets = [...]` constraint, so licenses + advisories only check the four target triples we actually ship. **This makes "minimize external dependencies" non-negotiable** — every new direct dep can drag Windows / Android / wasm transitives into `vendor/` that bloat the tree without ever being shipped. Recent example: adding `ureq 3.3.0` for the S3 transport pulled ~51 new vendored crates, of which roughly 20 are off-target placeholders (mostly Android `jni`-family + Windows `schannel` + wasm `webpki-root-certs`).
- **No build-script networking.** Dependencies' `build.rs` must not fetch anything or shell out to undocumented executables.
- **Dependency-add/upgrade checklist** (documented in PR description): license check, upstream maintenance signal, popularity baseline, diff review of vendored sources, **and an honest assessment of "could we hand-roll this instead?"**
- **Enforcement:** `cargo deny` for license + advisory + banned crates; `cargo audit` for RustSec advisories. Both are CI gates.

## Technical constraints

- **Language:** Rust. No `unsafe` outside well-justified, locally-audited blocks. No FFI in the core (FFI lives at UI boundaries only).
- **Target platforms (Phase 0):** macOS (aarch64 + x86_64) and Linux (x86_64 + aarch64). Windows is not a Phase 0 target.
- **Storage format:** KDBX4 (write); KDBX3 (read, for migration). No proprietary format.
- **State / vault default directory:** `$HOME/.local/state/falach/` on both macOS and Linux (deliberately consistent — not following macOS `Application Support/`). Per-vault override allowed.
- **Vault registration:** TOML at `$HOME/.local/state/falach/vaults.toml`.
- **Key libraries (locked in):**
  - `keepass-rs` (MIT) — KDBX read/write.
  - `zeroize` (MIT/Apache-2.0) — memory hygiene.
  - `rand` / `OsRng` (MIT/Apache-2.0) — CSPRNG.
  - `clap` (MIT/Apache-2.0) — CLI parsing.
  - `ratatui` (MIT) — TUI framework.
  - RustCrypto family — crypto primitives.
- **Phase-0 sync transport (lands in `features/s3-sync/` Phases 2–6):** S3-compatible object storage via a hand-rolled SigV4 signer + `ureq 3.3` (MIT OR Apache-2.0) over `rustls` with the `ring` provider, per design.md ADR-1. The earlier `gitoxide` / `gix-*` stack was removed in `features/s3-sync/` T1.

## Build system

**`make` is the build system of record.** Every developer-facing workflow — build, test, lint, format, vendor, supply-chain audit, docs — has a target in the top-level [`Makefile`](Makefile). Developer workstations and CI run identical commands by going through `make`; raw `cargo` invocations are reserved for ad-hoc exploration. Run `make` (or `make help`) to list every target.

The canonical targets:

| Target              | What it does                                                                                            |
| ------------------- | ------------------------------------------------------------------------------------------------------- |
| `make toolchain`    | One-time dev bootstrap: Rust (via `rustup`), `keepassxc-cli`, `cargo-deny`/`audit` (x-plat, idempotent) |
| `make build`        | `cargo build --workspace --offline --locked`                                                            |
| `make test`         | Default-parallel tests (`--offline --locked`)                                                           |
| `make test-ignored` | `#[ignore]`d tests, serial (`--test-threads=1`) — env-mutating tests, etc.                              |
| `make test-all`     | Both of the above                                                                                       |
| `make fmt`          | Auto-format the workspace                                                                               |
| `make fmt-check`    | Format check (CI gate)                                                                                  |
| `make lint`         | `cargo clippy ... -- -D warnings` (CI gate)                                                             |
| `make lint-fix`     | Apply safe clippy suggestions                                                                           |
| `make check`        | `fmt-check` + `lint` + `build` + `test` (the full local CI gate)                                        |
| `make deny`         | `cargo deny check` (license + advisory + bans)                                                          |
| `make audit`        | `cargo audit` (RustSec advisories)                                                                      |
| `make doc`          | Generate API docs (`cargo doc --no-deps --offline`)                                                     |
| `make vendor`       | Re-vendor deps (the only target that needs network)                                                     |
| `make clean`        | Remove build artifacts                                                                                  |

### Keeping the Makefile up to date — a project rule

**When new functionality introduces a new developer or CI command, add a corresponding `make` target in the same change.** This includes:

- A new lint, formatter, or static-analysis pass.
- A new test runner or test category (benchmarks, fuzzers, property-based, integration harnesses).
- A new code-generation step.
- A new shell-script harness (e.g., Phase-6 `tools/interop-tests/`).
- A new release / packaging / signing step.

Two reasons this rule is non-negotiable:

1. **Discoverability.** Every workflow lives in `make help`; no command exists only inside someone's shell history, a CI YAML, or a commit message.
2. **CI / dev parity.** CI invokes `make`, so anything CI does is reproducible locally with the same target name. The day a CI step diverges from a `make` target is the day "works on my machine" becomes possible.

Concretely: if a PR adds a `run: cargo ...` (or any shell command) to a CI workflow, the equivalent `make` target must land in the same PR. The Phase-6 tasks T6.2 (interop-tests harness), T6.3 (CI matrix completion), and T6.4 (KDF benchmark) will each add Makefile targets.

If a target's command becomes long or grows multiple cases, prefer adding flag variables (`CLIPPY_FLAGS`, etc.) over inlining; keeps the recipe readable and the variation surface visible.

## CLI conventions

- One-shot subcommands for every core operation.
- `--format json` for machine-readable output; secrets emitted only with explicit flags (e.g., `entry get --show-password`).
- Stable, documented exit codes: `0` success, `1` user error, `2` vault locked / auth failure, `3` sync conflict requiring user, `10+` internal errors.
- Shell completions for bash, zsh, fish produced by the build.

## Performance targets

- Vault open (Argon2id decrypt + parse, ≤500 entries) <500ms on M1 Mac / mid-tier x86_64 Linux.
- Search across an unlocked vault <50ms for ≤5,000 entries.

## Repo state

**Phase 0 progress (as of 2026-06-06): MVP code-complete.** All six MVP-critical features are implemented; the only open gate is one manual accessibility verification.

- **`vault-core`: complete.** KDBX read/write wrapper, vault registration, master-password unlock, atomic writes, advisory locking (20/20 tasks).
- **`entry-management`: complete.** CRUD across credential / secure-note / TOTP / attachment types; groups; tags; search; history (16/16 tasks).
- **`password-generation`: complete.** Random + EFF diceware via `getrandom` (11/11 tasks).
- **`security-behaviors`: complete.** Idle auto-lock, OS lock events (`LogindSource`/`IoKitSource`), clipboard auto-clear (12/12 tasks, all 5 phases).
- **`cli-skeleton`: complete.** `clap`-based one-shot subcommands, secure-stdin prompt, JSON output, stable exit codes, shell completions (all 4 phases).
- **`s3-sync`: complete.** Sync trait + S3-compatible transport (hand-rolled SigV4 + `ureq`) + in-app three-way merge with loser-as-history preservation (25/25 tasks; merged to `main` 2026-05-31).
- **`tui-skeleton`: code-complete.** `ratatui` tabbed-workspace shell — unlock, navigable tree, scrollable multi-type detail, action overlays (search/edit/generate/history), pinned tabs, MRU recents, Settings + live `falach-sync` integration with secure S3-credential entry (31/32 tasks; all 7 phases). The full workspace builds and all 193 `falach-tui` tests pass. **Sole open item: T7.4's manual NFR-015 (Orca) screen-reader verification** — cannot run headless.

**Open by design (not gating MVP code-completion):** the `pre-mvp-fixes` bucket (5/5 — all fixed as of 2026-06-11; see `features/index.md`) and the post-MVP `ssh-keys` + `agent` features (not yet planned).

See `…/features/index.md` for the per-feature rollup and each feature's `tasks/index.md` for live task-tracking tables.

## Shell command style

Prefer running commands as seperate Bash tool calls rather than chaining them with `&&`, `||`, `;`,
or pipes. Each command should be its own invocation so the permission matcher can authorize them
individual.

Exceptions where chaining is fine:

- Pipes that are part of a single logical operation (`grep ... | wc -l`, `cat foo | jq .bar`) - these
  only make sense as one command.

- `cd <dir> && <cmd>` when the directory change must scope to that one command and not persist.

When in doubt, run them separately.
