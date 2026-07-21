# Contributing to Falach

Thanks for your interest. Falach is a personal/OSS project that values
**simplicity over cleverness** and treats KDBX interop, durability, and
supply-chain hygiene as **non-negotiable**. Please read this document — and
[`CLAUDE.md`](CLAUDE.md) — before opening a PR.

Authoritative source documents (read these for scope):

- **Project PRD** and **engineering plans** live in the project notebook
  (paths referenced in [`CLAUDE.md`](CLAUDE.md) — section "Planning docs").
- **Supply-chain policy:** `notebook/.../falach/kb/supply-chain-policy.md`.
- **Test plan:** the test conventions in this document are the canonical
  summary of Test Plan §8.1 in the vault-core implementation plan.

---

## Workspace layout

```
falach/
├── Cargo.toml                # workspace manifest, resolver = "2"
├── Cargo.lock                # pinned, source of truth, checked in
├── rust-toolchain.toml       # pinned channel
├── deny.toml                 # cargo-deny config
├── .cargo/config.toml        # offline + vendored-sources
├── vendor/                   # all dependencies, checked in
├── .github/workflows/        # CI
├── crates/
│   ├── falach-core/         # library — KDBX I/O, registry, atomic, locking
│   ├── falach-cli/          # placeholder binary
│   ├── falach-tui/          # placeholder binary
│   └── falach-agent/        # placeholder binary
└── tools/
    └── interop-tests/        # bash harness, arrives in Phase 6
```

Only `falach-core` is implemented in Phase 0. The three binary crates are
stubs reserved for later features and must not be deleted (the layout is
part of the workspace contract).

---

## First-time setup

On a fresh machine (Linux or macOS), install all required tooling with one
command:

```sh
make toolchain     # Rust toolchain (via rustup), keepassxc-cli, cargo-deny, cargo-audit
```

It is cross-platform and idempotent — it uses `rustup` for the pinned Rust
toolchain (per `rust-toolchain.toml`), the native package manager for
`keepassxc-cli` (Homebrew on macOS; apt/dnf/pacman/zypper on Linux), and
`cargo install` for the supply-chain tools, at the same versions CI uses. It
skips anything already installed. `rustup` itself is the one prerequisite
(see <https://rustup.rs>). After it finishes, the offline `make` loop below
works from a clean clone.

## Building and testing

**Everything goes through `make`** — `make` is the build system of record
(see [`CLAUDE.md`](CLAUDE.md) §"Build system"). Run `make` alone (or
`make help`) to list every target. The day-to-day loop:

```sh
make build         # build the workspace (offline, vendored)
make test          # default-parallel tests
make test-ignored  # serial run of env-mutating / fault-injection tests
make fmt           # auto-format
make lint          # clippy with `-D warnings`
make check         # fmt-check + lint + build + test — the full local CI gate
make verify        # check + ignored tests + docs + supply-chain checks + interop
make deny          # cargo-deny (license + advisory + bans)
make vendor        # re-vendor dependencies (the only target that needs network)
```

These targets wrap `cargo` with `--workspace --offline --locked`. A clean
clone produces identical results to CI because `Cargo.lock`, `vendor/`,
`rust-toolchain.toml`, and the `Makefile` itself are all committed and
authoritative.

**Adding a new workflow?** If you add a new lint, test category, code-gen
step, harness, or CI step, add the matching `make` target in the same
change. This is a project rule — see [`CLAUDE.md`](CLAUDE.md)
§"Keeping the Makefile up to date" for the rationale.

---

## Adding a dependency

Every new dependency goes through this five-step workflow (from the
supply-chain policy, Rule 4). Document each step in the PR description.

### 1. License check

The dependency's license **must be one of**: `MIT`, `Apache-2.0`,
`Apache-2.0 WITH LLVM-exception`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`,
`Zlib`, `Unicode-3.0`, `Unicode-DFS-2016`, `Unlicense`, `CC0-1.0`.

The following are **forbidden**, including via transitive deps:
`GPL-*`, `LGPL-*`, `AGPL-*`, `SSPL-*`, `Commons Clause`,
**including GPL-with-linking-exception** (the ambiguity isn't worth it —
e.g., `libgit2` is banned in favor of `gitoxide`).

`cargo deny check licenses` enforces this.

**Clarification — linked vs. invoked test drivers:** GPL software
**linked or loaded** into the build (linked as a C library, loaded via
FFI, statically included) is forbidden by the rules above. GPL software
**invoked as a subprocess in tests** (e.g., the `keepassxc-cli` binary
used for KDBX round-trip verification) is **permitted** — it does not
enter `Cargo.lock` and is not redistributed with the binary. This is
documented to avoid future ambiguity.

### 2. Maintenance signal

Confirm the crate is actively maintained: recent commits, recent
releases, responsive issue tracker, no flood of unaddressed security
advisories. If the crate is dormant but the code is small and obvious,
prefer vendoring with patches over depending on a stale upstream.

### 3. Popularity baseline

The crate should be in widespread use within the Rust ecosystem
(typically: pulled in transitively by `cargo`, `rustup`, popular
runtimes, or major application crates). Lightly-used crates require
extra scrutiny in step 5.

### 4. Vendoring + Cargo.lock review

Add the dependency to `Cargo.toml`, then:

```sh
make vendor   # CARGO_NET_OFFLINE=false cargo vendor — needs network access
```

Inspect the diff in `vendor/` and `Cargo.lock`:

- Confirm only expected new directories appear.
- Skim `Cargo.toml` of each new vendored crate — look for `build.rs`
  scripts that fetch from the network or shell out to external tools.
  **Build-script networking is forbidden.**
- Confirm no banned crates (`openssl-sys`, `git2`, `libgit2-sys`,
  `native-tls`) appear in the dep graph.
- Run `make deny` locally — it must pass.

### 5. PR description checklist

The PR description must include a checklist of:

- [ ] License of each new (direct + transitive) crate — confirmed
      permissive
- [ ] Upstream maintenance status — last release, last commit, issue
      backlog
- [ ] Popularity — download count and notable users
- [ ] Vendored diff reviewed — no surprises
- [ ] `make deny` clean
- [ ] `make build` clean from a fresh clone

CI gates merge on `make deny` (license + advisory + bans) and
`make audit` (RustSec advisories).

### Dependency Review Log

Direct dependencies added through the workflow above, newest first. Each line
records the review at its add point; transitive crates are covered en masse by
`make deny` (license + bans) over the four Phase-0 targets.

#### `falach-tui` — `ratatui` TUI stack (tui-skeleton Phase 1, 2026-06-01)

The reference terminal UI's four direct deps, pinned to the latest stable
published ≥30 days old (impl-plan OQ-1). All MIT / MIT-OR-Apache-2.0 throughout;
`make deny` (licenses + bans + sources) green; no `build.rs` networking in any
vendored crate. `falach-core` + `falach-sync` are workspace path deps (no new
vendored sources); `libc` (`cfg(unix)`, the async-signal-safe `SIGHUP`/`SIGTERM`
handler) was already vendored.

| Crate | Ver | License | Maintenance / popularity | Notes |
| --- | --- | --- | --- | --- |
| `ratatui` | 0.30.0 | MIT | The maintained `tui-rs` successor; the de-facto Rust TUI framework. | Default features (`crossterm`, `all-widgets`, `macros`, `layout-cache`, `underline-color`). 0.30 split into `ratatui-core` / `ratatui-crossterm` / `ratatui-widgets` (all MIT). **Vendor footprint is larger than the original "~10–15" estimate (~60 new dirs)** — ratatui's color/layout tree (`csscolorparser`, `kasuari`, `compact_str`, …) plus its *optional* `termion`/`termwiz` backends, which are vendored-but-never-compiled (default features select crossterm only; off-target/optional cost per CLAUDE.md "off-target vendored sources"). |
| `crossterm` | 0.29.0 | MIT | The standard cross-platform terminal backend; ratatui's default. | Declared directly for raw-mode / alternate-screen (`terminal_guard`) and the `KeyEvent` types (`keys`). Single version in the tree (ratatui 0.30 rides crossterm 0.29). |
| `tui-input` | 0.15.3 | MIT | Small input-widget primitive. | `features = ["crossterm"]` (vendor the full tree once; wired by the Phase-2 `PasswordInput`). 0.15.3 targets crossterm 0.29 + ratatui 0.30 + unicode-width 0.2. |
| `unicode-width` | 0.2.2 | MIT OR Apache-2.0 | Unicode TR-11 display widths; ubiquitous. | Display-width-correct tab-label / detail truncation (Phase-2 T2.4 / OQ-N6). |

**Incidental supply-chain fix (separate from the TUI deps):** the re-vendor
surfaced that `aes 0.9.0` — a transitive of `keepass 0.12.9` (`falach-core`) —
was **yanked** upstream (after the 2026-05-31 `s3-sync` merge, so not caught
then), which `deny.toml`'s `yanked = "deny"` rejects. Resolved with the
registry's intended replacement via `cargo update -p aes --precise 0.9.1`
(satisfies keepass's `^0.9`; **no keepass change**). KDBX crypto behaviour
unchanged — verified by `cargo test -p falach-core -p falach-sync` (incl. the
`merge_semantics.rs` characterization suite). `make deny` + `make audit` green.

#### `keepass` `_merge` feature enabled (Phase 4, 2026-05-26)

**No new crate.** A feature flag on the already-vendored, exact-pinned
`keepass = "=0.12.9"` (in `falach-core`): `features = ["save_kdbx4", "_merge"]`.
`_merge` (an empty feature, `_merge = []`) compiles the crate's UUID-keyed
two-way `Database::merge`, which the sync layer reuses behind
`falach_sync::merge::reconcile` (design ADR-008). No dependency-graph, license,
or `cargo deny` impact (verified: `make check` green). It is an **experimental**
(`_`-prefixed) upstream feature, accepted under the same posture as keepass's
experimental KDBX4 *write* (KB `keepass-rs-library.md` limitation #1): pinned +
vendored so it only moves on a deliberate upgrade, and its observable semantics
are pinned by a defensive characterization suite
(`crates/falach-sync/tests/merge_semantics.rs`) that fails CI if a future bump
changes merge behaviour. **Upgrade rule:** any bump of the keepass pin must
re-run that suite and review upstream `_merge` changes before landing.

#### `falach-sync` — HTTPS transport + pure-Rust send-pack (Phase 2b, 2026-05-26)

ADR-007: gix 0.78 has no push and the mobile ship target rules out a `git`
subprocess, so **fetch runs over our own `rustls` HTTP backend** and **push is a
pure-Rust smart-HTTP `send-pack`** on gix plumbing. This adds the TLS stack and
promotes gix's base `http-client`/pack plumbing to direct deps. The T2b.1 spike
validated the whole flow against real GitHub (fetch) + a local `git http-backend`
(send-pack), and `falach-sync` `cargo check`s clean for **both** mobile targets
(`aarch64-apple-ios` via Xcode SDK, `aarch64-linux-android` via NDK clang).
`make deny` green.

| Crate | Ver | License | Maintenance / popularity | Notes |
| --- | --- | --- | --- | --- |
| `rustls` | 0.23 | MIT OR Apache-2.0 OR ISC | `rustls` project; the standard pure-Rust TLS. | `default-features=false` + `ring,std,tls12` — pins the **`ring`** provider, **NOT** the default `aws-lc-rs` (more C; ADR-007). Powers fetch + send-pack over HTTPS. |
| `ring` | 0.17 | `MIT AND ISC AND OpenSSL` (pre-cleared in `deny.toml [[licenses.clarify]]`) | `briansmith/ring`; the most-deployed Rust crypto provider, incl. iOS/Android. | Transitive via rustls's `ring` feature. Build compiles C/asm → needs the platform C toolchain (Xcode iOS SDK / Android NDK) — both verified to cross-compile. |
| `rustls-platform-verifier` | 0.5 | MIT OR Apache-2.0 | `rustls/rustls-platform-verifier`. | Native OS trust store (macOS/iOS/Android) + system-CA on Linux. **The linchpin that avoids `webpki-roots` (MPL-2.0, banned).** Pulls `-android` + `jni` on Android (runtime JVM-init = a Phase-2 Flutter-bridge detail). |
| `gix-transport` | 0.53 | MIT OR Apache-2.0 | gitoxide. | Base `http-client` feature only — the `Http` backend trait + generic smart-HTTP `Transport`, **without** curl/reqwest (C-free). We implement `Http` over rustls and use `connect_http`. |
| `gix-protocol` | 0.56 | MIT OR Apache-2.0 | gitoxide. | `blocking-client`; handshake / `ls-refs` / fetch. |
| `gix-pack` | 0.65 | MIT OR Apache-2.0 | gitoxide. | Pack-v2 generation for send-pack (`data::output::Entry::from_data` + `FromEntriesIter`; single-threaded, no `parallel` feature). |
| `gix-object` / `gix-odb` / `gix-hash` | 0.55 / 0.75 / 0.22 | MIT OR Apache-2.0 | gitoxide. | Object authoring + odb reads feeding pack generation. |
| `gix-url` | 0.35 | MIT OR Apache-2.0 | gitoxide. | URL parsing for `connect_http`. |

`ureq` was evaluated and **NOT** added: a hand-rolled minimal HTTP/1.1 client over
the rustls stream suffices, and `ureq` defaults its roots to `webpki-roots`
(MPL-2.0). SSH auth is **deferred** (FR-045; candidate `russh`).

Banned-crate scan after vendoring: confirmed **no `webpki-roots`,
`openssl`/`openssl-sys`, `native-tls`, `aws-lc-rs`/`aws-lc-sys`,
`git2`/`libgit2-sys`, or `curl`** in the graph. (rustls rides `ring`; cert-path
validation is `rustls-webpki`, Apache-2.0 OR ISC.) **Trust roots per target:**
macOS/iOS → `security-framework`; Android → `rustls-platform-verifier-android`
(+ `jni`); Linux → `rustls-native-certs` (+ `openssl-probe`) — all permissive.
**Note on `vendor/webpki-root-certs/`:** this is *not* the banned `webpki-roots`
(MPL-2.0) — it is a distinct crate (`CDLA-Permissive-2.0`) that
`rustls-platform-verifier` declares only as a **fallback for "other" platforms**.
It is **cfg-gated out of every target we ship** (verified absent from the
`cargo tree` graphs for macOS-arm64, Linux-x86_64, iOS-arm64 and Android-arm64;
the trust backend is selected by OS, not architecture, so the x86_64-macOS and
arm64-Linux siblings resolve identically); it appears under
`vendor/` solely because `cargo vendor` snapshots the full cfg-union of the lock,
exactly like the Windows-only `clipboard-win` (BSL-1.0). If a mobile/other triple
is ever added to `deny.toml`'s `targets`, decide then whether to allowlist
`CDLA-Permissive-2.0` or disable the fallback.

#### `falach-sync` — git sync (Phase 2, 2026-05-25)

The largest single addition so far: the `gix` family pulled the vendored tree
from 239 → 358 crates (+119). `make deny` is green; no `deny.toml` change was
needed (all new transitives resolve to a permitted license; the only
non-permissive licenses in the tree — `BSL-1.0` for `clipboard-win`,
`LGPL`/`0BSD` offered as an SPDX `OR` branch — are Windows-only (excluded by
`deny.toml` target scoping) or selectable under a permitted branch).

| Crate | Ver | License | Maintenance / popularity | Notes |
| --- | --- | --- | --- | --- |
| `gix` | 0.78 | MIT OR Apache-2.0 | `Byron/gitoxide`, very active; the pure-Rust git impl chosen over `libgit2`/`git2` (CLAUDE.md). | `default-features=false`; only `blocking-network-client` + `revision`. **Spike (T2.2) found gix 0.78 cannot push.** _(The original remedy here — git-CLI shell-out / T3.6 — was **superseded same-day by ADR-007**: push is a pure-Rust smart-HTTP send-pack, and the rustls HTTPS stack landed in Phase 2b above. See that entry.)_ |
| `argon2` | 0.5 | MIT OR Apache-2.0 | RustCrypto; foundational, widely used. | RST-CRED-1 KDF (design §2.2.3). **Duplicates `rust-argon2`** (keepass's KDBX KDF). T3.5 should decide whether to reuse `rust-argon2` and drop this — see follow-ups. |
| `chacha20poly1305` | 0.10 | Apache-2.0 OR MIT | RustCrypto; foundational. | RST-CRED-1 AEAD. |
| `base64` | 0.22 | MIT OR Apache-2.0 | `marshallpierce/rust-base64`; ubiquitous. | Already vendored transitively; now a direct dep for the credential container encoding. |
| `gethostname` | 1.1 | Apache-2.0 | `swsnr/gethostname`; small, stable, Unix+Windows. | Commit-message host line (design §2.6). |
| `proptest` (dev) | 1.x | MIT OR Apache-2.0 | `proptest-rs`; the standard Rust property-testing crate. | Merge-engine property tests (Phase 4/6). Dev-only. |
| `proptest-derive` (dev) | 0.5 | MIT OR Apache-2.0 | `proptest-rs`. | Dev-only. |
| `arbitrary` (dev) | 1.x | MIT OR Apache-2.0 | `rust-fuzz/arbitrary`; standard for fuzz input. | Fuzz-target structured input (Phase 6). Dev-only. |

Banned-crate scan after vendoring (at Phase-2 add-point): no
`openssl`/`openssl-sys`/`native-tls`/`git2`/`libgit2-sys`/`curl`. _(Phase 2b
subsequently added `rustls` + `ring` + `rustls-platform-verifier` for HTTPS —
still no `openssl`/`native-tls`/`aws-lc-rs`/`webpki-roots`; see the Phase-2b entry
above.)_
(Maintenance/popularity above is asserted from ecosystem familiarity; the
authoritative `vendor/` source-diff review is done by the reviewer per step 4.)

---

## Testing conventions

Established by Phase 0 (vault-core T1.4 / T1.5) and inherited by all
later features.

### Framework

- **Rust standard `#[test]`.** No third-party test framework (no
  `rstest`, no `cucumber`).
- **Assertions:** `assert!`, `assert_eq!`, `assert_ne!`, `assert_matches!`
  (stable Rust 1.82+). No `unwrap()` inside tests — use
  `expect("clear failure message")` so failures point at the right line.
  No `?` operator inside tests — let panics print the right location.

### Mocks

- **None.** Vault-core has no mock-worthy boundary; its dependencies
  are the filesystem and `keepass-rs`. Both are used real, in
  `tempfile::TempDir`-isolated sandboxes. Tests that need a "second
  process" (cross-process locking, fault injection) spawn one via
  `std::process::Command` against a tiny in-repo helper binary.

### Layout

- **Unit tests** live in a `#[cfg(test)] mod tests` block at the bottom
  of the module file they exercise.
- **Integration tests** live in `crates/falach-core/tests/`, one file
  per user scenario, named for the US identifier (`us_001_create_vault.rs`,
  etc.).
- **Shared helpers** live in `crates/falach-core/tests/common/mod.rs`
  (Cargo convention). Phase 0 establishes [`TestEnv`].
- **Helper binaries** (`lock_holder`, `fault_helper`, `vault_holder`,
  `falach-test-driver` — Phase 4+) are declared as `[[bin]]` entries
  in `Cargo.toml`. Tests discover them via
  `env!("CARGO_BIN_EXE_<name>")` — the standard Rust idiom — not via
  `cargo run --bin`.

### Table-driven tests

Where multiple inputs exercise the same behavior, use a
`cases: &[Case]` slice with a loop. Each case has a
`name: &'static str` field; assertion messages include the case name so
failures are unambiguous.

### Cleanup

- **Every test that touches the filesystem uses `tempfile::TempDir`**
  (or `NamedTempFile`); the directory is auto-deleted on drop.
- **No test writes to `$HOME`, `/tmp` directly, or any path resolved
  from the user's real environment.** The `TestEnv` helper enforces
  this by constructing a `FalachPaths` whose `state_dir` is inside the
  tempdir.

### `unsafe` in tests

Two specific test categories require `unsafe`:

1. **Zeroize verification** — `std::ptr::read_volatile` to inspect the
   underlying buffer of a `MasterPassword` / `Keyfile::Bytes` after
   calling `.zeroize()`. One test per sensitive type, with a documented
   block-level SAFETY comment.
2. **Environment mutation** — `std::env::set_var` / `remove_var` are
   `unsafe` in Rust 1.85+ due to libc-getenv thread-safety semantics.
   Tests that mutate env vars use an `EnvGuard` RAII helper that
   serializes via a module-local `Mutex<()>`.

Production code in `falach-core` is `#![cfg_attr(not(test), forbid(unsafe_code))]`.
The two test exceptions above are the only `unsafe` allowed in the
crate at Phase 0. `mlock` of the master key — the only other
candidate for `unsafe` — is deferred (design §3.9).

---

## Security-behaviours testing conventions

The `falach-security` crate carries two test-invocation conventions
that are not obvious from the `cargo test` defaults.

### Signal-handler test serialization (`SignalGuard`)

Tests that install a `signal-hook::iterator::Signals`, call
`signal::raise(...)`, send signals to spawned children, or otherwise
touch process-global signal disposition **must** acquire a shared
`Mutex<()>` at the top of their body. The shared lock lives at
`crates/falach-security/tests/common/signals.rs` (`SIGNAL_GUARD`) and
its module docstring documents the contract.

The lock prevents two parallel `cargo test` workers in the same test
binary from racing each other inside the kernel's process-global
signal state. Tests that do NOT touch signal disposition do not need
the guard. The pattern mirrors `falach-core`'s `EnvGuard` for `HOME`.

Phase 1 of the `security-behaviors` feature lands the guard; Phase 4
is the first phase whose tests consume it. The early landing is
intentional — adding the helper alongside its first consumer would be
a churn-y forwarding PR.

### Clipboard / OS-events test invocation (`make test-clipboard`, `make test-os-events`)

`falach-security`'s clipboard tests need a real display server (X11,
Wayland, or macOS Pasteboard) so they're `#[ignore]`d by default.

- `make test-clipboard` runs the `#[ignore]`d clipboard tests serially
  (`--test-threads=1`). On Linux CI, wrap the invocation in
  `xvfb-run -a make test-clipboard` so an X11-headed display is
  available. The matching test filter is `us_053_clipboard`.
- `make test-os-events` is a post-MVP placeholder. In MVP it runs zero
  tests (no matching test names exist); when `LogindSource` (Linux DBus)
  and `IoKitSource` (macOS) land in Phase 5 they will add tests under
  the `us_052_post_mvp` filter.

Both targets are wrappers over `cargo test`; the actual `#[ignore]`
filtering happens in code. The Makefile targets exist primarily for
discoverability via `make help` and for CI workflow parity.

---

## CLI conventions

The `falach-cli` crate is the reference scriptable surface (PRD §6.7,
FR-060..064). Its public behaviour is treated as a stable contract —
adding subcommands and JSON fields is additive; renames or removals are
breaking.

### No `--master-password` flag

There is no `--master-password` (or `--password`) flag anywhere in the
CLI, on any subcommand. The master password is collected *only* via the
no-echo secure stdin prompt (`rpassword`). A unit test in
`crates/falach-cli/src/cli.rs` walks the entire clap command tree at
build time and fails the build if any flag with this name appears.

Rationale: command-line flags are visible to anyone on the same host
via `ps`, are recorded in shell history, and end up in `~/.bash_history`
on disk.

### `FALACH_MASTER_PASSWORD` is reserved and ignored

If the environment variable `FALACH_MASTER_PASSWORD` is set when
`falach` starts, the CLI:

1. writes a warning to stderr (without echoing the value), and
2. calls `std::env::remove_var` to scrub it from the process
   environment before any subcommand runs.

This is defence-in-depth against `falach foo` being invoked from a
parent shell that already has the variable exported — even by mistake.
The scrub ensures no subprocess the CLI spawns can inherit the bypass
attempt.

### Secret-emission discipline

Default output never includes secret material. Subcommands that surface
secrets (`entry get`, `gen password`, `gen passphrase`) require an
explicit flag (`--show-password`, `--show-totp`, `--show`) before the
secret is rendered. This applies to both human and JSON output.

`--copy` is the preferred path: it hands the value to the
security-behaviors clipboard with an auto-clear timer and blocks
on the timer's expiry before the CLI exits.

### JSON schemas are a public contract

Per-subcommand `serde::Serialize` view structs live in
`crates/falach-cli/src/views/`. Each is the JSON schema for its
subcommand. Evolution rules:

- New optional fields are additive — use
  `#[serde(skip_serializing_if = "Option::is_none")]` so older
  consumers see no diff.
- Field renames and type changes are breaking — they require a major
  version bump.
- Errors in `--format json` mode go to **stdout** as
  `{"error":{"code":N,"kind":"...","message":"..."}}` so a single
  `falach ... --format json | jq` pipeline sees JSON regardless of
  exit status. Human-mode errors continue to go to stderr.

### Exit-code stability promise

The documented `CliExit` table (`crates/falach-cli/src/exit.rs`) is
frozen at MVP merge. Adding a new exit code is non-breaking; reusing
or reassigning an existing code is breaking.

The codes:

| Code | Meaning                                              |
| ---- | ---------------------------------------------------- |
| 0    | Success                                              |
| 1    | User error (bad flag, missing vault, parse failure)  |
| 2    | Vault locked / authentication failed / contended     |
| 3    | Sync conflict requiring user action (sync-git only)  |
| 10   | Internal / unexpected failure                        |
| 11   | Known unimplemented surface (slot subcommands)       |

Exhaustive `From<XxxError> for CliExit` impls cover every
consumed-library error variant. Adding a new variant in
`falach-core`'s `VaultError` (or any sibling crate's error enum)
fails the build until the new variant is mapped — the design contract.

### CLI dependency policy

The CLI's dep tree is intentionally minimal:

- **Integration tests** use `std::process::Command` with
  `env!("CARGO_BIN_EXE_falach")` directly rather than pulling in
  `assert_cmd` + `predicates` (which would add roughly fifteen
  transitive crates for no functional gain).
- **`clap`'s non-essential features** (`wrap_help`, `color`) are
  disabled at the manifest to avoid `anstream` / `terminal_size` /
  `colorchoice` and their transitives.
- **The secure no-echo prompt** uses `nix::sys::termios` directly
  (Unix-only, ~2 MB vendored) rather than `rpassword`. `rpassword`'s
  `cfg(windows)` branch pulls the `windows-sys` family plus seven
  architecture-stub crates — roughly 93 MB of vendored sources that
  would never compile on the project's supported macOS + Linux
  targets. The replacement helper is ~80 LoC in
  `crates/falach-cli/src/prompt.rs` (`read_password_no_echo` plus
  an `EchoGuard` RAII wrapper); the unsafe stays inside `nix`, so
  the crate keeps `#![cfg_attr(not(test), forbid(unsafe_code))]`.

New direct deps still go through the five-step "Adding a dependency"
workflow above.

### Subcommand surface

The complete `falach` subcommand tree as of MVP (FR-060). Subcommands
marked _slot_ parse their flags but return exit 11
(`not.implemented`); the flag surface is the forward-compat contract
with the implementing feature, which fills in only the body.

| Subcommand                | Purpose                                                                 | Status                       |
| ------------------------- | ----------------------------------------------------------------------- | ---------------------------- |
| `falach vault create`    | Create + register a new KDBX vault. Prompts for the master password.    | Implemented                  |
| `falach vault open`      | Probe vault unlock (MVP one-shot; agent caches in post-MVP).            | Implemented                  |
| `falach vault list`      | List registered vaults from `vaults.toml`.                              | Implemented                  |
| `falach vault set-lock`  | Configure or clear the per-vault idle-lock timeout.                     | Implemented                  |
| `falach vault set-sync`  | Configure the sync transport for a vault.                               | Slot → `features/sync-git/`  |
| `falach entry add`       | Add a new entry. `--password-stdin` or `--generate` is required.        | Implemented                  |
| `falach entry get`       | Read an entry by UUID or title. `--copy` hands to the clipboard.        | Implemented                  |
| `falach entry edit`      | Update entry fields and tags.                                            | Implemented                  |
| `falach entry rm`        | Remove an entry (recycle bin by default; `--permanent` skips it).        | Implemented                  |
| `falach entry list`      | List entries with optional tag / expiry filters + pagination.            | Implemented                  |
| `falach entry search`    | Full-text search over titles, usernames, URLs, notes.                    | Implemented                  |
| `falach gen password`    | Generate a random password. `--copy` hands to the clipboard.             | Implemented                  |
| `falach gen passphrase`  | Generate an EFF-large-wordlist diceware passphrase. `--copy` supported.  | Implemented                  |
| `falach sync`            | Synchronise a vault against its configured transport.                    | Slot → `features/sync-git/`  |
| `falach ssh add`         | Import an SSH key into a vault.                                          | Slot → `features/ssh-keys/`  |
| `falach ssh load`        | Load an SSH key from a vault into the running `ssh-agent`.               | Slot → `features/ssh-keys/`  |
| `falach ssh generate`    | Generate a new SSH keypair and store it in a vault.                      | Slot → `features/ssh-keys/`  |
| `falach completions`     | Emit a shell completion script (`bash`, `zsh`, `fish`).                  | Implemented                  |

`vault create` / `vault open` and every `entry` verb prompt for the
master password via the secure stdin path; `gen password` and
`gen passphrase` never touch the vault and never prompt.

### Shell completions

The CLI ships pre-generated completion scripts for `bash`, `zsh`, and
`fish` at the workspace root under
`shell-completions/{falach.bash,_falach,falach.fish}`. They are
generated by `make completions`, which invokes
`crates/falach-cli/examples/gen_completions.rs` over the same
`clap_complete` code path that `falach completions <shell>` uses at
runtime — runtime and packaged outputs cannot drift.

CI runs `make completions-check` (a wrapper that calls
`make completions` and then checks `git status --porcelain --
shell-completions/`) as a drift gate. Any contributor who adds a
subcommand or a flag without re-running the target fails the build.

If `make completions-check` fails locally:

```sh
make completions             # regenerate the three scripts
git add shell-completions/   # stage the updated outputs
```

Packaging (Phase 1+) will install the three files to system-standard
locations (`/usr/share/bash-completion/completions/falach`, etc.);
until then users source the files directly from a clone, e.g.:

```sh
source shell-completions/falach.bash
```

---

## Style

- `make fmt-check` is enforced by CI (wraps `cargo fmt --all --check`).
- `make lint` is enforced by CI (wraps
  `cargo clippy --workspace --all-targets -- -D warnings`). The
  workspace allows `pedantic` Clippy as a warning baseline; three lint
  families (`module_name_repetitions`, `must_use_candidate`,
  `missing_errors_doc`) are allowed because they fire on idiomatic API
  shapes.
- Public items in `falach-core` have rustdoc comments. CI runs
  `make doc` (wraps `cargo doc --no-deps --offline`) and (later) treats
  warnings as errors.

---

## Related documents

- [`CLAUDE.md`](CLAUDE.md) — non-negotiable rules (security, supply
  chain, technical constraints).
- [`README.md`](README.md) — project overview.
- **PRD** and **engineering plans** — referenced from `CLAUDE.md`.
- **Supply-chain policy:** `notebook/.../falach/kb/supply-chain-policy.md`.
- **Test plan:** Test Plan §8.1 in
  `notebook/.../features/vault-core/plans/implementation-plan.md`.
