# Falach

```
    ______      __           __
   / ____/___ _/ /___ ______/ /_
  / /_  / __ `/ / __ `/ ___/ __ \
 / __/ / /_/ / / /_/ / /__/ / / /
/_/    \__,_/_/\__,_/\___/_/ /_/
```

Falach (Scottish Gaelic: _"hidden, concealed"_, pronounced _FAH-luhkh_) is an offline-first secrets
manager built on a Rust core with thin cross-platform UIs. Vaults are stored in
the [KDBX (KeePass) format](https://keepass.info/help/kb/kdbx_4.html) via the
[`keepass-rs`](https://crates.io/crates/keepass) crate, so every Falach vault
is directly interoperable with KeePassXC, KeeWeb, KeePass2, and other
standards-compliant KDBX clients. Sync transport is S3-compatible object storage,
with in-app three-way merge at the entry level.

## !!WARNING!! PLEASE READ

This repository is a hobby project of a single person (or at best a few people). The author(s) of
this project wish to make the following **VERY** clear:

- This software is provided "AS IS", without warranty of any kind. (See **License** for further
  clarification)

- This software is not designed as enterprise grade security software (note the _hobby project_
  statement above). Users should not expect any sort of specific quality bar or reliability
  with this software.

- **Use at your own risk**. The authors of this software are in no way responsible for your use of
  the software and/or the security of data you store with this software.

- This software is opinionated in how it works. What that mostly means is that it was designed to
  solve the needs of the original author. It may or may not fit your needs.

## Workspace layout

| Crate             | Purpose                                                            |
| ----------------- | ------------------------------------------------------------------ |
| `falach-core`    | Library: KDBX I/O, vault registry, atomic writes, file locks, search |
| `falach-genpw`   | Library: random password and diceware passphrase generation        |
| `falach-security`| Library: auto-lock, OS lock events, clipboard, core-dump suppression |
| `falach-sync`    | Library: S3 sync transport, SigV4 signing, three-way merge engine  |
| `falach-cli`     | Binary: one-shot scriptable CLI (`falach`)                        |
| `falach-tui`     | Binary: interactive terminal UI (`falach-tui`)                    |
| `falach-agent`   | Binary: (placeholder) optional long-running unlock agent           |

## Supported platforms

Phase 0 targets macOS and Linux on x86_64 and aarch64. Windows, FreeBSD, and
network filesystems are not supported targets for the vault-core reliability
claims.

## Terminal UI

The TUI (`falach-tui`) is the reference UX. Launch it with `make run-tui` or
`cargo run -p falach-tui --offline --locked`.

### Keybinding presets and rebinding

Two presets ship: **vim** (default) and **plain** (arrow-first, no chords). To
rebind keys, edit `~/.config/falach/config.toml`:

```toml
[keymap]
preset = "vim"

[keymap.bindings]
copy-password = "y"          # rebind a single key
search = ["/", "ctrl+f"]     # multiple triggers
pin-toggle = false            # unbind
```

Run `falach-tui --dump-keys` to print the effective keymap, or
`falach keys` from the CLI.

### Themes

Five built-in themes: `default-dark`, `default-light`, `accessible`, `slate`,
`paper`. Each has an explicit ANSI-16 variant for 16-color terminals. User
themes are TOML files dropped in `~/.config/falach/themes/`:

```toml
# ~/.config/falach/themes/mint.toml
accent = "#5FFFAF"
match_hl = "#FFD75F"
```

Select a theme in `config.toml` or cycle through them in the Settings tab:

```toml
[theme]
dark = "default-dark"
light = "paper"
mode = "auto"     # "auto" | "dark" | "light"
```

### Search

Open the search overlay with `/` (vim preset) or `Ctrl+F`. Features:

| Key       | Action                                                      |
| --------- | ----------------------------------------------------------- |
| Type      | Fuzzy-filter entries (fzf-style scoring, match highlighting)|
| `Ctrl+S`  | Cycle scope: All / Group / Tag                              |
| `Alt+1..9`| Quick-select result by number                               |
| `Enter`   | Copy password (arms auto-clear) and close                   |
| `Tab`     | Jump to entry in tree (open detail)                         |
| `Esc`     | Close and restore pre-search selection                      |

Configure the default scope and Enter action in `config.toml`:

```toml
[search]
default-scope = "all"      # "all" | "group" | "tag"
enter-action = "copy"      # "copy" | "open"
```

### CLI search modes

```sh
falach entry search --vault work "github"                  # substring (default)
falach entry search --vault work --mode fuzzy "gh"         # fuzzy matching
falach entry search --vault work --scope group:Social "tw" # scoped to group
falach entry search --vault work --mode fuzzy --format json "api"  # JSON with score
```

### Other flags

```sh
falach-tui --vault work        # skip vault list, open directly
falach-tui --theme slate       # override theme
falach-tui --no-mouse          # keyboard-only session
falach-tui --read-only         # refuse vault mutations
falach-tui --config /path      # custom config location
falach-tui --dump-keys=json    # print keymap as JSON
```

### Mouse

Mouse is an accelerator: click to select/focus, click tabs to switch, wheel to
scroll. Every mouse action has a keyboard equivalent. Hold Shift while dragging
to use your terminal's native text selection. Disable with `--no-mouse` or
`mouse = false` in `config.toml`.

## Build from source

`make` is the canonical build interface — every workflow has a target. Run
`make` (or `make help`) to list them. The most common:

```sh
make build              # cargo build --workspace --offline --locked
make test               # default-parallel tests
make check              # fmt-check + lint + build + test — the full local CI gate
make verify             # full core verification: check + ignored tests + docs + supply chain + interop
make interop            # vault-core KeePassXC interop tests; requires keepassxc-cli >= 2.7
make interop-entry      # entry-management KeePassXC interop tests (TOTP cross-checks with oathtool if present)
make bench-search-gate  # NFR-002 gate: fails if search exceeds the latency budget
```

All dependencies are vendored in `vendor/`; offline is the only supported
build mode. From a clean clone, do not run `cargo update`; use the checked-in
`Cargo.lock` and vendored sources. To intentionally add or upgrade a Rust
dependency, follow the vendoring workflow in [CONTRIBUTING.md](CONTRIBUTING.md)
and run `make vendor` as the only networked dependency step.

## Security and supply chain

See [`CLAUDE.md`](CLAUDE.md)/[`AGENTS.md`](AGENTS.md) for the non-negotiable security and supply-chain
rules: zeroize on drop, no plaintext to disk, atomic writes, permissive-license
deps only, vendored + pinned, no telemetry.

## AI Coding Policy

This repository leverages AI Coding solutions as part of its development processes. The authors of
this repository recognize that some individuals will find that objectionable. We recognize and
appreciate that perspective and wish such individuals the very best in finding a codebase that
fit's their needs.
