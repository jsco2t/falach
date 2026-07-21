#!/usr/bin/env bash
# install-toolchain.sh — bootstrap the Falach developer toolchain.
#
# Cross-platform (Linux + macOS; Windows is out of scope per CLAUDE.md).
# Run via `make toolchain`. After it succeeds you can immediately run the
# full developer loop: `make check`, `make verify`, etc.
#
# Idempotent: every step checks whether the tool is already present and
# skips it, so re-running is cheap and safe.
#
# Tool versions are pinned to match CI (.github/workflows/ci.yml) so that
# "works in CI" and "works on my machine" stay the same thing.

set -euo pipefail

# --- versions (keep in lock-step with .github/workflows/ci.yml) -----------
CARGO_DENY_VERSION="0.19.6"
CARGO_AUDIT_VERSION="0.22.1"

# --- output helpers --------------------------------------------------------
log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m  ✓\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

OS="$(uname -s)"

# Install a package using whichever native Linux package manager is present.
# Per-manager package names are passed positionally because they occasionally
# differ (e.g. oathtool vs oath-toolkit). Positional args (no associative
# arrays) keep this working on macOS's bash 3.2 as well.
#   usage: linux_install <label> <apt-pkg> <dnf-pkg> <pacman-pkg> <zypper-pkg>
linux_install() {
  local label="$1" apt_pkg="$2" dnf_pkg="$3" pacman_pkg="$4" zypper_pkg="$5"
  if   have apt-get; then sudo apt-get update && sudo apt-get install -y "$apt_pkg"
  elif have dnf;     then sudo dnf install -y "$dnf_pkg"
  elif have pacman;  then sudo pacman -S --needed --noconfirm "$pacman_pkg"
  elif have zypper;  then sudo zypper install -y "$zypper_pkg"
  else
    err "no supported package manager (apt/dnf/pacman/zypper) found to install ${label}."
    return 1
  fi
}

# --------------------------------------------------------------------------
# 1. Rust toolchain — pinned by rust-toolchain.toml, managed via rustup.
# --------------------------------------------------------------------------
log "Rust toolchain (pinned by rust-toolchain.toml)"
if have rustup; then
  # `rustup show` honours rust-toolchain.toml: it installs the pinned
  # channel, its components (rustfmt, clippy) and declared targets if any
  # are missing, then prints the active toolchain.
  rustup show >/dev/null
  ok "$(rustup show active-toolchain 2>/dev/null || echo 'active toolchain ready')"
else
  err "rustup is not installed — it is the supported way to manage Falach's pinned Rust toolchain."
  case "$OS" in
    Darwin) err "Install it with:  brew install rustup-init && rustup-init -y    (or see https://rustup.rs)" ;;
    *)      err "Install it from https://rustup.rs, then re-run 'make toolchain'." ;;
  esac
  exit 1
fi

# --------------------------------------------------------------------------
# 2. keepassxc-cli — required by the interop test harnesses (make interop*).
# --------------------------------------------------------------------------
log "keepassxc-cli (KDBX interop test automation)"
if have keepassxc-cli; then
  ok "$(keepassxc-cli --version 2>/dev/null | head -n1) already installed"
else
  case "$OS" in
    Darwin)
      if have brew; then
        brew install --cask keepassxc
        # The cask ships the CLI inside the app bundle; expose it on PATH
        # exactly as CI does.
        if ! have keepassxc-cli && [ -x /Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli ]; then
          sudo ln -sf /Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli /usr/local/bin/keepassxc-cli
        fi
      else
        err "Homebrew not found. Install it (https://brew.sh) or install KeePassXC manually, then re-run."
        exit 1
      fi
      ;;
    Linux)
      linux_install "keepassxc-cli" keepassxc keepassxc keepassxc keepassxc
      ;;
    *)
      err "unsupported OS '$OS' for automatic keepassxc-cli install."
      exit 1
      ;;
  esac
  have keepassxc-cli && ok "$(keepassxc-cli --version 2>/dev/null | head -n1) installed"
fi

# --------------------------------------------------------------------------
# 3. cargo-deny / cargo-audit — supply-chain gates (make deny / make audit).
#
# `cargo install` must run OUTSIDE the repo: the project's
# .cargo/config.toml forces offline builds against the vendored tree, which
# does not contain these tools. Running from a scratch dir with
# CARGO_NET_OFFLINE=false (and the pinned toolchain) mirrors CI exactly.
# --------------------------------------------------------------------------
cargo_install_global() {
  local tool="$1" version="$2"
  if have "$tool"; then
    ok "$tool already installed ($("$tool" --version 2>/dev/null | head -n1))"
    return 0
  fi
  log "installing $tool $version (CI-pinned)"
  ( cd "${TMPDIR:-/tmp}" && CARGO_NET_OFFLINE=false RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-}" \
      cargo install --locked "$tool" --version "$version" )
}
cargo_install_global cargo-deny  "$CARGO_DENY_VERSION"
cargo_install_global cargo-audit "$CARGO_AUDIT_VERSION"

# --------------------------------------------------------------------------
# 4. oathtool — OPTIONAL. Used by the entry-management TOTP interop test
#    (make interop-entry) to cross-check generated codes. Best-effort: a
#    failure here does not fail the bootstrap.
# --------------------------------------------------------------------------
log "oathtool (optional — TOTP interop cross-check)"
if have oathtool; then
  ok "oathtool already installed"
else
  case "$OS" in
    Darwin) have brew && brew install oath-toolkit || warn "could not install oath-toolkit (optional); skipping." ;;
    Linux)  linux_install "oathtool" oathtool oathtool oath-toolkit oath-toolkit \
              || warn "could not install oathtool (optional); skipping." ;;
    *)      warn "unsupported OS for oathtool (optional); skipping." ;;
  esac
fi

# --------------------------------------------------------------------------
# Done.
# --------------------------------------------------------------------------
printf '\n'
log "Toolchain ready. Dependencies are vendored + committed, so you can work offline:"
printf '      make check      # fmt-check + lint + build + test (the CI gate)\n'
printf '      make verify     # full gate incl. docs, supply-chain, and interop\n'
printf '\n'
printf '  Note: only `make vendor` needs network access, and only when ADDING a dependency.\n'
