//! Per-subcommand dispatch functions.
//!
//! Phase 1 ships stub bodies — each `run` returns
//! [`crate::exit::CliExit::NotImplemented`]. Phases 2–4 replace these
//! bodies in place; the module shape is frozen now so the integration
//! test surface (and any external links into `falach_cli::commands::*`)
//! does not churn across phases.
//!
//! Helpers shared by more than one command module live here — they
//! define cross-cutting CLI contracts (the global `--registry` flag,
//! the `--format json` single-document envelope, the `--copy`
//! auto-clear TTL) that must not drift between subcommands.

use std::io::Write as _;
use std::time::Duration;

use falach_core::FalachPaths;
use falach_security::Clipboard;

use crate::cli::{Cli, OutputFormat};
use crate::exit::CliExit;
use crate::format::OutputFormatter;

pub mod completions;
pub mod entry;
pub mod gen;
pub mod keys;
pub mod ssh;
pub mod sync;
pub mod vault;

/// Default auto-clear TTL for the `--copy` flag. Mirrors
/// security-behaviors' default (30s); the CLI exposes no per-invocation
/// override in MVP (open-item OQ-3).
pub(crate) const CLIPBOARD_TTL_SECONDS: u64 = 30;

/// Resolve [`FalachPaths`] from the global `--registry <path>` flag,
/// honoring the exact file path the user supplied; when the flag is
/// omitted, fall back to `$HOME/.local/state/falach/vaults.toml` via
/// [`FalachPaths::from_env`].
pub(crate) fn resolve_paths(cli: &Cli) -> Result<FalachPaths, CliExit> {
    if let Some(registry) = cli.registry.as_deref() {
        return Ok(FalachPaths::with_registry_file(registry.to_path_buf()));
    }
    FalachPaths::from_env().map_err(CliExit::from)
}

/// Open the system clipboard, place `value` on it under a
/// [`CLIPBOARD_TTL_SECONDS`] auto-clear timer, and return the guard.
/// The caller is responsible for blocking on `guard.wait_for_clear()`
/// before exit — required on Wayland because the clipboard doesn't
/// survive the source process.
///
/// Returns BEFORE any stdout writes happen so a failure (no DISPLAY,
/// spawn failure, etc.) produces a single JSON error envelope rather
/// than "success view + error envelope" on stdout.
pub(crate) fn arm_clipboard(value: String) -> Result<falach_security::AutoClearGuard, CliExit> {
    let mut clipboard = Clipboard::new().map_err(CliExit::from)?;
    let ttl = Duration::from_secs(CLIPBOARD_TTL_SECONDS);
    let guard = clipboard
        .copy_with_autoclear(value, ttl)
        .map_err(CliExit::from)?;
    // Informational stderr note: human-mode users see why the CLI is
    // not returning to the prompt immediately. JSON-mode scripts can
    // also read this from stderr without polluting stdout.
    let _ = writeln!(
        std::io::stderr().lock(),
        "copied to clipboard; will auto-clear in {CLIPBOARD_TTL_SECONDS}s"
    );
    Ok(guard)
}

/// Write a success view through the [`OutputFormatter`] — the single
/// chokepoint for the `--format json` output contract.
pub(crate) fn write_success<V>(cli: &Cli, view: &V) -> Result<(), CliExit>
where
    V: serde::Serialize + crate::format::HumanFormat,
{
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut formatter = OutputFormatter::new(stdout.lock(), stderr.lock(), cli.format);
    formatter
        .write(view)
        .map_err(|e| CliExit::Internal(format!("failed to write output: {e}")))
}

/// Write a JSON-only success view through the shared [`OutputFormatter`].
///
/// Used when a command's canonical human output depends on runtime context
/// that does not belong in its serializable view.
pub(crate) fn write_json_success<V: serde::Serialize>(view: &V) -> Result<(), CliExit> {
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut formatter = OutputFormatter::new(stdout.lock(), stderr.lock(), OutputFormat::Json);
    formatter
        .write_json(view)
        .map_err(|e| CliExit::Internal(format!("failed to write output: {e}")))
}
