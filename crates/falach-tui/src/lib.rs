//! `falach-tui` — the Falach reference terminal UI.
//!
//! A `ratatui` + `crossterm` keyboard-driven presentation layer over the
//! Falach core crates. All business logic, crypto, and vault I/O live in
//! `falach-core` / `falach-security` / `falach-sync`; this crate renders and
//! dispatches keys, holding no vault logic of its own.
//!
//! The UI is a persistent tabbed workspace (Secrets + ≤5 pinned-secret tabs +
//! a Settings/Sync tab) reached after unlocking a registered vault; action
//! surfaces (search, add/edit, generate, history, sync, command palette) render as modal
//! overlays over the active tab.
//!
//! ## Discoverability & accessibility
//!
//! Every keybinding is discoverable at runtime: press `?` to open the command
//! palette, which is rendered from the command registry (`command::COMMANDS`
//! paired with the live `Keymap`) so it can never drift from the dispatch
//! logic. Theming resolves config and CLI/user-theme choices over terminal
//! capability detection; set `FALACH_TUI_THEME=accessible` (or `NO_COLOR`) to force
//! the monochrome, screen-reader-friendly palette. The
//! chosen palette name is printed to stderr before the alternate screen is
//! entered, so a theme-detection surprise is visible.
//!
//! ## Crate posture
//!
//! `deny(unsafe_code)` (the workspace default) with exactly **one** audited
//! `#[allow(unsafe_code)]` block — the async-signal-safe `SIGHUP`/`SIGTERM`
//! handler in `terminal_guard` — mirroring `falach-security`. No other
//! `unsafe` is permitted in this crate.
#![cfg_attr(not(test), deny(unsafe_code))]

pub(crate) mod app;
pub(crate) mod args;
pub(crate) mod clipboard;
pub(crate) mod command;
pub(crate) mod config;
pub(crate) mod error;
pub(crate) mod event;
pub(crate) mod jump_history;
pub(crate) mod overlay;
pub(crate) mod recents;
pub(crate) mod screens;
pub(crate) mod sync_runtime;
pub(crate) mod tabs;
pub(crate) mod terminal_guard;
pub(crate) mod theme;
pub(crate) mod user_config;
pub(crate) mod util;
pub(crate) mod widgets;

/// Hand-rolled snapshot harness + tree/detail golden tests (T3.5). In-crate
/// because the render functions it exercises are `pub(crate)` (the lesson
/// Phase 1/2 already hit: an integration test in `tests/` can't reach them).
#[cfg(test)]
mod snapshot_tests;

pub use args::{Args, DumpFormat, ParseOutcome};
pub use error::TuiError;

use std::io::stdout;

use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use falach_core::FalachPaths;

use crate::app::App;
use crate::command::Keymap;
use crate::terminal_guard::TerminalGuard;
use crate::user_config::UserConfig;

/// Top-level entry point invoked by `main.rs`.
///
/// Builds the `App` (registry I/O) *before* touching the terminal, so a
/// `NoVaultsRegistered` (or other startup) error prints on a normal terminal
/// instead of inside raw mode. Then installs the terminal guard (raw mode +
/// alternate screen + panic/signal restore) and runs the event loop; the guard
/// restores the terminal on any return path, panic, or fatal signal.
///
/// # Errors
///
/// Returns [`TuiError`] if the registry can't be loaded, no vaults are
/// registered, `--vault` names an unknown vault, terminal setup fails, or the
/// event loop fails.
pub fn run(args: &Args) -> Result<(), TuiError> {
    run_with(args, falach_security::harden_process, run_hardened)
}

fn run_with<T>(args: &Args, harden: impl FnOnce(), next: impl FnOnce(&Args) -> T) -> T {
    harden();
    next(args)
}

fn run_hardened(args: &Args) -> Result<(), TuiError> {
    if let Some(message) = args.deferred_option_error() {
        return Err(TuiError::UnsupportedOption(message));
    }
    dispatch_startup(
        args,
        |format| {
            dump_keys(args, format);
            Ok(())
        },
        || launch_tui(args),
    )
}

fn dispatch_startup<T>(
    args: &Args,
    dump: impl FnOnce(DumpFormat) -> T,
    launch: impl FnOnce() -> T,
) -> T {
    match args.dump_keys {
        Some(format) => dump(format),
        None => launch(),
    }
}

fn launch_tui(args: &Args) -> Result<(), TuiError> {
    let app = App::new(args)?;

    // Surface the detected palette before raw mode / the alternate screen, so a
    // wrong-palette surprise (R-7) is visible and not swallowed by the TUI.
    eprintln!("[falach-tui] theme: {}", app.theme.name);

    let _guard = TerminalGuard::new(app.mouse_enabled)?;
    let terminal = Terminal::new(CrosstermBackend::new(stdout()))?;

    event::run_event_loop(app, terminal)
}

/// Handle `--dump-keys`: load the effective keymap (config `[keymap]` preset +
/// patch, honoring `--config`) and print it to stdout. Never touches the
/// terminal or the vault registry, so it works even with no vaults registered.
/// Infallible: an unresolvable home directory falls back to the compiled-default
/// keymap rather than failing a read-only introspection command.
fn dump_keys(args: &Args, format: DumpFormat) {
    let (cfg, warnings) = load_dump_config(args, FalachPaths::from_env());
    for warning in warnings {
        eprintln!("[falach-tui] {warning}");
    }
    let (keymap, keymap_warnings) = Keymap::from_patch(&cfg.keymap);
    for warning in keymap_warnings {
        eprintln!("[falach-tui] {}", warning.message);
    }
    print!("{}", args::dump_keys(&keymap, format));
}

fn load_dump_config(
    args: &Args,
    default_paths: Result<FalachPaths, falach_core::VaultError>,
) -> (UserConfig, Vec<String>) {
    match args.config.as_deref() {
        Some(path) => UserConfig::load_from(path),
        None => match default_paths {
            Ok(paths) => UserConfig::load(&paths),
            Err(error) => (
                UserConfig::default(),
                vec![format!(
                    "Could not locate config.toml: {error}; using defaults."
                )],
            ),
        },
    }
}

/// Run process hardening, then build the `App` — in that order. Extracted as a
/// seam so the harden-before-build (and therefore harden-before-any-vault-open)
/// ordering is unit-testable without a TTY or the real `setrlimit` syscall.
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    // PMF-2 / T2.3: startup must run process hardening BEFORE building the App
    // (and therefore before any vault can open). Inject spies for both steps and
    // assert the order — no TTY, no real `setrlimit`.
    #[test]
    fn startup_hardens_before_building_app() {
        let order = RefCell::new(Vec::new());
        let result: Result<(), TuiError> = run_with(
            &Args::default(),
            || order.borrow_mut().push("harden"),
            |_| {
                order.borrow_mut().push("build");
                Err(TuiError::Internal("test seam"))
            },
        );
        assert!(result.is_err(), "the injected build returns the seam error");
        assert_eq!(*order.borrow(), ["harden", "build"]);
    }

    #[test]
    fn dump_route_is_also_hardened_first() {
        let order = RefCell::new(Vec::new());
        let args = Args {
            dump_keys: Some(DumpFormat::Text),
            ..Args::default()
        };
        let route = run_with(
            &args,
            || order.borrow_mut().push("harden"),
            |args| {
                dispatch_startup(
                    args,
                    |format| {
                        assert_eq!(format, DumpFormat::Text);
                        order.borrow_mut().push("dump");
                        "dump"
                    },
                    || {
                        order.borrow_mut().push("launch");
                        "launch"
                    },
                )
            },
        );
        assert_eq!(route, "dump");
        assert_eq!(*order.borrow(), ["harden", "dump"]);
    }

    #[test]
    fn dump_config_reports_path_resolution_failure() {
        let args = Args::default();
        let (cfg, warnings) =
            load_dump_config(&args, Err(falach_core::VaultError::HomeUnresolvable));
        assert_eq!(cfg, UserConfig::default());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Could not locate config.toml"));
    }
}
