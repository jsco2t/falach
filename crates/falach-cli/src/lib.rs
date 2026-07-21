//! Falach CLI library entry point.
//!
//! The binary at `src/main.rs` is a thin shim around [`run`]; integration
//! tests link against this library so they can exercise individual
//! modules without forking a subprocess.
//!
//! ## Layered architecture (per design §2.1)
//!
//! 1. `cli` — clap-derive command tree. Pure parsing, no I/O.
//! 2. `exit` — [`CliExit`] enum + exhaustive `From` impls. Pure mapping.
//! 3. `format` — `OutputFormatter` (JSON vs. human). Pure formatting.
//! 4. `prompt` — secure master-password prompt (FR-061).
//! 5. `agent` — `AgentClient` trait + `NoAgentClient` MVP impl.
//! 6. `commands` — per-subcommand dispatch functions. Phase 1: all stubs.
//! 7. `views` — per-subcommand serializable view structs. Phase 1: empty.
//!
//! Phase 1 ships the no-business-logic foundation. Phases 2–4 fill in
//! `commands/` and `views/`.

// `deny` (not `forbid`): the one production opt-out is the audited
// async-signal-safe echo-restore handler in `prompt::echo_signals`
// (Drop does not run on signal death, so a plain RAII guard cannot
// restore the terminal on ^C). Mirrors falach-tui's terminal_guard.
#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod agent;
pub mod cli;
pub mod commands;
pub mod exit;
pub mod format;
pub mod prompt;
pub mod views;

pub use cli::{Cli, Command, OutputFormat};
pub use exit::CliExit;

use clap::Parser;
use std::process::ExitCode;

use crate::format::OutputFormatter;

/// Library entry point — the binary's `main()` is a one-line call to
/// this function.
///
/// Parses the command line via [`Cli`], dispatches to the matching
/// subcommand handler, and translates the resulting [`CliExit`] into a
/// `std::process::ExitCode`. Errors are routed through
/// [`OutputFormatter::write_error`] so JSON-mode envelopes land on
/// stdout (design §3.4) and human-mode errors land on stderr.
#[must_use]
pub fn run() -> ExitCode {
    // FR-061 defense-in-depth: if FALACH_MASTER_PASSWORD is set in the
    // environment when the CLI starts, warn-and-remove it before any
    // subcommand runs (so subprocess invocations cannot inherit the
    // bypass attempt). Done here rather than per-subcommand because the
    // env-var inspection is process-global state.
    prompt::scrub_env_master_password(&mut std::io::stderr());

    let cli = Cli::parse();
    let format = cli.format;
    let result = dispatch(&cli);
    map_result_to_exit_code(result, format)
}

fn dispatch(cli: &Cli) -> Result<(), CliExit> {
    match &cli.command {
        Command::Vault(args) => commands::vault::run(cli, args),
        Command::Entry(args) => commands::entry::run(cli, args),
        Command::Gen(args) => commands::gen::run(cli, args),
        Command::Sync(args) => commands::sync::run(cli, args),
        Command::Ssh(args) => commands::ssh::run(cli, args),
        Command::Completions(args) => commands::completions::run(cli, args),
        Command::Keys(args) => commands::keys::run(cli, args),
    }
}

fn map_result_to_exit_code(result: Result<(), CliExit>, format: OutputFormat) -> ExitCode {
    let exit = match result {
        Ok(()) => CliExit::Success,
        Err(e) => e,
    };
    if !matches!(exit, CliExit::Success) {
        let stdout = std::io::stdout();
        let stderr = std::io::stderr();
        let mut formatter = OutputFormatter::new(stdout.lock(), stderr.lock(), format);
        let _ = formatter.write_error(&exit);
    }
    // `i32 -> u8` is safe — all documented codes fit in 0..=255 (see
    // exit.rs documented table).
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    ExitCode::from(exit.code() as u8)
}
