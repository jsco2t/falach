//! Binary entry point for `falach-tui`.
//!
//! A thin shell: parse CLI arguments (before any terminal setup), handle the
//! print-and-exit forms (`--help`/`--version`) and usage errors here, then hand
//! the parsed [`falach_tui::Args`] to the library's `run`. All real logic lives
//! in the library crate; `main` only adapts [`falach_tui::TuiError`] into
//! `anyhow::Error` for a clean process exit.

use std::process::ExitCode;

use falach_tui::ParseOutcome;

fn main() -> ExitCode {
    match falach_tui::Args::parse(std::env::args()) {
        Ok(ParseOutcome::Run(args)) => match falach_tui::run(&args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        // `--help` / `--version`: print to stdout and exit 0.
        Ok(ParseOutcome::Message(msg)) => {
            print!("{msg}");
            ExitCode::SUCCESS
        }
        // Unknown flag / missing value: usage already formatted, print to stderr
        // and exit 1 — before any terminal state is touched.
        Err(usage) => {
            eprint!("{usage}");
            ExitCode::FAILURE
        }
    }
}
