//! `falach ssh` slot — design §3.6.
//!
//! The three verbs (`add`, `load`, `generate`) exist for surface
//! stability so `falach ssh --help` lists the complete set the PRD
//! promises (FR-030..032 surface). Each body returns
//! [`CliExit::NotImplemented`] (exit 11) until `features/ssh-keys/`
//! ships the real implementation, which consumes the flag surfaces
//! declared in [`crate::cli::SshAddArgs`] / [`crate::cli::SshLoadArgs`] /
//! [`crate::cli::SshGenerateArgs`] verbatim.

use crate::cli::{Cli, SshArgs, SshVerb};
use crate::exit::CliExit;

/// `falach ssh` slot entry point — dispatches to the verb stub.
///
/// # Errors
///
/// Returns [`CliExit::NotImplemented`] from each verb stub until
/// `features/ssh-keys/` lands. A bare `falach ssh` (no verb) returns
/// [`CliExit::UserError`] so users see the right hint immediately.
pub fn run(_cli: &Cli, args: &SshArgs) -> Result<(), CliExit> {
    match &args.verb {
        Some(SshVerb::Add(_)) => Err(CliExit::NotImplemented(
            "falach ssh add — implementation arrives in features/ssh-keys/",
        )),
        Some(SshVerb::Load(_)) => Err(CliExit::NotImplemented(
            "falach ssh load — implementation arrives in features/ssh-keys/",
        )),
        Some(SshVerb::Generate(_)) => Err(CliExit::NotImplemented(
            "falach ssh generate — implementation arrives in features/ssh-keys/",
        )),
        // Bare `falach ssh` (no verb): the entire subcommand is a
        // slot, so return NotImplemented rather than UserError. Tests
        // and users can rely on exit 11 + the feature pointer in
        // stderr regardless of which verb (if any) was passed.
        None => Err(CliExit::NotImplemented(
            "falach ssh — implementation arrives in features/ssh-keys/",
        )),
    }
}
