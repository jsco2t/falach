//! `falach keys [--format json]` — relay the TUI's effective keymap (T4.3).
//!
//! The keymap lives in `falach-tui` (the command registry × preset × user
//! patch). Rather than duplicate it — or add a `falach-cli → falach-tui` crate
//! dependency that would drag `ratatui` into the CLI build — this subcommand
//! locates the `falach-tui` binary (`$FALACH_TUI_BIN`, else `falach-tui` on
//! `$PATH`) and relays its `--dump-keys` output verbatim.
//!
//! **Security:** this spawns a subprocess but passes NO secret material — keymap
//! data only. The TUI prints the dump *before* any terminal / vault setup.

use std::io::{self, Write};
use std::process::Command as ProcessCommand;

use crate::cli::{Cli, KeysArgs, OutputFormat};
use crate::exit::CliExit;

/// Environment override for the TUI binary path (used in tests and by packagers
/// who install the binaries outside `$PATH`).
const TUI_BIN_ENV: &str = "FALACH_TUI_BIN";
const DEFAULT_TUI_BIN: &str = "falach-tui";

/// Relay `falach-tui --dump-keys[=json]` to stdout (T4.3).
///
/// # Errors
/// - [`CliExit::UserError`] when the `falach-tui` binary is not installed.
/// - [`CliExit::Internal`] when it runs but exits non-zero or a write fails.
pub fn run(_cli: &Cli, args: &KeysArgs) -> Result<(), CliExit> {
    let bin = std::env::var(TUI_BIN_ENV).unwrap_or_else(|_| DEFAULT_TUI_BIN.to_string());
    let bytes = dump_keys_via(&bin, args.format)?;
    io::stdout()
        .write_all(&bytes)
        .map_err(|e| CliExit::Internal(format!("failed to write keymap to stdout: {e}")))
}

/// Run `<bin> --dump-keys[=json]` and return its stdout bytes. Errors:
/// - [`CliExit::UserError`] when the binary cannot be spawned (not installed).
/// - [`CliExit::Internal`] when it runs but exits non-zero.
fn dump_keys_via(bin: &str, format: OutputFormat) -> Result<Vec<u8>, CliExit> {
    let dump_arg = match format {
        OutputFormat::Json => "--dump-keys=json",
        OutputFormat::Human => "--dump-keys",
    };
    match ProcessCommand::new(bin).arg(dump_arg).output() {
        Ok(output) if output.status.success() => Ok(output.stdout),
        Ok(output) => Err(CliExit::Internal(format!(
            "{bin} --dump-keys exited with {}",
            output.status
        ))),
        Err(_) => Err(CliExit::UserError(format!(
            "falach keys requires the {DEFAULT_TUI_BIN} binary (install it or set {TUI_BIN_ENV})"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_binary_errors_with_actionable_message() {
        let err = dump_keys_via("falach-tui-does-not-exist-xyz", OutputFormat::Human)
            .expect_err("a missing binary must error");
        match err {
            CliExit::UserError(msg) => {
                assert!(msg.contains(DEFAULT_TUI_BIN), "names the binary: {msg}");
                assert!(
                    msg.contains(TUI_BIN_ENV),
                    "points at the env override: {msg}"
                );
            }
            other => panic!("expected UserError, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn relays_stub_binary_output_verbatim() {
        use std::os::unix::fs::PermissionsExt;

        // A stub `falach-tui` that prints canned dump-keys output, then exits 0.
        let dir = tempfile::tempdir().unwrap();
        let stub = dir.path().join("falach-tui-stub");
        std::fs::write(
            &stub,
            "#!/bin/sh\necho \"copy-password\\ty\\tcopy password\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();

        let bytes = dump_keys_via(stub.to_str().unwrap(), OutputFormat::Human)
            .expect("stub relays cleanly");
        let out = String::from_utf8(bytes).unwrap();
        assert!(out.contains("copy-password"), "relayed verbatim: {out}");
    }
}
