//! `falach completions <shell>` — emit a `clap_complete`-generated
//! completion script for the requested shell.
//!
//! Design §2.3.6. The body wraps [`clap_complete::aot::generate`] over
//! the workspace-pinned [`crate::cli::Cli`] command tree. The same code
//! path is invoked by `examples/gen_completions.rs` (build-time helper
//! used by `make completions`) so the runtime and build-time outputs
//! cannot drift.

use std::io::{self, Write};

use clap::CommandFactory;
use clap_complete::aot::{generate, Shell};

use crate::cli::{Cli, CompletionsArgs};
use crate::exit::CliExit;

/// Phase 4 entry point.
///
/// Routes the requested [`Shell`] to [`clap_complete::aot::generate`],
/// writing the completion script to stdout.
///
/// # Errors
///
/// - [`CliExit::UserError`] when no shell was passed (clap's
///   positional `Option<Shell>` lets the parser accept the bare
///   `falach completions` invocation; we surface the missing-value
///   case explicitly here so the message is helpful).
pub fn run(_cli: &Cli, args: &CompletionsArgs) -> Result<(), CliExit> {
    let Some(shell) = args.shell else {
        return Err(CliExit::UserError(
            "missing shell argument (try `falach completions bash|zsh|fish`)".to_string(),
        ));
    };
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    write_completions(shell, &mut handle);
    handle
        .flush()
        .map_err(|e| CliExit::Internal(format!("failed to flush completions to stdout: {e}")))
}

/// Generate the completion script for `shell` into `out`. Shared with
/// `examples/gen_completions.rs` via the library entry point.
pub fn write_completions(shell: Shell, out: &mut dyn Write) {
    let mut cmd = Cli::command();
    // `clap_complete::generate` swallows write errors silently; the
    // signature is `&mut dyn Write` so any wrapping that propagates
    // errors would have to be at the caller. For the build-time
    // helper we point at a file and trust the OS; for the runtime
    // dispatcher we point at stdout and a write failure surfaces on
    // the trailing `flush()` instead.
    generate(shell, &mut cmd, "falach", out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_completions_bash_is_non_empty() {
        let mut buf = Vec::new();
        write_completions(Shell::Bash, &mut buf);
        let s = String::from_utf8(buf).expect("bash output is utf-8");
        assert!(
            s.contains("falach"),
            "expected the bin name in the bash completion output: {s:?}"
        );
        assert!(!s.is_empty(), "bash completion output should be non-empty");
    }

    #[test]
    fn write_completions_zsh_is_non_empty() {
        let mut buf = Vec::new();
        write_completions(Shell::Zsh, &mut buf);
        let s = String::from_utf8(buf).expect("zsh output is utf-8");
        assert!(
            s.contains("#compdef falach") || s.contains("_falach"),
            "expected zsh compdef preamble; got:\n{s}"
        );
    }

    #[test]
    fn write_completions_fish_is_non_empty() {
        let mut buf = Vec::new();
        write_completions(Shell::Fish, &mut buf);
        let s = String::from_utf8(buf).expect("fish output is utf-8");
        assert!(
            s.contains("complete -c falach"),
            "expected fish 'complete -c falach' preamble; got:\n{s}"
        );
    }
}
