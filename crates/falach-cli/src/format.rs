//! Output formatter — JSON vs. human dispatch.
//!
//! Per design §2.2.5 the formatter holds the `--format` selector and a
//! pair of writers (stdout + stderr). Each per-subcommand view struct
//! implements both [`HumanFormat`] (hand-written line-oriented output)
//! and `serde::Serialize` (derived). The formatter routes accordingly.
//!
//! Error rendering (§3.4 design decision):
//!
//! - `--format json`: error envelope written to **stdout** so a single
//!   `falach ... | jq` pipeline sees JSON regardless of success/failure.
//! - `--format human`: human error line written to **stderr** in the
//!   conventional Unix way.
//!
//! Phase 1 lands the formatter, the JSON error envelope, and the
//! associated unit tests. Per-subcommand views land in Phases 2–4.

use std::io::Write;

use serde::Serialize;

use crate::cli::OutputFormat;
use crate::exit::CliExit;

/// Output formatter parameterized over the writer types so unit tests
/// can pass `Vec<u8>` buffers and production can pass concrete
/// `StdoutLock` + `StderrLock` (which are distinct types).
pub struct OutputFormatter<O: Write, E: Write> {
    /// Standard-output sink. JSON success payloads + JSON error envelopes go here.
    pub stdout: O,
    /// Standard-error sink. Human error lines go here.
    pub stderr: E,
    /// Output format selector (from the global `--format` flag).
    pub format: OutputFormat,
}

impl<O: Write, E: Write> OutputFormatter<O, E> {
    /// Construct a formatter from explicit writers + format.
    pub const fn new(stdout: O, stderr: E, format: OutputFormat) -> Self {
        Self {
            stdout,
            stderr,
            format,
        }
    }

    /// Write a success view, choosing JSON vs. human based on `self.format`.
    ///
    /// # Errors
    ///
    /// Returns any I/O error produced by the underlying writer or any
    /// JSON serialization error.
    pub fn write<V>(&mut self, view: &V) -> std::io::Result<()>
    where
        V: HumanFormat + Serialize,
    {
        match self.format {
            OutputFormat::Human => view.write_human(&mut self.stdout),
            OutputFormat::Json => write_json_to(&mut self.stdout, view),
        }
    }

    /// Write a JSON success view directly to stdout.
    ///
    /// This is for commands whose canonical human output needs runtime
    /// context that is intentionally absent from their serializable view.
    /// Callers must select JSON mode before invoking it.
    ///
    /// # Errors
    ///
    /// Returns any I/O or serialization error from the stdout writer.
    pub fn write_json<V: Serialize>(&mut self, view: &V) -> std::io::Result<()> {
        write_json_to(&mut self.stdout, view)
    }

    /// Write an error in the appropriate format.
    ///
    /// - JSON mode: envelope `{"error":{"code":N,"kind":"...","message":"..."}}` to stdout.
    /// - Human mode: line `error: <kind>: <message>` to stderr.
    ///
    /// The trailing newline is included.
    ///
    /// # Errors
    ///
    /// Returns any I/O error from the underlying writer.
    pub fn write_error(&mut self, exit: &CliExit) -> std::io::Result<()> {
        if matches!(exit, CliExit::Success) {
            return Ok(());
        }
        match self.format {
            OutputFormat::Human => exit.render_human(&mut self.stderr),
            OutputFormat::Json => {
                let envelope = error_envelope(exit);
                write_json_to(&mut self.stdout, &envelope)
            }
        }
    }
}

/// Trait implemented by per-subcommand view structs for human-readable
/// output. JSON output is handled uniformly via `serde::Serialize`.
pub trait HumanFormat {
    /// Write a line-oriented human-readable rendering of `self` to
    /// `out`. Implementations should append a trailing newline.
    ///
    /// # Errors
    ///
    /// Returns any I/O error produced by `out`.
    fn write_human(&self, out: &mut dyn Write) -> std::io::Result<()>;
}

fn write_json_to<V: Serialize, W: Write>(w: &mut W, view: &V) -> std::io::Result<()> {
    serde_json::to_writer(&mut *w, view).map_err(std::io::Error::other)?;
    w.write_all(b"\n")
}

/// JSON error-envelope payload — the public schema for error output in
/// `--format json` mode.
#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    error: ErrorView<'a>,
}

#[derive(Serialize)]
struct ErrorView<'a> {
    code: i32,
    kind: &'a str,
    message: String,
}

fn error_envelope(exit: &CliExit) -> ErrorEnvelope<'_> {
    ErrorEnvelope {
        error: ErrorView {
            code: exit.code(),
            kind: exit.kind(),
            message: exit.message(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct Hello {
        greeting: &'static str,
    }

    impl HumanFormat for Hello {
        fn write_human(&self, out: &mut dyn Write) -> std::io::Result<()> {
            writeln!(out, "{}", self.greeting)
        }
    }

    fn formatter(format: OutputFormat) -> OutputFormatter<Vec<u8>, Vec<u8>> {
        OutputFormatter::new(Vec::new(), Vec::new(), format)
    }

    #[test]
    fn human_mode_writes_view_to_stdout() {
        let mut f = formatter(OutputFormat::Human);
        f.write(&Hello { greeting: "hi" }).unwrap();
        assert_eq!(f.stdout, b"hi\n");
        assert!(f.stderr.is_empty());
    }

    #[test]
    fn json_mode_writes_compact_json_with_trailing_newline() {
        let mut f = formatter(OutputFormat::Json);
        f.write(&Hello { greeting: "hi" }).unwrap();
        let s = String::from_utf8(f.stdout.clone()).unwrap();
        assert_eq!(s, "{\"greeting\":\"hi\"}\n");
        assert!(f.stderr.is_empty());
    }

    #[test]
    fn human_mode_error_goes_to_stderr_not_stdout() {
        let mut f = formatter(OutputFormat::Human);
        f.write_error(&CliExit::UserError("nope".into())).unwrap();
        assert!(f.stdout.is_empty(), "stdout should stay empty");
        let s = String::from_utf8(f.stderr).unwrap();
        assert!(s.contains("error: user.error"), "{s:?}");
        assert!(s.contains("nope"), "{s:?}");
    }

    #[test]
    fn json_mode_error_goes_to_stdout_with_envelope() {
        // Design §3.4: JSON errors land on stdout so `| jq` pipelines
        // see a single JSON stream regardless of success/failure.
        let mut f = formatter(OutputFormat::Json);
        f.write_error(&CliExit::UserError("nope".into())).unwrap();
        assert!(f.stderr.is_empty(), "stderr should stay empty in JSON mode");
        let s = String::from_utf8(f.stdout).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(parsed["error"]["code"], 1);
        assert_eq!(parsed["error"]["kind"], "user.error");
        assert_eq!(parsed["error"]["message"], "nope");
    }

    #[test]
    fn write_error_on_success_is_a_no_op() {
        let mut f = formatter(OutputFormat::Json);
        f.write_error(&CliExit::Success).unwrap();
        assert!(f.stdout.is_empty());
        assert!(f.stderr.is_empty());
    }

    #[test]
    fn json_envelope_uses_documented_field_names() {
        // The schema is part of the public contract — guard field names
        // against accidental renames.
        let exit = CliExit::Internal("oops".into());
        let env = error_envelope(&exit);
        let s = serde_json::to_string(&env).unwrap();
        assert!(s.contains("\"error\":"), "{s}");
        assert!(s.contains("\"code\":10"), "{s}");
        assert!(s.contains("\"kind\":\"internal\""), "{s}");
        assert!(s.contains("\"message\":\"oops\""), "{s}");
    }

    #[test]
    fn json_mode_view_round_trips_through_serde() {
        let mut f = formatter(OutputFormat::Json);
        f.write(&Hello { greeting: "ω" }).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&f.stdout).unwrap();
        assert_eq!(parsed["greeting"], "ω");
    }
}
