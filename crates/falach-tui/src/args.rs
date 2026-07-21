//! Command-line arguments for the `falach-tui` binary (T3.2).
//!
//! Hand-parsed (no `clap` in this crate — design D-7; the binary takes only a
//! handful of flags and the "narrowest solution" supply-chain rule prefers ~120
//! lines here to dragging clap's derive machinery into the TUI build).
//!
//! Parsing runs in `main` **before** any terminal setup, so `--help`,
//! `--version`, `--dump-keys`, and error paths print to a normal screen and
//! never flash the alternate screen (T3.2 gotcha).
//!
//! Precedence for overlapping settings is **CLI > config.toml > compiled
//! default**, implemented once in [`Args::effective`] (unit-tested as a table).

use std::fmt::Write as _;
use std::path::PathBuf;

use crate::command::keymap::Keymap;
use crate::command::registry::COMMANDS;
use crate::user_config::UserConfig;

/// Output format for `--dump-keys`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DumpFormat {
    /// Human-readable, tab-separated columns grouped like the palette.
    Text,
    /// A JSON array of command objects (stable field names — `falach keys`
    /// (T4.3) and user scripts consume it).
    Json,
}

/// The parsed CLI arguments.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Args {
    /// `--vault NAME`: skip the vault list and open this vault's unlock prompt.
    pub vault: Option<String>,
    /// `--theme NAME`: override the configured theme selection.
    pub theme: Option<String>,
    /// `--config PATH`: load `config.toml` from this path instead of the default.
    pub config: Option<PathBuf>,
    /// Disable mouse capture even when `mouse = true` in config.toml.
    pub no_mouse: bool,
    /// Open the vault without permitting any KDBX mutation or sync.
    pub read_only: bool,
    /// `--dump-keys[=json]`: print the effective keymap and exit before terminal
    /// setup.
    pub dump_keys: Option<DumpFormat>,
}

/// The result of parsing: either run with the given args, or print a message
/// (help/version) and exit 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseOutcome {
    /// Proceed to [`crate::run`] with these args.
    Run(Args),
    /// Print this message to stdout and exit 0 (`--help` / `--version`).
    Message(String),
}

/// CLI-over-config-over-default resolution of the settings that both a flag and
/// `config.toml` can set. `config` path resolution is separate (it selects
/// *which* config to load, before this runs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Effective {
    /// The theme name to resolve (CLI `--theme`, else `None` → the resolver
    /// falls through to `config.theme`).
    pub theme: Option<String>,
    /// Whether mouse capture is enabled (`config.mouse` unless `--no-mouse`).
    pub mouse: bool,
    /// Whether this is a read-only session.
    pub read_only: bool,
}

impl Args {
    /// Parse arguments from an iterator (the first item — the program name — is
    /// skipped). Returns [`ParseOutcome::Message`] for `--help`/`--version`, or
    /// `Err(usage)` for an unknown flag or a missing value (the caller prints it
    /// to stderr and exits 1).
    ///
    /// # Errors
    /// Returns a usage string when a flag is unknown, a required value is
    /// missing, or a positional argument is supplied.
    pub fn parse<I: IntoIterator<Item = String>>(iter: I) -> Result<ParseOutcome, String> {
        let mut args = Args::default();
        let mut it = iter.into_iter().skip(1);
        while let Some(arg) = it.next() {
            // Split `--flag=value` into (`--flag`, Some("value")).
            let (flag, inline) = match arg.split_once('=') {
                Some((f, v)) => (f.to_string(), Some(v.to_string())),
                None => (arg.clone(), None),
            };
            match flag.as_str() {
                "--help" | "-h" => return Ok(ParseOutcome::Message(help_text())),
                "--version" | "-V" => return Ok(ParseOutcome::Message(version_text())),
                "--no-mouse" => {
                    reject_inline(&flag, inline.as_deref())?;
                    args.no_mouse = true;
                }
                "--read-only" => {
                    reject_inline(&flag, inline.as_deref())?;
                    args.read_only = true;
                }
                "--dump-keys" => {
                    args.dump_keys = Some(match inline.as_deref() {
                        None | Some("text") => DumpFormat::Text,
                        Some("json") => DumpFormat::Json,
                        Some(other) => {
                            return Err(usage(&format!(
                                "unknown --dump-keys format '{other}' (use 'text' or 'json')"
                            )))
                        }
                    });
                }
                "--vault" => args.vault = Some(take_value(&flag, inline, &mut it)?),
                "--theme" => args.theme = Some(take_value(&flag, inline, &mut it)?),
                "--config" => {
                    args.config = Some(PathBuf::from(take_value(&flag, inline, &mut it)?));
                }
                other if other.starts_with('-') => {
                    return Err(usage(&format!("unknown flag '{other}'")))
                }
                other => return Err(usage(&format!("unexpected argument '{other}'"))),
            }
        }
        Ok(ParseOutcome::Run(args))
    }

    /// Resolve CLI-over-config settings (see [`Effective`]).
    pub(crate) fn effective(&self, cfg: &UserConfig) -> Effective {
        Effective {
            theme: self.theme.clone(),
            mouse: cfg.mouse && !self.no_mouse,
            read_only: self.read_only,
        }
    }

    // A stable seam: future flags land as "reserved" here before their owning
    // feature ships. All Phase-4 flags (`--read-only` T4.7, `--no-mouse` T4.6)
    // are now live, so nothing is deferred.
    #[allow(clippy::unused_self)]
    pub(crate) fn deferred_option_error(&self) -> Option<String> {
        None
    }
}

/// A value-taking flag consumes its inline `=value` if present, else the next
/// argument. Errors if neither is available.
fn take_value<I: Iterator<Item = String>>(
    flag: &str,
    inline: Option<String>,
    it: &mut I,
) -> Result<String, String> {
    match inline {
        Some(v) => Ok(v),
        None => it
            .next()
            .ok_or_else(|| usage(&format!("flag '{flag}' requires a value"))),
    }
}

/// A boolean flag must not be given an `=value`.
fn reject_inline(flag: &str, inline: Option<&str>) -> Result<(), String> {
    if inline.is_some() {
        return Err(usage(&format!("flag '{flag}' takes no value")));
    }
    Ok(())
}

fn usage(problem: &str) -> String {
    format!("error: {problem}\n\n{}", help_text())
}

fn version_text() -> String {
    format!("falach-tui {}\n", env!("CARGO_PKG_VERSION"))
}

fn help_text() -> String {
    "\
falach-tui — the Falach terminal UI

USAGE:
    falach-tui [OPTIONS]

OPTIONS:
    --vault NAME        Open NAME's unlock prompt directly (skip the vault list)
    --theme NAME        Override the theme (built-in name or user theme file stem)
    --config PATH       Load config.toml from PATH instead of the default
    --no-mouse          Disable mouse capture (keyboard-only session)
    --read-only         Open the session read-only: vault mutations are refused
    --dump-keys[=json]  Print the effective keymap (text or json) and exit
    -h, --help          Print this help and exit
    -V, --version       Print version and exit

Precedence for overlapping settings: CLI flag > config.toml > default.
The --dump-keys JSON field names are stable and safe to script against.

Mouse: click to select/focus, click a tab to switch, wheel to scroll. Mouse is
an accelerator only — every action has a keyboard equivalent. Hold Shift while
dragging to bypass capture and use your terminal's native text selection/copy;
`--no-mouse` (or `mouse = false` in config.toml) disables capture entirely.
"
    .to_string()
}

/// Render the effective keymap as `--dump-keys` output. Context-free: every
/// command in the registry with its bound key(s), grouped like the palette.
pub(crate) fn dump_keys(keymap: &Keymap, format: DumpFormat) -> String {
    match format {
        DumpFormat::Text => dump_keys_text(keymap),
        DumpFormat::Json => dump_keys_json(keymap),
    }
}

/// Commands sorted for display: by group rank, then by their position in the
/// `COMMANDS` table (stable, matches the palette).
fn sorted_specs() -> Vec<&'static crate::command::registry::CommandSpec> {
    let mut specs: Vec<_> = COMMANDS.iter().collect();
    specs.sort_by_key(|s| s.group.rank());
    specs
}

fn dump_keys_text(keymap: &Keymap) -> String {
    let mut out = String::new();
    for spec in sorted_specs() {
        let keys = keymap
            .rendered_keys(spec.id)
            .unwrap_or_else(|| "(unbound)".to_string());
        // group \t name \t keys \t desc
        out.push_str(spec.group.label());
        out.push('\t');
        out.push_str(spec.name);
        out.push('\t');
        out.push_str(&keys);
        out.push('\t');
        out.push_str(spec.desc);
        out.push('\n');
    }
    out
}

fn dump_keys_json(keymap: &Keymap) -> String {
    let mut out = String::from("[\n");
    let specs = sorted_specs();
    for (i, spec) in specs.iter().enumerate() {
        let keys = keymap.rendered_key_parts(spec.id);
        let keys_json = keys
            .iter()
            .map(|k| format!("\"{}\"", json_escape(k)))
            .collect::<Vec<_>>()
            .join(", ");
        let contexts_json = spec
            .contexts
            .names()
            .iter()
            .map(|c| format!("\"{}\"", json_escape(c)))
            .collect::<Vec<_>>()
            .join(", ");
        // Writing to a `String` is infallible; the `write!` results are ignored.
        let _ = write!(
            out,
            "  {{\"name\": \"{}\", \"keys\": [{keys_json}], \"desc\": \"{}\", \
             \"group\": \"{}\", \"contexts\": [{contexts_json}]}}",
            json_escape(spec.name),
            json_escape(spec.desc),
            json_escape(spec.group.label()),
        );
        if i + 1 < specs.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("]\n");
    out
}

/// Escape a string for embedding in a JSON double-quoted value. Only `"` and
/// `\` occur in our static ASCII names/descs; escaped defensively (AC-8: no
/// `serde_json` dependency).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<ParseOutcome, String> {
        // Prepend a dummy argv[0].
        let mut v = vec!["falach-tui".to_string()];
        v.extend(args.iter().map(|s| (*s).to_string()));
        Args::parse(v)
    }

    fn run_args(args: &[&str]) -> Args {
        match parse(args).expect("parse ok") {
            ParseOutcome::Run(a) => a,
            ParseOutcome::Message(m) => panic!("expected Run, got message: {m}"),
        }
    }

    #[test]
    fn args_parse_all_forms() {
        // Separate and attached value forms; all boolean + value flags together.
        let a = run_args(&[
            "--vault",
            "work",
            "--theme=slate",
            "--config",
            "/tmp/c.toml",
            "--no-mouse",
            "--read-only",
            "--dump-keys=json",
        ]);
        assert_eq!(a.vault.as_deref(), Some("work"));
        assert_eq!(a.theme.as_deref(), Some("slate"));
        assert_eq!(
            a.config.as_deref(),
            Some(std::path::Path::new("/tmp/c.toml"))
        );
        assert!(a.no_mouse);
        assert!(a.read_only);
        assert_eq!(a.dump_keys, Some(DumpFormat::Json));

        // Attached vault form + bare dump-keys defaults to Text.
        let b = run_args(&["--vault=personal", "--dump-keys"]);
        assert_eq!(b.vault.as_deref(), Some("personal"));
        assert_eq!(b.dump_keys, Some(DumpFormat::Text));

        // No args → all defaults.
        assert_eq!(run_args(&[]), Args::default());
    }

    #[test]
    fn help_and_version_are_messages() {
        assert!(matches!(parse(&["--help"]), Ok(ParseOutcome::Message(_))));
        assert!(matches!(parse(&["-h"]), Ok(ParseOutcome::Message(_))));
        match parse(&["--version"]) {
            Ok(ParseOutcome::Message(m)) => assert!(m.contains(env!("CARGO_PKG_VERSION"))),
            other => panic!("expected version message, got {other:?}"),
        }
    }

    #[test]
    fn args_parse_rejects_unknown_flags_with_usage() {
        let err = parse(&["--bogus"]).expect_err("unknown flag");
        assert!(err.contains("unknown flag '--bogus'"), "{err}");
        assert!(err.contains("USAGE:"), "usage text included: {err}");
    }

    #[test]
    fn args_parse_rejects_missing_value_and_bad_dump_format() {
        assert!(parse(&["--vault"])
            .expect_err("missing value")
            .contains("requires a value"));
        assert!(parse(&["--no-mouse=1"])
            .expect_err("bool takes no value")
            .contains("takes no value"));
        assert!(parse(&["--dump-keys=yaml"])
            .expect_err("bad format")
            .contains("unknown --dump-keys format"));
        assert!(parse(&["stray"])
            .expect_err("positional")
            .contains("unexpected argument"));
    }

    #[test]
    fn cli_flags_override_config() {
        let mut cfg = UserConfig {
            mouse: true,
            ..UserConfig::default()
        };

        // --theme wins; absent → None (falls through to config at resolve time).
        assert_eq!(
            run_args(&["--theme=paper"])
                .effective(&cfg)
                .theme
                .as_deref(),
            Some("paper")
        );
        assert_eq!(run_args(&[]).effective(&cfg).theme, None);

        // --no-mouse forces mouse off regardless of config; absent → config value.
        assert!(!run_args(&["--no-mouse"]).effective(&cfg).mouse);
        assert!(run_args(&[]).effective(&cfg).mouse);
        cfg.mouse = false;
        assert!(
            !run_args(&[]).effective(&cfg).mouse,
            "config off falls through"
        );

        // --read-only is a pure pass-through.
        assert!(run_args(&["--read-only"]).effective(&cfg).read_only);
        assert!(!run_args(&[]).effective(&cfg).read_only);
    }

    #[test]
    fn phase4_input_flags_are_live() {
        // `--read-only` (T4.7) and `--no-mouse` (T4.6) are both live now — no
        // startup rejection for either.
        assert!(run_args(&["--read-only"]).deferred_option_error().is_none());
        assert!(run_args(&["--no-mouse"]).deferred_option_error().is_none());
        assert!(run_args(&[]).deferred_option_error().is_none());
    }

    #[test]
    fn dump_keys_text_lists_effective_keymap() {
        use crate::command::keymap::{KeymapPatch, Preset};
        let (km, _) = Keymap::from_patch(&KeymapPatch {
            preset: Some(Preset::Vim),
            bindings: std::collections::BTreeMap::new(),
        });
        let text = dump_keys(&km, DumpFormat::Text);
        // Every command appears with its tab-separated columns.
        for spec in COMMANDS {
            assert!(
                text.lines().any(|l| {
                    let mut cols = l.split('\t');
                    cols.next() == Some(spec.group.label()) && cols.next() == Some(spec.name)
                }),
                "text dump missing command {}",
                spec.name
            );
        }
        // A known binding is rendered.
        assert!(
            text.lines()
                .any(|l| l.contains("copy-password") && l.contains('y')),
            "copy-password should show its 'y' binding somewhere:\n{text}"
        );
    }

    #[test]
    fn dump_keys_json_is_stable_and_complete() {
        use crate::command::keymap::{BindValue, KeymapPatch, Preset};
        // Rebind copy-password to a key with a JSON metacharacter would be ideal,
        // but keys are constrained; assert escaping via a hypothetical instead.
        let mut bindings = std::collections::BTreeMap::new();
        bindings.insert("copy-password".to_string(), BindValue::One("y".to_string()));
        let (km, warnings) = Keymap::from_patch(&KeymapPatch {
            preset: Some(Preset::Vim),
            bindings,
        });
        assert!(warnings.is_empty(), "{warnings:?}");

        let json = dump_keys(&km, DumpFormat::Json);
        // Every command name appears as a JSON field.
        for spec in COMMANDS {
            assert!(
                json.contains(&format!("\"name\": \"{}\"", spec.name)),
                "json dump missing command {}",
                spec.name
            );
        }
        // The rebind is reflected and the stable fields are present.
        assert!(json.contains("\"name\": \"copy-password\""));
        assert!(
            json.contains("\"keys\": [\"y\"]"),
            "rebound key reflected:\n{json}"
        );
        assert!(json.contains("\"desc\":"));
        assert!(json.contains("\"group\":"));
        assert!(json.contains("\"contexts\":"));
    }

    #[test]
    fn json_escape_handles_metacharacters() {
        assert_eq!(json_escape(r#"a"b\c"#), r#"a\"b\\c"#);
        assert_eq!(json_escape("tab\tnl\n"), "tab\\tnl\\n");
        assert_eq!(json_escape("plain"), "plain");
    }
}
