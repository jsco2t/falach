//! `falach gen {password, passphrase}` dispatcher.
//!
//! Generation goes through `falach-genpw`'s `PasswordBuilder` /
//! `PassphraseBuilder`. The output is a [`zeroize::Zeroizing<String>`]
//! that lives only as long as needed.
//!
//! ## `--show` / `--copy` semantics (design §2.3.3)
//!
//! - Human mode default: print the value to stdout (so `falach gen
//!   password | pbcopy` works). `--copy` suppresses that and copies via
//!   security-behaviors instead.
//! - JSON mode default: emit structure but omit the value. `--show`
//!   flips it on. `--copy` is mutually exclusive with `--show`.

use falach_genpw::{CharSet, PassphraseBuilder, PasswordBuilder};

use crate::cli::{Cli, GenArgs, GenPassphraseArgs, GenPasswordArgs, GenVerb, OutputFormat};
use crate::commands::{arm_clipboard, write_success};
use crate::exit::CliExit;
use crate::views::gen::{PassphraseGenView, PasswordGenView};

/// Phase 3 entry point — dispatches to the verb handler.
///
/// # Errors
///
/// Any [`CliExit`] returned by the per-verb handlers.
pub fn run(cli: &Cli, args: &GenArgs) -> Result<(), CliExit> {
    match &args.verb {
        Some(GenVerb::Password(a)) => run_password(cli, a),
        Some(GenVerb::Passphrase(a)) => run_passphrase(cli, a),
        None => Err(CliExit::UserError(
            "missing subcommand verb (try `falach gen --help`)".to_string(),
        )),
    }
}

// ---------------------------------------------------------------------------
// gen password
// ---------------------------------------------------------------------------

fn run_password(cli: &Cli, args: &GenPasswordArgs) -> Result<(), CliExit> {
    let classes = CharSet {
        lowercase: !args.class_flags.no_lowercase,
        uppercase: !args.class_flags.no_uppercase,
        digits: !args.class_flags.no_digits,
        symbols: !args.class_flags.no_symbols,
    };
    let builder = PasswordBuilder::new()
        .length(args.length)
        .classes(classes)
        .exclude_ambiguous(args.class_flags.exclude_ambiguous);
    let value = builder.generate().map_err(CliExit::from)?;

    let class_names = enabled_class_names(classes);
    let show_value_in_output = args.show || (cli.format == OutputFormat::Human && !args.copy);

    let view = PasswordGenView {
        password: if show_value_in_output {
            Some(value.as_str())
        } else {
            None
        },
        length: args.length,
        classes: class_names,
        exclude_ambiguous: args.class_flags.exclude_ambiguous,
    };
    arm_and_write(cli, &view, args.copy, || value.as_str().to_owned())
}

// ---------------------------------------------------------------------------
// gen passphrase
// ---------------------------------------------------------------------------

fn run_passphrase(cli: &Cli, args: &GenPassphraseArgs) -> Result<(), CliExit> {
    let builder = PassphraseBuilder::new()
        .words(args.word_count)
        .separator(args.separator.as_str());
    let value = builder.generate().map_err(CliExit::from)?;

    let show_value_in_output = args.show || (cli.format == OutputFormat::Human && !args.copy);

    let view = PassphraseGenView {
        passphrase: if show_value_in_output {
            Some(value.as_str())
        } else {
            None
        },
        word_count: args.word_count,
        separator: args.separator.as_str(),
        wordlist: "eff-large",
    };
    arm_and_write(cli, &view, args.copy, || value.as_str().to_owned())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Sequence the clipboard arm, the success-view write, and the
/// blocking `wait_for_clear` so that an arming failure produces a
/// single JSON error envelope on stdout (no preceding success view),
/// and so that a `write_success` failure does NOT cancel the
/// clipboard timer (the secret is already on the OS clipboard; we
/// still want the auto-clear to fire).
///
/// `value_owned` is a closure rather than an eager parameter so the
/// caller doesn't allocate the cleartext String when `copy` is false.
fn arm_and_write<V, F>(cli: &Cli, view: &V, copy: bool, value_owned: F) -> Result<(), CliExit>
where
    V: serde::Serialize + crate::format::HumanFormat,
    F: FnOnce() -> String,
{
    if copy {
        let mut guard = arm_clipboard(value_owned())?;
        let write_result = write_success(cli, view);
        let wait_result = guard.wait_for_clear().map_err(CliExit::from);
        write_result?;
        return wait_result;
    }
    write_success(cli, view)
}

/// Stable-name list of enabled classes for the JSON view. Order is
/// fixed (lowercase, uppercase, digits, symbols) so the schema is
/// deterministic.
fn enabled_class_names(classes: CharSet) -> Vec<&'static str> {
    let mut names = Vec::with_capacity(4);
    if classes.lowercase {
        names.push("lowercase");
    }
    if classes.uppercase {
        names.push("uppercase");
    }
    if classes.digits {
        names.push("digits");
    }
    if classes.symbols {
        names.push("symbols");
    }
    names
}
