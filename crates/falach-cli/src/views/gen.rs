//! Gen subcommand view structs — JSON-schema contract for
//! `falach gen {password, passphrase}`.
//!
//! Each `#[derive(serde::Serialize)]` struct is the public JSON shape
//! for one verb. Field renames or type changes are breaking; new
//! optional fields are additive (`#[serde(skip_serializing_if =
//! "Option::is_none")]`).
//!
//! Per design §2.3.3, the default JSON shape omits the secret value;
//! `--show` flips it on. Human-mode output goes through these structs
//! too, but the human renderer prints the value directly so
//! `falach gen password | pbcopy` works.

use serde::Serialize;

use crate::format::HumanFormat;

// ---------------------------------------------------------------------------
// gen password
// ---------------------------------------------------------------------------

/// JSON output for `falach gen password`.
#[derive(Serialize, Debug)]
pub struct PasswordGenView<'a> {
    /// Password value — populated only when `--show` is set (JSON mode)
    /// or when the human renderer wants to emit it (always for `gen`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<&'a str>,
    /// Length (characters) of the generated password.
    pub length: usize,
    /// Enabled character classes (`"lowercase"`, `"uppercase"`,
    /// `"digits"`, `"symbols"`). Stable identifiers, in fixed order.
    pub classes: Vec<&'static str>,
    /// Whether visually ambiguous characters were excluded.
    pub exclude_ambiguous: bool,
}

impl HumanFormat for PasswordGenView<'_> {
    fn write_human(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        // Per design §2.3.3, the human-mode default is "print the value
        // and exit so `| pbcopy` works." The CLI populates `password`
        // for the human path. When `password` is None we fall back to
        // a structure summary (the `--copy` path takes this branch —
        // it doesn't want the value on stdout).
        if let Some(value) = self.password {
            writeln!(out, "{value}")
        } else {
            writeln!(
                out,
                "generated password: length={}, classes={}, ambiguous-excluded={}",
                self.length,
                self.classes.join(","),
                self.exclude_ambiguous,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// gen passphrase
// ---------------------------------------------------------------------------

/// JSON output for `falach gen passphrase`.
#[derive(Serialize, Debug)]
pub struct PassphraseGenView<'a> {
    /// Passphrase value — populated only when `--show` is set (JSON
    /// mode) or in the human path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<&'a str>,
    /// Number of words in the passphrase.
    pub word_count: usize,
    /// Separator inserted between words (verbatim, no escaping).
    pub separator: &'a str,
    /// Name of the wordlist used. Always `"eff-large"` in Phase 0.
    pub wordlist: &'static str,
}

impl HumanFormat for PassphraseGenView<'_> {
    fn write_human(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        if let Some(value) = self.passphrase {
            writeln!(out, "{value}")
        } else {
            writeln!(
                out,
                "generated passphrase: words={}, separator={:?}, wordlist={}",
                self.word_count, self.separator, self.wordlist,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Tests — JSON-schema regression gates per view.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn json_of<V: serde::Serialize>(view: &V) -> Value {
        let s = serde_json::to_string(view).expect("serialize");
        serde_json::from_str(&s).expect("parse")
    }

    // ---- password ----

    #[test]
    fn password_gen_view_omits_value_when_show_unset() {
        let view = PasswordGenView {
            password: None,
            length: 20,
            classes: vec!["lowercase", "uppercase", "digits", "symbols"],
            exclude_ambiguous: false,
        };
        let v = json_of(&view);
        assert!(v.get("password").is_none(), "password absent by default");
        assert_eq!(v["length"], 20);
        assert_eq!(
            v["classes"],
            json!(["lowercase", "uppercase", "digits", "symbols"])
        );
        assert_eq!(v["exclude_ambiguous"], false);
    }

    #[test]
    fn password_gen_view_emits_value_when_show_set() {
        let view = PasswordGenView {
            password: Some("hunter2"),
            length: 7,
            classes: vec!["lowercase", "digits"],
            exclude_ambiguous: true,
        };
        let v = json_of(&view);
        assert_eq!(v["password"], "hunter2");
        assert_eq!(v["exclude_ambiguous"], true);
    }

    #[test]
    fn password_gen_view_human_with_value_prints_value_only() {
        let view = PasswordGenView {
            password: Some("hunter2"),
            length: 7,
            classes: vec!["lowercase"],
            exclude_ambiguous: false,
        };
        let mut buf = Vec::new();
        view.write_human(&mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "hunter2\n");
    }

    #[test]
    fn password_gen_view_human_without_value_prints_summary() {
        let view = PasswordGenView {
            password: None,
            length: 32,
            classes: vec!["lowercase", "digits"],
            exclude_ambiguous: true,
        };
        let mut buf = Vec::new();
        view.write_human(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("length=32"), "{s}");
        assert!(s.contains("ambiguous-excluded=true"), "{s}");
    }

    // ---- passphrase ----

    #[test]
    fn passphrase_gen_view_omits_value_when_show_unset() {
        let view = PassphraseGenView {
            passphrase: None,
            word_count: 6,
            separator: "-",
            wordlist: "eff-large",
        };
        let v = json_of(&view);
        assert!(v.get("passphrase").is_none());
        assert_eq!(v["word_count"], 6);
        assert_eq!(v["separator"], "-");
        assert_eq!(v["wordlist"], "eff-large");
    }

    #[test]
    fn passphrase_gen_view_emits_value_when_show_set() {
        let view = PassphraseGenView {
            passphrase: Some("alpha-bravo-charlie"),
            word_count: 3,
            separator: "-",
            wordlist: "eff-large",
        };
        let v = json_of(&view);
        assert_eq!(v["passphrase"], "alpha-bravo-charlie");
    }

    #[test]
    fn passphrase_gen_view_human_with_value_prints_value_only() {
        let view = PassphraseGenView {
            passphrase: Some("alpha-bravo-charlie"),
            word_count: 3,
            separator: "-",
            wordlist: "eff-large",
        };
        let mut buf = Vec::new();
        view.write_human(&mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "alpha-bravo-charlie\n");
    }
}
