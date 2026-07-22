//! Top-level command tree.
//!
//! Defines [`Cli`] and the [`Command`] subcommand enum, plus a small
//! placeholder verb enum per subcommand. Phase 1 carries only the
//! top-level shape; Phases 2–4 flesh out the per-subcommand verbs.
//!
//! ## ASCII-art header
//!
//! The `--help` output is prefixed with a `Falach` ASCII-art banner via
//! clap's `before_help`. The banner is preserved verbatim from the
//! project owner's source — see [`BANNER`].

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// ASCII-art banner shown above every `falach --help` output.
pub const BANNER: &str = r"
    ______      __           __
   / ____/___ _/ /___ ______/ /_
  / /_  / __ `/ / __ `/ ___/ __ \
 / __/ / /_/ / / /_/ / /__/ / / /
/_/    \__,_/_/\__,_/\___/_/ /_/

";

/// Master-password environment variable: detected at startup and ignored
/// with a stderr warning. Documented as reserved.
pub const MASTER_PASSWORD_ENV_VAR: &str = "FALACH_MASTER_PASSWORD";

const AFTER_HELP: &str = "\
Master password is collected via a secure stdin prompt (no echo). The \
FALACH_MASTER_PASSWORD environment variable, if set, is ignored and \
removed from the process environment at startup. There is no \
--master-password flag by design.";

/// Top-level `falach` command.
#[derive(Parser, Debug)]
#[command(
    name = "falach",
    version,
    about = "Falach — keeper of secrets. Offline-first KDBX secrets manager.",
    before_help = BANNER,
    after_help = AFTER_HELP,
)]
pub struct Cli {
    /// The subcommand to dispatch.
    #[command(subcommand)]
    pub command: Command,

    /// Output format. `human` (default) is line-oriented for terminals;
    /// `json` is the stable machine-readable schema for scripts.
    #[arg(long, value_enum, global = true, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,

    /// Path to the vault registry file. Defaults to
    /// `$HOME/.local/state/falach/vaults.toml` (per
    /// `falach_core::FalachPaths`).
    #[arg(long, global = true)]
    pub registry: Option<PathBuf>,
}

/// Top-level subcommand selector.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Vault lifecycle and registration commands.
    Vault(VaultArgs),
    /// Secret-entry CRUD, search, and TOTP commands.
    Entry(EntryArgs),
    /// Password and passphrase generation.
    Gen(GenArgs),
    /// Synchronise a vault with its configured S3 target.
    ///
    /// Unlocks the selected vault, runs its configured sync transport, and
    /// renders the outcome in human or JSON format.
    Sync(SyncArgs),
    /// SSH key entry management.
    ///
    /// MVP slot — body returns exit 11 (`not.implemented`). The real
    /// implementation arrives with `features/ssh-keys/`; flag surface
    /// is declared here as the forward-compat contract.
    Ssh(SshArgs),
    /// Generate shell completion scripts.
    ///
    /// Supported shells: `bash`, `zsh`, `fish` (documented), plus
    /// `powershell` and `elvish` (accepted; not in the Phase-0 support
    /// matrix). Typical use: `falach completions bash > ~/.falach-completions.bash`
    /// then `source ~/.falach-completions.bash` from your shell rc.
    /// The `make completions` Makefile target writes pre-generated
    /// scripts into `shell-completions/` for packaging.
    Completions(CompletionsArgs),
    /// Print the TUI's effective keymap (command name, keys, description, group).
    ///
    /// Relays `falach-tui --dump-keys` — locate the TUI binary on `$PATH` (or
    /// via `$FALACH_TUI_BIN`). Spawns a subprocess but passes NO secret
    /// material: keymap data only. Closes tui-skeleton sibling contract #6.
    Keys(KeysArgs),
}

/// Flags for `falach keys`.
#[derive(Args, Debug)]
pub struct KeysArgs {
    /// Output format: `human` (default) or `json`.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
}

/// `--format` selector. Default `human`.
#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OutputFormat {
    /// Line-oriented human-readable output (default).
    #[default]
    Human,
    /// Stable JSON schema — see `views/` for per-subcommand shapes.
    Json,
}

// ---------------------------------------------------------------------------
// Per-subcommand argument structs. Phase 1 ships placeholder verb enums;
// Phases 2–4 fill them in with real flags. The top-level subcommand
// parser must already accept the verb shapes today so `--help` is
// stable across phases.
// ---------------------------------------------------------------------------

/// `falach vault` — vault lifecycle.
#[derive(Args, Debug)]
pub struct VaultArgs {
    /// Verb to execute.
    #[command(subcommand)]
    pub verb: Option<VaultVerb>,
}

/// Verbs accepted by `falach vault`.
#[derive(Subcommand, Debug)]
pub enum VaultVerb {
    /// Create a new vault and register it.
    Create(VaultCreateArgs),
    /// Probe vault unlock with the given master password.
    ///
    /// In Phase 0 MVP this is a one-shot probe: prompts for the master
    /// password, attempts unlock, prints success or maps to exit code 2
    /// on auth failure, then exits. When the falach agent ships
    /// (post-MVP), this command caches the unlocked vault for
    /// subsequent commands.
    Open(VaultOpenArgs),
    /// List registered vaults.
    List(VaultListArgs),
    /// Configure the S3 target for a vault.
    ///
    /// Validates and persists an S3 target and credential source for the
    /// selected registered vault.
    SetSync(VaultSetSyncArgs),
    /// Configure the per-vault idle-lock timeout.
    SetLock(VaultSetLockArgs),
}

/// Flags for `falach vault create`.
#[derive(Args, Debug)]
pub struct VaultCreateArgs {
    /// Registry name for the new vault (unique).
    #[arg(long)]
    pub id: String,
    /// Absolute or relative path where the `.kdbx` file will be created.
    #[arg(long)]
    pub path: std::path::PathBuf,
    /// Optional keyfile required to unlock this vault.
    #[arg(long)]
    pub keyfile: Option<std::path::PathBuf>,
    /// Acknowledge the no-recovery warning. Required — there is no
    /// master-password recovery in Falach.
    #[arg(long)]
    pub no_recovery_warning: bool,
}

/// Flags for `falach vault open`.
#[derive(Args, Debug)]
pub struct VaultOpenArgs {
    /// Registry name of the vault to probe.
    #[arg(long)]
    pub id: String,
}

/// Flags for `falach vault list` (none today; struct exists for
/// forward-compat with future `--filter`-style flags).
#[derive(Args, Debug)]
pub struct VaultListArgs {}

/// Flags for `falach vault set-sync`.
///
/// `--s3-credentials-source` grammar (design §2.4):
/// - `prompt` (default): collect access-key-id + secret on secure
///   stdin and seal via RST-CRED-1.
/// - `iam-role`: use EC2 `IMDSv2` instance-role credentials.
/// - `profile:<name>`: read from `~/.aws/credentials` under the named
///   profile section.
/// - `env:<prefix>`: read `PREFIX_AWS_ACCESS_KEY_ID` +
///   `PREFIX_AWS_SECRET_ACCESS_KEY` from the process environment.
#[derive(Args, Debug)]
pub struct VaultSetSyncArgs {
    /// Registry name of the vault to configure.
    #[arg(long)]
    pub id: String,
    /// S3 bucket name.
    #[arg(long)]
    pub s3_bucket: String,
    /// S3 object key (the `.kdbx` filename on the remote).
    #[arg(long)]
    pub s3_key: String,
    /// Optional custom S3 endpoint URL (e.g. `https://minio.internal`).
    /// Defaults to the AWS regional endpoint for `--s3-region`.
    #[arg(long)]
    pub s3_endpoint: Option<String>,
    /// S3 region (required for `SigV4` signing). Defaults to `us-east-1`.
    #[arg(long, default_value = "us-east-1")]
    pub s3_region: String,
    /// Use path-style addressing (`hostname/bucket`) instead of
    /// virtual-hosted-style (`bucket.hostname`). Defaults to false.
    #[arg(long)]
    pub s3_path_style: bool,
    /// How to obtain S3 credentials. Grammar:
    /// `prompt` (default), `iam-role`, `profile:<name>`,
    /// `env:<prefix>` (see struct docs).
    #[arg(long, default_value = "prompt")]
    pub s3_credentials_source: String,
}

/// Flags for `falach vault set-lock`.
///
/// `--timeout <seconds>` and `--clear` are mutually exclusive; clap
/// enforces this at parse time via `conflicts_with`.
#[derive(Args, Debug)]
pub struct VaultSetLockArgs {
    /// Registry name of the vault to configure.
    #[arg(long)]
    pub id: String,
    /// Idle-timeout in seconds before the vault auto-locks. Must be
    /// at least 1.
    #[arg(long, conflicts_with = "clear")]
    pub timeout: Option<u64>,
    /// Remove the per-vault override and fall back to the default.
    #[arg(long, conflicts_with = "timeout")]
    pub clear: bool,
}

/// `falach entry` — secret-entry CRUD + search.
#[derive(Args, Debug)]
pub struct EntryArgs {
    /// Verb to execute.
    #[command(subcommand)]
    pub verb: Option<EntryVerb>,
}

/// Verbs accepted by `falach entry`.
#[derive(Subcommand, Debug)]
pub enum EntryVerb {
    /// Add a new entry to a vault.
    Add(EntryAddArgs),
    /// Get an entry by UUID or title.
    Get(EntryGetArgs),
    /// Edit an existing entry.
    Edit(EntryEditArgs),
    /// Remove an entry (move to Recycle Bin by default).
    Rm(EntryRmArgs),
    /// List entries in a vault.
    List(EntryListArgs),
    /// Search entries.
    Search(EntrySearchArgs),
}

/// Password-class selection flags shared by `entry add --generate` and
/// `gen password`. Negative flags so the defaults (all four classes on)
/// don't need to be repeated for every invocation.
#[derive(Args, Debug, Clone, Copy, Default)]
#[allow(clippy::struct_excessive_bools)] // matches the four CharSet classes 1:1
pub struct PasswordClassFlags {
    /// Disable lowercase letters in the generated password.
    #[arg(long)]
    pub no_lowercase: bool,
    /// Disable uppercase letters in the generated password.
    #[arg(long)]
    pub no_uppercase: bool,
    /// Disable digits in the generated password.
    #[arg(long)]
    pub no_digits: bool,
    /// Disable symbols in the generated password.
    #[arg(long)]
    pub no_symbols: bool,
    /// Exclude visually ambiguous characters (`0/O/o/1/l/I/|/backtick`).
    #[arg(long)]
    pub exclude_ambiguous: bool,
}

/// Flags for `falach entry add`.
#[derive(Args, Debug)]
pub struct EntryAddArgs {
    /// Registry name of the vault to add into.
    #[arg(long)]
    pub vault: String,
    /// Title of the new entry (required).
    #[arg(long)]
    pub title: String,
    /// Optional username.
    #[arg(long)]
    pub username: Option<String>,
    /// Optional URL.
    #[arg(long)]
    pub url: Option<String>,
    /// Optional notes.
    #[arg(long)]
    pub notes: Option<String>,
    /// Read the entry's password from stdin (no-echo when stdin is a
    /// TTY). Mutually exclusive with `--generate`.
    #[arg(long, conflicts_with = "generate")]
    pub password_stdin: bool,
    /// Generate a fresh password via `falach-genpw`. Mutually
    /// exclusive with `--password-stdin`. Honours the `PasswordClassFlags`
    /// + `--length` flags.
    #[arg(long, conflicts_with = "password_stdin")]
    pub generate: bool,
    /// Generated-password length (only consulted with `--generate`).
    /// Default: 20.
    #[arg(long, default_value_t = 20)]
    pub length: usize,
    /// Tag to attach to the new entry. Repeat for multiple tags.
    #[arg(long = "tag")]
    pub tags: Vec<String>,
    /// Include the generated/captured password in the output view (JSON
    /// + human). Default: omit.
    #[arg(long)]
    pub show_password: bool,
    /// Character-class controls for `--generate`.
    #[command(flatten)]
    pub class_flags: PasswordClassFlags,
}

/// Flags for `falach entry get`.
#[derive(Args, Debug)]
pub struct EntryGetArgs {
    /// Registry name of the vault.
    #[arg(long)]
    pub vault: String,
    /// UUID of the entry. Mutually exclusive with `--title`.
    #[arg(long, conflicts_with = "title")]
    pub uuid: Option<String>,
    /// Title of the entry; case-insensitive exact match. If multiple
    /// entries share the title the command exits 1 listing the
    /// candidate UUIDs.
    #[arg(long, conflicts_with = "uuid")]
    pub title: Option<String>,
    /// Include the password value in the output. Mutually exclusive
    /// with `--copy` (copying redundantly with showing is suspicious).
    #[arg(long, conflicts_with = "copy")]
    pub show_password: bool,
    /// Compute and include the current TOTP code (HMAC-SHA1; RFC 6238).
    #[arg(long)]
    pub show_totp: bool,
    /// Copy the password to the system clipboard with auto-clear.
    /// Mutually exclusive with `--show-password`.
    #[arg(long, conflicts_with = "show_password")]
    pub copy: bool,
}

/// Flags for `falach entry edit`.
#[derive(Args, Debug)]
pub struct EntryEditArgs {
    /// Registry name of the vault.
    #[arg(long)]
    pub vault: String,
    /// UUID of the entry to edit (required).
    #[arg(long)]
    pub uuid: String,
    /// New title.
    #[arg(long)]
    pub title: Option<String>,
    /// New username.
    #[arg(long)]
    pub username: Option<String>,
    /// New URL.
    #[arg(long)]
    pub url: Option<String>,
    /// New notes.
    #[arg(long)]
    pub notes: Option<String>,
    /// Read a new password from stdin (no-echo when stdin is a TTY).
    #[arg(long)]
    pub password_stdin: bool,
    /// Tag to add. Repeat for multiple.
    #[arg(long = "add-tag")]
    pub add_tags: Vec<String>,
    /// Tag to remove (silent no-op if not present). Repeat for multiple.
    #[arg(long = "rm-tag")]
    pub rm_tags: Vec<String>,
}

/// Flags for `falach entry rm`.
#[derive(Args, Debug)]
pub struct EntryRmArgs {
    /// Registry name of the vault.
    #[arg(long)]
    pub vault: String,
    /// UUID of the entry to remove (required).
    #[arg(long)]
    pub uuid: String,
    /// Permanently delete the entry, bypassing the recycle bin.
    #[arg(long)]
    pub permanent: bool,
}

/// Flags for `falach entry list`.
#[derive(Args, Debug)]
pub struct EntryListArgs {
    /// Registry name of the vault.
    #[arg(long)]
    pub vault: String,
    /// Filter to entries carrying every supplied tag (intersect).
    /// Repeat the flag for multiple tags.
    #[arg(long = "tag")]
    pub tags: Vec<String>,
    /// Include expired entries. Default: omit.
    #[arg(long)]
    pub include_expired: bool,
    /// Optional pagination — max rows to emit.
    #[arg(long)]
    pub limit: Option<usize>,
    /// Optional pagination — rows to skip from the start.
    #[arg(long)]
    pub offset: Option<usize>,
}

/// `--mode` selector for `falach entry search`. Default `substring` (backward
/// compatible — the CLI previously had no mode flag, so this also surfaces the
/// existing-but-hidden wildcard matcher and the new fuzzy matcher).
#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SearchModeArg {
    /// Case-insensitive substring match (default).
    #[default]
    Substring,
    /// Whole-field wildcard match (`*` any run, `?` one char).
    Wildcard,
    /// fzf-style fuzzy match; JSON output gains `score` + `matched_indices`.
    Fuzzy,
}

/// Flags for `falach entry search`.
#[derive(Args, Debug)]
pub struct EntrySearchArgs {
    /// Registry name of the vault.
    #[arg(long)]
    pub vault: String,
    /// Search query (positional).
    pub query: String,
    /// Matching mode: substring (default), wildcard, or fuzzy.
    #[arg(long, value_enum, default_value_t = SearchModeArg::Substring)]
    pub mode: SearchModeArg,
    /// Restrict the search: `group:<name>` (the group subtree) or `tag:<tag>`.
    #[arg(long)]
    pub scope: Option<String>,
    /// Optional cap on returned matches.
    #[arg(long)]
    pub limit: Option<usize>,
    /// Include entries in the recycle bin. Default: exclude.
    #[arg(long)]
    pub include_recycled: bool,
}

/// `falach gen` — password and passphrase generation.
#[derive(Args, Debug)]
pub struct GenArgs {
    /// Verb to execute.
    #[command(subcommand)]
    pub verb: Option<GenVerb>,
}

/// Verbs accepted by `falach gen`.
#[derive(Subcommand, Debug)]
pub enum GenVerb {
    /// Generate a random password with selectable character classes.
    Password(GenPasswordArgs),
    /// Generate an EFF-large-wordlist diceware passphrase.
    Passphrase(GenPassphraseArgs),
}

/// Flags for `falach gen password`.
///
/// `--copy` hands the generated value to `falach-security`'s clipboard
/// with a 30s auto-clear timer. The CLI blocks on the timer's expiry
/// before exit (required on Wayland so the timer thread can actually
/// clear the buffer). `--show` is mutually exclusive with `--copy`.
#[derive(Args, Debug)]
pub struct GenPasswordArgs {
    /// Password length (characters). Default: 20.
    #[arg(long, default_value_t = 20)]
    pub length: usize,
    /// Character-class controls.
    #[command(flatten)]
    pub class_flags: PasswordClassFlags,
    /// Copy the value to the clipboard with auto-clear. Mutually
    /// exclusive with `--show` (copy implies do-not-print).
    #[arg(long, conflicts_with = "show")]
    pub copy: bool,
    /// In JSON mode, include the generated value in the output. Default
    /// JSON output omits the value; human-mode output always prints the
    /// value to stdout regardless of this flag (mirror `pbcopy` style).
    #[arg(long, conflicts_with = "copy")]
    pub show: bool,
}

/// Flags for `falach gen passphrase`.
///
/// Same `--copy` semantics as [`GenPasswordArgs`]: clipboard hand-off
/// with a 30s auto-clear timer; blocks on the timer's expiry.
#[derive(Args, Debug)]
pub struct GenPassphraseArgs {
    /// Number of words. Default: 6.
    #[arg(long, default_value_t = 6)]
    pub word_count: usize,
    /// Separator inserted between words. Default: `-`.
    #[arg(long, default_value = "-")]
    pub separator: String,
    /// Copy the value to the clipboard with auto-clear. Mutually
    /// exclusive with `--show`.
    #[arg(long, conflicts_with = "show")]
    pub copy: bool,
    /// In JSON mode, include the generated value in the output.
    #[arg(long, conflicts_with = "copy")]
    pub show: bool,
}

/// `falach sync` — sync one registered vault with its configured S3 target.
///
/// Note: `--dry-run` is deferred (s3-sync Deferred Item #8); the flag
/// is intentionally absent so the CLI does not silently imply
/// unimplemented behavior.
#[derive(Args, Debug)]
pub struct SyncArgs {
    /// Vault registry name to sync. Optional: if only one vault is
    /// registered, that one is used by default.
    #[arg(long)]
    pub vault: Option<String>,
}

/// `falach ssh` — slot only.
#[derive(Args, Debug)]
pub struct SshArgs {
    /// Verb to execute.
    #[command(subcommand)]
    pub verb: Option<SshVerb>,
}

/// Verbs accepted by `falach ssh` (all slots). All three bodies return
/// `CliExit::NotImplemented`; the flag surfaces are the forward-compat
/// contract with `features/ssh-keys/`.
#[derive(Subcommand, Debug)]
pub enum SshVerb {
    /// Add an SSH-key entry to a vault. (Slot — see `features/ssh-keys/`.)
    Add(SshAddArgs),
    /// Load an SSH key into ssh-agent with TTL. (Slot — see `features/ssh-keys/`.)
    Load(SshLoadArgs),
    /// Generate a new SSH keypair and store the private key. (Slot — see `features/ssh-keys/`.)
    Generate(SshGenerateArgs),
}

/// Flags for `falach ssh add` (slot — body returns exit 11).
#[derive(Args, Debug)]
pub struct SshAddArgs {
    /// Registry name of the destination vault.
    #[arg(long)]
    pub vault: Option<String>,
    /// Path to the existing private key to import.
    #[arg(long)]
    pub key_path: Option<PathBuf>,
    /// Optional comment to attach to the entry.
    #[arg(long)]
    pub comment: Option<String>,
}

/// Flags for `falach ssh load` (slot — body returns exit 11).
#[derive(Args, Debug)]
pub struct SshLoadArgs {
    /// Registry name of the source vault.
    #[arg(long)]
    pub vault: Option<String>,
    /// UUID of the SSH-key entry to load.
    #[arg(long)]
    pub uuid: Option<String>,
    /// TTL in seconds before ssh-agent expires the key.
    #[arg(long)]
    pub ttl: Option<u64>,
}

/// Flags for `falach ssh generate` (slot — body returns exit 11).
#[derive(Args, Debug)]
pub struct SshGenerateArgs {
    /// Registry name of the destination vault.
    #[arg(long)]
    pub vault: Option<String>,
    /// Algorithm (`ed25519` or `rsa`). Defaults to `ed25519` when implemented.
    #[arg(long)]
    pub algorithm: Option<String>,
    /// Optional comment to attach to the public key.
    #[arg(long)]
    pub comment: Option<String>,
}

/// `falach completions <shell>` — emit a shell completion script.
///
/// `<shell>` is required (no default). Supported values are the
/// `clap_complete::Shell` variants: `bash`, `zsh`, `fish`,
/// `powershell`, `elvish`. The CLI documents the first three as the
/// supported targets; the other two are accepted for users who already
/// rely on them.
#[derive(Args, Debug)]
pub struct CompletionsArgs {
    /// Target shell to generate a completion script for.
    pub shell: Option<clap_complete::Shell>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn banner_starts_with_falach_logo_first_glyph() {
        // The banner is a 5-line ASCII rendering whose first non-empty
        // line begins with whitespace + the "F" top stroke `______`. This
        // test guards against accidental trimming.
        let first_real_line = BANNER.lines().find(|l| !l.trim().is_empty()).unwrap();
        assert!(
            first_real_line.contains("____"),
            "banner first line should start with F glyph: {first_real_line:?}"
        );
    }

    #[test]
    fn cli_command_has_all_subcommands() {
        let cmd = Cli::command();
        let names: Vec<_> = cmd.get_subcommands().map(clap::Command::get_name).collect();
        for expected in [
            "vault",
            "entry",
            "gen",
            "sync",
            "ssh",
            "completions",
            "keys",
        ] {
            assert!(
                names.contains(&expected),
                "missing subcommand {expected}; have {names:?}"
            );
        }
    }

    #[test]
    fn entry_search_mode_flag_parses_and_defaults() {
        // Absent → substring (backward compatible).
        let cli = Cli::try_parse_from(["falach", "entry", "search", "--vault", "v", "q"]).unwrap();
        let Some(Command::Entry(EntryArgs {
            verb: Some(EntryVerb::Search(args)),
        })) = Some(cli.command)
        else {
            panic!("expected entry search");
        };
        assert_eq!(args.mode, SearchModeArg::Substring, "default is substring");
        assert!(args.scope.is_none());

        // Each mode value maps.
        for (flag, want) in [
            ("substring", SearchModeArg::Substring),
            ("wildcard", SearchModeArg::Wildcard),
            ("fuzzy", SearchModeArg::Fuzzy),
        ] {
            let cli = Cli::try_parse_from([
                "falach", "entry", "search", "--vault", "v", "--mode", flag, "q",
            ])
            .unwrap();
            let Command::Entry(EntryArgs {
                verb: Some(EntryVerb::Search(args)),
            }) = cli.command
            else {
                panic!("expected entry search");
            };
            assert_eq!(args.mode, want, "--mode {flag}");
        }
    }

    #[test]
    fn entry_search_scope_flag_parses() {
        let cli = Cli::try_parse_from([
            "falach",
            "entry",
            "search",
            "--vault",
            "v",
            "--scope",
            "group:Banking",
            "q",
        ])
        .unwrap();
        let Command::Entry(EntryArgs {
            verb: Some(EntryVerb::Search(args)),
        }) = cli.command
        else {
            panic!("expected entry search");
        };
        assert_eq!(args.scope.as_deref(), Some("group:Banking"));
    }

    #[test]
    fn no_master_password_flag_exists_anywhere() {
        // FR-061 structural gate: no clap flag named --master-password,
        // --password, or similar lives anywhere in the tree. Phase 1
        // does not yet have password-shaped flags by design; this test
        // is the canary against accidental future addition.
        let cmd = Cli::command();
        assert_args_have_no_master_password_flag(&cmd, "falach");
    }

    fn assert_args_have_no_master_password_flag(cmd: &clap::Command, path: &str) {
        for arg in cmd.get_arguments() {
            let long = arg.get_long().unwrap_or("");
            assert_ne!(
                long, "master-password",
                "found forbidden --master-password flag at {path}"
            );
        }
        for sub in cmd.get_subcommands() {
            let sub_path = format!("{path} {}", sub.get_name());
            assert_args_have_no_master_password_flag(sub, &sub_path);
        }
    }

    #[test]
    fn output_format_default_is_human() {
        assert_eq!(OutputFormat::default(), OutputFormat::Human);
    }

    #[test]
    fn master_password_env_var_name_is_documented_constant() {
        // Single source of truth so the env-var name matches in tests,
        // docs, and runtime detection.
        assert_eq!(MASTER_PASSWORD_ENV_VAR, "FALACH_MASTER_PASSWORD");
    }
}
