//! `falach vault {create, open, list, set-sync, set-lock}` dispatcher.
//!
//! `set-sync` configures a vault's S3 sync target — resolving a
//! credential source (default `prompt` seals the secret via RST-CRED-1),
//! building an `S3Config`, and persisting it through
//! `falach_sync::Sync::configure_remote`.
//!
//! ## State directory resolution
//!
//! The global `--registry <path>` flag is the path to the registry
//! file itself — `crate::commands::resolve_paths` honors the exact
//! file name via [`falach_core::FalachPaths::with_registry_file`].
//! When the flag is omitted we fall back to `FalachPaths::from_env`
//! (the `$HOME/.local/state/falach/vaults.toml` path).
//!
//! ## `[vault.lock]` schema
//!
//! The `[vault.lock] idle_timeout_seconds` on-disk schema is owned by
//! `falach-security` ([`VaultLockConfig`]); this module reads and
//! writes it exclusively through that crate's helpers so the CLI's
//! write path and security-behaviors' read path cannot drift.

use falach_core::{
    KdfParams, Keyfile, MasterPassword, NoRecoveryConfirmed, RegisteredVault, Vault, VaultError,
    VaultRegistry,
};
use falach_security::VaultLockConfig;
use falach_sync::s3::{EndpointBuilder, EndpointConfig};
use falach_sync::{encrypt_credential, CredentialSource, S3Config, Sync};
use zeroize::Zeroizing;

use crate::agent::NoAgentClient;
use crate::cli::{
    Cli, VaultArgs, VaultCreateArgs, VaultOpenArgs, VaultSetLockArgs, VaultSetSyncArgs, VaultVerb,
};
use crate::commands::{resolve_paths, write_success};
use crate::exit::CliExit;
use crate::prompt::{
    master_password, new_master_password_confirmed, prompt_line, read_password_no_echo, PromptOpts,
};
use crate::views::vault::{
    VaultCreateKdfView, VaultCreateView, VaultListEntry, VaultListView, VaultOpenView,
    VaultSetLockView, VaultSetSyncView,
};

/// Phase 2 entry point — dispatches to the verb handler.
///
/// # Errors
///
/// Any [`CliExit`] returned by the per-verb handlers.
pub fn run(cli: &Cli, args: &VaultArgs) -> Result<(), CliExit> {
    match &args.verb {
        Some(VaultVerb::Create(create)) => run_create(cli, create),
        Some(VaultVerb::Open(open)) => run_open(cli, open),
        Some(VaultVerb::List(_)) => run_list(cli),
        Some(VaultVerb::SetSync(set_sync)) => run_set_sync(cli, set_sync),
        Some(VaultVerb::SetLock(setlock)) => run_set_lock(cli, setlock),
        None => Err(CliExit::UserError(
            "missing subcommand verb (try `falach vault --help`)".to_string(),
        )),
    }
}

// ---------------------------------------------------------------------------
// vault create
// ---------------------------------------------------------------------------

fn run_create(cli: &Cli, args: &VaultCreateArgs) -> Result<(), CliExit> {
    if !args.no_recovery_warning {
        return Err(CliExit::UserError(
            "vault create requires --no-recovery-warning: there is no master-password recovery \
             in Falach (data lost on forgotten password)"
                .to_string(),
        ));
    }

    // Load the registry FIRST so a duplicate-id error surfaces before
    // we run the expensive Argon2id KDF + write a .kdbx file that the
    // user can't easily clean up. Belt-and-suspenders: the
    // `VaultRegistry::register` call below still re-checks for
    // duplicates, so a race between two concurrent `vault create`
    // invocations can't silently succeed.
    let paths = resolve_paths(cli)?;
    let mut registry = VaultRegistry::load(paths).map_err(CliExit::from)?;
    if registry.get(&args.id).is_some() {
        return Err(CliExit::from(falach_core::VaultError::AlreadyRegistered {
            name: args.id.clone(),
        }));
    }

    // Collect the password BEFORE touching disk so a user who Ctrl-Cs
    // out of the prompt doesn't leave a half-registered vault behind.
    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();
    let mut stderr = std::io::stderr().lock();
    let master = new_master_password_confirmed(&mut stdin, &mut stderr)?;
    let keyfile = args.keyfile.clone().map(Keyfile::Path);
    let kdf = KdfParams::default();

    let _vault = Vault::create(
        &args.path,
        &master,
        keyfile.as_ref(),
        kdf,
        NoRecoveryConfirmed::yes(),
    )
    .map_err(CliExit::from)?;
    // Drop the Vault handle here — Phase 2's `vault create` returns
    // immediately after registration; the file is on disk and the
    // registry will be updated below. The handle's exclusive lock is
    // released as it drops.

    registry
        .register(RegisteredVault {
            name: args.id.clone(),
            path: args.path.clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
            keyfile_path: args.keyfile.clone(),
            extra: toml::Table::new(),
        })
        .map_err(CliExit::from)?;
    registry.save().map_err(CliExit::from)?;

    let view = VaultCreateView {
        id: &args.id,
        path: &args.path,
        keyfile: args.keyfile.as_deref(),
        kdf: VaultCreateKdfView {
            algorithm: "argon2id",
            memory_kib: kdf.memory_kib,
            iterations: kdf.iterations,
            parallelism: kdf.parallelism,
        },
    };
    write_success(cli, &view)
}

// ---------------------------------------------------------------------------
// vault open (probe)
// ---------------------------------------------------------------------------

fn run_open(cli: &Cli, args: &VaultOpenArgs) -> Result<(), CliExit> {
    let paths = resolve_paths(cli)?;
    let registry = VaultRegistry::load(paths).map_err(CliExit::from)?;
    let record = registry
        .get(&args.id)
        .ok_or_else(|| {
            CliExit::from(VaultError::NotRegistered {
                name: args.id.clone(),
            })
        })?
        .clone();

    let agent = NoAgentClient;
    let opts = PromptOpts {
        vault: &args.id,
        agent: &agent,
        prompt_label: "Master password: ",
    };
    let master = master_password(&opts)?;

    let keyfile = record.keyfile_path.clone().map(Keyfile::Path);
    // The probe: open the vault, immediately drop it. The open call
    // produces `VaultError::AuthenticationFailed` (exit 2) on a wrong
    // master password, which is the whole point.
    let _vault = Vault::open(&record.path, &master, keyfile.as_ref()).map_err(CliExit::from)?;

    let view = VaultOpenView {
        id: &args.id,
        status: "unlocked-ok",
    };
    write_success(cli, &view)
}

// ---------------------------------------------------------------------------
// vault list
// ---------------------------------------------------------------------------

fn run_list(cli: &Cli) -> Result<(), CliExit> {
    let paths = resolve_paths(cli)?;
    let registry = VaultRegistry::load(paths).map_err(CliExit::from)?;

    let entries: Vec<VaultListEntry<'_>> = registry
        .list()
        .map(|r| VaultListEntry {
            id: &r.name,
            path: &r.path,
            keyfile: r.keyfile_path.as_deref(),
            created_at: &r.created_at,
            // Lenient read: `vault list` must not fail on a hand-edited
            // registry; malformed lock data displays as "no override".
            idle_timeout_seconds: VaultLockConfig::idle_timeout_seconds_from_extra(&r.extra),
        })
        .collect();
    let view = VaultListView { vaults: entries };
    write_success(cli, &view)
}

// ---------------------------------------------------------------------------
// vault set-sync
// ---------------------------------------------------------------------------

/// Configure a vault's S3 sync target (`falach vault set-sync`).
///
/// Resolves a [`CredentialSource`] from `--s3-credentials-source`
/// (default `prompt` collects the access-key-id + secret on secure stdin
/// and seals the secret via RST-CRED-1), builds an [`S3Config`], and
/// hands it to [`Sync::configure_remote`] (which runs the ADR-6
/// duplicate-target check and persists the registry).
///
/// Security posture: the secret access key is sealed before any registry
/// write and never echoed; the master password is collected via secure
/// stdin only (never a flag/env). See `credential_source_from_spec` for
/// the non-interactive forms.
///
/// # Errors
///
/// - [`CliExit::UserError`] — vault not registered, an unrecognized
///   credential-source spec, or a duplicate S3 target (via the
///   `From<SyncError>` mapping).
/// - [`CliExit::VaultLocked`] — a wrong master password at the `prompt`
///   verification probe (exit 2).
/// - [`CliExit::Internal`] — sealing the secret or persisting the
///   registry failed.
fn run_set_sync(cli: &Cli, args: &VaultSetSyncArgs) -> Result<(), CliExit> {
    let paths = resolve_paths(cli)?;
    let mut registry = VaultRegistry::load(paths).map_err(CliExit::from)?;
    // Resolve the record up-front: gives a clear "not registered" error
    // before any prompting, and (on the `prompt` path) supplies the KDBX
    // path + keyfile for the master-password verification probe.
    let record = registry
        .get(&args.id)
        .ok_or_else(|| {
            CliExit::from(VaultError::NotRegistered {
                name: args.id.clone(),
            })
        })?
        .clone();

    // Validate the S3 target BEFORE prompting: clap accepts explicit empty
    // strings (`--s3-bucket ""`), and `configure_remote` only checks
    // registration + duplicate targets, so an empty bucket/key/region would
    // persist as a broken config that fails opaquely at the next `sync`.
    // Rejecting here (and before the user types a secret) surfaces it as a
    // clean user error. Full endpoint validation is repeated authoritatively
    // by `Sync::configure_remote`; doing it here avoids prompting before a
    // known-bad target is rejected.
    validate_s3_target(args)?;

    let credentials = if args.s3_credentials_source == "prompt" {
        // Collect the (public) access-key-id echoed and the secret access
        // key with echo off. Scope the stdin lock so it is released before
        // `master_password` acquires its own lock — the reads continue from
        // the same shared buffer in order: akid, secret, then master.
        // The secret is held in `Zeroizing<String>` so its heap buffer is
        // wiped on drop (parity with the master password, which moves into
        // the `ZeroizeOnDrop` `MasterPassword`); the intermediate `read_line`
        // allocation is not separately wiped — same posture as
        // `kb/memory-hygiene.md` accepts for the master-password prompt.
        let (access_key_id, secret_access_key) = {
            let stdin = std::io::stdin();
            let mut stdin = stdin.lock();
            let mut stderr = std::io::stderr().lock();
            let access_key_id = prompt_line("AWS access key id: ", &mut stdin, &mut stderr)
                .map_err(|e| CliExit::UserError(format!("failed to read access key id: {e}")))?;
            let secret_access_key = Zeroizing::new(
                read_password_no_echo("AWS secret access key: ", &mut stdin, &mut stderr).map_err(
                    |e| CliExit::UserError(format!("failed to read secret access key: {e}")),
                )?,
            );
            (access_key_id, secret_access_key)
        };

        // Empty prompted credentials are invalid for SigV4 — reject before
        // sealing/persisting rather than storing a broken credential.
        if access_key_id.trim().is_empty() {
            return Err(CliExit::UserError(
                "AWS access key id must not be empty".to_string(),
            ));
        }
        if secret_access_key.trim().is_empty() {
            return Err(CliExit::UserError(
                "AWS secret access key must not be empty".to_string(),
            ));
        }

        let agent = NoAgentClient;
        let opts = PromptOpts {
            vault: &args.id,
            agent: &agent,
            prompt_label: "Master password: ",
        };
        let master = master_password(&opts)?;

        // Verify the master password before sealing. Without this probe a
        // typo would seal the secret under the wrong key and fail only at
        // the next `sync` as an opaque `CredentialDecryption` (exit 10).
        // The probe (mirror of `run_open`) surfaces a wrong password as
        // exit 2 now, at the point the user can fix it.
        let keyfile = record.keyfile_path.clone().map(Keyfile::Path);
        // Open then immediately drop: the `?` verifies the password, and the
        // bound `_` releases the vault's exclusive advisory lock and
        // zeroizes the decrypted database right away rather than holding
        // both across the seal + registry write below.
        let _ = Vault::open(&record.path, &master, keyfile.as_ref()).map_err(CliExit::from)?;

        // Seal the secret with RST-CRED-1 before it can reach the registry.
        // A failure here is an OS-entropy failure (not user input), so it
        // is an internal error, not a user error.
        let secret_access_key_encrypted = encrypt_credential(&secret_access_key, &master)
            .map_err(|e| CliExit::Internal(format!("failed to seal S3 credential: {e}")))?;

        CredentialSource::RstCred1 {
            access_key_id,
            secret_access_key_encrypted,
        }
    } else {
        credential_source_from_spec(&args.s3_credentials_source)?
    };

    // The kind tag for the (secret-free) output view — computed before
    // `credentials` is moved into the `S3Config`.
    let credentials_source = credentials_source_tag(&credentials);

    let mut s3 = S3Config::new(
        args.s3_bucket.clone(),
        args.s3_key.clone(),
        args.s3_region.clone(),
        credentials,
    );
    if args.s3_endpoint.is_some() {
        s3.set_endpoint(args.s3_endpoint.clone());
    }
    if args.s3_path_style {
        s3.set_path_style(true);
    }

    // `configure_remote` ignores the master password today (its parameter
    // is `_master_password`); the non-prompt sources have none to pass, so
    // an empty value is the honest "not needed" argument. If a future
    // version starts verifying it, the `prompt`-path probe above already
    // proves ownership; the non-prompt sources would need their own check.
    let unused_master = MasterPassword::new(String::new());
    Sync::configure_remote(&mut registry, &args.id, s3, &unused_master).map_err(CliExit::from)?;

    let view = VaultSetSyncView {
        id: &args.id,
        bucket: &args.s3_bucket,
        key: &args.s3_key,
        endpoint: args.s3_endpoint.as_deref(),
        credentials_source,
    };
    write_success(cli, &view)
}

/// Reject S3 target arguments that clap accepts but the transport cannot
/// use — an explicitly-empty `--s3-bucket`/`--s3-key`/`--s3-region`, or an
/// explicitly-empty or malformed `--s3-endpoint`.
///
/// # Errors
///
/// [`CliExit::UserError`] naming the first empty required flag.
fn validate_s3_target(args: &VaultSetSyncArgs) -> Result<(), CliExit> {
    for (flag, value) in [
        ("--s3-bucket", &args.s3_bucket),
        ("--s3-key", &args.s3_key),
        ("--s3-region", &args.s3_region),
    ] {
        if value.trim().is_empty() {
            return Err(CliExit::UserError(format!("{flag} must not be empty")));
        }
    }
    if let Some(endpoint) = &args.s3_endpoint {
        if endpoint.trim().is_empty() {
            return Err(CliExit::UserError(
                "--s3-endpoint must not be empty (omit it to use the default AWS \
                 regional endpoint for --s3-region)"
                    .to_string(),
            ));
        }
    }
    EndpointBuilder::from_config(&EndpointConfig {
        endpoint: args.s3_endpoint.as_deref(),
        region: &args.s3_region,
        bucket: &args.s3_bucket,
        force_path_style: args.s3_path_style,
    })
    .map_err(|e| CliExit::UserError(format!("invalid --s3-endpoint: {e}")))?;
    Ok(())
}

/// Parse a **non-`prompt`** `--s3-credentials-source` spec into a
/// [`CredentialSource`]. The interactive `prompt` form is handled in
/// [`run_set_sync`] (it needs stdin + the master password) and must not
/// reach here.
///
/// Grammar (plan §6 Q1 — explicit sub-forms, no heuristic sniffing):
/// `iam-role`, `profile:<name>`, `env:<prefix>`. An empty `<name>` /
/// `<prefix>` and any unrecognized spec are rejected as user errors —
/// notably `env:` (empty prefix) is refused because it would read the
/// ambient `AWS_*` variables, the cross-account footgun the per-vault
/// prefix exists to prevent.
///
/// # Errors
///
/// [`CliExit::UserError`] for an empty profile/prefix or an unrecognized
/// spec.
fn credential_source_from_spec(spec: &str) -> Result<CredentialSource, CliExit> {
    if spec == "iam-role" {
        return Ok(CredentialSource::IamInstanceRole {
            imds_endpoint: None,
        });
    }
    if let Some(profile) = spec.strip_prefix("profile:") {
        if profile.trim().is_empty() {
            return Err(CliExit::UserError(
                "`--s3-credentials-source profile:<name>` requires a non-empty profile name"
                    .to_string(),
            ));
        }
        return Ok(CredentialSource::AwsProfile {
            profile: profile.to_string(),
            credentials_file: None,
        });
    }
    if let Some(prefix) = spec.strip_prefix("env:") {
        if prefix.trim().is_empty() {
            return Err(CliExit::UserError(
                "`--s3-credentials-source env:<prefix>` requires a non-empty prefix; an empty \
                 prefix would read the ambient AWS_* variables (the cross-account footgun the \
                 per-vault prefix prevents)"
                    .to_string(),
            ));
        }
        return Ok(CredentialSource::EnvVars {
            prefix: prefix.to_string(),
        });
    }
    Err(CliExit::UserError(format!(
        "unrecognized --s3-credentials-source `{spec}` \
         (expected `prompt`, `iam-role`, `profile:<name>`, or `env:<prefix>`)"
    )))
}

/// Structural kind tag for a [`CredentialSource`], for the secret-free
/// output view. Never returns any credential value (access-key-id,
/// profile name, env prefix, or the sealed secret).
fn credentials_source_tag(source: &CredentialSource) -> &'static str {
    match source {
        CredentialSource::RstCred1 { .. } => "prompt",
        CredentialSource::AwsProfile { .. } => "aws-profile",
        CredentialSource::EnvVars { .. } => "env-vars",
        CredentialSource::IamInstanceRole { .. } => "iam-role",
        // `CredentialSource` is `#[non_exhaustive]`; a future variant
        // (e.g. an OS keychain) tags as "other" until wired explicitly.
        _ => "other",
    }
}

// ---------------------------------------------------------------------------
// vault set-lock
// ---------------------------------------------------------------------------

fn run_set_lock(cli: &Cli, args: &VaultSetLockArgs) -> Result<(), CliExit> {
    // Exactly one of --timeout / --clear is meaningful. clap's
    // `conflicts_with` blocks both being present; we enforce
    // "exactly one" here (neither set is also a user error).
    if args.timeout.is_none() && !args.clear {
        return Err(CliExit::UserError(
            "vault set-lock requires either --timeout <seconds> or --clear".to_string(),
        ));
    }
    if let Some(0) = args.timeout {
        // When security-behaviors lands it owns the canonical
        // validation. Until then, reject 0 at the CLI layer rather
        // than writing an obviously-broken value to the registry.
        return Err(CliExit::UserError(
            "--timeout must be at least 1 second".to_string(),
        ));
    }

    let paths = resolve_paths(cli)?;
    let mut registry = VaultRegistry::load(paths).map_err(CliExit::from)?;

    // The registry's API returns `&RegisteredVault`. We need owning
    // mutation. Take ownership of the vector via `into_records` is not
    // available; instead, re-read by name, mutate a clone, deregister,
    // re-register. That round-trip preserves all `extra` keys.
    let original = registry
        .get(&args.id)
        .ok_or_else(|| {
            CliExit::from(VaultError::NotRegistered {
                name: args.id.clone(),
            })
        })?
        .clone();

    let mut updated = original;
    VaultLockConfig::apply_idle_timeout(&mut updated.extra, args.timeout);

    registry
        .deregister(&args.id, false)
        .map_err(CliExit::from)?;
    registry.register(updated).map_err(CliExit::from)?;
    registry.save().map_err(CliExit::from)?;

    let view = VaultSetLockView {
        id: &args.id,
        idle_timeout_seconds: args.timeout,
    };
    write_success(cli, &view)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- credential_source_from_spec (pure, non-prompt forms) ------------
    //
    // The `prompt` form needs interactive stdin + the master password and
    // is covered end-to-end in `tests/cli_set_sync.rs`; these unit tests
    // pin the parsing of the non-interactive grammar (plan §7.2.2).

    #[test]
    fn credential_spec_iam_role() {
        assert_eq!(
            credential_source_from_spec("iam-role").unwrap(),
            CredentialSource::IamInstanceRole {
                imds_endpoint: None
            }
        );
    }

    #[test]
    fn credential_spec_profile_form() {
        assert_eq!(
            credential_source_from_spec("profile:personal").unwrap(),
            CredentialSource::AwsProfile {
                profile: "personal".to_string(),
                credentials_file: None,
            }
        );
    }

    #[test]
    fn credential_spec_env_form() {
        assert_eq!(
            credential_source_from_spec("env:PERSONAL_").unwrap(),
            CredentialSource::EnvVars {
                prefix: "PERSONAL_".to_string(),
            }
        );
    }

    #[test]
    fn credential_spec_empty_env_prefix_rejected() {
        // `env:` (empty prefix) must fail loudly — an empty prefix would
        // read the ambient AWS_* variables (the cross-account footgun).
        let err = credential_source_from_spec("env:").expect_err("empty env prefix rejected");
        assert_eq!(err.code(), 1);
        assert!(err.message().contains("prefix"), "{}", err.message());
    }

    #[test]
    fn credential_spec_empty_profile_rejected() {
        let err = credential_source_from_spec("profile:").expect_err("empty profile name rejected");
        assert_eq!(err.code(), 1);
        assert!(err.message().contains("profile"), "{}", err.message());
    }

    #[test]
    fn credential_spec_whitespace_profile_rejected() {
        let err = credential_source_from_spec("profile:   ")
            .expect_err("whitespace-only profile name rejected");
        assert_eq!(err.code(), 1);
        assert!(err.message().contains("profile"), "{}", err.message());
    }

    #[test]
    fn credential_spec_whitespace_env_prefix_rejected() {
        let err = credential_source_from_spec("env:   ")
            .expect_err("whitespace-only env prefix rejected");
        assert_eq!(err.code(), 1);
        assert!(err.message().contains("prefix"), "{}", err.message());
    }

    #[test]
    fn credential_spec_unknown_form_rejected() {
        // An unrecognized source must fail loudly, never silently fall
        // back to ambient credentials.
        let err = credential_source_from_spec("garbage").expect_err("unknown spec rejected");
        assert_eq!(err.code(), 1);
        assert!(err.message().contains("garbage"), "{}", err.message());
    }

    #[test]
    fn credential_spec_prompt_is_not_a_pure_form() {
        // `prompt` is handled interactively by the caller; if it ever
        // reaches the pure parser it must be rejected, not silently
        // mishandled.
        assert!(credential_source_from_spec("prompt").is_err());
    }

    // ---- validate_s3_target (empty required flags) -----------------------

    fn valid_set_sync_args() -> VaultSetSyncArgs {
        VaultSetSyncArgs {
            id: "personal".to_string(),
            s3_bucket: "bucket".to_string(),
            s3_key: "key".to_string(),
            s3_endpoint: None,
            s3_region: "us-east-1".to_string(),
            s3_path_style: false,
            s3_credentials_source: "iam-role".to_string(),
        }
    }

    #[test]
    fn validate_s3_target_accepts_valid_args() {
        assert!(validate_s3_target(&valid_set_sync_args()).is_ok());
    }

    #[test]
    fn validate_s3_target_rejects_empty_bucket() {
        let mut args = valid_set_sync_args();
        args.s3_bucket = String::new();
        let err = validate_s3_target(&args).expect_err("empty bucket rejected");
        assert_eq!(err.code(), 1);
        assert!(err.message().contains("--s3-bucket"), "{}", err.message());
    }

    #[test]
    fn validate_s3_target_rejects_whitespace_key() {
        let mut args = valid_set_sync_args();
        args.s3_key = "   ".to_string();
        let err = validate_s3_target(&args).expect_err("whitespace key rejected");
        assert_eq!(err.code(), 1);
        assert!(err.message().contains("--s3-key"), "{}", err.message());
    }

    #[test]
    fn validate_s3_target_rejects_empty_region() {
        let mut args = valid_set_sync_args();
        args.s3_region = String::new();
        assert_eq!(validate_s3_target(&args).unwrap_err().code(), 1);
    }

    #[test]
    fn validate_s3_target_rejects_explicit_empty_endpoint() {
        // An omitted endpoint (None) is fine; an explicit `--s3-endpoint ""`
        // is a user error (the default-endpoint path is the None case).
        let mut args = valid_set_sync_args();
        args.s3_endpoint = Some(String::new());
        let err = validate_s3_target(&args).expect_err("empty endpoint rejected");
        assert_eq!(err.code(), 1);
        assert!(err.message().contains("--s3-endpoint"), "{}", err.message());
    }

    #[test]
    fn validate_s3_target_rejects_malformed_endpoint() {
        let mut args = valid_set_sync_args();
        args.s3_endpoint = Some("minio.internal".to_string());
        let err = validate_s3_target(&args).expect_err("missing scheme rejected");
        assert_eq!(err.code(), 1);
        assert!(err.message().contains("scheme"), "{}", err.message());
    }

    #[test]
    fn validate_s3_target_rejects_endpoint_userinfo() {
        let mut args = valid_set_sync_args();
        args.s3_endpoint = Some("https://user:secret@minio.internal".to_string());
        let err = validate_s3_target(&args).expect_err("userinfo rejected");
        assert_eq!(err.code(), 1);
        assert!(err.message().contains("userinfo"), "{}", err.message());
    }

    // ---- credentials_source_tag (secret-free kind tags) ------------------

    #[test]
    fn credentials_source_tag_maps_each_variant() {
        assert_eq!(
            credentials_source_tag(&CredentialSource::RstCred1 {
                access_key_id: "AKIA".to_string(),
                secret_access_key_encrypted: "sealed".to_string(),
            }),
            "prompt"
        );
        assert_eq!(
            credentials_source_tag(&CredentialSource::AwsProfile {
                profile: "p".to_string(),
                credentials_file: None,
            }),
            "aws-profile"
        );
        assert_eq!(
            credentials_source_tag(&CredentialSource::EnvVars {
                prefix: "P_".to_string(),
            }),
            "env-vars"
        );
        assert_eq!(
            credentials_source_tag(&CredentialSource::IamInstanceRole {
                imds_endpoint: None,
            }),
            "iam-role"
        );
    }
}
