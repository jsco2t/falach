//! `falach sync` — configure-remote-aware sync of a registered vault
//! (features/cli-sync-wiring/ Phase 3).
//!
//! Resolves the target vault (`--vault`, or the sole registered vault),
//! unlocks it via the secure master-password prompt, runs
//! [`falach_sync::Sync::sync_now`], renders the [`falach_sync::SyncOutcome`] as a
//! [`SyncView`], and maps any [`falach_sync::SyncError`] onto the stable
//! exit-code contract.
//!
//! ## Output channels
//!
//! `--format json` writes the `SyncView` JSON to **stdout** (the stable
//! machine-readable contract). Human mode writes the one-line summary to
//! **stderr**, keeping stdout clean for scripts that only care about the
//! exit code (design §3.6 / task AC).

use std::io::Write as _;
use std::time::Instant;

use falach_core::{Keyfile, Vault, VaultError, VaultRegistry};
use falach_sync::sync::format_outcome;
use falach_sync::{Sync, SyncOptions};

use crate::agent::NoAgentClient;
use crate::cli::{Cli, OutputFormat, SyncArgs};
use crate::commands::{resolve_paths, write_json_success};
use crate::exit::CliExit;
use crate::prompt::{master_password, PromptOpts};
use crate::views::sync::SyncView;

/// Sync a registered vault against its configured S3 remote.
///
/// # Errors
///
/// - [`CliExit::UserError`] (1) — no/ambiguous vault, unknown vault, or a
///   sync that is not configured (`SyncError::NotConfigured`).
/// - [`CliExit::VaultLocked`] (2) — wrong master password at unlock.
/// - [`CliExit::SyncConflict`] (3) — an unresolvable same-second merge.
/// - [`CliExit::Internal`] (10+) — transport / S3 / backup failures.
pub fn run(cli: &Cli, args: &SyncArgs) -> Result<(), CliExit> {
    let paths = resolve_paths(cli)?;
    let mut registry = VaultRegistry::load(paths).map_err(CliExit::from)?;

    let vault_name = resolve_vault_name(&registry, args.vault.as_deref())?;
    let record = registry
        .get(&vault_name)
        .ok_or_else(|| {
            CliExit::from(VaultError::NotRegistered {
                name: vault_name.clone(),
            })
        })?
        .clone();

    // Unlock first: a wrong master password short-circuits here as exit 2,
    // before any network call.
    let agent = NoAgentClient;
    let opts = PromptOpts {
        vault: &vault_name,
        agent: &agent,
        prompt_label: "Master password: ",
    };
    let master = master_password(&opts)?;
    let keyfile = record.keyfile_path.clone().map(Keyfile::Path);
    let mut vault = Vault::open(&record.path, &master, keyfile.as_ref()).map_err(CliExit::from)?;

    let started = Instant::now();
    let outcome = Sync::sync_now(
        &mut vault,
        &vault_name,
        &mut registry,
        &master,
        keyfile.as_ref(),
        SyncOptions::default(),
    )
    .map_err(|e| attach_vault_name(CliExit::from(e), &vault_name))?;
    let elapsed = started.elapsed();

    let view = SyncView::from(&outcome);

    // JSON → stdout (machine contract). Human → stderr (stdout stays clean).
    if matches!(cli.format, OutputFormat::Json) {
        return write_json_success(&view);
    }
    let mut stderr = std::io::stderr().lock();
    writeln!(stderr, "{}", format_outcome(&outcome, elapsed))
        .map_err(|e| CliExit::Internal(format!("failed to write output: {e}")))
}

/// Resolve which vault to sync: an explicit `--vault <name>`, or — when the
/// flag is omitted — the sole registered vault. Zero or multiple registered
/// vaults with no `--vault` is a user error.
fn resolve_vault_name(
    registry: &VaultRegistry,
    requested: Option<&str>,
) -> Result<String, CliExit> {
    if let Some(name) = requested {
        return Ok(name.to_string());
    }
    let mut names = registry.list().map(|r| r.name.clone());
    match (names.next(), names.next()) {
        (None, _) => Err(CliExit::UserError(
            "no vaults registered; run `falach vault create ...` first".to_string(),
        )),
        (Some(only), None) => Ok(only),
        (Some(_), Some(_)) => Err(CliExit::UserError(
            "multiple vaults registered; specify which to sync with --vault <name>".to_string(),
        )),
    }
}

/// The `From<SyncError>` conversion cannot know the vault name
/// (`SyncError::Unresolvable` does not carry it), so a conflict arrives with
/// an empty `SyncConflict.vault`. Fill it in here, at the command boundary
/// where we do know it, so the exit-3 diagnostic names the vault.
fn attach_vault_name(mut exit: CliExit, vault_name: &str) -> CliExit {
    if let CliExit::SyncConflict { vault, .. } = &mut exit {
        if vault.is_empty() {
            *vault = vault_name.to_string();
        }
    }
    exit
}

#[cfg(test)]
mod tests {
    use super::*;
    use falach_core::{
        FalachPaths, KdfParams, MasterPassword, NoRecoveryConfirmed, RegisteredVault,
    };
    use tempfile::TempDir;

    fn fast_kdf() -> KdfParams {
        KdfParams {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        }
    }

    /// A registry in a tempdir with `names` registered (each backed by a
    /// throwaway KDBX so `get(...).path` is real).
    fn registry_with(names: &[&str]) -> (TempDir, VaultRegistry) {
        let tmp = TempDir::new().expect("tempdir");
        let reg_path = tmp.path().join("vaults.toml");
        let paths = FalachPaths::with_registry_file(reg_path);
        let mut registry = VaultRegistry::load(paths).expect("load");
        for name in names {
            let path = tmp.path().join(format!("{name}.kdbx"));
            drop(
                Vault::create(
                    &path,
                    &MasterPassword::new("pw".to_string()),
                    None,
                    fast_kdf(),
                    NoRecoveryConfirmed::yes(),
                )
                .expect("create"),
            );
            registry
                .register(RegisteredVault {
                    name: (*name).to_string(),
                    path,
                    created_at: "2026-01-01T00:00:00Z".to_string(),
                    keyfile_path: None,
                    extra: toml::Table::new(),
                })
                .expect("register");
        }
        (tmp, registry)
    }

    #[test]
    fn resolve_vault_name_uses_explicit_flag() {
        let (_tmp, reg) = registry_with(&["a", "b"]);
        assert_eq!(resolve_vault_name(&reg, Some("b")).unwrap(), "b");
    }

    #[test]
    fn resolve_vault_name_defaults_to_sole_vault() {
        let (_tmp, reg) = registry_with(&["only"]);
        assert_eq!(resolve_vault_name(&reg, None).unwrap(), "only");
    }

    #[test]
    fn resolve_vault_name_no_vaults_is_user_error() {
        let (_tmp, reg) = registry_with(&[]);
        let err = resolve_vault_name(&reg, None).expect_err("no vaults");
        assert_eq!(err.code(), 1);
        assert!(err.message().contains("no vaults"), "{}", err.message());
    }

    #[test]
    fn resolve_vault_name_multiple_without_flag_is_user_error() {
        let (_tmp, reg) = registry_with(&["a", "b"]);
        let err = resolve_vault_name(&reg, None).expect_err("ambiguous");
        assert_eq!(err.code(), 1);
        assert!(err.message().contains("--vault"), "{}", err.message());
    }

    #[test]
    fn attach_vault_name_fills_empty_conflict_vault() {
        let exit = attach_vault_name(
            CliExit::SyncConflict {
                vault: String::new(),
                detail: "merge cannot proceed".to_string(),
            },
            "personal",
        );
        assert_eq!(exit.code(), 3);
        assert!(exit.message().contains("personal"), "{}", exit.message());
    }

    #[test]
    fn attach_vault_name_preserves_nonempty_conflict_vault() {
        let exit = attach_vault_name(
            CliExit::SyncConflict {
                vault: "already-set".to_string(),
                detail: "d".to_string(),
            },
            "personal",
        );
        assert!(exit.message().contains("already-set"), "{}", exit.message());
        assert!(!exit.message().contains("personal"), "{}", exit.message());
    }

    #[test]
    fn attach_vault_name_ignores_non_conflict_exits() {
        let exit = attach_vault_name(CliExit::UserError("x".to_string()), "personal");
        assert_eq!(exit.code(), 1);
    }
}
