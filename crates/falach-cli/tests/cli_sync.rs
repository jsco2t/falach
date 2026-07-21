//! End-to-end `falach sync` error-path tests (non-gated — no `MinIO`).
//!
//! These exercise the short-circuit paths that return **before** any
//! transport call, so they run under `make test`. The happy-path outcomes
//! build a real `S3Transport` from registry config and cannot inject
//! `MemoryTransport` across the spawned-process boundary — those live in the
//! `MinIO`-gated `cli_sync_minio.rs`, while the sync state machine itself is
//! exhaustively covered in `falach-sync` (`tests/us_04*`, `sync.rs` units).
//! Per plan §7.5 the same-second exit-3 conflict is covered deterministically
//! by the `SyncError → CliExit` unit mapping plus the sync crate's
//! `same_second_collision_surfaces_unresolvable_with_backup`, not by a flaky
//! wall-clock race across two spawned processes.

mod common;

use common::{run_with_stdin, seed_vault, VaultsToml};

/// Syncing a vault with no `[vault.sync]` config is a clean user error
/// (exit 1) — the most common mistake. `sync_now` reports `NotConfigured`
/// before building a transport.
#[test]
fn cli_sync_unconfigured_exits_1() {
    let reg = VaultsToml::new();
    seed_vault(&reg, "personal", "master-pw");
    // Unlock succeeds (correct password), then sync_now → NotConfigured → 1.
    let (code, _out, stderr) =
        run_with_stdin(&reg, &["sync", "--vault", "personal"], "master-pw\n");
    assert_eq!(
        code, 1,
        "unconfigured sync should be a user error; stderr: {stderr}"
    );
}

/// A wrong master password short-circuits at unlock (exit 2) before any
/// transport call.
#[test]
fn cli_sync_wrong_master_password_exits_2() {
    let reg = VaultsToml::new();
    seed_vault(&reg, "personal", "correct-master");
    let (code, _out, _err) =
        run_with_stdin(&reg, &["sync", "--vault", "personal"], "WRONG-master\n");
    assert_eq!(code, 2, "wrong master password should exit 2");
}

/// No `--vault` with multiple registered vaults is an ambiguity user error
/// (exit 1), surfaced before any prompt.
#[test]
fn cli_sync_ambiguous_vault_exits_1() {
    let reg = VaultsToml::new();
    seed_vault(&reg, "a", "pw");
    seed_vault(&reg, "b", "pw");
    let (code, _out, stderr) = run_with_stdin(&reg, &["sync"], "");
    assert_eq!(
        code, 1,
        "ambiguous vault (no --vault, >1 registered) should exit 1; stderr: {stderr}"
    );
}

/// Syncing an unregistered vault is a user error (exit 1).
#[test]
fn cli_sync_unknown_vault_exits_1() {
    let reg = VaultsToml::new();
    seed_vault(&reg, "personal", "pw");
    let (code, _out, _err) = run_with_stdin(&reg, &["sync", "--vault", "ghost"], "");
    assert_eq!(code, 1, "unknown vault should exit 1");
}
