//! Pre-merge `.kdbx.bak` snapshot (design §2.2.10, ADR-5 §6.1 #5).
//!
//! Before any merge work the orchestrator copies the live `.kdbx` to a
//! sibling `.kdbx.bak` via `falach_core::atomic::write_atomic`, so a bad
//! merge is always recoverable (`cp my.kdbx.bak my.kdbx`). The copied
//! bytes are already-encrypted KDBX — no plaintext is involved.
//!
//! The snapshot lives next to the live vault (e.g.
//! `/var/state/work.kdbx` → `/var/state/work.kdbx.bak`). It is
//! intentionally NOT deleted at the end of a successful sync: keeping
//! the most-recent successful pre-merge snapshot around is a cheap
//! belt-and-suspenders against a same-day discovery of a bad merge.

use std::path::{Path, PathBuf};

use falach_core::atomic::write_atomic;

use crate::error::SyncError;

/// Atomically copy `vault_path` to its sibling `*.kdbx.bak`, overwriting
/// any stale backup from a prior interrupted sync. Returns the backup
/// path.
///
/// The atomicity guarantee: callers observe the backup as either fully
/// the new bytes or fully the old bytes — never a partial write. Under
/// the hood [`write_atomic`] writes to a sibling temp file and then
/// renames(2) it into place.
///
/// # Errors
///
/// Returns [`SyncError::BackupFailed`] when reading the source or writing
/// the sibling snapshot fails. Both pre-merge prerequisites have to
/// succeed before the orchestrator's merge proceeds; surfacing the
/// failure directly (rather than swallowing it as "best-effort") matches
/// PRD §11 Risk #5's "no data loss ever" stance.
pub fn snapshot_pre_merge(vault_path: &Path) -> Result<PathBuf, SyncError> {
    let backup_path = backup_path_for(vault_path);

    let bytes = std::fs::read(vault_path).map_err(|source| SyncError::BackupFailed { source })?;

    write_atomic(&backup_path, &bytes).map_err(|err| match err {
        falach_core::VaultError::Io { source, .. } => SyncError::BackupFailed { source },
        other => SyncError::Vault(other),
    })?;

    Ok(backup_path)
}

/// Return the `.kdbx.bak` path for a given vault `.kdbx` path.
///
/// `/x/y/work.kdbx` → `/x/y/work.kdbx.bak`. We append `.bak` to the full
/// filename (NOT replace the extension) so an unusual vault filename
/// like `work-2026-Q1.kdbx` produces `work-2026-Q1.kdbx.bak` rather than
/// silently clobbering a sibling.
#[must_use]
pub fn backup_path_for(vault_path: &Path) -> PathBuf {
    let mut name = vault_path
        .file_name()
        .map(std::ffi::OsString::from)
        .unwrap_or_default();
    name.push(".bak");
    vault_path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn backup_path_appends_bak_to_full_filename() {
        assert_eq!(
            backup_path_for(Path::new("/x/y/work.kdbx")),
            Path::new("/x/y/work.kdbx.bak")
        );
        assert_eq!(
            backup_path_for(Path::new("/x/y/work-2026-Q1.kdbx")),
            Path::new("/x/y/work-2026-Q1.kdbx.bak")
        );
    }

    #[test]
    fn snapshot_copies_bytes_atomically() {
        let tmp = TempDir::new().expect("tempdir");
        let vault = tmp.path().join("v.kdbx");
        std::fs::write(&vault, b"abcdef-encrypted-bytes").expect("seed vault");

        let bak = snapshot_pre_merge(&vault).expect("snapshot ok");
        assert_eq!(bak, vault.with_file_name("v.kdbx.bak"));
        let copied = std::fs::read(&bak).expect("read bak");
        assert_eq!(copied, b"abcdef-encrypted-bytes");
    }

    #[test]
    fn snapshot_overwrites_stale_bak() {
        let tmp = TempDir::new().expect("tempdir");
        let vault = tmp.path().join("v.kdbx");
        std::fs::write(&vault, b"new-bytes").expect("seed vault");
        // Existing .bak with old content.
        let bak = vault.with_file_name("v.kdbx.bak");
        std::fs::write(&bak, b"OLD-stale").expect("seed stale bak");

        snapshot_pre_merge(&vault).expect("snapshot ok");
        let copied = std::fs::read(&bak).expect("read bak");
        assert_eq!(copied, b"new-bytes", "stale bak overwritten");
    }

    #[test]
    fn snapshot_returns_backup_failed_when_source_missing() {
        let tmp = TempDir::new().expect("tempdir");
        let nope = tmp.path().join("does-not-exist.kdbx");
        let err = snapshot_pre_merge(&nope).expect_err("missing source must fail");
        assert!(matches!(err, SyncError::BackupFailed { .. }));
    }
}
