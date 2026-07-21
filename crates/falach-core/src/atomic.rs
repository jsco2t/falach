//! Atomic file-write helpers.
//!
//! Per design §2.2.4 and FR-054 / NFR-006: every on-disk mutation in
//! `falach-core` (KDBX vault saves, `vaults.toml` updates) funnels
//! through this module's [`write_atomic`] function. The algorithm is:
//!
//! 1. Create a sibling temp file in the same parent directory (`mkstemp(3)`
//!    semantics via `tempfile::NamedTempFile`).
//! 2. Write all bytes to the temp file.
//! 3. `fsync` the temp file's data and metadata.
//! 4. Detach from auto-delete (`into_temp_path()`).
//! 5. `rename(2)` (atomic on POSIX same-fs) onto the target path.
//! 6. Open the parent directory and `fsync` it to make the rename durable.
//!
//! On any ordinary error *before* step 5, the temp file is unlinked by
//! `NamedTempFile`'s `Drop`. A process killed by `SIGKILL` cannot run
//! destructors, so a Falach-owned temp file may be left behind; the next
//! atomic write in the same directory removes stale Falach temp files before
//! creating its own temp.
//!
//! Files are created with POSIX mode `0600`.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Write as _};
use std::path::Path;

use tempfile::{Builder as TempFileBuilder, NamedTempFile};

use crate::VaultError;

const TEMP_PREFIX: &str = ".falach-tmp-";

/// Atomically replace the file at `target` with `bytes`.
///
/// See the module-level [`self`] doc for the full algorithm.
///
/// # Errors
///
/// Returns [`VaultError::Io`] if any filesystem operation fails, including:
/// - inability to create a temp file in the parent directory
/// - write failure (disk-full, permission denied)
/// - `rename(2)` failure
/// - parent-directory `fsync` failure
pub fn write_atomic(target: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let parent = target.parent().ok_or_else(|| VaultError::Io {
        source: io::Error::new(
            io::ErrorKind::InvalidInput,
            "target path has no parent directory",
        ),
        path: target.to_path_buf(),
    })?;

    cleanup_stale_temp_files(parent)?;

    // Step 1-2: create temp file in the parent dir and write all bytes.
    //
    // `NamedTempFile::new_in` invokes `mkstemp(3)`, which on Unix creates
    // the file with mode `0600` per the `tempfile` crate's documented
    // guarantee. `persist()` below is a `rename(2)` and preserves those
    // permissions verbatim, so the final target file is also `0600` — no
    // explicit `set_permissions` is needed here.
    let mut temp = new_temp_file(parent)?;
    lock_temp_file(&temp, target)?;

    temp.write_all(bytes).map_err(|source| VaultError::Io {
        source,
        path: target.to_path_buf(),
    })?;

    maybe_signal_fault_phase(target, AtomicWritePhase::TempWritten)?;

    // Step 3: fsync the temp file's data.
    temp.as_file().sync_all().map_err(|source| VaultError::Io {
        source,
        path: target.to_path_buf(),
    })?;

    maybe_signal_fault_phase(target, AtomicWritePhase::FsyncDone)?;

    // Step 4-5: detach and atomically rename onto the target.
    let _persisted = temp.persist(target).map_err(|e| VaultError::Io {
        source: e.error,
        path: target.to_path_buf(),
    })?;

    maybe_signal_fault_phase(target, AtomicWritePhase::RenameDone)?;

    // Step 6: fsync the parent directory to make the rename durable.
    sync_parent_dir(parent).map_err(|source| VaultError::Io {
        source,
        path: parent.to_path_buf(),
    })?;

    Ok(())
}

/// Streaming variant of [`write_atomic`].
///
/// Instead of buffering all bytes in a `&[u8]`, accepts a closure that
/// writes directly into the temp file. This is used by the KDBX save path
/// so the entire encrypted vault never has to live in a single heap buffer.
///
/// The closure receives a mutable reference to the temp file; it should
/// write all desired bytes and return `Ok(())` on success. On error, the
/// temp file is cleaned up automatically.
///
/// # Errors
///
/// Same as [`write_atomic`] — returns [`VaultError::Io`] on any filesystem
/// failure. The `path` field in the error reflects the *target* path.
pub fn write_atomic_with<F>(target: &Path, write: F) -> Result<(), VaultError>
where
    F: FnOnce(&mut File) -> Result<(), VaultError>,
{
    let parent = target.parent().ok_or_else(|| VaultError::Io {
        source: io::Error::new(
            io::ErrorKind::InvalidInput,
            "target path has no parent directory",
        ),
        path: target.to_path_buf(),
    })?;

    cleanup_stale_temp_files(parent)?;

    // Step 1-2: create temp file and delegate to the writer closure.
    let mut temp = new_temp_file(parent)?;
    lock_temp_file(&temp, target)?;

    write(temp.as_file_mut())?;

    maybe_signal_fault_phase(target, AtomicWritePhase::TempWritten)?;

    // Step 3: fsync the temp file's data.
    temp.as_file().sync_all().map_err(|source| VaultError::Io {
        source,
        path: target.to_path_buf(),
    })?;

    maybe_signal_fault_phase(target, AtomicWritePhase::FsyncDone)?;

    // Step 4-5: detach and atomically rename.
    let _persisted = temp.persist(target).map_err(|e| VaultError::Io {
        source: e.error,
        path: target.to_path_buf(),
    })?;

    maybe_signal_fault_phase(target, AtomicWritePhase::RenameDone)?;

    // Step 6: fsync the parent directory.
    sync_parent_dir(parent).map_err(|source| VaultError::Io {
        source,
        path: parent.to_path_buf(),
    })?;

    Ok(())
}

/// Open `parent` and call `sync_all()` on it (fsync the directory).
///
/// This makes renames inside the directory durable across power loss.
/// On APFS / macOS this may be a no-op, but we invoke it unconditionally
/// for POSIX portability and clarity (design §4.5 in implementation-plan).
fn sync_parent_dir(parent: &Path) -> io::Result<()> {
    let dir = File::open(parent)?;
    dir.sync_all()
}

fn new_temp_file(parent: &Path) -> Result<NamedTempFile, VaultError> {
    TempFileBuilder::new()
        .prefix(TEMP_PREFIX)
        .tempfile_in(parent)
        .map_err(|source| VaultError::Io {
            source,
            path: parent.to_path_buf(),
        })
}

fn cleanup_stale_temp_files(parent: &Path) -> Result<(), VaultError> {
    for entry in std::fs::read_dir(parent).map_err(|source| VaultError::Io {
        source,
        path: parent.to_path_buf(),
    })? {
        let entry = entry.map_err(|source| VaultError::Io {
            source,
            path: parent.to_path_buf(),
        })?;
        if !entry.file_name().to_string_lossy().starts_with(TEMP_PREFIX) {
            continue;
        }
        let path = entry.path();
        let file = match OpenOptions::new().read(true).write(true).open(&path) {
            Ok(file) => file,
            Err(source) if source.kind() == io::ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(VaultError::Io { source, path });
            }
        };
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => continue,
            Err(TryLockError::Error(source)) => {
                return Err(VaultError::Io { source, path });
            }
        }
        std::fs::remove_file(&path).map_err(|source| VaultError::Io { source, path })?;
    }
    Ok(())
}

fn lock_temp_file(temp: &NamedTempFile, target: &Path) -> Result<(), VaultError> {
    temp.as_file().try_lock().map_err(|source| match source {
        TryLockError::WouldBlock => VaultError::Io {
            source: io::Error::new(
                io::ErrorKind::WouldBlock,
                "newly-created temp file unexpectedly locked",
            ),
            path: target.to_path_buf(),
        },
        TryLockError::Error(source) => VaultError::Io {
            source,
            path: target.to_path_buf(),
        },
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AtomicWritePhase {
    TempWritten,
    FsyncDone,
    RenameDone,
}

#[cfg(debug_assertions)]
impl AtomicWritePhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::TempWritten => "temp_written",
            Self::FsyncDone => "fsync_done",
            Self::RenameDone => "rename_done",
        }
    }
}

#[cfg(debug_assertions)]
fn maybe_signal_fault_phase(target: &Path, phase: AtomicWritePhase) -> Result<(), VaultError> {
    const TARGET_ENV: &str = "FALACH_ATOMIC_FAULT_TARGET";
    const SIGNAL_DIR_ENV: &str = "FALACH_ATOMIC_FAULT_SIGNAL_DIR";
    const PAUSE_PHASE_ENV: &str = "FALACH_ATOMIC_FAULT_PAUSE_PHASE";

    let Ok(expected_target) = std::env::var(TARGET_ENV) else {
        return Ok(());
    };

    if target != Path::new(&expected_target) {
        return Ok(());
    }

    if let Ok(signal_dir) = std::env::var(SIGNAL_DIR_ENV) {
        let signal_path = Path::new(&signal_dir).join(phase.as_str());
        std::fs::write(&signal_path, phase.as_str()).map_err(|source| VaultError::Io {
            source,
            path: signal_path,
        })?;
    }

    if std::env::var(PAUSE_PHASE_ENV).as_deref() == Ok(phase.as_str()) {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    Ok(())
}

#[cfg(not(debug_assertions))]
fn maybe_signal_fault_phase(_target: &Path, _phase: AtomicWritePhase) -> Result<(), VaultError> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, set_permissions, Permissions};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn write_atomic_creates_new_file_with_mode_0600() {
        let dir = tempfile::TempDir::new().expect("create tempdir");
        let target = dir.path().join("new_file.bin");

        write_atomic(&target, b"hello").expect("write_atomic succeeded");

        assert!(target.exists());
        assert_eq!(read_bytes(&target), b"hello");

        #[cfg(unix)]
        {
            let metadata = target.metadata().expect("stat the file");
            let mode = metadata.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "file mode should be 0600, got {mode:#o}");
        }
    }

    #[test]
    fn write_atomic_replaces_existing_file() {
        let dir = tempfile::TempDir::new().expect("create tempdir");
        let target = dir.path().join("replace.bin");

        // Write initial content.
        fs::write(&target, b"old data").expect("initial write");
        assert_eq!(read_bytes(&target), b"old data");

        // Atomic replace.
        write_atomic(&target, b"new data").expect("write_atomic succeeded");

        assert_eq!(read_bytes(&target), b"new data");
    }

    #[test]
    fn write_atomic_leaves_target_intact_on_pre_rename_failure() {
        let dir = tempfile::TempDir::new().expect("create tempdir");
        let target = dir.path().join("stable.bin");

        // Write initial content.
        fs::write(&target, b"original").expect("initial write");

        // Make the parent directory read-only so the temp file can be created
        // but persist() (rename) will fail.
        let old_perm = dir.path().metadata().unwrap().permissions().mode() & 0o777;
        set_permissions(dir.path(), Permissions::from_mode(0o500)).expect("chmod parent read-only");

        // The write should fail.
        let result = write_atomic(&target, b"overwritten");
        assert!(
            result.is_err(),
            "write_atomic should fail on read-only parent"
        );

        // Restore permissions so TempDir can clean up.
        set_permissions(dir.path(), Permissions::from_mode(old_perm)).expect("restore permissions");

        // The target must still be byte-identical to its original content.
        assert_eq!(read_bytes(&target), b"original");
    }

    #[test]
    fn write_atomic_cleans_up_temp_on_failure() {
        let dir = tempfile::TempDir::new().expect("create tempdir");

        // Make the parent directory read-only — prevents persist/rename.
        let old_perm = dir.path().metadata().unwrap().permissions().mode() & 0o777;
        set_permissions(dir.path(), Permissions::from_mode(0o500)).expect("chmod parent read-only");

        // Attempt a write that will fail during persist.
        let target = dir.path().join("should_fail.bin");
        let _ = write_atomic(&target, b"nope");

        // Restore permissions for cleanup.
        set_permissions(dir.path(), Permissions::from_mode(old_perm)).expect("restore permissions");

        // No orphan .tmp* files should remain in the parent dir.
        let orphans: Vec<_> = fs::read_dir(dir.path())
            .expect("read tempdir")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp"))
            .collect();
        assert!(
            orphans.is_empty(),
            "orphan temp files found: {:?}",
            orphans
                .iter()
                .map(std::fs::DirEntry::file_name)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn write_atomic_writes_zero_bytes_correctly() {
        let dir = tempfile::TempDir::new().expect("create tempdir");
        let target = dir.path().join("empty.bin");

        write_atomic(&target, &[]).expect("write_atomic with empty slice succeeded");

        assert!(target.exists());
        assert_eq!(fs::metadata(&target).unwrap().len(), 0);
    }

    #[test]
    fn write_atomic_writes_large_buffer_correctly() {
        let dir = tempfile::TempDir::new().expect("create tempdir");
        let target = dir.path().join("large.bin");

        // 10 MiB — typical for KDBX files with attachments.
        let data: Vec<u8> = (0_u32..10 * 1024 * 1024)
            .map(|i| u8::try_from(i & 0xff).expect("i & 0xff fits in u8"))
            .collect();

        write_atomic(&target, &data).expect("write_atomic large buffer succeeded");

        let written = fs::read(&target).expect("read target after atomic write");
        assert_eq!(written.len(), data.len());
        assert_eq!(written, data);
    }

    #[test]
    fn write_atomic_with_streaming_path_writes_bytes() {
        let dir = tempfile::TempDir::new().expect("create tempdir");
        let target = dir.path().join("streaming.bin");

        let data = b"streaming test content";

        write_atomic_with(&target, |f| {
            f.write_all(data).map_err(|source| VaultError::Io {
                source,
                path: target.clone(),
            })
        })
        .expect("write_atomic_with succeeded");

        assert_eq!(read_bytes(&target), data);
    }

    #[test]
    fn write_atomic_streaming_parity() {
        // Confirm that write_atomic_with produces the same result as
        // write_atomic for an identical byte payload.
        let dir = tempfile::TempDir::new().expect("create tempdir");
        let target_buf = dir.path().join("buffered.bin");
        let target_stream = dir.path().join("streaming.bin");

        let data: Vec<u8> = (0_u32..4096)
            .map(|i| u8::try_from(i & 0xff).expect("i & 0xff fits in u8"))
            .collect();

        write_atomic(&target_buf, &data).expect("buffered write succeeded");
        write_atomic_with(&target_stream, |f| {
            f.write_all(&data).map_err(|source| VaultError::Io {
                source,
                path: target_stream.clone(),
            })
        })
        .expect("streaming write succeeded");

        assert_eq!(
            fs::read(&target_buf).unwrap(),
            fs::read(&target_stream).unwrap()
        );
    }

    #[test]
    fn write_atomic_target_in_nonexistent_parent_dir_errors() {
        let dir = tempfile::TempDir::new().expect("create tempdir");
        // Use a path whose parent does not exist.
        let target = dir
            .path()
            .join("nonexistent")
            .join("subdir")
            .join("file.bin");

        let result = write_atomic(&target, b"data");
        assert!(
            result.is_err(),
            "write_atomic should fail on missing parent dir"
        );
    }

    fn read_bytes(path: &Path) -> Vec<u8> {
        fs::read(path).expect("read file")
    }
}
