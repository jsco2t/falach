//! Advisory file locking — exclusive and shared locks via `std::fs::File`.
//!
//! Per design §2.2.5 and NFR-007: every vault access acquires an advisory
//! lock so that concurrent Falach processes never corrupt a vault file.
//! Writes take an exclusive lock; reads take a shared lock. Locks are held
//! on a stable sibling sidecar file (`<vault>.lock`), not the KDBX file
//! itself, because saves atomically rename a replacement over the vault path.
//! Locking the vault inode directly would silently stop protecting the new
//! file after a successful rename. The lock is released automatically when
//! the guard value is dropped (RAII).
//!
//! ## Implementation: `std::fs::File`
//!
//! Stabilized in Rust 1.89 (`std::fs::File::{lock, lock_shared, try_lock,
//! try_lock_shared, unlock}` + [`std::fs::TryLockError`]). Internally uses
//! `flock(2)` on Unix and `LockFileEx` on Windows — identical syscalls to
//! the previous `fs2` dependency on macOS/Linux. The std API is preferred
//! because [`std::fs::TryLockError`] has a dedicated `WouldBlock` variant,
//! making contention structurally distinct from generic I/O errors (notably
//! `Interrupted`/EINTR, which we'd otherwise have to disambiguate by
//! `ErrorKind` matching).
//!
//! This is a deviation from design §3.3, which selected `fs2` — recorded
//! there as superseded once Rust 1.89 made the dep unnecessary.
//!
//! ## NFS caveat
//!
//! Advisory locks over NFS and SMB are unreliable — the underlying
//! `flock(2)` semantics differ from local filesystems on those mounts.
//! If a user places their vault on an NFS mount, locking is best-effort
//! only. This is the documented limitation referenced in US-055 AC #3.

use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};

use crate::VaultError;

/// An exclusive (write) advisory lock on a vault's sidecar lock file.
///
/// Acquired via [`acquire_exclusive`]. The lock is released when this value is
/// dropped, which also closes the underlying file handle.
#[derive(Debug)]
pub struct ExclusiveLock {
    file: File,
}

/// A shared (read) advisory lock on a vault's sidecar lock file.
///
/// Acquired via [`acquire_shared`]. The lock is released when this value is
/// dropped, which also closes the underlying file handle.
#[derive(Debug)]
pub struct SharedLock {
    file: File,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Open `path`'s sidecar lock file and acquire an exclusive advisory lock.
///
/// Returns [`VaultError::Contended`] if another process holds a
/// conflicting lock.
///
/// # Platform notes
///
/// Uses [`std::fs::File::try_lock`] under the hood, which maps to
/// `flock(2)` on macOS / Linux and `LockFileEx` on Windows. The lock is
/// released when this value is dropped (closing the file).
pub fn acquire_exclusive(path: &Path) -> Result<ExclusiveLock, VaultError> {
    let lock_path = sidecar_lock_path(path);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|source| VaultError::Io {
            source,
            path: lock_path.clone(),
        })?;

    try_acquire_with_eintr_retry(&file, LockKind::Exclusive)
        .map_err(|kind| kind.into_vault_error(path))?;

    Ok(ExclusiveLock { file })
}

/// Open `path`'s sidecar lock file and acquire a shared advisory lock.
///
/// Returns [`VaultError::Contended`] if another process holds an
/// exclusive lock.
///
/// # Platform notes
///
/// Uses [`std::fs::File::try_lock_shared`] under the hood. Multiple
/// shared locks may coexist on the same file. The lock is released when
/// this value is dropped (closing the file).
pub fn acquire_shared(path: &Path) -> Result<SharedLock, VaultError> {
    let lock_path = sidecar_lock_path(path);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|source| VaultError::Io {
            source,
            path: lock_path.clone(),
        })?;

    try_acquire_with_eintr_retry(&file, LockKind::Shared)
        .map_err(|kind| kind.into_vault_error(path))?;

    Ok(SharedLock { file })
}

/// Return a reference to the underlying file handle.
impl ExclusiveLock {
    /// Return the underlying locked file handle.
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Return a mutable reference to the underlying file handle.
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
}

impl SharedLock {
    /// Return the underlying locked file handle.
    pub fn file(&self) -> &File {
        &self.file
    }
}

// ---------------------------------------------------------------------------
// Lock release
//
// Two paths release the lock:
//
// 1. Normal drop of the guard value — our explicit `Drop` impls below
//    call `File::unlock` synchronously before the inner `File` is
//    dropped (and the FD closed). This is the well-defined, predictable
//    path.
//
// 2. Process death (or any case where `Drop` doesn't run, e.g.
//    `SIGKILL`) — the kernel cleans up the FD on process exit, and
//    closing the last FD referencing an open file description releases
//    every `flock(2)` held on it. This is what US-055 AC #2
//    ("stale-lock detection") relies on.
//
// **Why an explicit Drop and not just-rely-on-FD-close?**
//
// In principle path (2) alone would suffice — `close(fd)` is documented
// to release any flock held on that FD. In practice, under heavy
// parallel-test load on macOS APFS we observed
// `exclusive_lock_blocks_second_exclusive_in_same_process` flaking
// ~30% of runs: a fresh `try_lock` immediately after `drop(prev_lock)`
// would see `WouldBlock`, indicating the kernel had not yet processed
// the lock release. Calling `File::unlock` synchronously before the
// FD drop is a direct syscall and is observed to be reliable.
//
// `File::unlock` errors are intentionally swallowed — if it fails for
// any reason, the subsequent FD close still releases the lock as a
// fallback. The contract is "released by the time Drop returns," not
// "released by the unlock call specifically."
// ---------------------------------------------------------------------------

impl Drop for ExclusiveLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl Drop for SharedLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

// ---------------------------------------------------------------------------
// Lock-acquire helper
// ---------------------------------------------------------------------------

/// Which non-blocking std lock method to call.
#[derive(Clone, Copy)]
enum LockKind {
    Exclusive,
    Shared,
}

/// Outcome of a failed [`try_acquire_with_eintr_retry`] call. Constructed
/// only by the helper; carries enough info to map to the right
/// [`VaultError`] variant once the caller adds the path.
enum AcquireError {
    Contended,
    Io(io::Error),
}

impl AcquireError {
    fn into_vault_error(self, path: &Path) -> VaultError {
        match self {
            Self::Contended => VaultError::Contended { holder: None },
            Self::Io(source) => VaultError::Io {
                source,
                path: path.to_path_buf(),
            },
        }
    }
}

/// Call [`std::fs::File::try_lock`] / [`std::fs::File::try_lock_shared`]
/// and translate the result into [`AcquireError`].
///
/// The std API returns [`TryLockError`] with two structurally distinct
/// variants — `WouldBlock` (contention) and `Error(io::Error)` (genuine
/// I/O failure). Contention is therefore a *type* distinction, not a
/// `ErrorKind` discriminator, so EINTR can never be confused for
/// contention.
///
/// We still retry on `ErrorKind::Interrupted` for defensive correctness:
/// non-blocking `flock(2)` is not supposed to return EINTR on
/// Linux/macOS, but it can if a signal arrives during the syscall
/// entry/exit. Observed historically in `cargo test`'s parallel runner
/// when SIGCHLD from sibling subprocess tests landed during an
/// otherwise-non-blocking call. Retrying is the standard POSIX idiom.
fn try_acquire_with_eintr_retry(file: &File, kind: LockKind) -> Result<(), AcquireError> {
    loop {
        let result = match kind {
            LockKind::Exclusive => file.try_lock(),
            LockKind::Shared => file.try_lock_shared(),
        };
        match result {
            Ok(()) => return Ok(()),
            Err(TryLockError::WouldBlock) => return Err(AcquireError::Contended),
            Err(TryLockError::Error(e)) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(TryLockError::Error(e)) => return Err(AcquireError::Io(e)),
        }
    }
}

fn sidecar_lock_path(path: &Path) -> PathBuf {
    let mut lock_path = path.as_os_str().to_owned();
    lock_path.push(".lock");
    PathBuf::from(lock_path)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::{Child, Command};
    use tempfile::TempDir;

    /// Returns the path to the `lock_holder` binary.
    ///
    /// Resolution strategies, in order:
    /// 1. `CARGO_BIN_EXE_lock_holder` — set by Cargo for integration tests
    ///    (files under `tests/`). Not set for unit tests inside `src/`.
    /// 2. `<workspace>/target/{debug,release}/lock_holder` — resolved
    ///    from `CARGO_MANIFEST_DIR` (always set during compilation).
    ///    Two levels up from the crate dir reaches the workspace root.
    /// 3. `$CARGO_TARGET_DIR/{debug,release}/lock_holder` — honors the
    ///    user's custom target dir if set.
    ///
    /// If none of these resolve to an existing file, **panic with a
    /// diagnostic that lists every candidate tried** — silently
    /// returning a bare `"lock_holder"` would defer the failure to
    /// `Command::spawn` and produce a confusing "No such file or
    /// directory" error.
    fn lock_holder_path() -> std::path::PathBuf {
        // Strategy 1: CARGO_BIN_EXE_lock_holder.
        if let Ok(path) = std::env::var("CARGO_BIN_EXE_lock_holder") {
            return std::path::PathBuf::from(path);
        }

        let mut tried: Vec<std::path::PathBuf> = Vec::new();

        // Strategy 2: <workspace>/target/{debug,release}/lock_holder
        // (resolved relative to CARGO_MANIFEST_DIR).
        if let Some(manifest_dir) = option_env!("CARGO_MANIFEST_DIR") {
            let workspace_root = std::path::PathBuf::from(manifest_dir)
                .parent() // crates/
                .and_then(|p| p.parent()) // <workspace>/
                .map(std::path::Path::to_path_buf);
            if let Some(root) = workspace_root {
                for profile in ["debug", "release"] {
                    let candidate = root.join("target").join(profile).join("lock_holder");
                    if candidate.exists() {
                        return candidate;
                    }
                    tried.push(candidate);
                }
            }
        }

        // Strategy 3: $CARGO_TARGET_DIR/{debug,release}/lock_holder.
        let target = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());
        for profile in ["debug", "release"] {
            let candidate = std::path::PathBuf::from(&target)
                .join(profile)
                .join("lock_holder");
            if candidate.exists() {
                return candidate;
            }
            tried.push(candidate);
        }

        // Nothing found — fail loudly rather than producing a downstream
        // spawn error that hides the real cause.
        let tried_list = tried
            .iter()
            .map(|p| format!("    {}", p.display()))
            .collect::<Vec<_>>()
            .join("\n");
        panic!(
            "lock_holder binary not found. Searched:\n  \
             1. $CARGO_BIN_EXE_lock_holder — unset (only set for integration tests in tests/)\n  \
             2/3. Workspace + custom target paths:\n{tried_list}\n\
             To fix: run via `cargo test` (which auto-builds the [[bin]]), or build \
             explicitly with `cargo build --bin lock_holder` before running this test."
        );
    }

    // -------------------------------------------------------------------
    // Same-process tests (single-threaded — cheap, high-value).
    // -------------------------------------------------------------------

    #[test]
    fn exclusive_lock_blocks_second_exclusive_in_same_process() {
        let dir = tempfile::TempDir::new().expect("create tempdir");
        let path = dir.path().join("exclusive_test.kdbx");
        fs::write(&path, b"placeholder").expect("write placeholder");

        let lock1 = acquire_exclusive(&path).expect("first exclusive lock succeeded");
        let result = acquire_exclusive(&path);
        assert!(
            result.is_err(),
            "second exclusive lock should fail when first is held in same process"
        );
        if let Err(VaultError::Contended { holder }) = result {
            assert!(holder.is_none(), "holder PID should be None on macOS");
        } else {
            panic!("expected Contended error, got {result:?}");
        }

        // lock1 is still valid.
        drop(lock1);

        // After dropping the first lock, a new exclusive lock should succeed.
        acquire_exclusive(&path).expect("exclusive lock after drop succeeded");
    }

    #[test]
    fn shared_lock_permits_second_shared() {
        let dir = tempfile::TempDir::new().expect("create tempdir");
        let path = dir.path().join("shared_test.kdbx");
        fs::write(&path, b"placeholder").expect("write placeholder");

        let _lock1 = acquire_shared(&path).expect("first shared lock succeeded");
        let _lock2 = acquire_shared(&path).expect("second shared lock succeeded");
    }

    #[test]
    fn shared_lock_blocks_exclusive() {
        let dir = tempfile::TempDir::new().expect("create tempdir");
        let path = dir.path().join("shared_blocks_exclusive.kdbx");
        fs::write(&path, b"placeholder").expect("write placeholder");

        let _shared = acquire_shared(&path).expect("shared lock succeeded");
        let result = acquire_exclusive(&path);
        assert!(
            result.is_err(),
            "exclusive lock should fail when shared lock is held"
        );
        assert!(
            matches!(result, Err(VaultError::Contended { .. })),
            "expected Contended error, got {result:?}"
        );
    }

    #[test]
    fn lock_released_on_drop() {
        let dir = tempfile::TempDir::new().expect("create tempdir");
        let path = dir.path().join("drop_release.kdbx");
        fs::write(&path, b"placeholder").expect("write placeholder");

        {
            let _lock = acquire_exclusive(&path).expect("exclusive lock succeeded");
            // Lock is held inside the block.
        }
        // Lock has been dropped — a new exclusive lock should succeed.
        acquire_exclusive(&path).expect("exclusive lock after drop succeeded");
    }

    // -------------------------------------------------------------------
    // Cross-process tests (require `lock_holder` binary).
    // -------------------------------------------------------------------

    /// Spawn `lock_holder` holding an exclusive lock, then try to acquire from
    /// the parent process. The readiness signal file ensures we don't race
    /// before the subprocess has acquired its lock.
    struct ChildGuard {
        child: Child,
    }

    impl ChildGuard {
        fn new(child: Child) -> Self {
            Self { child }
        }

        fn kill_and_wait(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            self.kill_and_wait();
        }
    }

    fn spawn_exclusive_holder(dir: &TempDir) -> (ChildGuard, std::path::PathBuf) {
        let vault_path = dir.path().join("cross_exclusive.kdbx");
        fs::write(&vault_path, b"placeholder").expect("write placeholder");

        let signal_path = dir.path().join("exclusive_signal");
        if signal_path.exists() {
            fs::remove_file(&signal_path).expect("clean stale signal");
        }

        let child = Command::new(lock_holder_path())
            .arg("--exclusive")
            .arg(vault_path.to_str().unwrap())
            .arg(signal_path.to_str().unwrap())
            .spawn()
            .expect("spawn lock_holder");
        let guard = ChildGuard::new(child);

        // Poll for the readiness signal (no sleeps).
        poll_for_file(&signal_path, 5_000)
            .unwrap_or_else(|_| panic!("lock_holder did not signal within timeout"));

        (guard, vault_path)
    }

    /// Spawn `lock_holder` holding a shared lock.
    fn spawn_shared_holder(dir: &TempDir) -> (ChildGuard, std::path::PathBuf) {
        let vault_path = dir.path().join("cross_shared.kdbx");
        fs::write(&vault_path, b"placeholder").expect("write placeholder");

        let signal_path = dir.path().join("shared_signal");
        if signal_path.exists() {
            fs::remove_file(&signal_path).expect("clean stale signal");
        }

        let child = Command::new(lock_holder_path())
            .arg("--shared")
            .arg(vault_path.to_str().unwrap())
            .arg(signal_path.to_str().unwrap())
            .spawn()
            .expect("spawn lock_holder");
        let guard = ChildGuard::new(child);

        poll_for_file(&signal_path, 5_000)
            .unwrap_or_else(|_| panic!("lock_holder did not signal within timeout"));

        (guard, vault_path)
    }

    /// Poll for a file's existence with a short busy-wait loop. Times out
    /// after `max_ms` milliseconds, returning an error if the file never appears.
    fn poll_for_file(path: &Path, max_ms: u64) -> io::Result<()> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(max_ms);
        while std::time::Instant::now() < deadline {
            if path.exists() {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("signal file not created within {max_ms}ms"),
        ))
    }

    #[test]
    fn exclusive_lock_blocks_second_exclusive_across_processes() {
        let dir = tempfile::TempDir::new().expect("create tempdir");
        let (_child, vault_path) = spawn_exclusive_holder(&dir);

        // The subprocess holds an exclusive lock — our attempt should fail.
        let result = acquire_exclusive(&vault_path);
        assert!(
            result.is_err(),
            "cross-process: exclusive lock should be contended"
        );
        assert!(
            matches!(result, Err(VaultError::Contended { .. })),
            "expected Contended error, got {result:?}"
        );
    }

    #[test]
    fn shared_lock_permits_second_shared_across_processes() {
        let dir = tempfile::TempDir::new().expect("create tempdir");
        let (_child, vault_path) = spawn_shared_holder(&dir);

        // The subprocess holds a shared lock — another shared lock should succeed.
        acquire_shared(&vault_path).expect("cross-process: second shared lock succeeded");
    }

    #[test]
    fn shared_lock_blocks_exclusive_across_processes() {
        let dir = tempfile::TempDir::new().expect("create tempdir");
        let (_child, vault_path) = spawn_shared_holder(&dir);

        // The subprocess holds a shared lock — an exclusive lock should fail.
        let result = acquire_exclusive(&vault_path);
        assert!(
            result.is_err(),
            "cross-process: exclusive lock should be blocked by shared"
        );
        assert!(
            matches!(result, Err(VaultError::Contended { .. })),
            "expected Contended error, got {result:?}"
        );
    }

    #[test]
    fn lock_released_on_process_death() {
        let dir = tempfile::TempDir::new().expect("create tempdir");
        let (mut child, vault_path) = spawn_exclusive_holder(&dir);

        // Kill the subprocess — the kernel should release the flock.
        child.kill_and_wait();

        // A fresh exclusive lock should now succeed.
        acquire_exclusive(&vault_path).expect("exclusive lock acquired after holder process death");
    }
}
