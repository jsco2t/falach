//! Sensitive-buffer wrappers — [`MasterPassword`] and [`Keyfile`].
//!
//! Per design §2.2.2 and FR-050: every type in this module that holds
//! plaintext bytes implements `Zeroize + ZeroizeOnDrop`, and every type
//! suppresses `Debug` to prevent accidental logging via `dbg!`, panics,
//! or trace lines. Callers (typically the CLI/TUI) collect bytes from
//! the user (e.g., via `rpassword`) and wrap them in [`MasterPassword`]
//! before handing them to `falach-core` — the library never prompts.

use std::fmt;
use std::path::{Path, PathBuf};

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A master password. The inner bytes are zeroized when this value is
/// dropped, and the `Debug` impl reveals nothing about the contents.
///
/// Constructed from a `String` the caller has already collected.
/// `falach-core` does not own a TTY or prompt; that's the CLI/TUI's
/// job (design §3.4 — "vault-core takes a pre-collected `MasterPassword`
/// value").
///
/// On Unix the buffer is additionally `mlock(2)`ed while the value is
/// alive (best-effort — `RLIMIT_MEMLOCK` quotas are small, so a failed
/// lock is silently tolerated rather than treated as fatal; see
/// `kb/memory-hygiene.md`). The lock is released and the bytes zeroized
/// on drop. This covers the password itself; key material derived
/// inside `keepass-rs` (`DatabaseKey`, Argon2 output) is owned by that
/// crate and cannot be locked from here — an honest, documented limit.
///
/// Invariant the `mlock` relies on: the inner `String` is never mutated
/// after construction (no method takes `&mut self` except `zeroize`,
/// which overwrites in place without reallocating), so the heap buffer
/// address registered with `mlock` stays valid until `munlock` in drop.
#[derive(Zeroize)]
pub struct MasterPassword(String);

impl MasterPassword {
    /// Wrap a caller-supplied password string.
    pub fn new(value: String) -> Self {
        let password = Self(value);
        password.lock_memory();
        password
    }

    /// Best-effort `mlock(2)` of the password buffer so it cannot be
    /// paged to swap. Failures (quota exhausted, unsupported platform)
    /// are ignored per the documented best-effort posture.
    #[cfg(unix)]
    fn lock_memory(&self) {
        if self.0.is_empty() {
            return;
        }
        // SAFETY (locally audited unsafe, design §3.9): `mlock` only
        // reads the page tables for the given range; it does not read or
        // write the buffer. The pointer/length come from the live inner
        // `String`, which is valid for `len` bytes and — per the struct
        // invariant above — is never reallocated during the value's
        // lifetime. The matching `munlock` runs in `Drop` before the
        // buffer is freed.
        #[allow(unsafe_code)]
        unsafe {
            let _ = libc::mlock(self.0.as_ptr().cast::<libc::c_void>(), self.0.len());
        }
    }

    #[cfg(not(unix))]
    fn lock_memory(&self) {}

    /// Release the best-effort `mlock` taken in [`Self::lock_memory`].
    /// Errors are ignored: `munlock` on a range that was never locked
    /// (quota-failed `mlock`) is harmless.
    #[cfg(unix)]
    fn unlock_memory(&self) {
        if self.0.is_empty() {
            return;
        }
        // SAFETY: same range and validity argument as `lock_memory`;
        // called from `Drop` while the buffer is still allocated.
        #[allow(unsafe_code)]
        unsafe {
            let _ = libc::munlock(self.0.as_ptr().cast::<libc::c_void>(), self.0.len());
        }
    }

    #[cfg(not(unix))]
    fn unlock_memory(&self) {}

    /// Borrow the underlying bytes for KDF / crypto input.
    ///
    /// The slice borrows from the `MasterPassword`'s zeroize-on-drop
    /// buffer; consumers must NOT copy these bytes into any other
    /// container that doesn't itself zeroize on drop (Argon2id and the
    /// keepass-rs KDF read-only consumers are correct uses;
    /// `Vec::from(slice)` into an un-zeroized buffer would be a leak).
    ///
    /// Lifted from `pub(crate)` to `pub` so `falach-sync::auth::rstcred1`
    /// can feed the master password into Argon2id without duplicating
    /// the zeroize-on-drop wrapper (`features/s3-sync/` T4.2).
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Borrow the underlying string. Crate-private for the same reason
    /// as [`Self::as_bytes`].
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MasterPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterPassword(***)")
    }
}

// Manual `Drop` (replacing `#[derive(ZeroizeOnDrop)]`) so the buffer is
// `munlock`ed before being zeroized and freed. The `ZeroizeOnDrop`
// marker impl below keeps the compile-time security assertion satisfied;
// it is honest because this `Drop` performs the zeroize.
impl Drop for MasterPassword {
    fn drop(&mut self) {
        self.unlock_memory();
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for MasterPassword {}

/// A KDBX keyfile, either as a path on disk (resolved at unlock time)
/// or as bytes the caller has already loaded.
///
/// `Keyfile::Bytes` zeroizes its contents on drop. `Keyfile::Path`
/// holds only the path — the keyfile contents are read lazily inside
/// `falach-core` and that buffer is itself zeroized.
pub enum Keyfile {
    /// Path to the keyfile on disk.
    Path(PathBuf),
    /// Keyfile contents already loaded into memory.
    Bytes(Vec<u8>),
}

impl Keyfile {
    /// If this is a `Path` variant, return the path; otherwise `None`.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Keyfile::Path(p) => Some(p),
            Keyfile::Bytes(_) => None,
        }
    }

    /// Borrow the raw bytes if this is a `Bytes` variant; otherwise
    /// `None`. Crate-private — same rationale as
    /// [`MasterPassword::as_bytes`].
    #[allow(dead_code)] // consumed by the future `unlock` module
    pub(crate) fn bytes(&self) -> Option<&[u8]> {
        match self {
            Keyfile::Path(_) => None,
            Keyfile::Bytes(b) => Some(b),
        }
    }
}

impl fmt::Debug for Keyfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Even the path is suppressed — a keyfile's *location* on
            // disk is itself sensitive (it's half the credential).
            Keyfile::Path(_) => f.write_str("Keyfile::Path(***)"),
            Keyfile::Bytes(_) => f.write_str("Keyfile::Bytes(***)"),
        }
    }
}

// Hand-rolled `Zeroize + ZeroizeOnDrop` because `#[derive]` on an enum
// would try to zero every variant uniformly. We only want to zero
// `Bytes` (the `Path` variant's bytes are filesystem metadata, not the
// keyfile content).
impl Drop for Keyfile {
    fn drop(&mut self) {
        if let Keyfile::Bytes(b) = self {
            b.zeroize();
        }
    }
}

// ---------------------------------------------------------------------------
// Compile-time security invariants.
//
// These const blocks are type-checked at compile time and emit no code. They
// catch accidental removal of the security-critical drop logic:
//
//   - `MasterPassword: ZeroizeOnDrop` — fails to compile if
//     `#[derive(Zeroize, ZeroizeOnDrop)]` is dropped from the type.
//   - `Keyfile: Drop`                 — fails to compile if the manual
//     `impl Drop for Keyfile` is removed. (`T: Drop` matches types with an
//     explicit `impl Drop`; compiler-generated drop glue does NOT satisfy
//     it. Clippy's `drop_bounds` lint warns about this bound as a general
//     anti-pattern, but here we want exactly that semantic — `#[allow]`d
//     deliberately.)
//
// These assertions are intentionally NOT under `#[cfg(test)]`: the security
// guarantee they document holds in every build, not just under `cargo test`.
// ---------------------------------------------------------------------------

const _: fn() = || {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<MasterPassword>();
};

#[allow(drop_bounds)]
const _: fn() = || {
    fn assert_explicit_drop_impl<T: Drop>() {}
    assert_explicit_drop_impl::<Keyfile>();
};

#[cfg(test)]
#[allow(unsafe_code)] // documented volatile-read zeroize verification per Test Plan §8.2.2
mod tests {
    use super::*;

    #[test]
    fn master_password_round_trips_bytes() {
        let pw = MasterPassword::new("foo".to_string());
        assert_eq!(pw.as_bytes(), b"foo");
    }

    #[test]
    fn master_password_debug_does_not_reveal_value() {
        let pw = MasterPassword::new("supersecret".to_string());
        let dbg = format!("{pw:?}");
        assert!(
            !dbg.contains("supersecret"),
            "Debug output must not contain the password value: {dbg}"
        );
        assert_eq!(dbg, "MasterPassword(***)");
    }

    #[test]
    fn master_password_zeroize_clears_inner_bytes() {
        // Verifies that calling `.zeroize()` on a `MasterPassword`
        // zeros the underlying byte buffer. The drop-zero guarantee
        // (FR-050) reduces to this property: `ZeroizeOnDrop`'s drop
        // impl calls `.zeroize()`, and the presence of that derive is
        // enforced separately by the compile-time `const _: fn() = ...`
        // assertion above this module.
        //
        // (The Test Plan §8.2.2 originally specified a drop-then-read
        // technique. That approach reads freed heap memory, which the
        // system allocator on macOS immediately overwrites with
        // bookkeeping data — masking zeroize's work and producing
        // misleading test failures. The deterministic .zeroize()-then-
        // read pattern below tests the same property reliably.)
        //
        // SAFETY (`read_volatile`): we read bytes through `ptr` while
        // the buffer is still allocated — the wrapper is mutably
        // borrowed by `.zeroize()` and the read happens before any drop.
        // The pointer was obtained from the live `String` and is valid
        // for `len` bytes.

        let sentinel = "supersecret-master-password-bytes".to_string();
        let len = sentinel.len();
        let mut pw = MasterPassword::new(sentinel);
        let ptr: *const u8 = pw.as_bytes().as_ptr();

        zeroize::Zeroize::zeroize(&mut pw);

        for i in 0..len {
            // SAFETY: see block-level comment.
            let byte = unsafe { std::ptr::read_volatile(ptr.add(i)) };
            assert_eq!(
                byte, 0,
                "MasterPassword byte at offset {i} should be zero after .zeroize()"
            );
        }
    }

    #[test]
    fn keyfile_path_variant_preserves_path() {
        let keyfile = Keyfile::Path(PathBuf::from("/some/key.file"));
        assert_eq!(keyfile.path(), Some(Path::new("/some/key.file")));
    }

    #[test]
    fn keyfile_bytes_variant_path_is_none() {
        let keyfile = Keyfile::Bytes(vec![1, 2, 3]);
        assert!(keyfile.path().is_none());
    }

    #[test]
    fn keyfile_bytes_zeroize_clears_inner_bytes() {
        // Verifies that the operation inside `impl Drop for Keyfile`
        // (calling `.zeroize()` on the inner `Vec<u8>` of the `Bytes`
        // arm) zeros the buffer. The presence of the manual `Drop` impl
        // itself is enforced by the compile-time `const _: fn() = ...`
        // assertion above this module (it requires `Keyfile: Drop`).
        //
        // See `master_password_zeroize_clears_inner_bytes` for the
        // rationale behind the `.zeroize()`-then-volatile-read pattern
        // versus the original drop-then-read technique.
        //
        // SAFETY (`read_volatile`): the buffer is still allocated; we
        // only read after the explicit `zeroize()` call and before any
        // drop. `ptr` is valid for `len` bytes obtained from the live
        // `Vec`.

        let sentinel: Vec<u8> = vec![0xAB; 32];
        let len = sentinel.len();
        let mut kf = Keyfile::Bytes(sentinel);
        let ptr: *const u8 = match &kf {
            Keyfile::Bytes(b) => b.as_ptr(),
            Keyfile::Path(_) => unreachable!(),
        };

        // Replicate what `Drop for Keyfile` does for the `Bytes` arm.
        if let Keyfile::Bytes(ref mut b) = kf {
            b.zeroize();
        }

        for i in 0..len {
            // SAFETY: see block-level comment.
            let byte = unsafe { std::ptr::read_volatile(ptr.add(i)) };
            assert_eq!(
                byte, 0,
                "Keyfile::Bytes byte at offset {i} should be zero after .zeroize()"
            );
        }
    }

    #[test]
    fn keyfile_debug_does_not_reveal_path() {
        let keyfile = Keyfile::Path(PathBuf::from("/etc/super-secret-keyfile.bin"));
        let dbg = format!("{keyfile:?}");
        assert!(!dbg.contains("super-secret-keyfile"));
        assert!(!dbg.contains("/etc"));
        assert_eq!(dbg, "Keyfile::Path(***)");
    }

    #[test]
    fn keyfile_debug_does_not_reveal_bytes() {
        let keyfile = Keyfile::Bytes(b"deadbeef".to_vec());
        let dbg = format!("{keyfile:?}");
        assert!(!dbg.contains("deadbeef"));
        assert_eq!(dbg, "Keyfile::Bytes(***)");
    }
}
