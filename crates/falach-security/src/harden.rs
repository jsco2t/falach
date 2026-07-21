//! Process hardening (PMF-2 / FU-CORE-DUMP).
//!
//! Best-effort runtime mitigations applied **once at frontend startup, before
//! any vault is opened**. This module is the home for future process hardening
//! (e.g. `mlock` of the master key); today it suppresses core dumps.
//!
//! ## Audited `unsafe`
//!
//! The crate is `#![cfg_attr(not(test), deny(unsafe_code))]`. This module makes
//! one libc syscall (`setrlimit`) inside a single locally-`#[allow]`ed,
//! documented block — the same posture the crate reserves for `os_events::macos`
//! (and `falach-core` for its `mlock` block).

/// Apply best-effort process hardening. Call **once** at frontend startup,
/// before any vault is opened.
///
/// Today this suppresses core dumps by setting `RLIMIT_CORE` to zero: CLAUDE.md
/// (Security rules) requires it for the TUI/agent, because a core dump of the
/// live process can spill the unlocked vault and master key to disk.
///
/// Best-effort by design — a failure to set the limit cannot be meaningfully
/// recovered and must never abort startup, so the result is intentionally
/// ignored (there is no logging facility to route it to; project "no telemetry"
/// rule). On the Phase-0 targets (macOS, Linux) the syscall succeeds; the
/// `getrlimit`-readback unit test asserts the effect.
///
/// ## Honest limits (CLAUDE.md principle #5)
///
/// - Does **not** defend against a privileged attacker that re-raises the limit.
/// - `SIGKILL`, swap, and cold-boot / DMA attacks are out of scope.
/// - Not async-signal-safe; do not call from a signal handler.
/// - On non-Unix targets (never a Phase-0 ship target, but present in the
///   resolver's transitive triples) this is a no-op.
pub fn harden_process() {
    #[cfg(unix)]
    suppress_core_dumps();
}

/// Set the soft and hard `RLIMIT_CORE` to zero so the kernel never writes a
/// core dump for this process.
#[cfg(unix)]
fn suppress_core_dumps() {
    let rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `setrlimit` is a well-specified POSIX syscall. `rlim` is a fully
    // initialized plain-old-data `rlimit` on the stack; we pass a valid
    // `*const` to it and the kernel only reads it for the duration of the call
    // (no aliasing, no lifetime escape). The return code is best-effort
    // (see the `harden_process` doc); a non-zero result leaves the prior limit
    // in place and is not recoverable here.
    #[allow(unsafe_code)]
    unsafe {
        let _ = libc::setrlimit(libc::RLIMIT_CORE, &raw const rlim);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    // PMF-2 / T2.3: after `harden_process`, the core-dump soft limit is zero.
    //
    // This mutates the *process* `RLIMIT_CORE`, but only lowers it (to 0),
    // which no sibling test reads or depends on, so it runs on the normal fast
    // path rather than `#[ignore]`d. Reads the limit back via `getrlimit`.
    #[allow(unsafe_code)] // documented getrlimit readback
    #[test]
    fn harden_process_zeroes_core_rlimit() {
        harden_process();

        let mut rlim = libc::rlimit {
            rlim_cur: u64::MAX as libc::rlim_t,
            rlim_max: u64::MAX as libc::rlim_t,
        };
        // SAFETY: `getrlimit` reads the current limit into `rlim`, a fully
        // initialized POD struct we own; valid `*mut` for the call's duration.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &raw mut rlim) };
        assert_eq!(rc, 0, "getrlimit(RLIMIT_CORE) should succeed");
        assert_eq!(
            rlim.rlim_cur, 0,
            "core-dump soft limit must be 0 after harden_process"
        );
    }
}
