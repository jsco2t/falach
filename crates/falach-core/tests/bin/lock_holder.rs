//! Test helper binary: acquires an advisory lock on a vault file and
//! signals readiness via a separate signal file.
//!
//! Usage:
//!
//!     lock_holder --exclusive <vault_path> <signal_path>
//!     lock_holder --shared  <vault_path> <signal_path>
//!     lock_holder --help
//!
//! The binary acquires the requested lock, writes the signal file (so
//! the parent process knows the lock is held), then sleeps forever (or
//! until SIGKILL). This lets cross-process tests verify that:
//!
//! - An exclusive lock blocks other exclusive locks.
//! - A shared lock permits concurrent shared locks but blocks exclusive
//!   locks.
//! - The kernel releases the lock when the process dies (SIGKILL).
//!
//! Uses [`std::fs::File`]'s built-in locking API (Rust 1.89+); no
//! third-party crate.

use std::fs;
use std::path::Path;
use std::process;

use falach_core::locking::{acquire_exclusive, acquire_shared};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 4 || args.iter().any(|a| a == "--help" || a == "-h") {
        eprintln!("Usage:");
        eprintln!("  lock_holder --exclusive <vault_path> <signal_path>");
        eprintln!("  lock_holder --shared  <vault_path> <signal_path>");
        eprintln!("  lock_holder --help");
        eprintln!();
        eprintln!("The binary acquires an advisory lock, writes the signal file,");
        eprintln!("then sleeps until killed. PID: {}", std::process::id());
        process::exit(0);
    }

    let mode = args.get(1).expect("missing --exclusive or --shared");
    let vault_path = args.get(2).expect("missing vault_path");
    let signal_path = args.get(3).expect("missing signal_path");

    let vault_path = Path::new(vault_path);
    let lock = match mode.as_str() {
        "--exclusive" => HeldLock::Exclusive(
            acquire_exclusive(vault_path)
                .unwrap_or_else(|e| panic!("cannot acquire exclusive lock: {e}")),
        ),
        "--shared" => HeldLock::Shared(
            acquire_shared(vault_path)
                .unwrap_or_else(|e| panic!("cannot acquire shared lock: {e}")),
        ),
        other => panic!("unknown mode: {other}. Use --exclusive or --shared"),
    };

    // Signal readiness by creating the signal file.
    fs::write(signal_path, format!("{}", std::process::id()))
        .unwrap_or_else(|e| panic!("cannot write signal file {signal_path}: {e}"));

    // Sleep forever — the test will SIGKILL us when done. `lock` stays in
    // scope here, keeping the sidecar file lock held.
    loop {
        lock.keep_alive();
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

enum HeldLock {
    Exclusive(falach_core::ExclusiveLock),
    Shared(falach_core::SharedLock),
}

impl HeldLock {
    fn keep_alive(&self) {
        match self {
            Self::Exclusive(lock) => {
                std::hint::black_box(lock.file());
            }
            Self::Shared(lock) => {
                std::hint::black_box(lock.file());
            }
        }
    }
}
