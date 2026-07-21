//! `sigstop_helper` — test binary spawned by the US-052 integration
//! test.
//!
//! Built only with `--features test-binaries` (the `Cargo.toml`
//! `[[bin]]` entry declares `required-features = ["test-binaries"]`).
//! The integration test discovers it via
//! `env!("CARGO_BIN_EXE_sigstop_helper")`.
//!
//! ## Wire protocol
//!
//! 1. Construct an `AutoLockController` + attach a `SigstopSource`
//!    (which installs the SIGTSTP/SIGCONT handlers).
//! 2. **Only then** print `ready PID=<pid>\n` and flush. Critically,
//!    the parent must not send `SIGTSTP` before this marker arrives —
//!    if it does, the kernel's default `SIGTSTP` action (stop the
//!    process) wins the race against signal-hook's `sigaction`, the
//!    `OsLock { Sigstop }` event never fires, and the helper resumes
//!    after `SIGCONT` without ever locking.
//! 3. Loop on `controller.tick(Instant::now())` at ~100 Hz.
//! 4. On the first `LockState::Locked` returned by `tick`, print
//!    `locked\n` and flush — and stop calling `tick` so the message
//!    surfaces before the test sends `SIGCONT`.
//! 5. Block reading stdin so the parent can keep the child alive
//!    until it explicitly closes our stdin (signalling "test done").
//!    Exits with status 0 on stdin EOF.
//!
//! ## Why ~100 Hz?
//!
//! The integration test asserts that the controller observes the
//! `OsLock { Sigstop }` event within a small wall-clock window after
//! `SIGTSTP` is delivered. A real frontend's tick cadence is
//! whatever its event loop runs at (30 Hz for TUI, whenever-a-syscall-
//! returns for CLI). 100 Hz keeps the test latency bounded by
//! ~10 ms + channel-drain.

use std::io::{BufRead, Write};
use std::time::{Duration, Instant};

use falach_security::{AutoLockConfig, AutoLockController, LockState, SigstopSource};

fn main() {
    // Build a controller with a generous idle timeout — the test
    // drives the transition via `SIGTSTP`, not via idle. A very long
    // timeout means the test never accidentally observes "Locked"
    // from an idle path.
    let mut controller = AutoLockController::new(AutoLockConfig {
        idle_timeout: Duration::from_secs(3600),
    })
    .expect("1h timeout is valid");
    controller.register_activity(Instant::now());

    // Install SIGTSTP/SIGCONT handlers BEFORE printing the ready
    // marker. If we print first, the parent test races signal-hook's
    // `sigaction` call — observed empirically as ~40% test flake
    // where waitpid reports `Stopped(SIGTSTP)` (kernel default) and
    // the controller never sees `OsLock`.
    let source = SigstopSource::new().expect("SigstopSource::new should succeed on Unix");
    controller
        .attach_event_source(source)
        .expect("attach_event_source should succeed");

    // Ready marker — flush so the parent doesn't block on an
    // unbuffered stdout.
    println!("ready PID={}", std::process::id());
    if let Err(e) = std::io::stdout().flush() {
        eprintln!("sigstop_helper: failed to flush ready marker: {e}");
        std::process::exit(2);
    }

    // Tick at ~100 Hz until we see Locked. We deliberately do NOT
    // tick after observing Locked — once the lock marker is out,
    // the test sends SIGCONT and then closes our stdin; we want to
    // observe stdin EOF cleanly without burning CPU on more ticks.
    let mut locked = false;
    while !locked {
        match controller.tick(Instant::now()) {
            LockState::Locked => {
                println!("locked");
                if let Err(e) = std::io::stdout().flush() {
                    eprintln!("sigstop_helper: failed to flush lock marker: {e}");
                    std::process::exit(2);
                }
                locked = true;
            }
            LockState::Active | LockState::Expired => {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    // Block on stdin until the parent closes it. `read_line` returns
    // `Ok(0)` on EOF.
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut buf = String::new();
    loop {
        buf.clear();
        match reader.read_line(&mut buf) {
            Ok(0) => break, // EOF — parent closed our stdin
            Ok(_) => {
                // Ignore any input the parent writes; the protocol
                // only uses stdin's close signal.
            }
            Err(e) => {
                eprintln!("sigstop_helper: stdin read error: {e}");
                std::process::exit(2);
            }
        }
    }
}
