//! `logind_helper` — test binary spawned by US-052 post-MVP logind
//! integration tests.
//!
//! Same stdout-marker protocol as `sigstop_helper` (Phase 4 T4.3):
//!
//! 1. Construct controller + attach `LogindSource`.
//! 2. Print `ready PID=<pid>` and flush.
//! 3. Tick at ~100 Hz; on the first `LockState::Locked`, print
//!    `locked` and flush, then stop ticking.
//! 4. Block on stdin until EOF; exit 0.
//!
//! Built only with `--features test-binaries,logind`.

#![cfg(all(target_os = "linux", feature = "logind"))]

use std::io::{BufRead, Write};
use std::time::{Duration, Instant};

use falach_security::{AutoLockConfig, AutoLockController, LockState, LogindSource};

fn main() {
    let mut controller = AutoLockController::new(AutoLockConfig {
        idle_timeout: Duration::from_secs(3600),
    })
    .expect("1h timeout is valid");
    controller.register_activity(Instant::now());

    // Call `attach_event_source` BEFORE printing the ready marker so
    // the source's worker thread has at least been spawned by the
    // time the parent test acts on "ready". This is the same
    // discipline `sigstop_helper` follows for signal-hook (see
    // Phase 4 code review where the reverse ordering produced a
    // 40% test flake). NOTE: even with this ordering the parent
    // *still* needs a brief grace period after seeing "ready" before
    // emitting signals, because `LogindSource::run` opens its DBus
    // connections and subscribes asynchronously on the worker thread
    // — the helper's main thread cannot block on those completing
    // without re-introducing the inverse race. The integration test
    // sleeps 500ms after "ready" to cover the subscription window.
    let source = LogindSource::new().expect("LogindSource::new infallible");
    controller
        .attach_event_source(source)
        .expect("attach_event_source should succeed");

    println!("ready PID={}", std::process::id());
    if let Err(e) = std::io::stdout().flush() {
        eprintln!("logind_helper: failed to flush ready marker: {e}");
        std::process::exit(2);
    }

    let mut locked = false;
    while !locked {
        match controller.tick(Instant::now()) {
            LockState::Locked => {
                println!("locked");
                if let Err(e) = std::io::stdout().flush() {
                    eprintln!("logind_helper: failed to flush lock marker: {e}");
                    std::process::exit(2);
                }
                locked = true;
            }
            LockState::Active | LockState::Expired => {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut buf = String::new();
    loop {
        buf.clear();
        match reader.read_line(&mut buf) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                eprintln!("logind_helper: stdin read error: {e}");
                std::process::exit(2);
            }
        }
    }
}
