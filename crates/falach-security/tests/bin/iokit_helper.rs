//! `iokit_helper` — test binary spawned by the US-052 post-MVP `IOKit`
//! integration tests.
//!
//! Same stdout-marker protocol as `sigstop_helper` (Phase 4 T4.3) and
//! `logind_helper` (Phase 5 T5.1):
//!
//! 1. Construct controller + attach `IoKitSource`.
//! 2. Print `ready PID=<pid>` and flush.
//! 3. Tick at ~100 Hz; on the first `LockState::Locked`, print
//!    `locked` and flush, then stop ticking.
//! 4. Block on stdin until EOF; exit 0.
//!
//! Built only with `--features test-binaries,iokit`.

#![cfg(all(target_os = "macos", feature = "iokit"))]

use std::io::{BufRead, Write};
use std::time::{Duration, Instant};

use falach_security::{AutoLockConfig, AutoLockController, IoKitSource, LockState};

fn main() {
    let mut controller = AutoLockController::new(AutoLockConfig {
        idle_timeout: Duration::from_secs(3600),
    })
    .expect("1h timeout is valid");
    controller.register_activity(Instant::now());

    // Attach BEFORE printing the ready marker so the source's worker
    // thread is spawned by the time the parent acts on "ready". Same
    // discipline as `logind_helper`. The `IoKitSource` registers its
    // observers and starts its `CFRunLoop` on that worker thread; the
    // parent still allows a brief grace after "ready" before expecting
    // events (the observers must finish registering on the run loop).
    let source = IoKitSource::new().expect("IoKitSource::new infallible");
    controller
        .attach_event_source(source)
        .expect("attach_event_source should succeed");

    println!("ready PID={}", std::process::id());
    if let Err(e) = std::io::stdout().flush() {
        eprintln!("iokit_helper: failed to flush ready marker: {e}");
        std::process::exit(2);
    }

    let mut locked = false;
    while !locked {
        match controller.tick(Instant::now()) {
            LockState::Locked => {
                println!("locked");
                if let Err(e) = std::io::stdout().flush() {
                    eprintln!("iokit_helper: failed to flush lock marker: {e}");
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
                eprintln!("iokit_helper: stdin read error: {e}");
                std::process::exit(2);
            }
        }
    }
}
