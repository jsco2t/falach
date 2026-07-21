//! US-052 — Lock on macOS OS events (post-MVP Phase 5 T5.2 slice).
//!
//! Manual verification: a human tester triggers the OS event (system
//! sleep, screen lock) and the test observes the helper transition to
//! `Locked`. macOS-only and `iokit`-feature-gated.
//!
//! ## Why manual
//!
//! `IoKitSource` observes the `NSWorkspaceWillSleepNotification` (sleep)
//! and the `com.apple.screenIsLocked` distributed notification (screen
//! lock). Neither can be faithfully *synthesised* the way the logind
//! slice fires `DBus` signals with `dbus-send`:
//!
//! - There is no supported API to *post* `com.apple.screenIsLocked` as
//!   another process; the `WindowServer` is the only legitimate poster.
//! - `NSWorkspaceWillSleepNotification` is posted by the OS only on a
//!   real sleep transition.
//!
//! So each case prints an `INSTRUCTION:` line and waits up to
//! [`EVENT_TIMEOUT`] for the tester to perform the action. GitHub-hosted
//! macOS runners have no interactive session / display, so these are
//! `#[ignore]`d and excluded from CI; they run on a developer machine
//! via `make test-os-events`.
//!
//! ## Deviation from the task AC
//!
//! Task T5.2's AC named a `screensaver_start_locks_helper` case driven
//! by `open -a ScreenSaverEngine`. Starting the screensaver does **not**
//! lock the screen and does **not** post `com.apple.screenIsLocked`, so
//! that trigger would never satisfy the source. The case is therefore a
//! screen-*lock* case (`screen_lock_locks_helper`, Ctrl-Cmd-Q), matching
//! the event `IoKitSource` actually observes. See the `os_events::macos`
//! module rustdoc for the full deviation rationale.

#![cfg(all(target_os = "macos", feature = "iokit"))]

use std::io::{BufRead, BufReader};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::Duration;

/// How long the tester has to perform the instructed action before the
/// case fails. Generous because a human is in the loop.
const EVENT_TIMEOUT: Duration = Duration::from_secs(60);

/// Background stdout reader that lets the main test apply a timeout on
/// the helper's output. Same pattern as `us_052_post_mvp_logind.rs`.
struct ReaderWorker {
    request: Sender<()>,
    responses: Receiver<Result<String, std::io::Error>>,
}

impl ReaderWorker {
    fn spawn(stdout: ChildStdout) -> Self {
        let (req_tx, req_rx) = mpsc::channel::<()>();
        let (resp_tx, resp_rx) = mpsc::channel::<Result<String, std::io::Error>>();
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            while req_rx.recv().is_ok() {
                let mut line = String::new();
                let outcome = match reader.read_line(&mut line) {
                    Ok(0) => Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "helper stdout closed",
                    )),
                    Ok(_) => Ok(line.trim_end().to_owned()),
                    Err(e) => Err(e),
                };
                if resp_tx.send(outcome).is_err() {
                    break;
                }
            }
        });
        Self {
            request: req_tx,
            responses: resp_rx,
        }
    }

    /// Read a line, waiting up to `timeout`.
    fn read_line_within(&self, timeout: Duration) -> String {
        self.request
            .send(())
            .expect("reader worker accepts request");
        match self.responses.recv_timeout(timeout) {
            Ok(Ok(line)) => line,
            Ok(Err(e)) => panic!("helper stdout read failed: {e}"),
            Err(RecvTimeoutError::Timeout) => {
                panic!("helper stdout delivered no line within {timeout:?}")
            }
            Err(RecvTimeoutError::Disconnected) => {
                panic!("reader worker disconnected before delivering a line")
            }
        }
    }
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }
    fn as_mut(&mut self) -> &mut Child {
        self.0.as_mut().expect("child already taken")
    }
    fn take(mut self) -> Child {
        self.0.take().expect("child already taken")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let Some(mut child) = self.0.take() else {
            return;
        };
        drop(child.stdin.take());
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn spawn_helper() -> ChildGuard {
    let exe = env!("CARGO_BIN_EXE_iokit_helper");
    let child = Command::new(exe)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn iokit_helper");
    ChildGuard::new(child)
}

fn parse_ready_pid(line: &str) -> i32 {
    line.strip_prefix("ready PID=")
        .unwrap_or_else(|| panic!("expected `ready PID=<n>`, got {line:?}"))
        .parse()
        .unwrap_or_else(|e| panic!("could not parse PID from {line:?}: {e}"))
}

fn reap(guard: ChildGuard) {
    let mut child = guard.take();
    drop(child.stdin.take());
    let _ = child.wait();
}

/// Drive one manual case: spawn the helper, wait for ready, emit the
/// instruction, and assert the helper reports `locked` within
/// [`EVENT_TIMEOUT`].
fn run_manual_case(instruction: &str) {
    let mut child = spawn_helper();
    let stdout = child.as_mut().stdout.take().expect("child stdout");
    let reader = ReaderWorker::spawn(stdout);

    // The helper's first line is the readiness marker.
    let _pid = parse_ready_pid(&reader.read_line_within(Duration::from_secs(10)));

    // Grace for `IoKitSource` to finish registering its observers on
    // the worker thread's run loop before the tester acts.
    std::thread::sleep(Duration::from_millis(500));

    eprintln!("\n================ MANUAL TEST STEP ================");
    eprintln!("INSTRUCTION: {instruction}");
    eprintln!(
        "(waiting up to {}s for the helper to report `locked`)",
        EVENT_TIMEOUT.as_secs()
    );
    eprintln!("=================================================\n");

    let locked = reader.read_line_within(EVENT_TIMEOUT);
    assert_eq!(
        locked, "locked",
        "helper should print `locked` after the instructed event",
    );

    reap(child);
}

/// US-052 post-MVP AC (sleep): a system-sleep transition fires
/// `NSWorkspaceWillSleepNotification` → helper observes `Locked`.
#[test]
#[ignore = "manual: requires a macOS dev machine + interactive sleep trigger; run via `make test-os-events`"]
fn sleep_transition_locks_helper() {
    run_manual_case(
        "Put the machine to sleep within the timeout — run `pmset sleepnow` \
         in another terminal, or close the lid. (The will-sleep notification \
         fires before the machine actually suspends, so the helper records \
         `locked` first; you may need to wake the machine to see the result.)",
    );
}

/// US-052 post-MVP AC (screen lock): locking the screen fires
/// `com.apple.screenIsLocked` → helper observes `Locked`. (Deviates
/// from the AC's `screensaver_start` trigger — see file rustdoc.)
#[test]
#[ignore = "manual: requires a macOS dev machine + interactive screen lock; run via `make test-os-events`"]
fn screen_lock_locks_helper() {
    run_manual_case(
        "Lock the screen within the timeout — press Ctrl-Cmd-Q (or choose \
         the Apple menu → Lock Screen). Do NOT merely start the screensaver; \
         the source observes screen *lock*, not screensaver start.",
    );
}
