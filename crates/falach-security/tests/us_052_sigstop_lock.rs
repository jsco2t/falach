//! US-052 — Lock on SIGTSTP (MVP slice).
//!
//! Spawns the `sigstop_helper` test binary as a child process and
//! drives the end-to-end "SIGTSTP arrives → `OsLock { Sigstop }` →
//! controller transitions to `Locked`" flow with real signals.
//!
//! Both cases are `#[ignore]`d because the helper binary installs a
//! process-wide signal handler. They run under `make test-ignored`
//! which forces `--test-threads=1` for cross-binary serialisation
//! against the in-module `SigstopSource` unit tests.
//!
//! ## Wire protocol
//!
//! - Helper prints `ready PID=<pid>` on startup.
//! - Helper prints `locked` on the first `LockState::Locked` it sees.
//! - Helper exits with status 0 on stdin EOF.
//!
//! Stdout reads use a dedicated worker thread per child so the test
//! can apply wall-clock timeouts via `mpsc::Receiver::recv_timeout`.
//! Without a timeout, a helper bug that never prints `locked` would
//! hang the test indefinitely.

#![cfg(unix)]

mod common;

use std::io::{BufRead, BufReader};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::Duration;

use common::signals::SIGNAL_GUARD;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;

/// Wall-clock budget for waiting on a single line of helper stdout.
/// Generous (5s) because CI runners can be slow; the happy-path
/// latency is ~10ms (the helper's tick cadence).
const STDOUT_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Background observation window for the negative test (no signal
/// should yield no `locked` marker).
const NEGATIVE_OBSERVATION_WINDOW: Duration = Duration::from_millis(500);

/// A request/response channel pair backed by a worker thread that
/// owns the child's stdout. Send `()` on `request` to ask the worker
/// to read one line; the worker delivers the result via `responses`.
/// `Ok(line)` on a non-empty line; `Err` on EOF or read error.
struct ReaderWorker {
    request: Sender<()>,
    responses: Receiver<Result<String, std::io::Error>>,
}

impl ReaderWorker {
    /// Spawn a worker that owns `stdout` and serves one line per
    /// request.
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

    /// Read one line, failing the test with a clear diagnostic if the
    /// budget expires.
    fn read_line(&self) -> String {
        self.request
            .send(())
            .expect("reader worker should accept request");
        match self.responses.recv_timeout(STDOUT_READ_TIMEOUT) {
            Ok(Ok(line)) => line,
            Ok(Err(e)) => panic!("helper stdout read failed: {e}"),
            Err(RecvTimeoutError::Timeout) => {
                panic!("helper stdout did not deliver a line within {STDOUT_READ_TIMEOUT:?}")
            }
            Err(RecvTimeoutError::Disconnected) => {
                panic!("reader worker disconnected before delivering a line")
            }
        }
    }

    /// Attempt to read a line within `budget`. Returns `Some(line)`
    /// if the helper delivered output; `None` if the budget elapsed
    /// with no output. Used by the negative test to assert "nothing
    /// happened during this window."
    fn try_read_within(&self, budget: Duration) -> Option<String> {
        self.request.send(()).expect("reader worker accepts");
        match self.responses.recv_timeout(budget) {
            Ok(Ok(line)) => Some(line),
            Ok(Err(_)) | Err(_) => None,
        }
    }
}

/// RAII wrapper that guarantees the helper child is reaped even when
/// the test panics partway through. Without this, a stuck helper
/// (e.g., parked on stdin after `Locked`, or stopped via SIGSTOP) is
/// orphaned across the test runner and accumulates on flaky CI runs.
///
/// `Drop` closes stdin (the cooperative shutdown signal) and sends
/// `SIGCONT` + `SIGKILL` as a fallback for the case where the helper
/// is still stopped or wedged. Wait is best-effort: if the kernel
/// won't reap, we'd rather move on than block forever in `Drop`.
struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }

    /// Borrow the inner `Child` for normal interactions.
    fn as_mut(&mut self) -> &mut Child {
        self.0.as_mut().expect("child already taken")
    }

    /// Hand off the `Child` for an explicit, ordered teardown. After
    /// this, `Drop` is a no-op.
    fn take(mut self) -> Child {
        self.0.take().expect("child already taken")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let Some(mut child) = self.0.take() else {
            return;
        };
        // 1. Cooperative shutdown: close stdin so the helper's
        //    `read_line` loop sees EOF and exits.
        drop(child.stdin.take());
        // 2. If the helper is stopped (SIGSTOP from a test-half that
        //    panicked between TSTP and CONT), resume it so its main
        //    thread can observe the EOF.
        if let Ok(pid) = i32::try_from(child.id()) {
            let _ = kill(Pid::from_raw(pid), Signal::SIGCONT);
        }
        // 3. Hard kill as a fallback; harmless if the child already
        //    exited via stdin-EOF.
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// Spawn the helper as a child with piped stdin + stdout, wrapped in
/// a [`ChildGuard`] so a test panic still reaps the process.
fn spawn_helper() -> ChildGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_sigstop_helper"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn sigstop_helper");
    ChildGuard::new(child)
}

/// Parse `ready PID=<pid>` → `<pid>`.
fn parse_ready_pid(line: &str) -> i32 {
    line.strip_prefix("ready PID=")
        .unwrap_or_else(|| panic!("expected `ready PID=<n>`, got {line:?}"))
        .parse()
        .unwrap_or_else(|e| panic!("could not parse PID from {line:?}: {e}"))
}

/// Reap the child cleanly via the cooperative path. Closing stdin
/// signals "test done" to the helper; the helper exits on EOF.
fn reap(guard: ChildGuard) {
    let mut child = guard.take();
    drop(child.stdin.take());
    let _ = child.wait();
}

/// US-052 AC #1 (MVP slice): sending `SIGTSTP` to a process running
/// `AutoLockController + SigstopSource` causes the controller to
/// transition to `Locked` and the helper to print `"locked"`.
#[test]
#[ignore = "spawns a child + sends real signals; run via `make test-ignored`"]
fn sigtstp_to_helper_transitions_controller_to_locked() {
    let _guard = SIGNAL_GUARD.lock().expect("signal guard poisoned");

    let mut child = spawn_helper();
    let stdout = child.as_mut().stdout.take().expect("child stdout");
    let reader = ReaderWorker::spawn(stdout);

    // 1. Read "ready PID=<pid>".
    let pid = parse_ready_pid(&reader.read_line());

    // 2. Send SIGTSTP. The helper's `SigstopSource` catches it on
    //    its dedicated thread, sends `OsLock { Sigstop }` to the
    //    controller's channel, then re-raises `SIGSTOP` — which
    //    stops *every* thread in the helper, including the main
    //    thread driving `tick`. So the helper has NOT yet observed
    //    the queued event at this point; it's frozen.
    let nix_pid = Pid::from_raw(pid);
    kill(nix_pid, Signal::SIGTSTP).expect("kill(SIGTSTP)");

    // 3. Wait for the helper to actually transition to stopped via
    //    `waitpid(WUNTRACED)`. Without this, sending SIGCONT below
    //    could race with SigstopSource's `raise(SIGSTOP)` and lose:
    //    POSIX leaves the delivery order of pending signals
    //    unspecified, and the kernel typically processes lower-
    //    numbered signals first — so a SIGCONT (18) queued before
    //    the helper's `raise(SIGSTOP)` (19) could be consumed
    //    while no stop is pending, then SIGSTOP fires and leaves
    //    the process stopped forever.
    //
    //    The helper installs its SIGTSTP handler BEFORE printing
    //    "ready PID=", so by the time the test sends SIGTSTP above
    //    the handler is always in place and `waitpid` must observe
    //    `Stopped(SIGSTOP)` — the signal `SigstopSource` re-raises
    //    after sending `OsLock` to the controller's channel. A
    //    `Stopped(SIGTSTP)` here would mean the kernel's default
    //    SIGTSTP action won the race against `sigaction`, the event
    //    was never sent, and the helper would tick forever without
    //    observing `Locked`. We assert the strict expectation so a
    //    regression to the racy "print ready first, install handler
    //    after" order surfaces immediately.
    let stopped = waitpid(nix_pid, Some(WaitPidFlag::WUNTRACED))
        .expect("waitpid(WUNTRACED) should observe a state change");
    match stopped {
        WaitStatus::Stopped(_, Signal::SIGSTOP) => {
            // Expected: SigstopSource caught SIGTSTP, sent `OsLock`,
            // then re-raised SIGSTOP.
        }
        WaitStatus::Stopped(_, Signal::SIGTSTP) => panic!(
            "helper stopped via raw SIGTSTP (kernel default) — handler installation \
             raced with the parent's `kill(SIGTSTP)`. The helper must install its \
             `SigstopSource` BEFORE printing the ready marker.",
        ),
        other => panic!("expected helper to stop via SIGSTOP, got {other:?}"),
    }

    // 4. Send SIGCONT so the helper resumes. Now its main thread
    //    drains the queued `OsLock` event on the next tick,
    //    observes `LockState::Locked`, and prints "locked". This
    //    SIGTSTP-then-SIGCONT sequence is exactly what a user's
    //    `Ctrl-Z` then `fg` produces — the production code path
    //    the PRD exercises (§6.6 FR-052).
    kill(nix_pid, Signal::SIGCONT).expect("kill(SIGCONT)");

    // 5. Read "locked". The helper prints it inside the same tick
    //    that drains the channel — bounded by the helper's 10ms
    //    tick cadence + scheduler latency.
    let locked = reader.read_line();
    assert_eq!(
        locked, "locked",
        "helper should print `locked` after SIGTSTP + SIGCONT",
    );

    // 6. Reap. Dropping stdin signals "done" to the helper, which
    //    exits cleanly on EOF.
    reap(child);
}

/// US-052 AC #2: a stray `SIGCONT` (no prior `SIGTSTP`) must NOT
/// produce a "locked" marker. Guards against a regression that maps
/// `SIGCONT` to `SecurityEvent::Activity` (or any other lock-causing
/// event) — that would let any process able to deliver `SIGCONT`
/// keep the vault unlocked indefinitely.
#[test]
#[ignore = "spawns a child + sends real signals; run via `make test-ignored`"]
fn sigcont_alone_does_not_unlock_helper() {
    let _guard = SIGNAL_GUARD.lock().expect("signal guard poisoned");

    let mut child = spawn_helper();
    let pid = i32::try_from(child.as_mut().id()).expect("child PID fits in i32");
    let stdout = child.as_mut().stdout.take().expect("child stdout");
    let reader = ReaderWorker::spawn(stdout);

    // Read "ready PID=<pid>" and confirm it matches.
    let ready_line = reader.read_line();
    let parsed_pid = parse_ready_pid(&ready_line);
    assert_eq!(
        parsed_pid, pid,
        "helper's reported PID should match Child::id()",
    );

    // Send a bare SIGCONT and check the helper does NOT print
    // anything within the observation window. (Helper only prints on
    // `Locked`; any output here would be a regression.)
    kill(Pid::from_raw(pid), Signal::SIGCONT).expect("kill(SIGCONT)");
    if let Some(line) = reader.try_read_within(NEGATIVE_OBSERVATION_WINDOW) {
        panic!("helper printed {line:?} after bare SIGCONT — must not lock without SIGTSTP");
    }

    // Tear the helper down: SIGTERM ends its tick loop, then reap.
    let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
    reap(child);
}
