//! US-052 — Lock on logind events (post-MVP Phase 5 T5.1 slice).
//!
//! Fires real `DBus` signals via `dbus-send` shelling out, observes the
//! helper transition to `Locked`. Linux-only and feature-gated.
//!
//! ## How signals are fired
//!
//! `dbus-send` is part of the `dbus-daemon` distribution (in `dbus`
//! on Fedora, `dbus-bin`/`libdbus-1-3` on Debian). The test panics
//! loudly if it's missing — a silent skip would hide real coverage
//! gaps.
//!
//! Two cases:
//!
//! 1. `prepare_for_sleep_signal_transitions_to_locked` —
//!    `dbus-send` emits `org.freedesktop.login1.Manager.PrepareForSleep(true)`
//!    on the system bus. The helper's `LogindSource` receives it,
//!    sends `OsLock { Sleep }`, and the controller transitions to
//!    `Locked`.
//!
//! 2. `session_lock_signal_transitions_to_locked` —
//!    `dbus-send` emits `org.freedesktop.login1.Session.Lock` on the
//!    helper's session path (resolved at runtime via
//!    `Manager.GetSessionByPID`).
//!
//! ## Environment requirements
//!
//! Both cases require **all** of the following:
//!
//! 1. A logind-enabled host (`busctl --system list | grep
//!    org.freedesktop.login1` succeeds). Phase 5 risk #2 covers the
//!    GitHub-runner question.
//! 2. `dbus-send` and `busctl` on `$PATH` (Fedora's `dbus-tools` /
//!    Debian's `dbus`).
//! 3. **Sufficient privileges to emit the signals as
//!    `org.freedesktop.login1` on the system bus.** Most distros
//!    ship a default policy in `/usr/share/dbus-1/system.d/org.freedesktop.login1.conf`
//!    that allows only root (the logind UID) to send signals on
//!    these interfaces. Running the tests as an unprivileged user
//!    typically gets `dbus-send` "Rejected send message" — that is
//!    the broker's policy enforcement, not a bug in the test. Run
//!    as root (or with a local policy override) to exercise the
//!    full path.
//! 4. The cargo-test process must be in an active logind session
//!    (`loginctl show-session "$XDG_SESSION_ID"` succeeds). Cargo
//!    test spawned from outside a session (e.g., a remote shell
//!    or a sandbox shim) makes `GetSessionByPID` return "PID does
//!    not belong to any known session" — observable in the
//!    `session_lock_signal_transitions_to_locked` failure mode.
//!
//! On hosts where these prerequisites are missing the tests panic
//! loudly with environment-specific diagnostics (see
//! [`preflight_environment`]) — silent skip would let CI accidentally
//! green with zero logind coverage.

#![cfg(all(target_os = "linux", feature = "logind"))]

use std::io::{BufRead, BufReader};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::Duration;

const STDOUT_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Background stdout reader that lets the main test apply
/// `recv_timeout`-style bounds on the helper's output. Same pattern
/// as `us_052_sigstop_lock.rs::ReaderWorker`.
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

    fn read_line(&self) -> String {
        self.request
            .send(())
            .expect("reader worker accepts request");
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
    let exe = env!("CARGO_BIN_EXE_logind_helper");
    let child = Command::new(exe)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn logind_helper");
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

/// Distinguish "binary missing from PATH" from "binary present but
/// failed at runtime" so the panic message points at the right fix.
fn run_or_explain(cmd: &str, args: &[&str]) -> std::process::Output {
    match Command::new(cmd).args(args).output() {
        Ok(out) => out,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            panic!(
                "ENV: `{cmd}` not on $PATH — install your distro's dbus-tools \
                 package (Fedora: `dbus-tools`; Debian/Ubuntu: `dbus`). \
                 See the file rustdoc \"Environment requirements\" section.",
            )
        }
        Err(e) => panic!("`{cmd}` failed to spawn: {e}"),
    }
}

/// Preflight: confirm the host can host this test before we start
/// spawning helpers. Panics with environment-shaped diagnostics —
/// distinct from coverage-shaped panics emitted later in the test —
/// so an operator who can't run the test recognises the failure mode
/// instantly (vs. seeing a stack trace that looks like a real defect).
fn preflight_environment() {
    let out = run_or_explain("busctl", &["--system", "list", "--no-pager"]);
    if !out.status.success() {
        panic!(
            "ENV: `busctl --system list` failed (status: {}). The system DBus \
             daemon is either not running or unreachable from this process. \
             See the file rustdoc.",
            out.status,
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !stdout.contains("org.freedesktop.login1") {
        panic!(
            "ENV: `org.freedesktop.login1` is not registered on the system \
             bus. systemd-logind is not running on this host. Phase 5 risk \
             #2 covers the GitHub-runner question; see the file rustdoc.",
        );
    }
}

/// Best-effort: emit a PrepareForSleep(true) signal on the system
/// bus via `dbus-send`. Fails the test if `dbus-send` is missing or
/// the broker's policy refuses the emission.
fn emit_prepare_for_sleep() {
    let out = run_or_explain(
        "dbus-send",
        &[
            "--system",
            "--type=signal",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager.PrepareForSleep",
            "boolean:true",
        ],
    );
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("Rejected send message") || stderr.contains("AccessDenied") {
            panic!(
                "ENV: system bus policy refused PrepareForSleep emission. \
                 Default logind policy restricts signals on \
                 `org.freedesktop.login1.Manager` to the logind UID (root). \
                 Re-run as root (or install a local policy override). See \
                 the file rustdoc \"Environment requirements\".",
            );
        }
        panic!(
            "dbus-send refused PrepareForSleep emission (status: {}); stderr={stderr:?}",
            out.status,
        );
    }
}

/// Resolve the helper's session path via `loginctl show-session
/// $(loginctl session-status -p Session ...)` would be elaborate.
/// Simpler: call `loginctl list-sessions` and pick the one matching
/// our user. The test only needs *some* session path; the helper's
/// `LogindSource` resolves its own via `GetSessionByPID` regardless.
/// For emitting a `Session.Lock` signal we just need to target the
/// SAME path the helper's `LogindSource` is subscribed to.
fn emit_session_lock(session_path: &str) {
    let out = run_or_explain(
        "dbus-send",
        &[
            "--system",
            "--type=signal",
            session_path,
            "org.freedesktop.login1.Session.Lock",
        ],
    );
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("Rejected send message") || stderr.contains("AccessDenied") {
            panic!(
                "ENV: system bus policy refused Session.Lock emission. \
                 Default logind policy restricts signals on \
                 `org.freedesktop.login1.Session` to the logind UID. \
                 Re-run as root or with a local policy override.",
            );
        }
        panic!(
            "dbus-send refused Session.Lock emission (status: {}); stderr={stderr:?}",
            out.status,
        );
    }
}

/// Resolve the session path the helper would subscribe to. Uses
/// `loginctl show-session $(loginctl session-status -p ID)` — but
/// easier: use the helper's own resolution. We invoke
/// `loginctl --no-legend list-sessions` and pick the first matching
/// row's session ID, then construct the path. The path format is
/// `/org/freedesktop/login1/session/_<id>` where `<id>` is the
/// session ID with `c` prefix for graphical sessions.
fn helper_session_path(pid: i32) -> String {
    // Use `busctl call` to ask logind for our session path directly.
    // Equivalent to the helper's `Manager.GetSessionByPID(pid)`.
    let output = run_or_explain(
        "busctl",
        &[
            "call",
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
            "GetSessionByPID",
            "u",
            &pid.to_string(),
        ],
    );
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("does not belong to any known session") {
            panic!(
                "ENV: PID {pid} is not in any logind session. The cargo-test \
                 process must run inside an active session — e.g., from a \
                 graphical login terminal, not from a remote shell or sandbox \
                 shim. See the file rustdoc.",
            );
        }
        panic!(
            "busctl GetSessionByPID failed (status: {}); stderr={stderr:?}",
            output.status,
        );
    }
    // `busctl call ... GetSessionByPID` prints e.g. `o "/org/freedesktop/login1/session/c1"`
    let stdout = String::from_utf8_lossy(&output.stdout);
    let path = stdout
        .split('"')
        .nth(1)
        .unwrap_or_else(|| panic!("could not parse session path from busctl output: {stdout:?}"));
    path.to_owned()
}

/// US-052 post-MVP AC: PrepareForSleep(true) → helper observes Locked.
#[test]
#[ignore = "requires logind-enabled host + dbus-send + privileges to emit on the system bus; run via `make test-os-events`"]
fn prepare_for_sleep_signal_transitions_to_locked() {
    preflight_environment();
    let mut child = spawn_helper();
    let stdout = child.as_mut().stdout.take().expect("child stdout");
    let reader = ReaderWorker::spawn(stdout);

    let _pid = parse_ready_pid(&reader.read_line());

    // Brief grace so the helper's `LogindSource` finishes its
    // `Connection::system().await` and signal subscription before
    // we emit. Without this the signal can fire before the
    // subscription is registered with the broker, and the helper
    // never sees it.
    std::thread::sleep(Duration::from_millis(500));

    emit_prepare_for_sleep();

    let locked = reader.read_line();
    assert_eq!(
        locked, "locked",
        "helper should print `locked` after PrepareForSleep(true)",
    );

    reap(child);
}

/// US-052 post-MVP AC: Session.Lock signal → helper observes Locked.
#[test]
#[ignore = "requires logind-enabled host + dbus-send + busctl + privileges; run via `make test-os-events`"]
fn session_lock_signal_transitions_to_locked() {
    preflight_environment();
    let mut child = spawn_helper();
    let pid = i32::try_from(child.as_mut().id()).expect("child PID fits in i32");
    let stdout = child.as_mut().stdout.take().expect("child stdout");
    let reader = ReaderWorker::spawn(stdout);

    let _ready_pid = parse_ready_pid(&reader.read_line());

    std::thread::sleep(Duration::from_millis(500));

    let session_path = helper_session_path(pid);
    emit_session_lock(&session_path);

    let locked = reader.read_line();
    assert_eq!(
        locked, "locked",
        "helper should print `locked` after Session.Lock on {session_path}",
    );

    reap(child);
}
