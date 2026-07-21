//! Secure master-password prompt (FR-061).
//!
//! Strategy (per design §2.2.2):
//!
//! 1. **Warn-and-remove** `FALACH_MASTER_PASSWORD` from the
//!    environment if set. Done once at startup via
//!    [`scrub_env_master_password`] — see `lib.rs::run` for the call.
//! 2. **Consult the agent** first via the supplied
//!    [`crate::agent::AgentClient`]. The MVP `NoAgentClient` always
//!    returns `Unavailable`, so this is a no-op in Phase 0.
//! 3. **Fall through to a no-echo stdin prompt** implemented directly
//!    over `nix::sys::termios` — see [`read_password_no_echo`].
//!
//! Memory hygiene: the intermediate `String` from
//! [`read_password_no_echo`] moves straight into [`MasterPassword`],
//! which is `Zeroize + ZeroizeOnDrop`. The bytes are scrubbed on drop.
//! The intermediate stack allocation is not separately zeroized — that
//! is the same hygiene posture vault-core accepts (see
//! `kb/memory-hygiene.md`).
//!
//! ## Why not `rpassword`?
//!
//! `rpassword` would pull `rtoolbox` + the `windows-sys` family
//! (~93 MB of vendored sources) via its `cfg(windows)` branch, none of
//! which compiles on the project's supported macOS + Linux targets.
//! `nix` is a safe Unix-only wrapper around the same termios calls and
//! adds a single small dep. The crate's one `unsafe` opt-out is the
//! `echo_signals` handler below — signal death can't be handled from
//! safe RAII code.

use std::io::{BufRead, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};

use falach_core::MasterPassword;
use nix::sys::termios::{tcgetattr, tcsetattr, LocalFlags, SetArg, Termios};

use crate::agent::{AgentClient, AgentError};
use crate::cli::MASTER_PASSWORD_ENV_VAR;
use crate::exit::CliExit;

/// Detect the `FALACH_MASTER_PASSWORD` env var; if set, write a
/// warning to `stderr` and remove the variable from the process
/// environment so subprocesses cannot inherit a bypass attempt.
///
/// Safe to call repeatedly; the second call is a no-op when the
/// variable is already absent.
pub fn scrub_env_master_password(stderr: &mut dyn Write) {
    if std::env::var_os(MASTER_PASSWORD_ENV_VAR).is_none() {
        return;
    }
    let _ = writeln!(
        stderr,
        "warning: {MASTER_PASSWORD_ENV_VAR} is set and will be ignored; \
         use the interactive prompt instead"
    );
    std::env::remove_var(MASTER_PASSWORD_ENV_VAR);
}

/// Inputs to [`master_password`]. Bundled in a struct so the prompt
/// function stays a stable signature as additional knobs (e.g., a
/// retry count) accumulate.
pub struct PromptOpts<'a> {
    /// Registry name of the vault the password is being collected for.
    /// Forwarded to the agent's `try_unlock` call.
    pub vault: &'a str,
    /// Agent client to consult before the stdin prompt. Pass
    /// `&NoAgentClient` in MVP.
    pub agent: &'a dyn AgentClient,
    /// Prompt label shown to the user when the rpassword fallback fires.
    pub prompt_label: &'a str,
}

/// Collect a master password. Tries the agent first, falls through to
/// a no-echo stdin prompt.
///
/// # Errors
///
/// - [`CliExit::UserError`] if the stdin read fails.
/// - [`CliExit::Internal`] if the agent returns an unexpected error
///   ([`AgentError::Other`]).
pub fn master_password(opts: &PromptOpts<'_>) -> Result<MasterPassword, CliExit> {
    match opts.agent.try_unlock(opts.vault) {
        Ok(mp) => return Ok(mp),
        Err(AgentError::Unavailable | AgentError::Locked) => { /* fall through */ }
        Err(AgentError::Other(detail)) => {
            return Err(CliExit::Internal(format!("agent error: {detail}")));
        }
    }

    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();
    let mut stderr = std::io::stderr().lock();
    let raw = read_password_no_echo(opts.prompt_label, &mut stdin, &mut stderr)
        .map_err(|e| CliExit::UserError(format!("failed to read password: {e}")))?;
    Ok(MasterPassword::new(raw))
}

/// Maximum times [`new_master_password_confirmed`] re-prompts on a
/// mismatch before giving up. Exposed as a constant so the integration
/// tests can pipe the exact stdin needed.
pub const NEW_PASSWORD_MAX_ATTEMPTS: u8 = 3;

/// Collect a new master password with confirmation.
///
/// Prompts twice; on mismatch, emits a stderr line and re-prompts.
/// Gives up after [`NEW_PASSWORD_MAX_ATTEMPTS`] complete attempts and
/// returns [`CliExit::UserError`].
///
/// Memory hygiene: each candidate `String` is dropped immediately after
/// the comparison; the matching value moves directly into
/// [`MasterPassword`]. The intermediate stack allocation is not
/// separately zeroized — same posture as
/// [`master_password`] / `kb/memory-hygiene.md`.
///
/// # Errors
///
/// - [`CliExit::UserError`] if reading either prompt fails or if all
///   attempts produce mismatched pairs.
pub fn new_master_password_confirmed<R: BufRead, W: Write>(
    stdin: &mut R,
    stderr: &mut W,
) -> Result<MasterPassword, CliExit> {
    for attempt in 1..=NEW_PASSWORD_MAX_ATTEMPTS {
        let first = read_password_no_echo("New master password: ", stdin, stderr)
            .map_err(|e| CliExit::UserError(format!("failed to read password: {e}")))?;
        let second = read_password_no_echo("Confirm master password: ", stdin, stderr)
            .map_err(|e| CliExit::UserError(format!("failed to read password: {e}")))?;
        if first == second {
            // Wrap one of the matching values; both `String`s drop at
            // end of scope so the unwrapped duplicate is released
            // immediately. We do not zeroize the duplicate — same
            // posture as `master_password` (see `kb/memory-hygiene.md`).
            return Ok(MasterPassword::new(first));
        }
        let _ = writeln!(
            stderr,
            "passwords did not match (attempt {attempt}/{NEW_PASSWORD_MAX_ATTEMPTS})"
        );
    }
    Err(CliExit::UserError(format!(
        "passwords did not match after {NEW_PASSWORD_MAX_ATTEMPTS} attempts"
    )))
}

/// Read a single line from `stdin` with terminal echo disabled (when
/// `stdin` is a TTY). Writes `prompt_label` to `stderr` first, and
/// emits a final newline to `stderr` so the cursor advances after the
/// (silent) Enter keypress.
///
/// When `stdin` is not a TTY (e.g., piped input from a test harness or
/// a script feeding the password), `tcgetattr` returns an error and
/// the function falls back to a plain `read_line` — input passes
/// through unchanged, which is the documented "piped-input" behaviour
/// (`verifications/01-local/03-master-password.md`).
///
/// Restoration of the original terminal mode is handled by a
/// private RAII guard's `Drop` impl so a panic between the
/// disable and the restore still leaves the terminal usable; a
/// SIGINT/SIGTERM/SIGQUIT during the prompt restores via the
/// `echo_signals` handler (Drop does not run on signal death).
///
/// # Errors
///
/// Returns any `std::io::Error` produced by writing the prompt or
/// reading the line. Failures to read/restore termios state are
/// silently ignored — they only affect input echo, never correctness
/// of the read value.
pub fn read_password_no_echo<R: BufRead, W: Write>(
    prompt_label: &str,
    stdin: &mut R,
    stderr: &mut W,
) -> std::io::Result<String> {
    write!(stderr, "{prompt_label}")?;
    stderr.flush()?;

    // Keep `stdin_handle` alive for the duration of the guard's
    // lifetime — `BorrowedFd` is tied to the `Stdin` value.
    let stdin_handle = std::io::stdin();
    let _guard = EchoGuard::disable(stdin_handle.as_fd());

    let mut line = String::new();
    let read_result = stdin.read_line(&mut line);

    // The user's Enter keypress wasn't echoed when ECHO was off; add a
    // newline so the next line of terminal output starts cleanly.
    // Unconditional — harmless when echo was actually on.
    writeln!(stderr)?;

    read_result?;
    // Strip the trailing newline `read_line` leaves on the buffer.
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    Ok(line)
}

/// Read a single line from `stdin` with terminal echo **left on**,
/// writing `prompt_label` to `stderr` first. This is the echoed
/// counterpart to [`read_password_no_echo`] — use it for **non-secret**
/// inputs the user should see as they type (e.g. an AWS access-key-id,
/// which is public per AWS posture and appears in CloudTrail/IAM as
/// cleartext). Never use it for secret material.
///
/// The trailing `\n` (and a preceding `\r`) are stripped, matching
/// [`read_password_no_echo`]'s contract so both prompts return a clean
/// value.
///
/// # Errors
///
/// Returns any `std::io::Error` produced by writing the prompt or
/// reading the line.
pub fn prompt_line<R: BufRead, W: Write>(
    prompt_label: &str,
    stdin: &mut R,
    stderr: &mut W,
) -> std::io::Result<String> {
    write!(stderr, "{prompt_label}")?;
    stderr.flush()?;
    let mut line = String::new();
    stdin.read_line(&mut line)?;
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    Ok(line)
}

/// RAII guard: when constructed via [`Self::disable`] it turns off the
/// ECHO local flag on the given fd; on drop it restores the prior
/// `Termios` value. If the fd is not a TTY (or any termios call
/// fails) the guard does nothing — same effect as if the user piped
/// input through a file.
struct EchoGuard<'fd> {
    fd: BorrowedFd<'fd>,
    original: Option<Termios>,
}

impl<'fd> EchoGuard<'fd> {
    fn disable(fd: BorrowedFd<'fd>) -> Self {
        let Ok(original) = tcgetattr(fd) else {
            return Self { fd, original: None };
        };
        let mut modified = original.clone();
        modified.local_flags &= !LocalFlags::ECHO;
        if tcsetattr(fd, SetArg::TCSANOW, &modified).is_err() {
            // Couldn't disable echo — leave terminal alone, no need
            // to restore.
            return Self { fd, original: None };
        }
        // ECHO is now off but ISIG is still on: ^C (SIGINT) or a `kill`
        // (SIGTERM) would terminate the process WITHOUT running this
        // guard's Drop, leaving the user's terminal permanently
        // echo-less. Arm an async-signal-safe handler that restores the
        // saved termios before re-raising the signal.
        echo_signals::arm(fd.as_raw_fd(), original.clone().into());
        Self {
            fd,
            original: Some(original),
        }
    }
}

impl Drop for EchoGuard<'_> {
    fn drop(&mut self) {
        if let Some(ref original) = self.original {
            // Best-effort restore; if it fails the user may have to
            // type `stty echo` to recover. There is no good way to
            // surface this from Drop, so the failure is swallowed.
            let _ = tcsetattr(self.fd, SetArg::TCSANOW, original);
            echo_signals::disarm();
        }
    }
}

/// Async-signal-safe echo restore for signal death during the prompt.
///
/// Rust does not unwind on signals: without this, ^C at the
/// master-password prompt leaves the terminal with `ECHO` off until the
/// user types `stty echo` blind. While the guard is armed, `SIGINT`,
/// `SIGTERM`, and `SIGQUIT` restore the saved termios and then re-raise
/// with the default disposition (so the exit status is the expected
/// signal death). Previous handlers are restored on disarm.
///
/// This is the crate's one `unsafe` module (see `lib.rs`), mirroring
/// `falach-tui::terminal_guard::signals`: an async-signal-safe handler
/// may only issue raw syscalls (`tcsetattr`, `signal`, `raise`) — no
/// allocation, locks, or Rust runtime services — which rules out the
/// safe `nix` wrappers used elsewhere in this file.
///
/// Concurrency: the CLI runs exactly one prompt at a time on the main
/// thread (arm/disarm are strictly nested), so plain statics written
/// before handler installation and read-only inside the handler are
/// race-free.
#[cfg(unix)]
mod echo_signals {
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};

    static ARMED: AtomicBool = AtomicBool::new(false);
    static FD: AtomicI32 = AtomicI32::new(-1);
    /// Previous handler for each signal in [`SIGNALS`], restored on disarm.
    static PREV_HANDLERS: [AtomicUsize; 3] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];
    /// Termios saved before echo was disabled. Written in `arm` (before
    /// the handlers are installed) and only read by the handler.
    static mut SAVED_TERMIOS: Option<libc::termios> = None;

    /// Keyboard- and `kill`-reachable terminating signals while the
    /// prompt is up. `SIGHUP` (terminal gone) is pointless to handle —
    /// there is no terminal left to restore.
    const SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGQUIT];

    pub(super) fn arm(fd: libc::c_int, termios: libc::termios) {
        FD.store(fd, Ordering::SeqCst);
        // SAFETY: `SAVED_TERMIOS` is written before any handler is
        // installed and never written again until the strictly-nested
        // `disarm`; the handler only reads it. Single-threaded prompt
        // path per the module docs.
        #[allow(unsafe_code)]
        unsafe {
            *std::ptr::addr_of_mut!(SAVED_TERMIOS) = Some(termios);
        }
        ARMED.store(true, Ordering::SeqCst);
        for (i, sig) in SIGNALS.iter().enumerate() {
            // SAFETY: installing a handler that is itself async-signal-
            // safe (see `handler`). The previous disposition is saved
            // for restoration in `disarm`.
            #[allow(unsafe_code)]
            let prev = unsafe { libc::signal(*sig, handler as *const () as libc::sighandler_t) };
            PREV_HANDLERS[i].store(prev, Ordering::SeqCst);
        }
    }

    pub(super) fn disarm() {
        for (i, sig) in SIGNALS.iter().enumerate() {
            let prev = PREV_HANDLERS[i].load(Ordering::SeqCst);
            // SAFETY: restores the disposition captured in `arm`.
            #[allow(unsafe_code)]
            unsafe {
                libc::signal(*sig, prev);
            }
        }
        ARMED.store(false, Ordering::SeqCst);
    }

    /// Restore the saved termios, then re-raise with the default
    /// disposition. Only async-signal-safe syscalls and reads of
    /// statics written before installation.
    extern "C" fn handler(sig: libc::c_int) {
        // SAFETY: `tcsetattr`, `signal`, and `raise` are async-signal-
        // safe; the statics are read-only here (written before the
        // handler could fire). No allocation, no locks.
        #[allow(unsafe_code)]
        unsafe {
            if ARMED.load(Ordering::SeqCst) {
                if let Some(termios) = std::ptr::addr_of!(SAVED_TERMIOS).read() {
                    libc::tcsetattr(
                        FD.load(Ordering::SeqCst),
                        libc::TCSANOW,
                        std::ptr::addr_of!(termios),
                    );
                }
            }
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
    }
}

/// On non-Unix targets (not a Phase-0 platform) signal handling is a
/// no-op; the guard's Drop remains the only restore path.
#[cfg(not(unix))]
mod echo_signals {
    pub(super) fn arm(_fd: i32, _termios: ()) {}
    pub(super) fn disarm() {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Env-var tests mutate process global state and must not run in
    // parallel with each other or with any other env-touching test.
    // The Mutex makes that explicit.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn scrub_is_noop_when_env_var_is_unset() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var(MASTER_PASSWORD_ENV_VAR);
        let mut buf = Vec::new();
        scrub_env_master_password(&mut buf);
        assert!(buf.is_empty(), "no warning when unset");
        assert!(std::env::var_os(MASTER_PASSWORD_ENV_VAR).is_none());
    }

    #[test]
    fn scrub_warns_and_removes_when_env_var_is_set() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var(MASTER_PASSWORD_ENV_VAR, "leak-me-if-you-can");
        let mut buf = Vec::new();
        scrub_env_master_password(&mut buf);
        let warning = String::from_utf8(buf).unwrap();
        assert!(warning.contains("ignored"), "warning text: {warning:?}");
        assert!(warning.contains(MASTER_PASSWORD_ENV_VAR));
        assert!(
            std::env::var_os(MASTER_PASSWORD_ENV_VAR).is_none(),
            "env var must be removed"
        );
        // The value itself must NOT appear in the warning — the warn-
        // and-remove flow exists to prevent a leak; echoing the leaked
        // value would defeat the point.
        assert!(
            !warning.contains("leak-me-if-you-can"),
            "warning leaked the secret value: {warning:?}"
        );
    }

    // --- Agent dispatch -------------------------------------------------

    struct FakeAgent {
        result: std::sync::Mutex<Option<Result<MasterPassword, AgentError>>>,
    }
    impl FakeAgent {
        fn new(r: Result<MasterPassword, AgentError>) -> Self {
            Self {
                result: std::sync::Mutex::new(Some(r)),
            }
        }
    }
    impl AgentClient for FakeAgent {
        fn try_unlock(&self, _vault: &str) -> Result<MasterPassword, AgentError> {
            self.result
                .lock()
                .unwrap()
                .take()
                .unwrap_or(Err(AgentError::Unavailable))
        }
    }

    #[test]
    fn agent_success_returns_password_without_prompting() {
        let agent = FakeAgent::new(Ok(MasterPassword::new("agent-pw".to_string())));
        let opts = PromptOpts {
            vault: "test",
            agent: &agent,
            prompt_label: "Master password: ",
        };
        let pw = master_password(&opts).expect("agent path should succeed");
        assert_eq!(
            pw.as_bytes(),
            b"agent-pw",
            "the agent-supplied password must be returned unchanged"
        );
    }

    #[test]
    fn agent_other_error_maps_to_internal_exit() {
        let agent = FakeAgent::new(Err(AgentError::Other("ipc dropped".into())));
        let opts = PromptOpts {
            vault: "test",
            agent: &agent,
            prompt_label: "Master password: ",
        };
        let err = master_password(&opts).expect_err("Other error should bubble out");
        assert_eq!(err.code(), 10);
        assert!(err.message().contains("ipc dropped"), "{}", err.message());
    }

    // --- read_password_no_echo --------------------------------------------
    //
    // The TTY-aware path (termios disable + restore) requires a real
    // terminal and is exercised manually via the verification suite.
    // What CAN be tested here is the non-TTY fallback: the function
    // must still write the prompt label, read the line, strip the
    // trailing newline, and emit a closing newline to stderr.

    #[test]
    fn read_password_no_echo_writes_prompt_label_to_stderr() {
        let mut stdin = std::io::Cursor::new(b"hunter2\n".to_vec());
        let mut stderr = Vec::new();
        let pw = read_password_no_echo("Master password: ", &mut stdin, &mut stderr).unwrap();
        let stderr_str = String::from_utf8(stderr).unwrap();
        assert!(
            stderr_str.starts_with("Master password: "),
            "stderr should start with the prompt label; got {stderr_str:?}"
        );
        assert_eq!(pw, "hunter2");
    }

    #[test]
    fn read_password_no_echo_emits_trailing_newline_to_stderr() {
        // After the user's Enter keypress (which wasn't echoed when
        // ECHO was off), the function must advance the cursor by
        // writing a newline to stderr — otherwise the next terminal
        // output collides with the prompt line.
        let mut stdin = std::io::Cursor::new(b"x\n".to_vec());
        let mut stderr = Vec::new();
        read_password_no_echo("> ", &mut stdin, &mut stderr).unwrap();
        let stderr_str = String::from_utf8(stderr).unwrap();
        assert!(
            stderr_str.ends_with('\n'),
            "stderr should end with newline; got {stderr_str:?}"
        );
    }

    #[test]
    fn read_password_no_echo_strips_trailing_lf() {
        let mut stdin = std::io::Cursor::new(b"plain-newline\n".to_vec());
        let mut stderr = Vec::new();
        let pw = read_password_no_echo("> ", &mut stdin, &mut stderr).unwrap();
        assert_eq!(pw, "plain-newline");
    }

    #[test]
    fn read_password_no_echo_strips_trailing_crlf() {
        let mut stdin = std::io::Cursor::new(b"crlf-line\r\n".to_vec());
        let mut stderr = Vec::new();
        let pw = read_password_no_echo("> ", &mut stdin, &mut stderr).unwrap();
        assert_eq!(pw, "crlf-line");
    }

    #[test]
    fn read_password_no_echo_accepts_empty_password() {
        // The Phase-1 task plan §8.2.3 calls this out: an empty
        // password is a valid (if unwise) caller input; the prompt
        // function shouldn't reject it.
        let mut stdin = std::io::Cursor::new(b"\n".to_vec());
        let mut stderr = Vec::new();
        let pw = read_password_no_echo("> ", &mut stdin, &mut stderr).unwrap();
        assert_eq!(pw, "");
    }

    // --- new_master_password_confirmed ------------------------------------

    #[test]
    fn new_master_password_confirmed_matching_pair_first_try_succeeds() {
        let mut stdin = std::io::Cursor::new(b"hunter2\nhunter2\n".to_vec());
        let mut stderr = Vec::new();
        let pw = new_master_password_confirmed(&mut stdin, &mut stderr)
            .expect("matching pair on first try");
        drop(pw);
        let stderr_str = String::from_utf8(stderr).unwrap();
        assert!(
            !stderr_str.contains("did not match"),
            "no mismatch warning expected; got {stderr_str:?}"
        );
    }

    #[test]
    fn new_master_password_confirmed_mismatch_then_match_recovers() {
        // attempt 1: pw1 != pw2 (mismatch). attempt 2: pwA == pwA (match).
        let mut stdin = std::io::Cursor::new(b"pw1\npw2\npwA\npwA\n".to_vec());
        let mut stderr = Vec::new();
        let pw = new_master_password_confirmed(&mut stdin, &mut stderr).expect("recovers");
        drop(pw);
        let stderr_str = String::from_utf8(stderr).unwrap();
        assert!(
            stderr_str.contains("did not match"),
            "expected one mismatch line; got {stderr_str:?}"
        );
    }

    #[test]
    fn new_master_password_confirmed_three_strikes_exits_user_error() {
        // All three attempts mismatch. Need 6 lines on stdin.
        let mut stdin = std::io::Cursor::new(b"a\nb\nc\nd\ne\nf\n".to_vec());
        let mut stderr = Vec::new();
        let err = new_master_password_confirmed(&mut stdin, &mut stderr)
            .expect_err("three strikes should fail");
        assert_eq!(err.code(), 1);
        assert!(err.message().contains("did not match"), "{}", err.message());
        assert!(err.message().contains('3'), "{}", err.message());
    }

    #[test]
    fn new_master_password_confirmed_never_leaks_value_to_stderr() {
        let mut stdin = std::io::Cursor::new(b"top-secret\ntop-secret\n".to_vec());
        let mut stderr = Vec::new();
        new_master_password_confirmed(&mut stdin, &mut stderr).unwrap();
        let stderr_str = String::from_utf8(stderr).unwrap();
        assert!(
            !stderr_str.contains("top-secret"),
            "stderr leaked password value: {stderr_str:?}"
        );
    }

    // --- prompt_line (echoed, non-secret inputs) --------------------------

    #[test]
    fn prompt_line_writes_label_and_strips_newline() {
        let mut stdin = std::io::Cursor::new(b"AKIAEXAMPLE\n".to_vec());
        let mut stderr = Vec::new();
        let value = prompt_line("AWS access key id: ", &mut stdin, &mut stderr).unwrap();
        assert_eq!(value, "AKIAEXAMPLE");
        let stderr_str = String::from_utf8(stderr).unwrap();
        assert!(
            stderr_str.starts_with("AWS access key id: "),
            "stderr should start with the prompt label; got {stderr_str:?}"
        );
    }

    #[test]
    fn prompt_line_strips_trailing_crlf() {
        let mut stdin = std::io::Cursor::new(b"AKIACRLF\r\n".to_vec());
        let mut stderr = Vec::new();
        let value = prompt_line("> ", &mut stdin, &mut stderr).unwrap();
        assert_eq!(value, "AKIACRLF");
    }

    #[test]
    fn read_password_no_echo_does_not_echo_value_to_stderr() {
        // Defence-in-depth: even when stdin is piped (no termios
        // toggle), the function must never write the password value
        // to stderr — only the prompt label and a trailing newline.
        let mut stdin = std::io::Cursor::new(b"super-secret-value\n".to_vec());
        let mut stderr = Vec::new();
        let pw = read_password_no_echo("Master password: ", &mut stdin, &mut stderr).unwrap();
        let stderr_str = String::from_utf8(stderr).unwrap();
        assert!(
            !stderr_str.contains("super-secret-value"),
            "stderr leaked the password value: {stderr_str:?}"
        );
        assert_eq!(pw, "super-secret-value");
    }
}
