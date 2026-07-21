//! Phase 4 (T4.3) integration tests for the master-password collection
//! contract (FR-061 + design §2.6).
//!
//! All tests in this file are `#[ignore]`d because they either mutate
//! the spawned child's environment (`FALACH_MASTER_PASSWORD`) or
//! exercise the `--master-password`-flag-doesn't-exist rule via the
//! parse layer — running them in parallel with the rest of the
//! integration suite would pollute observation of the env-var warning.
//! Invoked by `make test-ignored`.
//!
//! The TTY no-echo verification cannot be expressed in a portable
//! Rust test without a PTY harness; it is covered by the manual
//! verification document `verifications/01-local/03-master-password.md`
//! per design §6 row 9.

mod common;

use std::io::Write as _;
use std::process::{Command, Stdio};

use common::{falach_bin, VaultsToml};

/// Build a `Command` for the `falach` binary that **does not** strip
/// `FALACH_MASTER_PASSWORD` from the spawned environment, so we can
/// verify the runtime warn-and-remove path. `common::falach_cmd`
/// strips the env var for normal tests; this helper is the exception.
fn falach_cmd_keep_env() -> Command {
    Command::new(falach_bin())
}

/// Helper: seed a fast-KDF vault registered as `mp` with the given
/// master password inside `reg` (via `common::seed_vault` — this file
/// tests password *collection*, not the create path or the KDF).
fn create_fixture_vault(reg: &VaultsToml, password: &str) {
    common::seed_vault(reg, "mp", password);
}

#[test]
#[ignore = "mutates FALACH_MASTER_PASSWORD on the spawned child; run via `make test-ignored`"]
fn env_var_warns_to_stderr_then_is_ignored_for_open() {
    // The runtime contract: if FALACH_MASTER_PASSWORD is set when the
    // CLI starts, we (a) emit a warning to stderr, (b) remove it from
    // the process environment, and (c) fall through to the secure
    // stdin prompt. Verify the end-to-end behaviour: a correct
    // password piped via stdin still unlocks the vault, the env-var
    // value is ignored, and the warning lands in stderr.
    let reg = VaultsToml::new();
    create_fixture_vault(&reg, "correct");

    let mut cmd = falach_cmd_keep_env();
    cmd.env("FALACH_MASTER_PASSWORD", "leak-me-if-you-can")
        .env_remove("FALACH_STATE_DIR")
        .args([
            "--registry",
            &reg.registry_arg(),
            "vault",
            "open",
            "--id",
            "mp",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn falach vault open");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"correct\n")
        .expect("write stdin");
    let output = child
        .wait_with_output()
        .expect("wait for falach vault open");

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "exit code should be 0; stderr was:\n{stderr}"
    );
    assert!(
        stderr.contains("FALACH_MASTER_PASSWORD") && stderr.contains("ignored"),
        "expected warn-and-ignore line in stderr; got:\n{stderr}"
    );
    // Defence-in-depth: the warning text must NOT echo the env-var's
    // value — that would defeat the leak-prevention contract.
    assert!(
        !stderr.contains("leak-me-if-you-can"),
        "stderr leaked the env-var value: {stderr:?}"
    );
}

#[test]
#[ignore = "mutates FALACH_MASTER_PASSWORD on the spawned child; run via `make test-ignored`"]
fn env_var_value_is_not_used_as_password() {
    // When FALACH_MASTER_PASSWORD is set to a non-matching value AND
    // the stdin prompt receives the WRONG password, the env-var value
    // must not be used as a fallback. The expected behaviour is auth
    // failure (exit 2) for the wrong stdin value — the env var is
    // ignored, full stop.
    let reg = VaultsToml::new();
    create_fixture_vault(&reg, "correct");

    let mut cmd = falach_cmd_keep_env();
    cmd.env("FALACH_MASTER_PASSWORD", "correct")
        .env_remove("FALACH_STATE_DIR")
        .args([
            "--registry",
            &reg.registry_arg(),
            "vault",
            "open",
            "--id",
            "mp",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn falach vault open");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"wrong\n")
        .expect("write stdin");
    let output = child
        .wait_with_output()
        .expect("wait for falach vault open");

    // If the env-var value were used as a fallback, this would
    // succeed (because `correct` does match). It must fail with
    // exit 2 (vault.locked).
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected auth-failure exit 2 — env var must not be used; \
         stderr was:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "grouped with the env-var tests in the test-ignored tier"]
fn no_master_password_flag_is_rejected_by_clap() {
    // FR-061 structural gate: there is no `--master-password` flag
    // anywhere. clap rejects the unknown argument with its standard
    // exit code 2 (per the design's two-meanings-for-exit-2 note in
    // §2.4.2 — distinct from CliExit::VaultLocked which also uses 2,
    // but produced by clap's parser rather than the runtime).
    let output = Command::new(falach_bin())
        .env_remove("FALACH_MASTER_PASSWORD")
        .env_remove("FALACH_STATE_DIR")
        .args(["vault", "open", "--id", "x", "--master-password=bypass"])
        .output()
        .expect("spawn falach");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(
        output.status.code(),
        Some(2),
        "clap should reject the unknown flag with exit 2; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("--master-password") || stderr.to_lowercase().contains("unexpected"),
        "stderr should name the rejected argument:\n{stderr}"
    );
    // Defence-in-depth: the value MUST NOT leak into stderr.
    assert!(
        !stderr.contains("bypass"),
        "stderr leaked the would-be password value: {stderr:?}"
    );
}

#[test]
#[ignore = "spawns the binary repeatedly; serialized with the env-var tests in test-ignored"]
fn rpassword_replacement_uses_no_echo_path() {
    // The TTY no-echo path runs inside `read_password_no_echo` (see
    // `crates/falach-cli/src/prompt.rs`) and toggles termios via
    // `nix::sys::termios::tcsetattr`. Asserting the actual echo state
    // requires a PTY harness, which is out of scope for CI per design
    // §6 row 9. The unit tests in `prompt.rs::tests` exercise the
    // pipe-fallback path (no echo to toggle); the manual verification
    // document `verifications/01-local/03-master-password.md` covers
    // the real-TTY case.
    //
    // What we CAN verify here is the structural invariant: the prompt
    // function is reachable via the `vault open` happy path with
    // stdin piped. If this passes, the prompt path itself ran.
    let reg = VaultsToml::new();
    create_fixture_vault(&reg, "correct");

    let mut cmd = falach_cmd_keep_env();
    cmd.env_remove("FALACH_MASTER_PASSWORD")
        .env_remove("FALACH_STATE_DIR")
        .args([
            "--registry",
            &reg.registry_arg(),
            "vault",
            "open",
            "--id",
            "mp",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn falach vault open");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"correct\n")
        .expect("write stdin");
    let output = child
        .wait_with_output()
        .expect("wait for falach vault open");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "happy-path open should succeed; stderr was:\n{stderr}"
    );
    // The prompt label written to stderr proves the prompt path ran.
    assert!(
        stderr.contains("Master password:"),
        "expected the prompt label to appear in stderr:\n{stderr}"
    );
}
