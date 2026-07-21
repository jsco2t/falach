//! `entry get --copy` clipboard hand-off — gated behind
//! `make test-clipboard` (runs `cargo test -- --ignored`) because the
//! `arboard` backend requires a real X11 / Wayland display server.
//!
//! No CI job runs this file (hosted runners lack a usable display);
//! run it locally via `make test-clipboard` (wrap in `xvfb-run -a` on
//! a headless Linux box). On a Linux dev box without a display server
//! the test will fail to open the clipboard and the binary will exit
//! code 10 — `make test-clipboard` is the shield against running these
//! from a headless tty. CI compiles (but does not run) this file via
//! `make check-feature-gates`.
//!
//! The test does NOT inspect the clipboard contents (that's
//! security-behaviors' US-053 territory). Here we just assert the CLI
//! hands the value to security-behaviors correctly:
//!
//! - Exit code is 0 (the auto-clear timer fired and the wait returned).
//! - stdout is empty (the password was not echoed).
//! - stderr contains the documented "copied to clipboard" line.
//! - The whole call returns within `TTL + slack`.
//!
//! The whole file is gated behind the `clipboard-tests` cargo feature
//! so the blanket `make test-ignored` sweep
//! (`cargo test --workspace -- --ignored`) never compiles or runs it on
//! a headless host. Only `make test-clipboard` enables the feature.
#![cfg(feature = "clipboard-tests")]

mod common;

use std::time::{Duration, Instant};

use common::{run_with_stdin, VaultsToml};
use serde_json::Value;

/// Slack added to the 30s TTL so a slightly-late timer doesn't fail the
/// assertion. Picked generously — the test isn't a benchmark.
const SLACK_SECS: u64 = 15;

#[test]
#[ignore = "requires a display server; gated by `make test-clipboard`"]
fn entry_get_copy_invokes_clipboard_and_blocks_on_wait_for_clear() {
    let reg = VaultsToml::new();
    let path = reg.tempdir.path().join("c.kdbx");
    let pw = "pw";

    // Seed: create vault + one entry with a known password via --generate.
    let (code, _stdout, stderr) = run_with_stdin(
        &reg,
        &[
            "vault",
            "create",
            "--id",
            "c",
            "--path",
            path.to_str().unwrap(),
            "--no-recovery-warning",
        ],
        &format!("{pw}\n{pw}\n"),
    );
    assert_eq!(code, 0, "create stderr:\n{stderr}");

    let (code, stdout, stderr) = run_with_stdin(
        &reg,
        &[
            "--format",
            "json",
            "entry",
            "add",
            "--vault",
            "c",
            "--title",
            "Copy",
            "--generate",
        ],
        &format!("{pw}\n"),
    );
    assert_eq!(code, 0, "add stderr:\n{stderr}");
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    let uuid = v["uuid"].as_str().unwrap().to_owned();

    // Act: invoke `entry get --copy` and time the call.
    let start = Instant::now();
    let (code, stdout, stderr) = run_with_stdin(
        &reg,
        &["entry", "get", "--vault", "c", "--uuid", &uuid, "--copy"],
        &format!("{pw}\n"),
    );
    let elapsed = start.elapsed();

    // Assert: exit 0, stdout free of the password, stderr says copy.
    assert_eq!(code, 0, "stderr:\n{stderr}");
    assert!(
        !stdout.contains("password"),
        "stdout must not echo the password under --copy: {stdout:?}"
    );
    assert!(
        stderr.contains("copied to clipboard"),
        "stderr should announce the copy:\n{stderr}"
    );
    assert!(
        elapsed < Duration::from_secs(30 + SLACK_SECS),
        "call should return within TTL + slack ({SLACK_SECS}s); took {elapsed:?}"
    );
}
