//! End-to-end gen-subcommand integration tests.
//!
//! `falach gen` is the only family that does not open a vault, so the
//! tests are pleasantly terse: no master-password prompt, no
//! `--registry` argument needed, the binary just needs to be invoked.

mod common;

use common::run_args;
use serde_json::Value;

#[test]
fn gen_password_default_human_prints_value() {
    let (code, stdout, _) = run_args(&["gen", "password"]);
    assert_eq!(code, 0);
    // Default length is 20; human-mode output is `<value>\n`.
    let line = stdout.trim_end();
    assert_eq!(line.chars().count(), 20, "default length 20; got {line:?}");
}

#[test]
fn gen_password_custom_length_human() {
    let (code, stdout, _) = run_args(&["gen", "password", "--length", "32"]);
    assert_eq!(code, 0);
    let line = stdout.trim_end();
    assert_eq!(line.chars().count(), 32);
}

#[test]
fn gen_password_json_default_omits_value() {
    let (code, stdout, _) = run_args(&["--format", "json", "gen", "password", "--length", "16"]);
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert!(
        v.get("password").is_none(),
        "JSON default must omit the password value"
    );
    assert_eq!(v["length"], 16);
    assert!(v["classes"].is_array(), "classes field is an array");
    assert_eq!(v["exclude_ambiguous"], false);
}

#[test]
fn gen_password_json_show_emits_value() {
    let (code, stdout, _) = run_args(&[
        "--format", "json", "gen", "password", "--length", "16", "--show",
    ]);
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let pw = v["password"].as_str().expect("password present");
    assert_eq!(pw.chars().count(), 16);
}

#[test]
fn gen_password_class_disable_propagates_to_json() {
    let (code, stdout, _) = run_args(&[
        "--format",
        "json",
        "gen",
        "password",
        "--length",
        "12",
        "--no-symbols",
        "--no-digits",
    ]);
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let classes: Vec<&str> = v["classes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    assert!(classes.contains(&"lowercase"));
    assert!(classes.contains(&"uppercase"));
    assert!(!classes.contains(&"digits"));
    assert!(!classes.contains(&"symbols"));
}

#[test]
fn gen_password_exclude_ambiguous_propagates_to_json() {
    let (code, stdout, _) = run_args(&[
        "--format",
        "json",
        "gen",
        "password",
        "--length",
        "20",
        "--exclude-ambiguous",
    ]);
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["exclude_ambiguous"], true);
}

#[test]
fn gen_passphrase_default_human_six_words() {
    let (code, stdout, _) = run_args(&["gen", "passphrase"]);
    assert_eq!(code, 0);
    let line = stdout.trim_end();
    let words: Vec<&str> = line.split('-').collect();
    assert_eq!(words.len(), 6, "default 6 words; got {line:?}");
}

#[test]
fn gen_passphrase_custom_word_count() {
    let (code, stdout, _) = run_args(&["gen", "passphrase", "--word-count", "8"]);
    assert_eq!(code, 0);
    let words: Vec<&str> = stdout.trim_end().split('-').collect();
    assert_eq!(words.len(), 8);
}

#[test]
fn gen_passphrase_custom_separator() {
    let (code, stdout, _) =
        run_args(&["gen", "passphrase", "--word-count", "4", "--separator", " "]);
    assert_eq!(code, 0);
    let words: Vec<&str> = stdout.trim_end().split(' ').collect();
    assert_eq!(words.len(), 4);
}

#[test]
fn gen_passphrase_json_default_omits_value() {
    let (code, stdout, _) =
        run_args(&["--format", "json", "gen", "passphrase", "--word-count", "5"]);
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert!(
        v.get("passphrase").is_none(),
        "JSON default must omit the passphrase value"
    );
    assert_eq!(v["word_count"], 5);
    assert_eq!(v["separator"], "-");
    assert_eq!(v["wordlist"], "eff-large");
}

#[test]
fn gen_passphrase_json_show_emits_value() {
    let (code, stdout, _) = run_args(&[
        "--format",
        "json",
        "gen",
        "passphrase",
        "--word-count",
        "3",
        "--show",
    ]);
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let value = v["passphrase"].as_str().expect("passphrase present");
    assert_eq!(value.split('-').count(), 3);
}

#[test]
fn gen_password_show_and_copy_are_mutually_exclusive() {
    // clap rejects conflicting flags with its own exit 2 (parse error).
    let (code, _stdout, _stderr) = run_args(&["gen", "password", "--show", "--copy"]);
    assert_eq!(code, 2);
}

/// Regression test for the "two JSON docs on stdout" bug: when
/// `--copy` is requested and the clipboard backend is unavailable
/// (headless host with no `$DISPLAY` / `$WAYLAND_DISPLAY`), the CLI
/// must emit exactly ONE JSON document — the error envelope. The old
/// code wrote the success view before attempting the clipboard arm,
/// so a failure produced two concatenated JSON documents and broke
/// any `--format json | jq` pipeline.
#[test]
fn gen_password_copy_json_failure_emits_single_error_envelope_on_stdout() {
    // Clear the display env vars on the spawned child so arboard's
    // backend construction fails deterministically with
    // ClipboardUnavailable. Note: on macOS the NSPasteboard is
    // available regardless of $DISPLAY, so this test only meaningfully
    // exercises the failure path on Linux. On macOS dev hosts the
    // arming succeeds and the test would block on wait_for_clear for
    // 30s; gate the assertion on the observed exit code so the test
    // is a no-op when the clipboard happens to be available.
    use std::process::Command;
    let output = Command::new(env!("CARGO_BIN_EXE_falach"))
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("FALACH_MASTER_PASSWORD")
        .env_remove("FALACH_STATE_DIR")
        .args(["--format", "json", "gen", "password", "--copy"])
        .output()
        .expect("spawn falach");

    if output.status.code() == Some(0) {
        // Host had a clipboard available; can't trigger the failure
        // path here. The arming-failure branch is covered on headless
        // CI runners.
        return;
    }
    assert_eq!(
        output.status.code(),
        Some(10),
        "expected exit 10 (Internal) for ClipboardUnavailable; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let docs: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        docs.len(),
        1,
        "expected exactly ONE JSON doc on stdout; got {n} documents:\n{stdout}",
        n = docs.len()
    );
    let parsed: Value = serde_json::from_str(docs[0]).expect("valid JSON");
    assert!(
        parsed.get("error").is_some(),
        "expected error envelope on stdout, got: {parsed}"
    );
    // No success-shape key should appear alongside the error.
    assert!(
        parsed.get("password").is_none() && parsed.get("length").is_none(),
        "stdout leaked the success view: {parsed}"
    );
}
