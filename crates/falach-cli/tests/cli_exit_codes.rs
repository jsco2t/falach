//! Phase-1-reachable exit codes:
//!
//! - **0** — `--help` short-circuit
//! - **2** — clap's parse-failure default (e.g. unknown subcommand)
//! - **11** — `CliExit::NotImplemented` returned by every stub body
//!
//! Phases 2–4 add coverage for codes 1 (real user-error paths), 2
//! (real auth failure via vault-core), 3 (sync conflict), and 10
//! (internal errors). The codes table itself is frozen at MVP merge.

mod common;

use common::{run_args, run_with_stdin, VaultsToml};

#[test]
fn help_exits_zero() {
    let (code, _stdout, _stderr) = run_args(&["--help"]);
    assert_eq!(code, 0);
}

#[test]
fn unknown_subcommand_exits_two_via_clap() {
    // clap's default exit code for parse failures is 2. Documented in
    // the design's exit-code table (code 1 is reserved for user errors
    // produced by *the program*; clap's own parse failures fall under
    // 2 by clap convention).
    let (code, _stdout, stderr) = run_args(&["definitely-not-a-subcommand"]);
    assert_eq!(code, 2, "stderr was:\n{stderr}");
}

#[test]
fn vault_with_no_verb_exits_user_error() {
    // Phase 2: `vault` is a real verb tree now. Invoking it without
    // a sub-verb returns a clear UserError (exit 1) rather than
    // panicking or printing nothing. (Phase 1 returned NotImplemented
    // exit 11 since the body was a stub; Phase 2 replaced the stub
    // with a verb dispatcher.)
    let (code, _stdout, stderr) = run_args(&["vault"]);
    assert_eq!(code, 1, "expected UserError; stderr:\n{stderr}");
    assert!(
        stderr.contains("user.error"),
        "stderr should mention user.error kind:\n{stderr}"
    );
    assert!(
        stderr.contains("missing subcommand"),
        "stderr should explain the missing-verb cause:\n{stderr}"
    );
}

#[test]
fn entry_with_no_verb_exits_user_error() {
    // Phase 3: `entry` is a real verb tree now. Invoking it without a
    // sub-verb returns UserError (exit 1) rather than the Phase-1 stub
    // exit-11.
    let (code, _stdout, stderr) = run_args(&["entry"]);
    assert_eq!(code, 1, "expected UserError; stderr:\n{stderr}");
    assert!(
        stderr.contains("user.error"),
        "stderr should name the kind:\n{stderr}"
    );
    assert!(
        stderr.contains("missing subcommand"),
        "stderr should explain the missing-verb cause:\n{stderr}"
    );
}

#[test]
fn gen_with_no_verb_exits_user_error() {
    // Phase 3: same pattern as `entry`.
    let (code, _stdout, stderr) = run_args(&["gen"]);
    assert_eq!(code, 1, "expected UserError; stderr:\n{stderr}");
    assert!(
        stderr.contains("missing subcommand"),
        "stderr should explain the missing-verb cause:\n{stderr}"
    );
}

// `falach sync` was a NotImplemented slot through Phase 2; its exit-11
// stub tests (`sync_slot_exits_eleven`, `sync_slot_with_vault_flag_exits_eleven`)
// were removed when the real body landed (features/cli-sync-wiring/ Phase 3).
// End-to-end behaviour now lives in `cli_sync.rs` (error paths) +
// `cli_sync_minio.rs` (gated happy path).

#[test]
fn ssh_slot_exits_eleven() {
    let (code, _stdout, stderr) = run_args(&["ssh"]);
    assert_eq!(code, 11);
    assert!(
        stderr.contains("features/ssh-keys/"),
        "stub message should point at the implementing feature:\n{stderr}"
    );
}

#[test]
fn ssh_add_slot_exits_eleven_with_feature_pointer() {
    let (code, _stdout, stderr) = run_args(&[
        "ssh",
        "add",
        "--vault",
        "test",
        "--key-path",
        "/tmp/id_ed25519",
    ]);
    assert_eq!(code, 11, "stderr was:\n{stderr}");
    assert!(
        stderr.contains("ssh add") && stderr.contains("features/ssh-keys/"),
        "stub message should name the verb + feature:\n{stderr}"
    );
}

#[test]
fn ssh_load_slot_exits_eleven_with_feature_pointer() {
    let (code, _stdout, stderr) = run_args(&[
        "ssh",
        "load",
        "--vault",
        "test",
        "--uuid",
        "11111111-2222-3333-4444-555555555555",
        "--ttl",
        "60",
    ]);
    assert_eq!(code, 11, "stderr was:\n{stderr}");
    assert!(
        stderr.contains("ssh load") && stderr.contains("features/ssh-keys/"),
        "stub message should name the verb + feature:\n{stderr}"
    );
}

#[test]
fn ssh_generate_slot_exits_eleven_with_feature_pointer() {
    let (code, _stdout, stderr) = run_args(&[
        "ssh",
        "generate",
        "--vault",
        "test",
        "--algorithm",
        "ed25519",
    ]);
    assert_eq!(code, 11, "stderr was:\n{stderr}");
    assert!(
        stderr.contains("ssh generate") && stderr.contains("features/ssh-keys/"),
        "stub message should name the verb + feature:\n{stderr}"
    );
}

// `vault set-sync` was a NotImplemented slot in Phase 1; its exit-11
// stub test was removed when the real body landed (features/cli-sync-
// wiring/ Phase 2). End-to-end behaviour now lives in `cli_set_sync.rs`.

#[test]
fn json_format_flag_parses_globally() {
    // `--format json` should be accepted as a global flag on any
    // subcommand. We use `--help` after it to avoid running stub
    // bodies (which would still exit 11 — that's fine, just slower).
    let (code, _stdout, _stderr) = run_args(&["--format", "json", "vault", "--help"]);
    assert_eq!(code, 0);
}

#[test]
fn json_format_flag_after_subcommand_also_works() {
    // clap derive `global = true` lets the flag appear before OR after
    // the subcommand. Test both — drift in this behaviour silently
    // breaks user scripts.
    let (code, _stdout, _stderr) = run_args(&["vault", "--format", "json", "--help"]);
    assert_eq!(code, 0);
}

// ---------------------------------------------------------------------------
// Phase 2: vault-specific exit-code paths.
// ---------------------------------------------------------------------------

/// `falach vault list` against an empty registry: exit 0, JSON shape
/// `{"vaults": []}`.
#[test]
fn exit_code_0_vault_list_empty_registry() {
    let reg = VaultsToml::new();
    let (code, stdout, stderr) = run_with_stdin(&reg, &["vault", "list", "--format", "json"], "");
    assert_eq!(code, 0, "stderr was:\n{stderr}");
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(parsed["vaults"], serde_json::json!([]));
}

/// `falach vault open --id nonexistent` → exit 1 (`NotRegistered`).
/// The probe never reaches the password prompt because the registry
/// lookup fails first, so no stdin input needed.
#[test]
fn exit_code_1_vault_open_not_registered() {
    let reg = VaultsToml::new();
    let (code, _stdout, stderr) = run_with_stdin(&reg, &["vault", "open", "--id", "ghost"], "");
    assert_eq!(code, 1, "stderr was:\n{stderr}");
    assert!(
        stderr.contains("ghost"),
        "stderr should name the missing vault:\n{stderr}"
    );
    assert!(
        stderr.contains("user.error"),
        "stderr should mention user.error kind:\n{stderr}"
    );
}

/// `falach vault create` without `--no-recovery-warning` → exit 1.
#[test]
fn exit_code_1_vault_create_missing_no_recovery_warning() {
    let reg = VaultsToml::new();
    let path = reg.tempdir.path().join("new.kdbx");
    let (code, _stdout, stderr) = run_with_stdin(
        &reg,
        &[
            "vault",
            "create",
            "--id",
            "new",
            "--path",
            path.to_str().unwrap(),
        ],
        "",
    );
    assert_eq!(code, 1, "stderr was:\n{stderr}");
    assert!(
        stderr.contains("no-recovery"),
        "stderr should mention no-recovery requirement:\n{stderr}"
    );
}

/// `vault set-lock` rejects `--timeout 0` with exit 1.
#[test]
fn exit_code_1_vault_set_lock_timeout_zero_rejected() {
    let reg = VaultsToml::new();
    // Pre-register a vault so the dispatch reaches the timeout check.
    common::seed_vault(&reg, "v", "match");

    let (code, _stdout, stderr) = run_with_stdin(
        &reg,
        &["vault", "set-lock", "--id", "v", "--timeout", "0"],
        "",
    );
    assert_eq!(code, 1, "stderr was:\n{stderr}");
    assert!(
        stderr.contains("at least 1"),
        "stderr should explain the rejection:\n{stderr}"
    );
}

/// Auth failure path: create a vault with `correct`, then probe with
/// `wrong` → exit 2 (`vault.locked`).
#[test]
fn exit_code_2_vault_open_auth_failure() {
    let reg = VaultsToml::new();
    common::seed_vault(&reg, "auth", "correct");

    let (open_code, _stdout, stderr) =
        run_with_stdin(&reg, &["vault", "open", "--id", "auth"], "wrong\n");
    assert_eq!(open_code, 2, "wrong password → exit 2; stderr:\n{stderr}");
    assert!(
        stderr.contains("vault.locked"),
        "stderr should mention vault.locked kind:\n{stderr}"
    );
}

/// Same auth-failure path in JSON mode: error envelope on **stdout**,
/// not stderr.
#[test]
fn exit_code_2_vault_open_auth_failure_json_envelope_on_stdout() {
    let reg = VaultsToml::new();
    common::seed_vault(&reg, "auth2", "correct");

    let (open_code, stdout, _stderr) = run_with_stdin(
        &reg,
        &["--format", "json", "vault", "open", "--id", "auth2"],
        "wrong\n",
    );
    assert_eq!(open_code, 2);
    // Strip any leading/trailing whitespace; JSON envelope is a single
    // compact line per design §3.4.
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("JSON envelope on stdout");
    assert_eq!(parsed["error"]["code"], 2);
    assert_eq!(parsed["error"]["kind"], "vault.locked");
}

// ---------------------------------------------------------------------------
// Phase 3: entry- and gen-specific exit-code paths.
// ---------------------------------------------------------------------------

/// `falach entry get --uuid <bogus>` against a vault that lacks the
/// UUID → exit 1 (`EntryNotFound`).
#[test]
fn exit_code_1_entry_not_found() {
    let reg = VaultsToml::new();
    common::seed_vault(&reg, "e", "pw");

    let bogus = "11111111-2222-3333-4444-555555555555";
    let (code, _stdout, stderr) = run_with_stdin(
        &reg,
        &["entry", "get", "--vault", "e", "--uuid", bogus],
        "pw\n",
    );
    assert_eq!(code, 1, "stderr:\n{stderr}");
    assert!(
        stderr.contains("entry not found"),
        "stderr should mention entry-not-found:\n{stderr}"
    );
}

/// `falach entry list` against a vault with the wrong master password
/// → exit 2 (`vault.locked`).
#[test]
fn exit_code_2_auth_failure_on_entry_vault() {
    let reg = VaultsToml::new();
    common::seed_vault(&reg, "ev", "right");

    let (code, _stdout, stderr) =
        run_with_stdin(&reg, &["entry", "list", "--vault", "ev"], "wrong\n");
    assert_eq!(code, 2, "stderr:\n{stderr}");
    assert!(
        stderr.contains("vault.locked"),
        "stderr should name the kind:\n{stderr}"
    );
}

/// `falach gen password --no-lowercase --no-uppercase --no-digits
/// --no-symbols` → exit 1 (`NoClassesEnabled` mapped from `GenError`).
#[test]
fn exit_code_1_gen_password_all_classes_disabled() {
    let (code, _stdout, stderr) = run_args(&[
        "gen",
        "password",
        "--no-lowercase",
        "--no-uppercase",
        "--no-digits",
        "--no-symbols",
    ]);
    assert_eq!(code, 1, "stderr:\n{stderr}");
    assert!(
        stderr.contains("user.error"),
        "stderr should name the kind:\n{stderr}"
    );
}
