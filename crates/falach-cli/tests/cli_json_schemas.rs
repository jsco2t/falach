//! JSON-schema regression gate for the `vault` subcommand views.
//!
//! Each test invokes a `falach vault ... --format json` command
//! against an isolated tempdir-rooted registry and parses the stdout
//! into a `serde_json::Value`. The assertions compare specific
//! field/type pairs rather than full structural equality — this
//! keeps the test stable across new optional fields (additive
//! evolution) while still catching renames or type changes
//! (breaking).
//!
//! Per design §2.4.1, the per-subcommand view structs in
//! `crates/falach-cli/src/views/vault.rs` ARE the schema; these tests
//! are the runtime regression gate.

mod common;

use common::{run_with_stdin, VaultsToml};

#[test]
fn vault_create_view_json_schema() {
    let reg = VaultsToml::new();
    let path = reg.tempdir.path().join("new.kdbx");
    let (code, stdout, stderr) = run_with_stdin(
        &reg,
        &[
            "--format",
            "json",
            "vault",
            "create",
            "--id",
            "new",
            "--path",
            path.to_str().unwrap(),
            "--no-recovery-warning",
        ],
        "match-me\nmatch-me\n",
    );
    assert_eq!(code, 0, "stderr:\n{stderr}");

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(parsed["id"], "new");
    assert_eq!(parsed["path"], path.display().to_string());
    assert!(
        parsed.get("keyfile").is_none(),
        "keyfile must be absent when not supplied"
    );
    // KDF sub-object — verify field names + types, not exact numeric
    // values (those come from falach-core's KdfParams::default and
    // may evolve).
    let kdf = &parsed["kdf"];
    assert_eq!(kdf["algorithm"], "argon2id");
    assert!(kdf["memory_kib"].is_u64(), "memory_kib must be an integer");
    assert!(kdf["iterations"].is_u64(), "iterations must be an integer");
    assert!(
        kdf["parallelism"].is_u64(),
        "parallelism must be an integer"
    );
}

#[test]
fn vault_list_view_json_schema_with_one_entry() {
    let reg = VaultsToml::new();
    let path = common::seed_vault(&reg, "p", "x");

    let (code, stdout, stderr) = run_with_stdin(&reg, &["--format", "json", "vault", "list"], "");
    assert_eq!(code, 0, "stderr:\n{stderr}");

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let entries = parsed["vaults"].as_array().expect("vaults is an array");
    assert_eq!(entries.len(), 1);
    let e = &entries[0];
    assert_eq!(e["id"], "p");
    assert_eq!(e["path"], path.display().to_string());
    assert!(e["created_at"].is_string(), "created_at must be a string");
    // Optional fields absent when unset.
    assert!(e.get("keyfile").is_none(), "keyfile absent");
    assert!(
        e.get("idle_timeout_seconds").is_none(),
        "idle_timeout_seconds absent when no override set"
    );
}

#[test]
fn vault_set_lock_view_json_schema_with_timeout() {
    let reg = VaultsToml::new();
    common::seed_vault(&reg, "locked", "y");

    let (code, stdout, stderr) = run_with_stdin(
        &reg,
        &[
            "--format",
            "json",
            "vault",
            "set-lock",
            "--id",
            "locked",
            "--timeout",
            "600",
        ],
        "",
    );
    assert_eq!(code, 0, "stderr:\n{stderr}");
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(parsed["id"], "locked");
    assert_eq!(parsed["idle_timeout_seconds"], 600);
}

#[test]
fn vault_set_lock_view_json_schema_cleared_omits_field() {
    let reg = VaultsToml::new();
    common::seed_vault(&reg, "c", "z");
    // First set, then clear.
    run_with_stdin(
        &reg,
        &["vault", "set-lock", "--id", "c", "--timeout", "300"],
        "",
    );
    let (code, stdout, stderr) = run_with_stdin(
        &reg,
        &[
            "--format", "json", "vault", "set-lock", "--id", "c", "--clear",
        ],
        "",
    );
    assert_eq!(code, 0, "stderr:\n{stderr}");
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(parsed["id"], "c");
    assert!(
        parsed.get("idle_timeout_seconds").is_none(),
        "cleared override must omit the field, not emit null"
    );
}

// ---------------------------------------------------------------------------
// Phase 3: entry + gen JSON-schema gates.
// ---------------------------------------------------------------------------

const PW: &str = "pw";

/// Seed a vault named `v` and add one entry; return its UUID.
fn seed_entry(reg: &VaultsToml) -> String {
    common::seed_vault(reg, "v", PW);
    let (code, stdout, _) = run_with_stdin(
        reg,
        &[
            "--format",
            "json",
            "entry",
            "add",
            "--vault",
            "v",
            "--title",
            "GitHub",
            "--username",
            "alice",
            "--generate",
            "--length",
            "16",
        ],
        &format!("{PW}\n"),
    );
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    v["uuid"].as_str().unwrap().to_owned()
}

#[test]
fn entry_add_view_json_schema() {
    let reg = VaultsToml::new();
    let uuid = seed_entry(&reg);
    // `seed_entry` already validated exit 0; here we just check the
    // schema shape from a second invocation that re-asserts.
    let (code, stdout, _) = run_with_stdin(
        &reg,
        &[
            "--format",
            "json",
            "entry",
            "add",
            "--vault",
            "v",
            "--title",
            "Second",
            "--generate",
        ],
        &format!("{PW}\n"),
    );
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert!(v["uuid"].is_string(), "uuid is a string");
    assert_eq!(v["title"], "Second");
    assert!(v["group"].is_string(), "group is a string");
    assert!(
        v.get("password").is_none(),
        "password omitted without --show-password"
    );
    // The original `uuid` returned by `seed_entry` is also a valid v4
    // UUID — sanity.
    assert!(uuid::Uuid::parse_str(&uuid).is_ok());
}

#[test]
fn entry_get_view_json_schema_without_password() {
    let reg = VaultsToml::new();
    let uuid = seed_entry(&reg);
    let (code, stdout, _) = run_with_stdin(
        &reg,
        &[
            "--format", "json", "entry", "get", "--vault", "v", "--uuid", &uuid,
        ],
        &format!("{PW}\n"),
    );
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["uuid"], uuid);
    assert_eq!(v["title"], "GitHub");
    assert!(v["tags"].is_array());
    assert!(v["expired"].is_boolean());
    assert!(v["has_attachments"].is_boolean());
    assert!(v["has_totp"].is_boolean());
    assert!(
        v.get("password").is_none(),
        "password omitted without --show-password"
    );
    assert!(v.get("totp_code").is_none());
}

#[test]
fn entry_list_view_json_schema() {
    let reg = VaultsToml::new();
    let _ = seed_entry(&reg);
    let (code, stdout, _) = run_with_stdin(
        &reg,
        &["--format", "json", "entry", "list", "--vault", "v"],
        &format!("{PW}\n"),
    );
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let entries = v["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 1);
    let e = &entries[0];
    assert!(e["uuid"].is_string());
    assert_eq!(e["title"], "GitHub");
    assert!(e["group"].is_string());
    assert!(e["tags"].is_array());
    assert!(e["expired"].is_boolean());
}

#[test]
fn entry_search_view_json_schema() {
    let reg = VaultsToml::new();
    let _ = seed_entry(&reg);
    let (code, stdout, _) = run_with_stdin(
        &reg,
        &[
            "--format", "json", "entry", "search", "--vault", "v", "github",
        ],
        &format!("{PW}\n"),
    );
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["query"], "github");
    let matches = v["matches"].as_array().expect("matches array");
    assert_eq!(matches.len(), 1);
}

#[test]
fn entry_rm_view_json_schema() {
    let reg = VaultsToml::new();
    let uuid = seed_entry(&reg);
    let (code, stdout, _) = run_with_stdin(
        &reg,
        &[
            "--format", "json", "entry", "rm", "--vault", "v", "--uuid", &uuid,
        ],
        &format!("{PW}\n"),
    );
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["uuid"], uuid);
    assert_eq!(v["recycle_bin"], true);
}

#[test]
fn gen_password_view_json_schema_omits_value_by_default() {
    let (code, stdout, _) = run_with_stdin(
        &VaultsToml::new(),
        &["--format", "json", "gen", "password", "--length", "20"],
        "",
    );
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert!(v.get("password").is_none());
    assert_eq!(v["length"], 20);
    assert!(v["classes"].is_array());
    assert_eq!(v["exclude_ambiguous"], false);
}

#[test]
fn gen_passphrase_view_json_schema_omits_value_by_default() {
    let (code, stdout, _) = run_with_stdin(
        &VaultsToml::new(),
        &["--format", "json", "gen", "passphrase", "--word-count", "5"],
        "",
    );
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert!(v.get("passphrase").is_none());
    assert_eq!(v["word_count"], 5);
    assert_eq!(v["separator"], "-");
    assert_eq!(v["wordlist"], "eff-large");
}

#[test]
fn error_envelope_json_schema_on_auth_failure() {
    let reg = VaultsToml::new();
    common::seed_vault(&reg, "auth", "correct");
    let (code, stdout, _stderr) = run_with_stdin(
        &reg,
        &["--format", "json", "vault", "open", "--id", "auth"],
        "wrong\n",
    );
    assert_eq!(code, 2);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    // Envelope shape: {"error": {"code": N, "kind": "...", "message": "..."}}
    let err = &parsed["error"];
    assert_eq!(err["code"], 2);
    assert_eq!(err["kind"], "vault.locked");
    assert!(
        err["message"].as_str().is_some_and(|s| !s.is_empty()),
        "error.message must be a non-empty string"
    );
}
