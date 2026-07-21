//! End-to-end entry-subcommand integration tests.
//!
//! Each test exercises a single user-visible flow against a fresh
//! `--registry`-isolated tempdir. Vaults are seeded with a fast test
//! KDF via `common::seed_vault` (not the binary's production-KDF
//! `vault create`) so the test body — and every unlock the spawned
//! binary performs — focuses on the `entry`-specific behaviour instead
//! of re-paying Argon2id.

mod common;

use common::{run_with_stdin, seed_vault, VaultsToml};
use serde_json::Value;

/// Master password used by every test below. Kept tiny — Argon2id is
/// the same cost regardless of input length.
const PW: &str = "pw";

/// Create a fresh registry + fast-KDF vault named `name`.
fn vault_named(name: &str) -> VaultsToml {
    let reg = VaultsToml::new();
    seed_vault(&reg, name, PW);
    reg
}

/// Add a known entry (title `"GitHub"`, generated password) and return
/// its UUID, as parsed from the JSON-mode `entry add` output.
fn add_github_entry(reg: &VaultsToml) -> String {
    let (code, stdout, stderr) = run_with_stdin(
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
            "--url",
            "https://github.com",
            "--generate",
            "--length",
            "24",
            "--tag",
            "work",
            "--tag",
            "personal",
        ],
        &format!("{PW}\n"),
    );
    assert_eq!(code, 0, "entry add failed: {stderr}");
    let parsed: Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(parsed["title"], "GitHub");
    parsed["uuid"].as_str().expect("uuid string").to_owned()
}

#[test]
fn entry_lifecycle_add_get_edit_rm() {
    let reg = vault_named("v");
    let uuid = add_github_entry(&reg);

    // 1. get with JSON omits password by default
    let (code, stdout, _) = run_with_stdin(
        &reg,
        &[
            "--format", "json", "entry", "get", "--vault", "v", "--uuid", &uuid,
        ],
        &format!("{PW}\n"),
    );
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["uuid"], uuid);
    assert_eq!(v["title"], "GitHub");
    assert_eq!(v["username"], "alice");
    assert_eq!(v["url"], "https://github.com");
    assert!(v.get("password").is_none(), "password absent by default");
    let tags = v["tags"].as_array().unwrap();
    assert!(tags.iter().any(|t| t == "work"));
    assert!(tags.iter().any(|t| t == "personal"));

    // 2. edit — add a tag, remove another
    let (code, stdout, _) = run_with_stdin(
        &reg,
        &[
            "--format",
            "json",
            "entry",
            "edit",
            "--vault",
            "v",
            "--uuid",
            &uuid,
            "--add-tag",
            "urgent",
            "--rm-tag",
            "personal",
        ],
        &format!("{PW}\n"),
    );
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["uuid"], uuid);
    let modified = v["modified_fields"].as_array().unwrap();
    assert!(modified.iter().any(|m| m == "tags"));

    // 3. get again — confirm tag mutations persisted
    let (code, stdout, _) = run_with_stdin(
        &reg,
        &[
            "--format", "json", "entry", "get", "--vault", "v", "--uuid", &uuid,
        ],
        &format!("{PW}\n"),
    );
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    let tags = v["tags"].as_array().unwrap();
    assert!(tags.iter().any(|t| t == "urgent"), "urgent tag added");
    assert!(
        !tags.iter().any(|t| t == "personal"),
        "personal tag removed"
    );

    // 4. rm with recycle-bin default
    let (code, stdout, _) = run_with_stdin(
        &reg,
        &[
            "--format", "json", "entry", "rm", "--vault", "v", "--uuid", &uuid,
        ],
        &format!("{PW}\n"),
    );
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["uuid"], uuid);
    assert_eq!(v["recycle_bin"], true);
}

#[test]
fn entry_get_password_redacted_by_default() {
    let reg = vault_named("v");
    let uuid = add_github_entry(&reg);

    let (code, stdout, _) = run_with_stdin(
        &reg,
        &[
            "--format", "json", "entry", "get", "--vault", "v", "--uuid", &uuid,
        ],
        &format!("{PW}\n"),
    );
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert!(
        v.get("password").is_none(),
        "password key must be absent without --show-password"
    );
}

#[test]
fn entry_get_password_with_show() {
    let reg = vault_named("v");
    let uuid = add_github_entry(&reg);

    let (code, stdout, _) = run_with_stdin(
        &reg,
        &[
            "--format",
            "json",
            "entry",
            "get",
            "--vault",
            "v",
            "--uuid",
            &uuid,
            "--show-password",
        ],
        &format!("{PW}\n"),
    );
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    let pw_value = v["password"].as_str().expect("password present");
    assert_eq!(pw_value.chars().count(), 24, "length matches --length 24");
}

#[test]
fn entry_get_by_title_resolves_single_match() {
    let reg = vault_named("v");
    let _uuid = add_github_entry(&reg);

    let (code, stdout, _) = run_with_stdin(
        &reg,
        &[
            "--format", "json", "entry", "get", "--vault", "v", "--title", "GitHub",
        ],
        &format!("{PW}\n"),
    );
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["title"], "GitHub");
}

#[test]
fn entry_add_password_stdin_reads_from_stdin() {
    let reg = vault_named("v");
    // First line is the master password (vault unlock), second is the
    // entry password.
    let (code, stdout, stderr) = run_with_stdin(
        &reg,
        &[
            "--format",
            "json",
            "entry",
            "add",
            "--vault",
            "v",
            "--title",
            "Manual",
            "--password-stdin",
        ],
        &format!("{PW}\nmy-secret\n"),
    );
    assert_eq!(code, 0, "stderr:\n{stderr}");
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    let uuid = v["uuid"].as_str().unwrap().to_owned();

    // Confirm the entry password was actually stored.
    let (code, stdout, _) = run_with_stdin(
        &reg,
        &[
            "--format",
            "json",
            "entry",
            "get",
            "--vault",
            "v",
            "--uuid",
            &uuid,
            "--show-password",
        ],
        &format!("{PW}\n"),
    );
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["password"], "my-secret");
}

#[test]
fn entry_list_after_two_adds_returns_both() {
    let reg = vault_named("v");
    let _ = add_github_entry(&reg);
    let (code, _stdout, _) = run_with_stdin(
        &reg,
        &[
            "entry",
            "add",
            "--vault",
            "v",
            "--title",
            "GitLab",
            "--generate",
            "--tag",
            "work",
        ],
        &format!("{PW}\n"),
    );
    assert_eq!(code, 0);

    let (code, stdout, _) = run_with_stdin(
        &reg,
        &["--format", "json", "entry", "list", "--vault", "v"],
        &format!("{PW}\n"),
    );
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    let entries = v["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    let titles: Vec<&str> = entries
        .iter()
        .map(|e| e["title"].as_str().unwrap())
        .collect();
    assert!(titles.contains(&"GitHub"));
    assert!(titles.contains(&"GitLab"));
}

#[test]
fn entry_list_with_tag_filter_intersects() {
    let reg = vault_named("v");
    let _ = add_github_entry(&reg); // tags: work, personal
    let (code, _stdout, _) = run_with_stdin(
        &reg,
        &[
            "entry",
            "add",
            "--vault",
            "v",
            "--title",
            "GitLab",
            "--generate",
            "--tag",
            "work",
        ],
        &format!("{PW}\n"),
    );
    assert_eq!(code, 0);

    // Filter to entries with BOTH `work` AND `personal` — should only
    // hit the GitHub entry (which carries both).
    let (code, stdout, _) = run_with_stdin(
        &reg,
        &[
            "--format", "json", "entry", "list", "--vault", "v", "--tag", "work", "--tag",
            "personal",
        ],
        &format!("{PW}\n"),
    );
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    let entries = v["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "intersection of work + personal");
    assert_eq!(entries[0]["title"], "GitHub");
}

#[test]
fn entry_search_returns_matches() {
    let reg = vault_named("v");
    let _ = add_github_entry(&reg);

    let (code, stdout, _) = run_with_stdin(
        &reg,
        &[
            "--format", "json", "entry", "search", "--vault", "v", "github",
        ],
        &format!("{PW}\n"),
    );
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["query"], "github");
    let matches = v["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0]["title"], "GitHub");
}

#[test]
fn entry_rm_permanent_skips_recycle_bin() {
    let reg = vault_named("v");
    let uuid = add_github_entry(&reg);

    let (code, stdout, _) = run_with_stdin(
        &reg,
        &[
            "--format",
            "json",
            "entry",
            "rm",
            "--vault",
            "v",
            "--uuid",
            &uuid,
            "--permanent",
        ],
        &format!("{PW}\n"),
    );
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["recycle_bin"], false);

    // Confirm the entry no longer appears in list output.
    let (code, stdout, _) = run_with_stdin(
        &reg,
        &["--format", "json", "entry", "list", "--vault", "v"],
        &format!("{PW}\n"),
    );
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert!(
        v["entries"].as_array().unwrap().is_empty(),
        "purged entry must not appear in list"
    );
}

#[test]
fn entry_get_by_title_no_match_exits_user_error() {
    let reg = vault_named("v");
    let _ = add_github_entry(&reg);

    let (code, _stdout, stderr) = run_with_stdin(
        &reg,
        &[
            "entry",
            "get",
            "--vault",
            "v",
            "--title",
            "Definitely-not-a-real-title",
        ],
        &format!("{PW}\n"),
    );
    assert_eq!(code, 1, "stderr:\n{stderr}");
    assert!(
        stderr.contains("no entry with title"),
        "stderr should mention missing title:\n{stderr}"
    );
}

#[test]
fn entry_add_invalid_tag_with_semicolon_rejected() {
    let reg = vault_named("v");
    let (code, _stdout, stderr) = run_with_stdin(
        &reg,
        &[
            "entry",
            "add",
            "--vault",
            "v",
            "--title",
            "X",
            "--tag",
            "a;b",
            "--generate",
        ],
        &format!("{PW}\n"),
    );
    assert_eq!(code, 1, "stderr:\n{stderr}");
    assert!(
        stderr.contains("invalid tag"),
        "stderr should explain why:\n{stderr}"
    );
}
