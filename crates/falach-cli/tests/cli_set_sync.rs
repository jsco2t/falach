//! End-to-end `falach vault set-sync` integration tests.
//!
//! `Sync::configure_remote` performs only a registry write + the ADR-6
//! duplicate-target check — no network — so the full command (prompt →
//! seal → persist) is testable reliably without `MinIO`. The
//! security-critical no-plaintext property can only be verified by
//! inspecting the on-disk `vaults.toml`, which a unit test of the pure
//! parts cannot do (plan §7.3.1).

mod common;

use common::{assert_file_lacks_bytes, run_with_stdin, seed_vault, VaultsToml};
use falach_core::{FalachPaths, VaultRegistry};
use falach_sync::{CredentialSource, SyncConfig};
use secrecy::ExposeSecret;

/// The set-sync `prompt` path must seal the secret access key via
/// RST-CRED-1 and leave **no** plaintext copy of it on any channel —
/// not in `vaults.toml`, not on stdout, not on stderr. This is the
/// single most important test in the feature (CLAUDE.md: no plaintext to
/// disk, ever; no secret material in output).
#[test]
fn set_sync_prompt_seals_secret_and_leaves_no_plaintext_on_disk() {
    let reg = VaultsToml::new();
    seed_vault(&reg, "personal", "master-pw");

    let secret = "wJalrXUtnFEMI-K7MDENG-bPxRfiCYEXAMPLEKEY";
    // Prompt order (matches the command): access-key-id, secret, master.
    let stdin = format!("AKIAIOSFODNN7EXAMPLE\n{secret}\nmaster-pw\n");
    let (code, stdout, stderr) = run_with_stdin(
        &reg,
        &[
            "vault",
            "set-sync",
            "--id",
            "personal",
            "--s3-bucket",
            "my-bucket",
            "--s3-key",
            "personal.kdbx",
        ],
        &stdin,
    );

    assert_eq!(code, 0, "set-sync should succeed; stderr: {stderr}");

    // The sealed RST-CRED-1 container is persisted...
    let toml = std::fs::read_to_string(&reg.vaults_toml).expect("read vaults.toml");
    assert!(
        toml.contains("secret_access_key_encrypted"),
        "sealed credential field should be present: {toml}"
    );
    assert!(
        toml.contains("AKIAIOSFODNN7EXAMPLE"),
        "the public access-key-id should be stored in cleartext: {toml}"
    );

    // ...but the plaintext secret must appear on NONE of the three sinks.
    assert_file_lacks_bytes(&reg.vaults_toml, secret);
    assert!(
        !stdout.contains(secret),
        "secret leaked to stdout: {stdout}"
    );
    assert!(
        !stderr.contains(secret),
        "secret leaked to stderr: {stderr}"
    );

    // ...and the sealed container must decrypt back to the EXACT secret
    // under the vault's master password. Without this, sealing an empty
    // string, a truncated value, or the access-key-id by mistake would
    // still pass every assertion above (the real secret would simply be
    // absent from disk). This proves recoverability — the actual contract.
    let container = extract_sealed_container(&toml);
    let recovered = falach_sync::auth::rstcred1::decrypt_credential(
        &container,
        &falach_core::MasterPassword::new("master-pw".to_string()),
    )
    .expect("sealed container decrypts under the master password");
    assert_eq!(
        recovered.expose_secret(),
        secret,
        "the sealed container must round-trip to the exact secret"
    );
}

/// A wrong master password at the `prompt` verification probe fails fast
/// with exit 2 (`vault.locked`) — BEFORE sealing — and leaves the
/// registry unwritten. This proves the probe-before-seal ordering: a
/// typo surfaces here, not as an opaque `CredentialDecryption` at the
/// next `sync`.
#[test]
fn set_sync_wrong_master_password_exits_2_and_writes_nothing() {
    let reg = VaultsToml::new();
    seed_vault(&reg, "personal", "correct-master");

    // Snapshot the registry bytes BEFORE the failed command so we can prove
    // the failed probe left it untouched (not merely "no sealed field").
    let before = std::fs::read(&reg.vaults_toml).expect("registry readable after seed");

    // access-key-id, secret, then the WRONG master password.
    let stdin = "AKIAIOSFODNN7EXAMPLE\nsome-secret-value\nWRONG-master\n";
    let (code, _stdout, _stderr) = run_with_stdin(
        &reg,
        &[
            "vault",
            "set-sync",
            "--id",
            "personal",
            "--s3-bucket",
            "b",
            "--s3-key",
            "k",
        ],
        stdin,
    );

    assert_eq!(
        code, 2,
        "wrong master password should exit 2 (vault.locked)"
    );
    // The probe runs before any registry write, so the registry must be
    // byte-for-byte identical to its pre-command state. An unconditional
    // read (not `if let Ok`) — a conditional check would pass vacuously had
    // the command deleted or corrupted the file.
    let after =
        std::fs::read(&reg.vaults_toml).expect("registry still readable after failed set-sync");
    assert_eq!(
        before, after,
        "a failed probe must leave the registry byte-for-byte unchanged"
    );
}

/// Every S3 flag round-trips through the registry into the typed
/// `S3Config` — bucket, key, region, custom endpoint, and path-style — not
/// just the credential kind tag. Guards against a field being dropped or
/// mis-wired while the credential-tag assertions still pass.
#[test]
fn set_sync_all_options_round_trip_through_registry() {
    let reg = VaultsToml::new();
    seed_vault(&reg, "personal", "pw");

    let (code, _stdout, stderr) = run_with_stdin(
        &reg,
        &[
            "vault",
            "set-sync",
            "--id",
            "personal",
            "--s3-bucket",
            "prod-bucket",
            "--s3-key",
            "vaults/personal.kdbx",
            "--s3-region",
            "eu-west-1",
            "--s3-endpoint",
            "https://minio.internal",
            "--s3-path-style",
            "--s3-credentials-source",
            "iam-role",
        ],
        "",
    );
    assert_eq!(
        code, 0,
        "all-options set-sync should succeed; stderr: {stderr}"
    );

    // Reload the registry and read back the typed S3Config — proves every
    // flag wired into the persisted config.
    let paths = FalachPaths::with_registry_file(reg.vaults_toml.clone());
    let registry = VaultRegistry::load(paths).expect("load registry");
    let record = registry.get("personal").expect("vault present");
    let cfg = SyncConfig::from_vault_entry(record).expect("sync config present");
    let s3 = cfg.s3.as_ref().expect("s3 config present");

    assert_eq!(s3.bucket(), "prod-bucket");
    assert_eq!(s3.key(), "vaults/personal.kdbx");
    assert_eq!(s3.region(), "eu-west-1");
    assert_eq!(s3.endpoint(), Some("https://minio.internal"));
    assert!(s3.path_style(), "path-style flag must persist");
    assert!(
        matches!(s3.credentials(), CredentialSource::IamInstanceRole { .. }),
        "credential source must persist as IamInstanceRole"
    );
}

/// Pull the `secret_access_key_encrypted` value out of the rendered
/// `vaults.toml`. A deliberately small hand-parse (not a full TOML
/// dependency) — the surrounding test already owns the file's shape.
fn extract_sealed_container(toml: &str) -> String {
    let line = toml
        .lines()
        .find(|l| l.trim_start().starts_with("secret_access_key_encrypted"))
        .expect("sealed field line present");
    line.split_once('=')
        .expect("key = value")
        .1
        .trim()
        .trim_matches('"')
        .to_string()
}

/// The `iam-role` source persists without any prompt and records the
/// matching `CredentialSource` kind in the registry.
#[test]
fn set_sync_iam_role_persists_source() {
    let reg = VaultsToml::new();
    seed_vault(&reg, "personal", "pw");

    let (code, _stdout, stderr) = run_with_stdin(
        &reg,
        &[
            "vault",
            "set-sync",
            "--id",
            "personal",
            "--s3-bucket",
            "b",
            "--s3-key",
            "k",
            "--s3-credentials-source",
            "iam-role",
        ],
        "",
    );

    assert_eq!(
        code, 0,
        "iam-role set-sync should succeed; stderr: {stderr}"
    );
    let toml = std::fs::read_to_string(&reg.vaults_toml).expect("read vaults.toml");
    // serde tags the variant as `kind = "iam_instance_role"` (snake_case).
    assert!(
        toml.contains("iam_instance_role"),
        "iam-role source should persist its kind tag: {toml}"
    );
}

/// The `profile:<name>` source persists the profile name.
#[test]
fn set_sync_profile_persists_source() {
    let reg = VaultsToml::new();
    seed_vault(&reg, "personal", "pw");

    let (code, _stdout, stderr) = run_with_stdin(
        &reg,
        &[
            "vault",
            "set-sync",
            "--id",
            "personal",
            "--s3-bucket",
            "b",
            "--s3-key",
            "k",
            "--s3-credentials-source",
            "profile:work-vaults",
        ],
        "",
    );

    assert_eq!(code, 0, "profile set-sync should succeed; stderr: {stderr}");
    let toml = std::fs::read_to_string(&reg.vaults_toml).expect("read vaults.toml");
    assert!(
        toml.contains("aws_profile"),
        "profile source should persist its kind tag: {toml}"
    );
    assert!(
        toml.contains("work-vaults"),
        "profile name should persist: {toml}"
    );
}

/// The `env:<prefix>` source persists the prefix.
#[test]
fn set_sync_env_persists_source() {
    let reg = VaultsToml::new();
    seed_vault(&reg, "personal", "pw");

    let (code, _stdout, stderr) = run_with_stdin(
        &reg,
        &[
            "vault",
            "set-sync",
            "--id",
            "personal",
            "--s3-bucket",
            "b",
            "--s3-key",
            "k",
            "--s3-credentials-source",
            "env:PERSONAL_",
        ],
        "",
    );

    assert_eq!(code, 0, "env set-sync should succeed; stderr: {stderr}");
    let toml = std::fs::read_to_string(&reg.vaults_toml).expect("read vaults.toml");
    assert!(
        toml.contains("env_vars"),
        "env source should persist its kind tag: {toml}"
    );
    assert!(
        toml.contains("PERSONAL_"),
        "env prefix should persist: {toml}"
    );
}

/// clap accepts an explicit empty `--s3-bucket ""`, but it is an invalid
/// S3 target — the CLI must reject it (exit 1) rather than persist a broken
/// config that only fails opaquely at the next `sync`.
#[test]
fn set_sync_empty_bucket_exits_1() {
    let reg = VaultsToml::new();
    seed_vault(&reg, "personal", "pw");

    let (code, _stdout, stderr) = run_with_stdin(
        &reg,
        &[
            "vault",
            "set-sync",
            "--id",
            "personal",
            "--s3-bucket",
            "",
            "--s3-key",
            "k",
            "--s3-credentials-source",
            "iam-role",
        ],
        "",
    );
    assert_eq!(
        code, 1,
        "empty bucket should be a user error; stderr: {stderr}"
    );
    // Rejected before persisting — no sync config written.
    let paths = FalachPaths::with_registry_file(reg.vaults_toml.clone());
    let registry = VaultRegistry::load(paths).expect("load registry");
    let record = registry.get("personal").expect("vault present");
    assert!(
        SyncConfig::from_vault_entry(record).is_none(),
        "empty-bucket set-sync must not persist a sync config"
    );
}

/// An empty `env:` prefix is refused (exit 1) — the ambient-AWS_*
/// cross-account footgun the per-vault prefix exists to prevent.
#[test]
fn set_sync_empty_env_prefix_exits_1() {
    let reg = VaultsToml::new();
    seed_vault(&reg, "personal", "pw");

    let (code, _stdout, stderr) = run_with_stdin(
        &reg,
        &[
            "vault",
            "set-sync",
            "--id",
            "personal",
            "--s3-bucket",
            "b",
            "--s3-key",
            "k",
            "--s3-credentials-source",
            "env:",
        ],
        "",
    );

    assert_eq!(
        code, 1,
        "empty env prefix should be a user error; stderr: {stderr}"
    );
}

/// A malformed endpoint is rejected before prompting or persistence. This
/// keeps invalid user input out of the registry and prevents a later sync
/// from misclassifying it as an internal transport failure.
#[test]
fn set_sync_malformed_endpoint_exits_1_and_writes_nothing() {
    let reg = VaultsToml::new();
    seed_vault(&reg, "personal", "pw");
    let before = std::fs::read(&reg.vaults_toml).expect("read registry before command");

    let (code, _stdout, stderr) = run_with_stdin(
        &reg,
        &[
            "vault",
            "set-sync",
            "--id",
            "personal",
            "--s3-bucket",
            "b",
            "--s3-key",
            "k",
            "--s3-endpoint",
            "minio.internal",
            "--s3-credentials-source",
            "iam-role",
        ],
        "",
    );

    assert_eq!(
        code, 1,
        "malformed endpoint should be a user error: {stderr}"
    );
    let after = std::fs::read(&reg.vaults_toml).expect("read registry after command");
    assert_eq!(
        after, before,
        "invalid endpoint must not modify vaults.toml"
    );
}

#[test]
fn set_sync_invalid_endpoint_authority_exits_1_and_writes_nothing() {
    let reg = VaultsToml::new();
    seed_vault(&reg, "personal", "pw");
    let before = std::fs::read(&reg.vaults_toml).expect("read registry before command");

    let (code, _stdout, stderr) = run_with_stdin(
        &reg,
        &[
            "vault",
            "set-sync",
            "--id",
            "personal",
            "--s3-bucket",
            "b",
            "--s3-key",
            "k",
            "--s3-endpoint",
            "https://host:not-a-port",
            "--s3-credentials-source",
            "iam-role",
        ],
        "",
    );

    assert_eq!(
        code, 1,
        "invalid authority should be a user error: {stderr}"
    );
    let after = std::fs::read(&reg.vaults_toml).expect("read registry after command");
    assert_eq!(
        after, before,
        "invalid authority must not modify vaults.toml"
    );
}

/// Endpoint userinfo can contain passwords and must never be accepted for
/// persistence or echoed by a successful configuration response.
#[test]
fn set_sync_endpoint_userinfo_exits_1_without_leaking_password() {
    let reg = VaultsToml::new();
    seed_vault(&reg, "personal", "pw");
    let marker = "SUPER-SECRET-ENDPOINT-PASSWORD";
    let endpoint = format!("https://user:{marker}@minio.internal");

    let (code, stdout, stderr) = run_with_stdin(
        &reg,
        &[
            "vault",
            "set-sync",
            "--id",
            "personal",
            "--s3-bucket",
            "b",
            "--s3-key",
            "k",
            "--s3-endpoint",
            &endpoint,
            "--s3-credentials-source",
            "iam-role",
        ],
        "",
    );

    assert_eq!(code, 1, "endpoint userinfo should be rejected");
    assert!(!stdout.contains(marker), "stdout leaked endpoint password");
    assert!(!stderr.contains(marker), "stderr leaked endpoint password");
    let registry = std::fs::read_to_string(&reg.vaults_toml).expect("read registry");
    assert!(
        !registry.contains(marker),
        "registry leaked endpoint password"
    );
}

/// Query strings are not part of an S3 endpoint origin and may contain
/// credentials. Reject them without persisting or reflecting their content.
#[test]
fn set_sync_endpoint_query_exits_1_without_leaking_secret() {
    let reg = VaultsToml::new();
    seed_vault(&reg, "personal", "pw");
    let marker = "SUPER-SECRET-QUERY-TOKEN";
    let endpoint = format!("https://minio.internal?token={marker}");

    let (code, stdout, stderr) = run_with_stdin(
        &reg,
        &[
            "vault",
            "set-sync",
            "--id",
            "personal",
            "--s3-bucket",
            "b",
            "--s3-key",
            "k",
            "--s3-endpoint",
            &endpoint,
            "--s3-credentials-source",
            "iam-role",
        ],
        "",
    );

    assert_eq!(code, 1, "endpoint query should be rejected");
    assert!(!stdout.contains(marker), "stdout leaked endpoint query");
    assert!(!stderr.contains(marker), "stderr leaked endpoint query");
    let registry = std::fs::read_to_string(&reg.vaults_toml).expect("read registry");
    assert!(!registry.contains(marker), "registry leaked endpoint query");
}

/// Two vaults configured to the same `(endpoint, bucket, key)` collide:
/// the second exits 1 (ADR-6 duplicate-target guard, via the CLI).
#[test]
fn set_sync_duplicate_target_exits_1() {
    let reg = VaultsToml::new();
    seed_vault(&reg, "v1", "pw");
    seed_vault(&reg, "v2", "pw");

    let args = |id: &str| {
        vec![
            "vault".to_string(),
            "set-sync".to_string(),
            "--id".to_string(),
            id.to_string(),
            "--s3-bucket".to_string(),
            "shared".to_string(),
            "--s3-key".to_string(),
            "vault.kdbx".to_string(),
            "--s3-credentials-source".to_string(),
            "iam-role".to_string(),
        ]
    };

    let a1 = args("v1");
    let a1: Vec<&str> = a1.iter().map(String::as_str).collect();
    let (code1, _o1, e1) = run_with_stdin(&reg, &a1, "");
    assert_eq!(code1, 0, "first configuration should succeed; stderr: {e1}");

    let a2 = args("v2");
    let a2: Vec<&str> = a2.iter().map(String::as_str).collect();
    let (code2, _o2, _e2) = run_with_stdin(&reg, &a2, "");
    assert_eq!(code2, 1, "duplicate target should be a user error (exit 1)");
}

/// `--format json` emits the documented, secret-free schema.
#[test]
fn set_sync_json_schema_omits_secret() {
    let reg = VaultsToml::new();
    seed_vault(&reg, "personal", "pw");

    let (code, stdout, stderr) = run_with_stdin(
        &reg,
        &[
            "--format",
            "json",
            "vault",
            "set-sync",
            "--id",
            "personal",
            "--s3-bucket",
            "b",
            "--s3-key",
            "k",
            "--s3-credentials-source",
            "iam-role",
        ],
        "",
    );

    assert_eq!(code, 0, "json set-sync should succeed; stderr: {stderr}");
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be a JSON document");
    assert_eq!(v["id"], "personal");
    assert_eq!(v["bucket"], "b");
    assert_eq!(v["key"], "k");
    assert_eq!(v["credentials_source"], "iam-role");
    // Default endpoint omitted, and no secret-bearing fields present.
    let obj = v.as_object().expect("json object");
    assert!(obj.get("endpoint").is_none(), "default endpoint omitted");
    for forbidden in [
        "access_key_id",
        "secret_access_key",
        "secret_access_key_encrypted",
    ] {
        assert!(
            obj.get(forbidden).is_none(),
            "json output must not expose `{forbidden}`: {stdout}"
        );
    }
}

/// Configuring an unregistered vault is a clean user error (exit 1)
/// before any prompting.
#[test]
fn set_sync_unregistered_vault_exits_1() {
    let reg = VaultsToml::new();
    // No seed_vault — the registry is empty.
    let (code, _stdout, _stderr) = run_with_stdin(
        &reg,
        &[
            "vault",
            "set-sync",
            "--id",
            "ghost",
            "--s3-bucket",
            "b",
            "--s3-key",
            "k",
            "--s3-credentials-source",
            "iam-role",
        ],
        "",
    );
    assert_eq!(code, 1, "unregistered vault should be a user error");
}
