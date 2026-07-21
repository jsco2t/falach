//! US-040 — configure an S3 sync target for a vault (FR-040, FR-045; impl
//! plan §8.4.3). Verifies `Sync::configure_remote` writes the per-vault
//! `[sync.s3]` block, that it round-trips through `vaults.toml`, and that
//! the ADR-6 duplicate-target guard rejects two vaults pointed at the same
//! `(endpoint, bucket, key)`.

#![allow(clippy::doc_markdown)]

mod common;

use common::sync_env::SyncTestEnv;
use falach_core::VaultRegistry;
use falach_sync::{CredentialSource, S3Config, Sync, SyncConfig, SyncError};

fn sample_s3(bucket: &str, key: &str) -> S3Config {
    S3Config::new(
        bucket.to_string(),
        key.to_string(),
        "us-east-1".to_string(),
        CredentialSource::RstCred1 {
            access_key_id: "AKIAEXAMPLE".to_string(),
            secret_access_key_encrypted: "UkMwMSDV-base64-placeholder".to_string(),
        },
    )
}

#[test]
fn configure_writes_and_round_trips_through_vaults_toml() {
    let mut dev = SyncTestEnv::new("work");
    let name = dev.name().to_string();
    let paths = dev.registry().paths().clone();
    let master = dev.master();

    Sync::configure_remote(
        dev.registry_mut(),
        &name,
        sample_s3("jason-vaults", "work.kdbx"),
        &master,
    )
    .expect("configure_remote ok");

    // Reload from disk — proves the config was persisted, not just mutated
    // in memory.
    let fresh = VaultRegistry::load(paths).expect("reload registry");
    let cfg = SyncConfig::from_vault_entry(fresh.get(&name).expect("vault present"))
        .expect("sync config present after configure");
    let s3 = cfg.s3.expect("s3 sub-config present");
    assert_eq!(s3.bucket(), "jason-vaults");
    assert_eq!(s3.key(), "work.kdbx");
    assert_eq!(s3.region(), "us-east-1");
}

#[test]
fn duplicate_target_is_rejected() {
    // Two vaults in one registry; the second pointed at the SAME target as
    // the first must be rejected (ADR-6 / FR — prevents two vaults silently
    // clobbering one object).
    let mut dev = SyncTestEnv::new("work");
    let master = dev.master();
    // Register a second vault in the same registry by hand.
    let second = SyncTestEnv::new("personal");
    dev.registry_mut()
        .register(falach_core::RegisteredVault {
            name: "personal".to_string(),
            path: second.vault_path().to_path_buf(),
            created_at: "2026-05-29T00:00:00Z".to_string(),
            keyfile_path: None,
            extra: toml::Table::new(),
        })
        .expect("register second vault");

    Sync::configure_remote(
        dev.registry_mut(),
        "work",
        sample_s3("shared-bucket", "vault.kdbx"),
        &master,
    )
    .expect("first configure ok");

    let err = Sync::configure_remote(
        dev.registry_mut(),
        "personal",
        sample_s3("shared-bucket", "vault.kdbx"),
        &master,
    )
    .expect_err("second configure against the same target must be rejected");

    assert!(
        matches!(err, SyncError::DuplicateTarget { ref existing_vault, .. } if existing_vault == "work"),
        "expected DuplicateTarget naming the existing vault, got {err:?}"
    );
}
