//! Tests for the sync-layer `Vault` additions: `open_from_bytes` and
//! `replace_database` (design §4.4, sync-git contract #5).
//!
//! These two `#[doc(hidden)] pub` methods exist so `falach-sync` can decrypt a
//! remote vault snapshot from bytes and install a merged/fast-forwarded
//! database, without a second filesystem round-trip or a key re-derivation
//! shortcut that bypasses authentication.

mod common;

use common::{fast_kdf, master, TestEnv};
use falach_core::{fields, NoRecoveryConfirmed, Vault, VaultError};

#[test]
fn open_from_bytes_round_trips_a_saved_vault() {
    let env = TestEnv::new();
    let path = env.tempdir().join("snap.kdbx");
    let password = master("correct");

    {
        let mut vault = Vault::create(
            &path,
            &password,
            None,
            fast_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create");
        vault
            .database_mut()
            .root_mut()
            .add_entry()
            .edit(|e| e.set_unprotected(fields::TITLE, "Email"));
        vault.save().expect("save");
    }

    let bytes = std::fs::read(&path).expect("read raw kdbx bytes");
    let db = Vault::open_from_bytes(&bytes, &password, None).expect("open_from_bytes");

    assert!(
        db.root().entry_by_name("Email").is_some(),
        "the entry saved to disk must be present in the bytes-decrypted database"
    );
}

#[test]
fn open_from_bytes_with_wrong_password_is_authentication_failure() {
    let env = TestEnv::new();
    let path = env.tempdir().join("snap.kdbx");

    drop(
        Vault::create(
            &path,
            &master("right"),
            None,
            fast_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create"),
    );

    let bytes = std::fs::read(&path).expect("read raw kdbx bytes");
    let err = Vault::open_from_bytes(&bytes, &master("wrong"), None)
        .expect_err("decrypt with the wrong password must fail");

    assert!(
        matches!(err, VaultError::AuthenticationFailed),
        "wrong password must surface as AuthenticationFailed, got {err:?}"
    );
}

#[test]
fn replace_database_installs_a_matching_identity_database() {
    let env = TestEnv::new();
    let path = env.tempdir().join("vault.kdbx");
    let password = master("pw");

    let mut vault = Vault::create(
        &path,
        &password,
        None,
        fast_kdf(),
        NoRecoveryConfirmed::yes(),
    )
    .expect("create");
    vault.save().expect("save");

    // A same-identity database: it is a snapshot of this very vault, so its
    // root-group UUID matches. Mutate it, then install it.
    let bytes = std::fs::read(&path).expect("read raw kdbx bytes");
    let mut snapshot = Vault::open_from_bytes(&bytes, &password, None).expect("snapshot");
    snapshot
        .root_mut()
        .add_entry()
        .edit(|e| e.set_unprotected(fields::TITLE, "Merged"));

    vault
        .replace_database(snapshot)
        .expect("installing a matching-identity database must succeed");

    assert!(
        vault.database().root().entry_by_name("Merged").is_some(),
        "the installed database must be the live in-memory database"
    );
}

#[test]
fn replace_database_rejects_a_foreign_identity_database() {
    let env = TestEnv::new();
    let password = master("pw");

    let path_a = env.tempdir().join("a.kdbx");
    let mut vault_a = Vault::create(
        &path_a,
        &password,
        None,
        fast_kdf(),
        NoRecoveryConfirmed::yes(),
    )
    .expect("create a");

    // A separate vault has an independently-generated root-group UUID.
    let path_b = env.tempdir().join("b.kdbx");
    drop(
        Vault::create(
            &path_b,
            &password,
            None,
            fast_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create b"),
    );
    let b_bytes = std::fs::read(&path_b).expect("read b bytes");
    let b_db = Vault::open_from_bytes(&b_bytes, &password, None).expect("open b snapshot");

    let err = vault_a
        .replace_database(b_db)
        .expect_err("installing a foreign-identity database must be refused");

    assert!(
        matches!(err, VaultError::DatabaseIdentityMismatch { .. }),
        "a different root-group UUID must be refused, got {err:?}"
    );
}
