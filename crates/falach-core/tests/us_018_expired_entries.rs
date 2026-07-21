mod common;

use chrono::{TimeZone, Utc};
use falach_core::{EntryBuilder, NoRecoveryConfirmed, Vault, VaultReadOnly};

use common::{fast_kdf, master, TestEnv};

fn at(secs: i64) -> chrono::DateTime<chrono::Utc> {
    Utc.timestamp_opt(secs, 0)
        .single()
        .expect("valid timestamp")
}

#[test]
fn expiration_round_trips_through_save_and_reopen() {
    let env = TestEnv::new();
    let path = env.tempdir().join("expiration.kdbx");
    let password = master("expiration password");
    let yesterday = at(1_000_000);
    let next_year = at(4_000_000_000);

    let uuid = {
        let mut vault = Vault::create(
            &path,
            &password,
            None,
            fast_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create vault");
        let root = vault.root_group_uuid();
        let uuid = vault
            .add_entry(root, EntryBuilder::credential("Login").build())
            .expect("add entry");

        vault.set_expiration(uuid, yesterday).expect("set past");
        vault.save().expect("save vault");
        uuid
    };

    let now = at(2_000_000);
    {
        let vault = Vault::open(&path, &password, None).expect("reopen");
        assert!(
            vault.is_expired(uuid, now).expect("query expired"),
            "past expiration is expired after reopen"
        );
    }

    // Push the cutoff into the future and re-check.
    {
        let mut vault = Vault::open(&path, &password, None).expect("reopen mut");
        vault
            .set_expiration(uuid, next_year)
            .expect("set far future");
        vault.save().expect("save vault");
    }

    let vault = Vault::open(&path, &password, None).expect("reopen");
    assert!(
        !vault.is_expired(uuid, now).expect("query non-expired"),
        "future expiration is not expired"
    );
}

#[test]
fn builder_expires_at_wires_through_add_entry() {
    let env = TestEnv::new();
    let path = env.tempdir().join("builder-expiry.kdbx");
    let password = master("expiration password");
    let when = at(1_500_000);

    let mut vault = Vault::create(
        &path,
        &password,
        None,
        fast_kdf(),
        NoRecoveryConfirmed::yes(),
    )
    .expect("create vault");
    let root = vault.root_group_uuid();
    let uuid = vault
        .add_entry(
            root,
            EntryBuilder::credential("ExpiresAt")
                .expires_at(when)
                .build(),
        )
        .expect("add entry with expiration");

    assert!(vault.is_expired(uuid, when).expect("at boundary"));
    assert!(vault
        .is_expired(uuid, at(when.timestamp() + 1))
        .expect("after"));
    assert!(!vault
        .is_expired(uuid, at(when.timestamp() - 1))
        .expect("before"));
}

#[test]
fn clear_expiration_removes_expired_state() {
    let env = TestEnv::new();
    let path = env.tempdir().join("clear.kdbx");
    let password = master("expiration password");
    let when = at(1_000_000);

    let mut vault = Vault::create(
        &path,
        &password,
        None,
        fast_kdf(),
        NoRecoveryConfirmed::yes(),
    )
    .expect("create vault");
    let root = vault.root_group_uuid();
    let uuid = vault
        .add_entry(root, EntryBuilder::credential("Login").build())
        .expect("add entry");

    vault.set_expiration(uuid, when).expect("set");
    assert!(vault.is_expired(uuid, when).expect("expired before clear"));

    vault.clear_expiration(uuid).expect("clear");
    assert!(
        !vault.is_expired(uuid, when).expect("query after clear"),
        "clear_expiration must remove the expired state"
    );
}

#[test]
fn read_only_vault_can_query_expiration() {
    let env = TestEnv::new();
    let path = env.tempdir().join("readonly-expiry.kdbx");
    let password = master("expiration password");
    let when = at(1_000_000);

    let uuid = {
        let mut vault = Vault::create(
            &path,
            &password,
            None,
            fast_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create vault");
        let root = vault.root_group_uuid();
        let uuid = vault
            .add_entry(root, EntryBuilder::credential("Login").build())
            .expect("add entry");
        vault.set_expiration(uuid, when).expect("set");
        vault.save().expect("save");
        uuid
    };

    let ro = VaultReadOnly::open(&path, &password, None).expect("open ro");
    assert!(ro.is_expired(uuid, when).expect("ro expired query"));
    assert!(!ro
        .is_expired(uuid, at(when.timestamp() - 1))
        .expect("ro before"));
}
