mod common;

use falach_core::{EntryBuilder, NoRecoveryConfirmed, Vault, VaultError};

use common::{fast_kdf, master, TestEnv};

#[test]
fn delete_entry_moves_to_recycle_bin_when_enabled() {
    let env = TestEnv::new();
    let path = env.tempdir().join("delete-bin.kdbx");
    let password = master("delete password");
    let mut vault = Vault::create(
        &path,
        &password,
        None,
        fast_kdf(),
        NoRecoveryConfirmed::yes(),
    )
    .expect("create vault");
    vault.database_mut().meta.recyclebin_enabled = Some(true);
    let uuid = vault
        .add_entry(
            vault.root_group_uuid(),
            EntryBuilder::credential("Trash").build(),
        )
        .expect("add entry");

    vault.delete_entry(uuid).expect("delete entry");
    vault.delete_entry(uuid).expect("second delete is no-op");

    let bin = vault
        .database()
        .recycle_bin()
        .expect("recycle bin should be lazily created");
    assert!(
        bin.entries().any(|entry| entry.id().uuid() == uuid),
        "deleted entry should be directly in recycle bin"
    );
    assert_eq!(
        vault
            .get_entry(uuid)
            .expect("entry still addressable")
            .uuid(),
        uuid
    );
}

#[test]
fn delete_entry_permanently_removes_when_recycle_bin_disabled() {
    let env = TestEnv::new();
    let path = env.tempdir().join("delete-permanent.kdbx");
    let password = master("delete password");
    let mut vault = Vault::create(
        &path,
        &password,
        None,
        fast_kdf(),
        NoRecoveryConfirmed::yes(),
    )
    .expect("create vault");
    vault.database_mut().meta.recyclebin_enabled = Some(false);
    let uuid = vault
        .add_entry(
            vault.root_group_uuid(),
            EntryBuilder::credential("Trash").build(),
        )
        .expect("add entry");

    vault.delete_entry(uuid).expect("delete entry");
    assert!(matches!(
        vault.get_entry(uuid),
        Err(VaultError::EntryNotFound { uuid: missing }) if missing == uuid
    ));
}

#[test]
fn purge_entry_permanently_removes_regardless_of_recycle_bin_setting() {
    let env = TestEnv::new();
    let path = env.tempdir().join("purge.kdbx");
    let password = master("delete password");
    let mut vault = Vault::create(
        &path,
        &password,
        None,
        fast_kdf(),
        NoRecoveryConfirmed::yes(),
    )
    .expect("create vault");
    vault.database_mut().meta.recyclebin_enabled = Some(true);
    let uuid = vault
        .add_entry(
            vault.root_group_uuid(),
            EntryBuilder::credential("Trash").build(),
        )
        .expect("add entry");

    vault.purge_entry(uuid).expect("purge entry");
    assert!(matches!(
        vault.get_entry(uuid),
        Err(VaultError::EntryNotFound { uuid: missing }) if missing == uuid
    ));
}
