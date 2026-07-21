mod common;

use falach_core::{
    EntryBuilder, NoRecoveryConfirmed, Vault, VaultError, VaultReadOnly,
    DEFAULT_MAX_ATTACHMENT_BYTES,
};

use common::{fast_kdf, master, TestEnv};

#[test]
fn attachment_round_trips_through_save_and_reopen() {
    let env = TestEnv::new();
    let path = env.tempdir().join("attachment.kdbx");
    let password = master("attachment password");
    let bytes: Vec<u8> = (0..1024u16)
        .map(|n| u8::try_from(n % 256).unwrap_or(0))
        .collect();

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
            .add_entry(root, EntryBuilder::credential("Doc").build())
            .expect("add entry");
        vault
            .add_attachment(uuid, "file.bin", &bytes)
            .expect("add attachment");
        vault.save().expect("save vault");
        uuid
    };

    let vault = Vault::open(&path, &password, None).expect("reopen vault");
    let read = vault
        .get_attachment(uuid, "file.bin")
        .expect("get attachment after reopen");
    assert_eq!(read.as_slice(), bytes.as_slice());
}

#[test]
fn rejects_oversized_attachment_and_preserves_existing() {
    let env = TestEnv::new();
    let path = env.tempdir().join("oversized.kdbx");
    let password = master("attachment password");
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
        .add_entry(root, EntryBuilder::credential("Doc").build())
        .expect("add entry");

    // Lower the cap so we can test the oversized rejection cheaply
    // without allocating 5+ MiB just for the test.
    vault
        .set_max_attachment_bytes(4096)
        .expect("set cap to 4 KiB");

    let small = vec![0xAB; 1024];
    vault
        .add_attachment(uuid, "small.bin", &small)
        .expect("small attachment fits within cap");

    let oversized = vec![0xCD; 4097];
    let err = vault
        .add_attachment(uuid, "huge.bin", &oversized)
        .expect_err("oversized add must fail");

    assert!(matches!(
        err,
        VaultError::AttachmentTooLarge {
            actual: 4097,
            limit: 4096
        }
    ));

    // The pre-existing 1 KB attachment must still be readable, byte-identical.
    let read = vault
        .get_attachment(uuid, "small.bin")
        .expect("prior attachment still readable");
    assert_eq!(read.as_slice(), small.as_slice());
}

#[test]
fn default_cap_is_five_mib_and_persists_through_save_reopen() {
    let env = TestEnv::new();
    let path = env.tempdir().join("cap.kdbx");
    let password = master("attachment password");
    {
        let mut vault = Vault::create(
            &path,
            &password,
            None,
            fast_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create vault");
        assert_eq!(vault.max_attachment_bytes(), DEFAULT_MAX_ATTACHMENT_BYTES);
        vault
            .set_max_attachment_bytes(2 * 1024 * 1024)
            .expect("set cap");
        vault.save().expect("save vault");
    }

    let vault = Vault::open(&path, &password, None).expect("reopen vault");
    assert_eq!(
        vault.max_attachment_bytes(),
        2 * 1024 * 1024,
        "cap persists through save+reopen"
    );
}

#[test]
fn remove_attachment_drops_data_after_save_reopen() {
    let env = TestEnv::new();
    let path = env.tempdir().join("remove.kdbx");
    let password = master("attachment password");

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
            .add_entry(root, EntryBuilder::credential("Doc").build())
            .expect("add entry");
        vault
            .add_attachment(uuid, "tmp.bin", &[1u8, 2, 3])
            .expect("add attachment");
        vault.remove_attachment(uuid, "tmp.bin").expect("remove");
        vault.save().expect("save vault");
        uuid
    };

    let vault = Vault::open(&path, &password, None).expect("reopen vault");
    let err = vault
        .get_attachment(uuid, "tmp.bin")
        .expect_err("attachment should be gone after remove + reopen");
    assert!(matches!(err, VaultError::AttachmentNotFound { .. }));
    assert_eq!(
        vault.database().num_attachments(),
        0,
        "pool entry should be freed"
    );
}

#[test]
fn read_only_vault_can_list_and_read_attachments() {
    let env = TestEnv::new();
    let path = env.tempdir().join("readonly.kdbx");
    let password = master("attachment password");
    let bytes = b"read-only".to_vec();

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
            .add_entry(root, EntryBuilder::credential("Doc").build())
            .expect("add entry");
        vault
            .add_attachment(uuid, "ro.bin", &bytes)
            .expect("add attachment");
        vault.save().expect("save");
        uuid
    };

    let read_only = VaultReadOnly::open(&path, &password, None).expect("open ro");
    let list = read_only
        .list_attachments(uuid)
        .expect("list via read-only");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "ro.bin");
    assert_eq!(list[0].size_bytes, bytes.len() as u64);

    let read = read_only
        .get_attachment(uuid, "ro.bin")
        .expect("get via read-only");
    assert_eq!(read.as_slice(), bytes.as_slice());
}
