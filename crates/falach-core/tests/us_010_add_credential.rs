mod common;

use falach_core::{EntryBuilder, NoRecoveryConfirmed, Tag, Vault};

use common::{fast_kdf, master, TestEnv};

#[test]
fn add_credential_round_trips_through_save_and_reopen() {
    let env = TestEnv::new();
    let path = env.tempdir().join("entries.kdbx");
    let password = master("entry password");

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
            .add_entry(
                root,
                EntryBuilder::credential("Example")
                    .username("alice")
                    .password("secret")
                    .url("https://example.com")
                    .notes("notes")
                    .tag(Tag::new("work"))
                    .build(),
            )
            .expect("add credential");
        vault.save().expect("save vault");
        uuid
    };

    let vault = Vault::open(&path, &password, None).expect("reopen vault");
    let entry = vault.get_entry(uuid).expect("entry exists after reopen");
    assert_eq!(entry.uuid(), uuid);
    assert_eq!(entry.title(), "Example");
    assert_eq!(entry.username(), "alice");
    assert_eq!(entry.password(), "secret");
    assert_eq!(entry.url(), "https://example.com");
    assert_eq!(entry.notes(), "notes");
    assert_eq!(entry.tags(), vec![Tag::new("work")]);
}

#[test]
fn identical_drafts_receive_distinct_uuids() {
    let env = TestEnv::new();
    let path = env.tempdir().join("distinct.kdbx");
    let password = master("entry password");
    let mut vault = Vault::create(
        &path,
        &password,
        None,
        fast_kdf(),
        NoRecoveryConfirmed::yes(),
    )
    .expect("create vault");
    let root = vault.root_group_uuid();

    let first = vault
        .add_entry(root, EntryBuilder::credential("Example").build())
        .expect("add first entry");
    let second = vault
        .add_entry(root, EntryBuilder::credential("Example").build())
        .expect("add second entry");

    assert_ne!(first, second);
}
