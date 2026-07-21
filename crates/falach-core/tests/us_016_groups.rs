mod common;

use falach_core::{EntryBuilder, GroupDeleteBehavior, NoRecoveryConfirmed, Tag, Vault, VaultError};

use common::{fast_kdf, master, TestEnv};

#[test]
fn group_create_rename_move_and_delete_behaviors_work() {
    let env = TestEnv::new();
    let path = env.tempdir().join("groups.kdbx");
    let password = master("group password");
    let mut vault = Vault::create(
        &path,
        &password,
        None,
        fast_kdf(),
        NoRecoveryConfirmed::yes(),
    )
    .expect("create vault");

    let root = vault.root_group_uuid();
    let banking = vault.create_group(root, "Banking").expect("create banking");
    let email = vault.create_group(root, "Email").expect("create email");
    let work = vault.create_group(root, "Work").expect("create work");
    let entry = vault
        .add_entry(banking, EntryBuilder::credential("Checking").build())
        .expect("add banking entry");

    let banking_view = vault.group_view(banking).expect("banking view");
    assert_eq!(banking_view.name(), "Banking");
    assert_eq!(banking_view.entry_uuids(), vec![entry]);

    vault
        .rename_group(banking, "Finance")
        .expect("rename banking");
    assert_eq!(
        vault.group_view(banking).expect("renamed view").name(),
        "Finance"
    );

    vault
        .move_group(email, banking)
        .expect("move email under finance");
    assert!(
        vault
            .group_view(banking)
            .expect("finance view")
            .child_group_uuids()
            .contains(&email),
        "Email should be a child of Finance"
    );

    let refused = vault.delete_group(banking, GroupDeleteBehavior::Refuse);
    assert!(matches!(refused, Err(VaultError::GroupNotEmpty { uuid }) if uuid == banking));

    let root_delete = vault.delete_group(root, GroupDeleteBehavior::Recurse);
    assert!(matches!(root_delete, Err(VaultError::CannotModifyRoot)));

    let cycle = vault.move_group(banking, email);
    assert!(matches!(cycle, Err(VaultError::InvalidGroupTarget { .. })));

    let empty = vault.create_group(work, "Empty").expect("create empty");
    vault
        .delete_group(empty, GroupDeleteBehavior::Refuse)
        .expect("delete empty group");
    let bin = vault
        .database()
        .recycle_bin()
        .expect("recycle bin should exist after empty group delete");
    assert!(
        bin.groups().any(|group| group.id().uuid() == empty),
        "empty group should move to recycle bin"
    );

    vault
        .delete_group(banking, GroupDeleteBehavior::Recurse)
        .expect("move finance subtree to bin");
    let bin = vault
        .database()
        .recycle_bin()
        .expect("recycle bin should exist");
    assert!(
        bin.groups().any(|group| group.id().uuid() == banking),
        "Finance group should be under recycle bin"
    );
    assert_eq!(
        vault.get_entry(entry).expect("entry preserved").uuid(),
        entry
    );
}

#[test]
fn create_group_with_unknown_parent_returns_group_not_found() {
    let env = TestEnv::new();
    let path = env.tempdir().join("group-missing.kdbx");
    let password = master("group password");
    let mut vault = Vault::create(
        &path,
        &password,
        None,
        fast_kdf(),
        NoRecoveryConfirmed::yes(),
    )
    .expect("create vault");
    let missing = uuid::Uuid::new_v4();

    let err = vault
        .create_group(missing, "Nope")
        .expect_err("missing parent should fail");
    assert!(matches!(err, VaultError::GroupNotFound { uuid } if uuid == missing));
}

#[test]
fn tag_crud_and_vault_level_listing_work() {
    let env = TestEnv::new();
    let path = env.tempdir().join("tags.kdbx");
    let password = master("tag password");
    let mut vault = Vault::create(
        &path,
        &password,
        None,
        fast_kdf(),
        NoRecoveryConfirmed::yes(),
    )
    .expect("create vault");
    let first = vault
        .add_entry(
            vault.root_group_uuid(),
            EntryBuilder::credential("First")
                .tag(Tag::new("finance"))
                .build(),
        )
        .expect("add first entry");
    let second = vault
        .add_entry(
            vault.root_group_uuid(),
            EntryBuilder::credential("Second")
                .tag(Tag::new("finance"))
                .tag(Tag::new("work"))
                .build(),
        )
        .expect("add second entry");

    vault.add_tag(first, Tag::new("work")).expect("add tag");
    vault
        .add_tag(first, Tag::new("work"))
        .expect("idempotent add tag");
    assert_eq!(
        vault.get_entry(first).expect("first entry").tags(),
        vec![Tag::new("finance"), Tag::new("work")]
    );

    vault
        .remove_tag(first, &Tag::new("finance"))
        .expect("remove tag");
    assert_eq!(
        vault.get_entry(first).expect("first entry").tags(),
        vec![Tag::new("work")]
    );

    vault
        .set_tags(first, [Tag::new("admin"), Tag::new("work")])
        .expect("replace tags");
    assert_eq!(
        vault.get_entry(first).expect("first entry").tags(),
        vec![Tag::new("admin"), Tag::new("work")]
    );
    assert!(matches!(
        Tag::from("a;b"),
        Err(VaultError::InvalidTag { value }) if value == "a;b"
    ));
    assert_eq!(
        vault.get_entry(first).expect("first entry").history().len(),
        0,
        "vault tag helpers should not append KDBX history"
    );

    vault.delete_entry(second).expect("recycle second entry");
    assert_eq!(vault.list_tags(), vec![Tag::new("admin"), Tag::new("work")]);
}
