mod common;

use chrono::{TimeZone, Utc};
use falach_core::{EntryBuilder, GroupDeleteBehavior, NoRecoveryConfirmed, Tag, Vault};

use common::{fast_kdf, master, TestEnv};

type UuidMutation = fn(&mut Vault, uuid::Uuid);

#[test]
#[allow(clippy::too_many_lines)]
fn uuid_stable_across_phase_two_uuid_preserving_operations() {
    let cases: &[(&str, UuidMutation)] = &[
        ("update_entry_password_change", |vault, uuid| {
            vault
                .update_entry(uuid, |entry| {
                    entry.set_password("changed");
                    Ok(())
                })
                .expect("update password");
        }),
        ("update_entry_url_change", |vault, uuid| {
            vault
                .update_entry(uuid, |entry| {
                    entry.set_url("https://changed.example");
                    Ok(())
                })
                .expect("update URL");
        }),
        ("update_entry_add_tag", |vault, uuid| {
            vault.add_tag(uuid, Tag::new("new")).expect("add tag");
        }),
        ("update_after_history_at_max", |vault, uuid| {
            vault.set_max_history_per_entry(2).expect("set history cap");
            for n in 1..=3 {
                vault
                    .update_entry(uuid, |entry| {
                        entry.set_notes(format!("version {n}"));
                        Ok(())
                    })
                    .expect("update entry at history cap");
            }
        }),
        ("move_entry_to_new_group", |vault, uuid| {
            let group = vault
                .create_group(vault.root_group_uuid(), "Archive")
                .expect("create group");
            vault.move_entry(uuid, group).expect("move entry");
        }),
        ("delete_entry_moves_to_bin", |vault, uuid| {
            vault.delete_entry(uuid).expect("delete entry");
        }),
        ("add_attachment", |vault, uuid| {
            vault
                .add_attachment(uuid, "file.bin", &[1, 2, 3])
                .expect("add attachment");
        }),
        ("remove_attachment", |vault, uuid| {
            vault
                .add_attachment(uuid, "file.bin", &[1, 2, 3])
                .expect("add attachment");
            vault
                .remove_attachment(uuid, "file.bin")
                .expect("remove attachment");
        }),
        ("set_expiration", |vault, uuid| {
            let when = Utc
                .timestamp_opt(1_000_000, 0)
                .single()
                .expect("valid timestamp");
            vault.set_expiration(uuid, when).expect("set expiration");
        }),
        ("clear_expiration", |vault, uuid| {
            let when = Utc
                .timestamp_opt(1_000_000, 0)
                .single()
                .expect("valid timestamp");
            vault.set_expiration(uuid, when).expect("set expiration");
            vault.clear_expiration(uuid).expect("clear expiration");
        }),
    ];

    for (name, mutate) in cases {
        let env = TestEnv::new();
        let path = env.tempdir().join(format!("{name}.kdbx"));
        let password = master("uuid stable");
        let uuid = {
            let mut vault = Vault::create(
                &path,
                &password,
                None,
                fast_kdf(),
                NoRecoveryConfirmed::yes(),
            )
            .expect("create vault");
            let uuid = vault
                .add_entry(
                    vault.root_group_uuid(),
                    EntryBuilder::credential("Example")
                        .username("alice")
                        .password("secret")
                        .build(),
                )
                .expect("add entry");
            mutate(&mut vault, uuid);
            vault.save().expect("save mutated vault");
            uuid
        };

        let vault = Vault::open(&path, &password, None).expect("reopen vault");
        let entry = vault
            .get_entry(uuid)
            .unwrap_or_else(|_| panic!("{name}: entry should be findable by original UUID"));
        assert_eq!(entry.uuid(), uuid, "{name}: UUID should be stable");
    }
}

#[test]
fn group_operations_preserve_nested_entry_uuid() {
    let env = TestEnv::new();
    let path = env.tempdir().join("group-preserve.kdbx");
    let password = master("uuid stable");
    let mut vault = Vault::create(
        &path,
        &password,
        None,
        fast_kdf(),
        NoRecoveryConfirmed::yes(),
    )
    .expect("create vault");

    let parent = vault
        .create_group(vault.root_group_uuid(), "Parent")
        .expect("create parent");
    let child = vault.create_group(parent, "Child").expect("create child");
    let uuid = vault
        .add_entry(child, EntryBuilder::credential("Nested").build())
        .expect("add nested entry");

    let new_parent = vault
        .create_group(vault.root_group_uuid(), "New Parent")
        .expect("create new parent");
    vault.move_group(parent, new_parent).expect("move group");
    vault
        .delete_group(parent, GroupDeleteBehavior::Recurse)
        .expect("move group subtree to recycle bin");

    let entry = vault
        .get_entry(uuid)
        .expect("nested entry remains addressable");
    assert_eq!(entry.uuid(), uuid);
}
