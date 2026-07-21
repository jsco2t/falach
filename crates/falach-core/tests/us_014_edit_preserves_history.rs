mod common;

use falach_core::{EntryBuilder, NoRecoveryConfirmed, Vault, VaultError};

use common::{fast_kdf, master, TestEnv};

#[test]
fn update_entry_preserves_history_and_prunes_oldest() {
    let env = TestEnv::new();
    let path = env.tempdir().join("history.kdbx");
    let password = master("history password");

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
                    .password("password-v1")
                    .build(),
            )
            .expect("add entry");

        for version in 2..=4 {
            vault
                .update_entry(uuid, |entry| {
                    entry.set_password(format!("password-v{version}"));
                    Ok(())
                })
                .expect("update password");
        }

        {
            let entry = vault.get_entry(uuid).expect("entry exists");
            let history = entry.history();
            assert_eq!(history.len(), 3);
            assert_eq!(history[0].password(), "password-v3");
            assert_eq!(history[1].password(), "password-v2");
            assert_eq!(history[2].password(), "password-v1");
        }

        vault.set_max_history_per_entry(2).expect("set history cap");
        vault
            .update_entry(uuid, |entry| {
                entry.set_password("password-v5");
                Ok(())
            })
            .expect("update with pruned history");
        vault.save().expect("save vault");
        uuid
    };

    let vault = Vault::open(&path, &password, None).expect("reopen vault");
    let entry = vault.get_entry(uuid).expect("entry exists after reopen");
    let history = entry.history();
    assert_eq!(entry.password(), "password-v5");
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].password(), "password-v4");
    assert_eq!(history[1].password(), "password-v3");
}

#[test]
fn update_entry_closure_failure_rolls_back_entry_and_history() {
    let env = TestEnv::new();
    let path = env.tempdir().join("rollback.kdbx");
    let password = master("history password");
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
                .password("original")
                .build(),
        )
        .expect("add entry");

    let result = vault.update_entry(uuid, |entry| {
        entry.set_password("should roll back");
        Err(VaultError::InvalidGroupTarget {
            reason: "intentional test failure",
        })
    });

    assert!(matches!(result, Err(VaultError::InvalidGroupTarget { .. })));
    let entry = vault.get_entry(uuid).expect("entry still exists");
    assert_eq!(entry.password(), "original");
    assert_eq!(entry.history().len(), 0);
}
