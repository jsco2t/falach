mod common;

use falach_core::{fields, NoRecoveryConfirmed, Vault, VaultError};

use common::{fast_kdf, master, TestEnv};

#[test]
fn two_vaults_can_be_created_and_independently_opened() {
    let env = TestEnv::new();
    let a_path = env.tempdir().join("a.kdbx");
    let b_path = env.tempdir().join("b.kdbx");

    drop(
        Vault::create(
            &a_path,
            &master("a-password"),
            None,
            fast_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create A"),
    );
    drop(
        Vault::create(
            &b_path,
            &master("b-password"),
            None,
            fast_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create B"),
    );

    Vault::open(&a_path, &master("a-password"), None).expect("open A");
    Vault::open(&b_path, &master("b-password"), None).expect("open B");
    assert!(matches!(
        Vault::open(&a_path, &master("b-password"), None),
        Err(VaultError::AuthenticationFailed)
    ));
}

#[test]
fn operations_on_one_vault_do_not_modify_the_other() {
    let env = TestEnv::new();
    let a_path = env.tempdir().join("a.kdbx");
    let b_path = env.tempdir().join("b.kdbx");

    drop(
        Vault::create(
            &a_path,
            &master("a-password"),
            None,
            fast_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create A"),
    );
    drop(
        Vault::create(
            &b_path,
            &master("b-password"),
            None,
            fast_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create B"),
    );

    {
        let mut a = Vault::open(&a_path, &master("a-password"), None).expect("open A");
        a.database_mut().root_mut().add_entry().edit(|entry| {
            entry.set_unprotected(fields::TITLE, "Only in A");
        });
        a.save().expect("save A");
    }

    let b = Vault::open(&b_path, &master("b-password"), None).expect("open B");
    assert!(b.database().root().entry_by_name("Only in A").is_none());
}
