mod common;

use falach_core::{NoRecoveryConfirmed, Vault, VaultReadOnly};

use common::{assert_no_temp_files, fast_kdf, master, TestEnv};

#[test]
fn open_succeeds_with_correct_password() {
    let env = TestEnv::new();
    let path = env.tempdir().join("personal.kdbx");
    let password = master("correct");

    drop(
        Vault::create(
            &path,
            &password,
            None,
            fast_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create"),
    );

    let vault = Vault::open(&path, &password, None).expect("open rw");
    assert_eq!(vault.database().root().name, "");
}

#[test]
fn read_only_open_leaves_no_temp_files() {
    let env = TestEnv::new();
    let path = env.tempdir().join("readonly.kdbx");
    let password = master("correct");

    drop(
        Vault::create(
            &path,
            &password,
            None,
            fast_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create"),
    );

    let vault = VaultReadOnly::open(&path, &password, None).expect("open readonly");
    assert_eq!(vault.path(), path.as_path());
    assert_no_temp_files(env.tempdir());
    drop(vault);
    assert_no_temp_files(env.tempdir());
}
