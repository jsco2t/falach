mod common;

use falach_core::{Keyfile, NoRecoveryConfirmed, Vault, VaultError};

use common::{fast_kdf, master, TestEnv};

#[test]
fn create_vault_produces_valid_kdbx4_file() {
    let env = TestEnv::new();
    let path = env.tempdir().join("personal.kdbx");
    let password = master("create password");

    {
        let vault = Vault::create(
            &path,
            &password,
            None,
            fast_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create vault");
        assert_eq!(vault.path(), path.as_path());
        assert!(path.exists());
    }

    let reopened = Vault::open(&path, &password, None).expect("reopen created vault");
    assert_eq!(reopened.path(), path.as_path());
}

#[test]
fn create_vault_with_keyfile_succeeds_and_opens_with_keyfile() {
    let env = TestEnv::new();
    let path = env.tempdir().join("keyed.kdbx");
    let keyfile_path = env.tempdir().join("keyfile.bin");
    std::fs::write(&keyfile_path, b"keyfile contents").expect("write keyfile");

    let password = master("create password");
    let keyfile = Keyfile::Path(keyfile_path);

    drop(
        Vault::create(
            &path,
            &password,
            Some(&keyfile),
            fast_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create keyed vault"),
    );

    assert!(matches!(
        Vault::open(&path, &password, None),
        Err(VaultError::AuthenticationFailed)
    ));
    Vault::open(&path, &password, Some(&keyfile)).expect("open with keyfile");
}
