mod common;

use falach_core::{Keyfile, NoRecoveryConfirmed, Vault, VaultError, VaultReadOnly};

use common::{fast_kdf, master, TestEnv};

#[test]
fn open_with_wrong_password_returns_auth_failed() {
    let env = TestEnv::new();
    let path = env.tempdir().join("personal.kdbx");

    drop(
        Vault::create(
            &path,
            &master("correct"),
            None,
            fast_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create"),
    );

    assert!(matches!(
        Vault::open(&path, &master("wrong"), None),
        Err(VaultError::AuthenticationFailed)
    ));
    assert!(matches!(
        VaultReadOnly::open(&path, &master("wrong"), None),
        Err(VaultError::AuthenticationFailed)
    ));
}

#[test]
fn open_with_wrong_keyfile_returns_auth_failed() {
    let env = TestEnv::new();
    let path = env.tempdir().join("keyed.kdbx");
    let correct_keyfile = Keyfile::Bytes(b"correct keyfile".to_vec());
    let wrong_keyfile = Keyfile::Bytes(b"wrong keyfile".to_vec());

    drop(
        Vault::create(
            &path,
            &master("correct"),
            Some(&correct_keyfile),
            fast_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create"),
    );

    let Err(err) = Vault::open(&path, &master("correct"), Some(&wrong_keyfile)) else {
        panic!("wrong keyfile should fail");
    };
    assert!(matches!(err, VaultError::AuthenticationFailed));

    let display = err.to_string().to_ascii_lowercase();
    let debug = format!("{err:?}").to_ascii_lowercase();
    assert!(!display.contains("keyfile"));
    assert!(!debug.contains("keyfile"));
}
