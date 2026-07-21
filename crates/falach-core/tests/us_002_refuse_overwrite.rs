mod common;

use falach_core::locking::acquire_exclusive;
use falach_core::{NoRecoveryConfirmed, Vault, VaultError};

use common::{fast_kdf, master, TestEnv};

#[test]
fn create_refuses_when_target_exists() {
    let env = TestEnv::new();
    let path = env.tempdir().join("existing.kdbx");
    std::fs::write(&path, b"do not overwrite").expect("seed existing file");
    let before = std::fs::read(&path).expect("read before");

    let Err(err) = Vault::create(
        &path,
        &master("password"),
        None,
        fast_kdf(),
        NoRecoveryConfirmed::yes(),
    ) else {
        panic!("create should refuse existing path");
    };

    assert!(matches!(err, VaultError::PathExists { path: ref p } if p == &path));
    assert_eq!(std::fs::read(&path).expect("read after"), before);
}

#[test]
fn create_respects_existing_sidecar_lock() {
    let env = TestEnv::new();
    let path = env.tempdir().join("locked-before-create.kdbx");
    let _lock = acquire_exclusive(&path).expect("pre-hold sidecar lock");

    let Err(err) = Vault::create(
        &path,
        &master("password"),
        None,
        fast_kdf(),
        NoRecoveryConfirmed::yes(),
    ) else {
        panic!("create should refuse while sidecar lock is held");
    };

    assert!(matches!(err, VaultError::Contended { .. }));
    assert!(
        !path.exists(),
        "failed create should remove reservation file"
    );
}
