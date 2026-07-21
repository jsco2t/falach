mod common;

use falach_core::{NoRecoveryConfirmed, Vault, VaultError};

use common::{fast_kdf, master, TestEnv};

#[test]
fn change_master_password_succeeds() {
    let env = TestEnv::new();
    let path = env.tempdir().join("personal.kdbx");

    let mut vault = Vault::create(
        &path,
        &master("old"),
        None,
        fast_kdf(),
        NoRecoveryConfirmed::yes(),
    )
    .expect("create");

    vault
        .change_master_password(&master("old"), &master("new"))
        .expect("change password");
    vault.save().expect("save after change");
    drop(vault);

    assert!(matches!(
        Vault::open(&path, &master("old"), None),
        Err(VaultError::AuthenticationFailed)
    ));
    Vault::open(&path, &master("new"), None).expect("open with new password");
}

#[test]
fn change_master_password_with_wrong_current_returns_auth() {
    let env = TestEnv::new();
    let path = env.tempdir().join("personal.kdbx");

    let mut vault = Vault::create(
        &path,
        &master("old"),
        None,
        fast_kdf(),
        NoRecoveryConfirmed::yes(),
    )
    .expect("create");

    let err = vault
        .change_master_password(&master("wrong"), &master("new"))
        .expect_err("wrong current should fail");
    assert!(matches!(err, VaultError::AuthenticationFailed));
    drop(vault);

    Vault::open(&path, &master("old"), None).expect("old password still works");
}

#[cfg(unix)]
#[test]
fn interrupted_change_master_password_preserves_old_vault() {
    use std::process::Command;
    use std::time::{Duration, Instant};

    let env = TestEnv::new();
    let path = env.tempdir().join("personal.kdbx");

    drop(
        Vault::create(
            &path,
            &master("old"),
            None,
            fast_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create"),
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_fault_helper"))
        .arg("change-password")
        .arg(&path)
        .arg("old")
        .arg("new")
        .env("FALACH_ATOMIC_FAULT_TARGET", &path)
        .env("FALACH_ATOMIC_FAULT_SIGNAL_DIR", env.tempdir())
        .env("FALACH_ATOMIC_FAULT_PAUSE_PHASE", "fsync_done")
        .spawn()
        .expect("spawn fault helper");

    let signal = env.tempdir().join("fsync_done");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !signal.exists() {
        assert!(
            Instant::now() < deadline,
            "helper did not pause after temp fsync in time"
        );
        std::thread::yield_now();
    }

    child.kill().expect("kill paused helper");
    child.wait().expect("wait for helper");

    Vault::open(&path, &master("old"), None).expect("old password preserved");
    assert!(matches!(
        Vault::open(&path, &master("new"), None),
        Err(VaultError::AuthenticationFailed)
    ));
}

#[cfg(not(unix))]
#[test]
fn interrupted_change_master_password_preserves_old_vault() {
    let env = TestEnv::new();
    let path = env.tempdir().join("personal.kdbx");

    let mut vault = Vault::create(
        &path,
        &master("old"),
        None,
        fast_kdf(),
        NoRecoveryConfirmed::yes(),
    )
    .expect("create");

    let result = vault.change_master_password(&master("old"), &master("new"));

    assert!(
        result.is_err(),
        "save should fail before replacing the vault"
    );
    drop(vault);

    Vault::open(&path, &master("old"), None).expect("old password preserved");
}
