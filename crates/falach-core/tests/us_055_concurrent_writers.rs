mod common;

use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use falach_core::{fields, NoRecoveryConfirmed, Vault, VaultError};

use common::{fast_kdf, master, TestEnv};

const PASSWORD: &str = "password";

#[test]
fn second_process_returns_contended_while_first_holds() {
    let env = TestEnv::new();
    let path = env.tempdir().join("personal.kdbx");
    create_vault(&path);
    let release = env.tempdir().join("release");

    let mut holder = spawn_holder("hold", &path, env.tempdir().join("held"), &release, None);
    wait_for_path(&env.tempdir().join("held"), "holder signal");

    let result = Vault::open(&path, &master(PASSWORD), None);
    assert!(matches!(result, Err(VaultError::Contended { .. })));

    std::fs::write(&release, b"release").expect("release holder");
    holder.wait().expect("wait holder");
}

#[test]
fn second_process_succeeds_after_first_exits_normally() {
    let env = TestEnv::new();
    let path = env.tempdir().join("personal.kdbx");
    create_vault(&path);
    let release = env.tempdir().join("release");

    let mut holder = spawn_holder("hold", &path, env.tempdir().join("held"), &release, None);
    wait_for_path(&env.tempdir().join("held"), "holder signal");
    std::fs::write(&release, b"release").expect("release holder");
    holder.wait().expect("wait holder");

    Vault::open(&path, &master(PASSWORD), None).expect("open after normal holder exit");
}

#[test]
fn second_process_succeeds_after_first_is_killed() {
    let env = TestEnv::new();
    let path = env.tempdir().join("personal.kdbx");
    create_vault(&path);

    let mut holder = spawn_holder(
        "hold",
        &path,
        env.tempdir().join("held"),
        &env.tempdir().join("never-release"),
        None,
    );
    wait_for_path(&env.tempdir().join("held"), "holder signal");

    holder.kill().expect("kill holder");
    holder.wait().expect("wait killed holder");

    Vault::open(&path, &master(PASSWORD), None).expect("open after killed holder");
}

#[test]
fn concurrent_writes_do_not_corrupt() {
    let env = TestEnv::new();
    let path = env.tempdir().join("personal.kdbx");
    create_vault(&path);
    let release = env.tempdir().join("release");

    let mut holder = spawn_holder(
        "write-hold",
        &path,
        env.tempdir().join("held"),
        &release,
        Some("from-holder"),
    );
    wait_for_path(&env.tempdir().join("held"), "holder signal");

    assert!(matches!(
        Vault::open(&path, &master(PASSWORD), None),
        Err(VaultError::Contended { .. })
    ));

    std::fs::write(&release, b"release").expect("release holder");
    holder.wait().expect("wait writer holder");

    let mut vault = Vault::open(&path, &master(PASSWORD), None).expect("open second writer");
    vault.database_mut().root_mut().add_entry().edit(|entry| {
        entry.set_unprotected(fields::TITLE, "from-second");
    });
    vault.save().expect("save second writer");
    drop(vault);

    let vault =
        Vault::open(&path, &master(PASSWORD), None).expect("reopen after concurrent writes");
    assert!(vault
        .database()
        .root()
        .entry_by_name("from-holder")
        .is_some());
    assert!(vault
        .database()
        .root()
        .entry_by_name("from-second")
        .is_some());
}

fn create_vault(path: &Path) {
    drop(
        Vault::create(
            path,
            &master(PASSWORD),
            None,
            fast_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create"),
    );
}

fn spawn_holder(
    mode: &str,
    path: &Path,
    held_signal: impl AsRef<Path>,
    release_signal: &Path,
    title: Option<&str>,
) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_vault_holder"));
    command
        .arg(mode)
        .arg(path)
        .arg(PASSWORD)
        .arg(held_signal.as_ref())
        .arg(release_signal);
    if let Some(title) = title {
        command.arg(title);
    }
    command.spawn().expect("spawn vault holder")
}

fn wait_for_path(path: &Path, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(Instant::now() < deadline, "{label} did not appear");
        std::thread::yield_now();
    }
}
