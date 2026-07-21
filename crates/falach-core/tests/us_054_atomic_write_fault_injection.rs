mod common;

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use falach_core::{fields, NoRecoveryConfirmed, Vault};

use common::{assert_no_temp_files, fast_kdf, master, TestEnv};

const PASSWORD: &str = "password";

#[test]
fn kill_after_temp_write_leaves_original_intact() {
    let env = TestEnv::new();
    let path = env.tempdir().join("personal.kdbx");
    create_seed_vault(&path);

    let mut child = spawn_faulting_save(&path, env.tempdir(), "temp_written", "after");
    wait_for_signal(env.tempdir(), "temp_written");
    kill_and_wait(&mut child);

    assert_entry_exists(&path, "before");
    assert_entry_missing(&path, "after");
}

#[test]
fn kill_after_fsync_leaves_original_intact() {
    let env = TestEnv::new();
    let path = env.tempdir().join("personal.kdbx");
    create_seed_vault(&path);

    let mut child = spawn_faulting_save(&path, env.tempdir(), "fsync_done", "after");
    wait_for_signal(env.tempdir(), "fsync_done");
    kill_and_wait(&mut child);

    assert_entry_exists(&path, "before");
    assert_entry_missing(&path, "after");
}

#[test]
fn kill_between_rename_and_dir_fsync_yields_post_edit_state() {
    let env = TestEnv::new();
    let path = env.tempdir().join("personal.kdbx");
    create_seed_vault(&path);

    let mut child = spawn_faulting_save(&path, env.tempdir(), "rename_done", "after");
    wait_for_signal(env.tempdir(), "rename_done");
    kill_and_wait(&mut child);

    assert_entry_exists(&path, "before");
    assert_entry_exists(&path, "after");
}

#[test]
fn no_orphan_temp_files_after_any_fault() {
    let env = TestEnv::new();
    let path = env.tempdir().join("personal.kdbx");
    create_seed_vault(&path);

    for phase in ["temp_written", "fsync_done", "rename_done"] {
        let mut child = spawn_faulting_save(&path, env.tempdir(), phase, phase);
        wait_for_signal(env.tempdir(), phase);
        kill_and_wait(&mut child);
        recover_with_successful_save(&path);
        assert_no_temp_files(env.tempdir());
    }
}

fn create_seed_vault(path: &Path) {
    let mut vault = Vault::create(
        path,
        &master(PASSWORD),
        None,
        fast_kdf(),
        NoRecoveryConfirmed::yes(),
    )
    .expect("create");
    vault.database_mut().root_mut().add_entry().edit(|entry| {
        entry.set_unprotected(fields::TITLE, "before");
    });
    vault.save().expect("save seed entry");
}

fn spawn_faulting_save(path: &Path, signal_dir: &Path, phase: &str, title: &str) -> Child {
    Command::new(env!("CARGO_BIN_EXE_fault_helper"))
        .arg("save")
        .arg(path)
        .arg(PASSWORD)
        .arg(title)
        .env("FALACH_ATOMIC_FAULT_TARGET", path)
        .env("FALACH_ATOMIC_FAULT_SIGNAL_DIR", signal_dir)
        .env("FALACH_ATOMIC_FAULT_PAUSE_PHASE", phase)
        .spawn()
        .expect("spawn fault helper")
}

fn wait_for_signal(dir: &Path, phase: &str) -> PathBuf {
    let signal = dir.join(phase);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !signal.exists() {
        assert!(Instant::now() < deadline, "helper did not signal {phase}");
        std::thread::yield_now();
    }
    signal
}

fn kill_and_wait(child: &mut Child) {
    child.kill().expect("kill fault helper");
    child.wait().expect("wait for fault helper");
}

fn assert_entry_exists(path: &Path, title: &str) {
    let vault = Vault::open(path, &master(PASSWORD), None).expect("open after fault");
    assert!(
        vault.database().root().entry_by_name(title).is_some(),
        "entry should exist: {title}"
    );
}

fn assert_entry_missing(path: &Path, title: &str) {
    let vault = Vault::open(path, &master(PASSWORD), None).expect("open after fault");
    assert!(
        vault.database().root().entry_by_name(title).is_none(),
        "entry should be absent: {title}"
    );
}

fn recover_with_successful_save(path: &Path) {
    let mut vault = Vault::open(path, &master(PASSWORD), None).expect("open for recovery save");
    vault.save().expect("recovery save");
}
