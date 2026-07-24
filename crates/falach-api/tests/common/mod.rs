#![allow(dead_code)]

use std::sync::mpsc;

use falach_api::dto::LockEvent;
use falach_api::event::{EventSink, MpscEventSink};
use falach_core::{FalachPaths, KdfParams, MasterPassword, NoRecoveryConfirmed, Vault};
use tempfile::TempDir;

pub struct TestEnv {
    paths: FalachPaths,
    tempdir: TempDir,
}

impl TestEnv {
    pub fn new() -> Self {
        let tempdir = TempDir::new().expect("test env: create tempdir");
        let state = tempdir.path().join("state");
        let paths = FalachPaths::with_state_dir(state);
        Self { paths, tempdir }
    }

    pub fn paths(&self) -> &FalachPaths {
        &self.paths
    }

    pub fn paths_clone(&self) -> FalachPaths {
        FalachPaths::with_state_dir(self.paths.state_dir().to_path_buf())
    }

    pub fn tempdir(&self) -> &std::path::Path {
        self.tempdir.path()
    }
}

pub fn master(value: &str) -> MasterPassword {
    MasterPassword::new(value.to_string())
}

pub fn fast_kdf() -> KdfParams {
    KdfParams {
        memory_kib: 1_024,
        iterations: 1,
        parallelism: 1,
    }
}

pub fn create_test_vault(env: &TestEnv, name: &str, password: &str) -> std::path::PathBuf {
    let paths = env.paths();
    paths.ensure_exists().expect("ensure state dir");
    let vault_path = paths.state_dir().join(format!("{name}.kdbx"));
    let master = master(password);
    let _vault = Vault::create(
        &vault_path,
        &master,
        None,
        fast_kdf(),
        NoRecoveryConfirmed::yes(),
    )
    .expect("create test vault");
    vault_path
}

pub fn register_vault(env: &TestEnv, name: &str, vault_path: &std::path::Path) {
    use falach_core::{RegisteredVault, VaultRegistry};
    let mut registry = VaultRegistry::load(env.paths_clone()).expect("load registry");
    let rv = RegisteredVault {
        name: name.to_string(),
        path: vault_path.to_path_buf(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        keyfile_path: None,
        extra: toml::Table::new(),
    };
    registry.register(rv).expect("register vault");
    registry.save().expect("save registry");
}

pub struct RecordingLockSink {
    rx: mpsc::Receiver<LockEvent>,
}

impl RecordingLockSink {
    pub fn new() -> (Box<dyn EventSink<LockEvent>>, Self) {
        let (tx, rx) = mpsc::channel();
        let sink: Box<dyn EventSink<LockEvent>> = Box::new(MpscEventSink::new(tx));
        (sink, Self { rx })
    }

    pub fn try_recv(&self) -> Option<LockEvent> {
        self.rx.try_recv().ok()
    }

    pub fn drain(&self) -> Vec<LockEvent> {
        let mut events = Vec::new();
        while let Ok(e) = self.rx.try_recv() {
            events.push(e);
        }
        events
    }
}
