mod common;

use falach_core::{RegisteredVault, VaultError, VaultRegistry};

use common::TestEnv;

fn record(name: &str, path: std::path::PathBuf) -> RegisteredVault {
    RegisteredVault {
        name: name.to_string(),
        path,
        created_at: "2026-05-20T12:00:00-06:00".to_string(),
        keyfile_path: None,
        extra: toml::Table::new(),
    }
}

#[test]
fn deregister_without_delete_preserves_file() {
    let env = TestEnv::new();
    let path = env.tempdir().join("personal.kdbx");
    std::fs::write(&path, b"vault bytes").expect("write vault");
    let before = std::fs::read(&path).expect("read before");

    let mut registry = VaultRegistry::with_paths(env.paths().clone());
    registry
        .register(record("personal", path.clone()))
        .expect("register");

    let removed = registry
        .deregister("personal", false)
        .expect("deregister only");
    assert_eq!(removed.name, "personal");
    assert!(registry.get("personal").is_none());
    assert_eq!(std::fs::read(&path).expect("file preserved"), before);
}

#[test]
fn deregister_with_delete_removes_file() {
    let env = TestEnv::new();
    let path = env.tempdir().join("personal.kdbx");
    std::fs::write(&path, b"vault bytes").expect("write vault");

    let mut registry = VaultRegistry::with_paths(env.paths().clone());
    registry
        .register(record("personal", path.clone()))
        .expect("register");

    registry
        .deregister("personal", true)
        .expect("deregister and delete");
    assert!(registry.get("personal").is_none());
    assert!(!path.exists());
}

#[test]
fn deregister_unknown_returns_not_registered() {
    let env = TestEnv::new();
    let mut registry = VaultRegistry::with_paths(env.paths().clone());

    let err = registry
        .deregister("missing", false)
        .expect_err("unknown should fail");
    assert!(matches!(err, VaultError::NotRegistered { ref name } if name == "missing"));
}
