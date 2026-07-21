//! US-045 — sync failure leaves the vault fully usable locally with a clear,
//! actionable error (FR-044; impl plan §8.4.3). Covers the "not configured"
//! and "remote unreachable" failure modes deterministically; the live-wire
//! unreachable case is MINIO-011. The local vault must be unharmed.

#![allow(clippy::doc_markdown)]

mod common;

use common::sync_env::{open_vault, SyncTestEnv};
use falach_sync::sync::run_state_machine;
use falach_sync::transport::memory::MemoryTransport;
use falach_sync::{backup, Sync, SyncError, SyncOptions};

#[test]
fn sync_now_on_unconfigured_vault_returns_not_configured() {
    // A registered vault with no `[sync]` block must surface NotConfigured —
    // a clear, actionable error. `vault`, `name`, and `master` are all owned
    // by the time the registry is borrowed, so the single `&mut` borrow is
    // the registry argument.
    let mut dev = SyncTestEnv::new("work");
    dev.add_entry("local-only");
    let name = dev.name().to_string();
    let master = dev.master();
    let mut vault = open_vault(&dev);

    let err = Sync::sync_now(
        &mut vault,
        &name,
        dev.registry_mut(),
        &master,
        None,
        SyncOptions::default(),
    )
    .expect_err("unconfigured vault must error");
    assert!(matches!(err, SyncError::NotConfigured), "got {err:?}");
}

#[test]
fn remote_unreachable_leaves_local_vault_intact() {
    let dev = SyncTestEnv::new("work");
    dev.add_entry("local-only");
    let pre_bytes = std::fs::read(dev.vault_path()).unwrap();

    // A transport whose HEAD fails → SyncError::RemoteUnreachable.
    let mut transport = MemoryTransport::new();
    transport.set_fail_head(true);

    {
        let mut vault = open_vault(&dev);
        let err = run_state_machine(
            &mut vault,
            &dev.master(),
            None,
            &mut transport,
            None,
            None,
            SyncOptions::default(),
        )
        .expect_err("HEAD failure must surface an error");
        assert!(
            matches!(err, SyncError::RemoteUnreachable { .. }),
            "got {err:?}"
        );
    }

    // The local vault is byte-identical and still opens; no `.kdbx.bak` was
    // written (we failed before any merge work).
    assert_eq!(
        std::fs::read(dev.vault_path()).unwrap(),
        pre_bytes,
        "local vault unchanged"
    );
    assert!(
        !backup::backup_path_for(dev.vault_path()).exists(),
        "no .kdbx.bak on a pre-merge failure"
    );
    let _ = open_vault(&dev); // still opens cleanly with the same password
}
