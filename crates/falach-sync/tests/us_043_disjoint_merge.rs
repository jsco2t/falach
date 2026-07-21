//! US-043 — disjoint edits on two devices merge cleanly without prompting
//! (FR-043; impl plan §8.4.3). Inherits the archive's merge-engine-centric
//! assertions; only the transport changed (now `MemoryTransport`). Both
//! devices' edits are visible after the merge.

#![allow(clippy::doc_markdown)]

mod common;

use common::sync_env::{open_vault, vault_entry_titles, SyncTestEnv};
use falach_sync::sync::run_state_machine;
use falach_sync::transport::memory::MemoryTransport;
use falach_sync::transport::SyncTransport;
use falach_sync::{SyncOptions, SyncOutcome};

#[test]
fn disjoint_edits_merge_without_data_loss() {
    // Shared base, synced.
    let dev_a = SyncTestEnv::new("work");
    dev_a.add_entry("base");
    let base_sha = dev_a.local_sha();

    // Device B adds a disjoint entry and pushes.
    let dev_b = dev_a.clone_to("work-b");
    dev_b.add_entry("from-b");
    let mut transport = MemoryTransport::new();
    {
        let b_bytes = std::fs::read(dev_b.vault_path()).unwrap();
        transport
            .put_conditional(&b_bytes, None)
            .expect("device B push");
    }

    // Device A adds a *different* disjoint entry, then syncs → both diverged.
    dev_a.add_entry("from-a");
    let mut vault = open_vault(&dev_a);
    let (outcome, _) = run_state_machine(
        &mut vault,
        &dev_a.master(),
        None,
        &mut transport,
        Some("stale-etag".to_string()), // ≠ remote → remote_changed
        Some(&base_sha),                // ≠ current local → local_changed
        SyncOptions::default(),
    )
    .expect("disjoint merge sync ok");

    assert!(
        matches!(outcome, SyncOutcome::Merged { .. }),
        "got {outcome:?}"
    );

    // No data loss: base + both devices' entries are present.
    let titles = vault_entry_titles(&vault);
    for want in ["base", "from-a", "from-b"] {
        assert!(
            titles.contains(&want.to_string()),
            "missing {want}: {titles:?}"
        );
    }
}

#[test]
fn merge_result_uploads_and_is_idempotent_on_resync() {
    // After a merge sync, an immediate re-sync (no further edits) is a no-op:
    // remote == local-synced. Confirms the merged state is the new base.
    let dev_a = SyncTestEnv::new("work");
    dev_a.add_entry("base");
    let base_sha = dev_a.local_sha();

    let dev_b = dev_a.clone_to("work-b");
    dev_b.add_entry("from-b");
    let mut transport = MemoryTransport::new();
    {
        let b_bytes = std::fs::read(dev_b.vault_path()).unwrap();
        transport
            .put_conditional(&b_bytes, None)
            .expect("device B push");
    }

    dev_a.add_entry("from-a");
    let mut vault = open_vault(&dev_a);
    let (_, pointers) = run_state_machine(
        &mut vault,
        &dev_a.master(),
        None,
        &mut transport,
        Some("stale-etag".to_string()),
        Some(&base_sha),
        SyncOptions::default(),
    )
    .expect("merge sync ok");
    drop(vault);

    // Re-sync from the just-recorded pointers → AlreadyInSync.
    let mut vault = open_vault(&dev_a);
    let (outcome, _) = run_state_machine(
        &mut vault,
        &dev_a.master(),
        None,
        &mut transport,
        pointers.remote_etag.clone(),
        pointers.local_sha256.as_deref(),
        SyncOptions::default(),
    )
    .expect("resync ok");
    assert!(
        matches!(outcome, SyncOutcome::AlreadyInSync),
        "got {outcome:?}"
    );
}
