//! US-041 — fast-replace on open (FR-041; impl plan §8.4.3). When the remote
//! advanced but the local vault is unchanged since the last sync, the
//! orchestrator replaces the local with the remote bytes WITHOUT invoking the
//! merge engine. Driven through `MemoryTransport` — no network, no S3 types.

#![allow(clippy::doc_markdown)]

mod common;

use common::sync_env::{open_vault, vault_entry_titles, SyncTestEnv};
use falach_sync::sync::run_state_machine;
use falach_sync::transport::memory::MemoryTransport;
use falach_sync::transport::SyncTransport;
use falach_sync::{SyncOptions, SyncOutcome};

#[test]
fn remote_advanced_local_unchanged_fast_replaces() {
    // Device A: create a vault and "sync" it (seed the remote with its bytes).
    let dev_a = SyncTestEnv::new("work");
    dev_a.add_entry("base");
    let mut transport = MemoryTransport::new();
    let synced_etag = {
        let bytes = std::fs::read(dev_a.vault_path()).unwrap();
        transport
            .put_conditional(&bytes, None)
            .expect("seed remote")
    };
    let synced_sha = dev_a.local_sha();

    // Device B: same logical vault, adds an entry, pushes → remote advances.
    let dev_b = dev_a.clone_to("work-b");
    dev_b.add_entry("from-b");
    {
        let b_bytes = std::fs::read(dev_b.vault_path()).unwrap();
        transport
            .put_conditional(&b_bytes, Some(&synced_etag))
            .expect("device B push advances the remote");
    }

    // Device A syncs: remote changed (etag moved), local unchanged (sha ==
    // last-synced). → FastReplaced, merge NOT invoked.
    let mut vault = open_vault(&dev_a);
    let (outcome, pointers) = run_state_machine(
        &mut vault,
        &dev_a.master(),
        None,
        &mut transport,
        Some(synced_etag.0),
        Some(&synced_sha),
        SyncOptions::default(),
    )
    .expect("fast-replace sync ok");

    assert!(
        matches!(outcome, SyncOutcome::FastReplaced),
        "got {outcome:?}"
    );

    // Device A now sees device B's entry (the remote replaced the local).
    let titles = vault_entry_titles(&vault);
    assert!(titles.contains(&"base".to_string()));
    assert!(
        titles.contains(&"from-b".to_string()),
        "remote bytes replaced local: {titles:?}"
    );
    assert!(pointers.remote_etag.is_some() && pointers.local_sha256.is_some());
}
