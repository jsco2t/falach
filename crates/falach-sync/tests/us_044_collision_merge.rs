//! US-044 — same-entry collision merge (FR-043; impl plan §8.4.3). Two
//! devices edit the *same* entry; the most-recently-modified value wins and
//! the loser is preserved as a KDBX history entry under the same UUID. No
//! data is destroyed. Inherits the archive's assertions; transport is now
//! `MemoryTransport`.

#![allow(clippy::doc_markdown)]

mod common;

use common::sync_env::{current_title, entry_history_titles, open_vault, SyncTestEnv};
use falach_sync::sync::run_state_machine;
use falach_sync::transport::memory::MemoryTransport;
use falach_sync::transport::SyncTransport;
use falach_sync::{backup, SyncError, SyncOptions, SyncOutcome};

// Explicit modification stamps (Unix secs) so the collision direction is
// deterministic: device A (newer) must win over device B (older). Both are
// after the base seed (~1_700_000_000).
const B_EDIT_TIME: i64 = 1_700_001_000;
const A_EDIT_TIME: i64 = 1_700_002_000;

#[test]
fn same_entry_collision_newer_wins_loser_in_history() {
    // Shared base entry, synced.
    let dev_a = SyncTestEnv::new("work");
    let uuid = dev_a.seed_entry("base");
    let base_sha = dev_a.local_sha();

    // Device B edits the shared entry (older) and pushes.
    let dev_b = dev_a.clone_to("work-b");
    dev_b.edit_entry_at(uuid, "from-b", B_EDIT_TIME);
    let mut transport = MemoryTransport::new();
    {
        let b_bytes = std::fs::read(dev_b.vault_path()).unwrap();
        transport
            .put_conditional(&b_bytes, None)
            .expect("device B push");
    }

    // Device A edits the SAME entry (newer), then syncs → collision merge.
    dev_a.edit_entry_at(uuid, "from-a", A_EDIT_TIME);
    let mut vault = open_vault(&dev_a);
    let (outcome, _) = run_state_machine(
        &mut vault,
        &dev_a.master(),
        None,
        &mut transport,
        Some("stale-etag".to_string()),
        Some(&base_sha),
        SyncOptions::default(),
    )
    .expect("collision merge sync ok");

    assert!(
        matches!(outcome, SyncOutcome::Merged { .. }),
        "got {outcome:?}"
    );

    // Newer (device A) wins the current value.
    assert_eq!(
        current_title(&vault, uuid).as_deref(),
        Some("from-a"),
        "most-recently-modified value must win"
    );

    // The loser (device B's value) is preserved as history — no data loss.
    let history = entry_history_titles(&vault, uuid);
    assert!(
        history.contains(&"from-b".to_string()),
        "the collision loser must survive as a history entry, history={history:?}"
    );
}

/// Same-entry collision where BOTH devices edit at the *same second* with
/// differing content: the merge engine cannot pick a winner (FR-043), so
/// `sync` must surface `SyncError::Unresolvable` carrying the pre-merge
/// `.kdbx.bak` path — the value the CLI maps to exit 3 and the TUI renders
/// prominently.
///
/// This guards the orchestrator's `MergeError::Unresolvable` →
/// `SyncError::Unresolvable` wrapping (`sync.rs`). Without it the conflict
/// leaks out as the generic `SyncError::Merge(_)` → the CLI's exit-3 arm
/// and the TUI's prominent-conflict arm are both unreachable at runtime.
#[test]
fn same_second_collision_surfaces_unresolvable_with_backup() {
    // A single second both edits share — differing content at an identical
    // modification stamp is exactly the unresolvable case.
    const SAME_SECOND: i64 = 1_700_005_000;

    let dev_a = SyncTestEnv::new("work");
    let uuid = dev_a.seed_entry("base");
    let base_sha = dev_a.local_sha();

    // Device B edits the shared entry (at SAME_SECOND) and pushes.
    let dev_b = dev_a.clone_to("work-b");
    dev_b.edit_entry_at(uuid, "from-b", SAME_SECOND);
    let mut transport = MemoryTransport::new();
    {
        let b_bytes = std::fs::read(dev_b.vault_path()).unwrap();
        transport
            .put_conditional(&b_bytes, None)
            .expect("device B push");
    }

    // Device A edits the SAME entry at the SAME second with different content
    // → both diverged → merge → unresolvable.
    dev_a.edit_entry_at(uuid, "from-a", SAME_SECOND);
    let mut vault = open_vault(&dev_a);
    let result = run_state_machine(
        &mut vault,
        &dev_a.master(),
        None,
        &mut transport,
        Some("stale-etag".to_string()),
        Some(&base_sha),
        SyncOptions::default(),
    );

    match result {
        Err(SyncError::Unresolvable { backup_path, .. }) => {
            assert_eq!(
                backup_path,
                backup::backup_path_for(dev_a.vault_path()),
                "backup_path must be the vault's .kdbx.bak sibling"
            );
            assert!(
                backup_path.exists(),
                "the pre-merge .kdbx.bak must exist at the reported path: {}",
                backup_path.display()
            );
        }
        other => panic!("expected SyncError::Unresolvable, got {other:?}"),
    }
}
