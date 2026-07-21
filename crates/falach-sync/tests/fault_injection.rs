//! Fault-injection tests for the pre-merge `.kdbx.bak` guarantee (FR-048;
//! s3-sync T6.4; impl plan §8.4.5).
//!
//! These verify the *orchestrator's sequencing*: that `.kdbx.bak` is written
//! before any state that's hard to roll back, so a process killed mid-sync
//! always leaves a recoverable vault. We can't kill a real process from a
//! unit test, so [`MemoryTransport::set_panic_after`] injects a panic at a
//! well-defined boundary (the next trait-method call), and
//! `std::panic::catch_unwind` lets the test inspect the on-disk state after.
//!
//! All three run under the default `cargo test` (no live backend needed).

#![allow(clippy::doc_markdown)]

mod common;

use std::panic::{self, AssertUnwindSafe};

use common::sync_env::{current_title, entry_history_titles, SyncTestEnv};
use falach_core::Uuid;
use falach_sync::backup::backup_path_for;
use falach_sync::sync::run_state_machine;
use falach_sync::transport::memory::MemoryTransport;
use falach_sync::transport::SyncTransport;
use falach_sync::{FaultBoundary, SyncError, SyncOptions};

/// Build the `(true, true)` merge scenario shared by all three tests:
/// device A holds `base + from-a`; the MemoryTransport's remote holds
/// `base + from-b` (device B's diverged push). Returns the env, the shared
/// entry UUID, the seeded MemoryTransport, and the synced-base pointers.
fn diverged_setup() -> (SyncTestEnv, Uuid, MemoryTransport, String, String) {
    let dev_a = SyncTestEnv::new("work");
    let uuid = dev_a.seed_entry("base");
    let base_sha = dev_a.local_sha();

    // Device B: same logical vault, adds a disjoint entry, "pushes" to the
    // in-memory remote.
    let dev_b = dev_a.clone_to("work-b");
    dev_b.add_entry("from-b");
    let mut transport = MemoryTransport::new();
    let b_bytes = std::fs::read(dev_b.vault_path()).unwrap();
    let _b_version = transport
        .put_conditional(&b_bytes, None)
        .expect("seed remote");

    // Device A diverges locally too.
    dev_a.add_entry("from-a");

    // Pointers: a stale remote etag (≠ B's) → remote_changed; the pre-edit
    // base sha (≠ A's current) → local_changed. Both axes true → merge path.
    (dev_a, uuid, transport, "stale-etag".to_string(), base_sha)
}

/// Serializes the process-global panic-hook swap below. The three fault
/// tests run in parallel by default; without this, their `take_hook` /
/// `set_hook` pairs could interleave and leave a no-op hook installed for
/// the rest of the binary. Holding it across the (fast) `catch_unwind` is
/// fine — and because the panic is caught *inside* the guard, the mutex is
/// never poisoned.
static PANIC_HOOK_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Run `run_state_machine` under a suppressed panic hook, returning whether
/// it panicked. The vault is opened + dropped inside so its advisory lock is
/// released before the caller inspects / re-opens the file.
fn run_expecting_panic(
    dev: &SyncTestEnv,
    transport: &mut MemoryTransport,
    last_remote: &str,
    last_local_sha: &str,
) -> bool {
    let _guard = PANIC_HOOK_GUARD
        .lock()
        .expect("panic-hook guard not poisoned");
    let prev_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {})); // silence the injected panic's output
    let result = {
        let mut vault = dev.open();
        panic::catch_unwind(AssertUnwindSafe(|| {
            let _ = run_state_machine(
                &mut vault,
                &dev.master(),
                None,
                transport,
                Some(last_remote.to_string()),
                Some(last_local_sha),
                SyncOptions::default(),
            );
        }))
        // `vault` drops here → advisory lock released.
    };
    panic::set_hook(prev_hook);
    result.is_err()
}

// ---------------------------------------------------------------------------
// Merge-conflict error path (FR-048) — the one conflict a user can actually
// hit: the same entry edited on two devices within KDBX's one-second
// timestamp granularity. `reconcile` may leave the in-memory database
// partially modified on error, so the orchestrator's contract is: surface
// `SyncError::Unresolvable` (carrying the `.kdbx.bak` path — the value the
// CLI maps to exit 3 and the TUI renders prominently), never save the
// half-merged state, and leave `.kdbx.bak` holding the pre-merge vault.
// ---------------------------------------------------------------------------
#[test]
fn unresolvable_merge_surfaces_error_and_preserves_disk_state() {
    // Same-second divergence: both devices edit the same entry with the
    // same last_modification stamp but different content.
    const SAME_SECOND: i64 = 1_800_000_000;

    let dev_a = SyncTestEnv::new("conflict");
    let uuid = dev_a.seed_entry("base");
    let base_sha = dev_a.local_sha();

    let dev_b = dev_a.clone_to("conflict-b");
    dev_b.edit_entry_at(uuid, "from-b", SAME_SECOND);
    let mut transport = MemoryTransport::new();
    let b_bytes = std::fs::read(dev_b.vault_path()).unwrap();
    transport
        .put_conditional(&b_bytes, None)
        .expect("seed remote");

    dev_a.edit_entry_at(uuid, "from-a", SAME_SECOND);
    let pre_bytes = std::fs::read(dev_a.vault_path()).unwrap();

    let err = {
        let mut vault = dev_a.open();
        run_state_machine(
            &mut vault,
            &dev_a.master(),
            None,
            &mut transport,
            Some("stale-etag".to_string()),
            Some(&base_sha),
            SyncOptions::default(),
        )
        .expect_err("same-second divergence must surface a merge conflict")
        // vault drops here → advisory lock released before file reads.
    };
    match &err {
        SyncError::Unresolvable { backup_path, .. } => {
            assert_eq!(
                *backup_path,
                backup_path_for(dev_a.vault_path()),
                "the error must carry the pre-merge .kdbx.bak path"
            );
        }
        other => panic!("the conflict must map to SyncError::Unresolvable, got {other:?}"),
    }

    let post_bytes = std::fs::read(dev_a.vault_path()).unwrap();
    assert_eq!(
        post_bytes, pre_bytes,
        "the half-merged in-memory state must never reach disk"
    );
    let bak = backup_path_for(dev_a.vault_path());
    assert!(bak.exists(), ".kdbx.bak must exist on a merge conflict");
    assert_eq!(
        std::fs::read(&bak).unwrap(),
        pre_bytes,
        ".kdbx.bak must hold the pre-merge vault"
    );
}

// ---------------------------------------------------------------------------
// TC-FAULT-001 — panic after `.kdbx.bak`, before the fetch. The backup
// exists and equals the (untouched) original local vault; no merge happened.
// ---------------------------------------------------------------------------
#[test]
fn panic_after_bak_before_fetch_leaves_bak_and_original_intact() {
    let (dev, uuid, mut transport, last_remote, last_sha) = diverged_setup();
    let pre_bytes = std::fs::read(dev.vault_path()).unwrap();

    transport.set_panic_after(FaultBoundary::AfterBakBeforeFetch);
    let panicked = run_expecting_panic(&dev, &mut transport, &last_remote, &last_sha);
    assert!(panicked, "the injected boundary must panic");

    let bak = backup_path_for(dev.vault_path());
    assert!(
        bak.exists(),
        ".kdbx.bak must exist (written before the fetch)"
    );

    // The live vault is byte-identical to its pre-sync state (no save ran),
    // and the backup is a faithful copy of it.
    let post_bytes = std::fs::read(dev.vault_path()).unwrap();
    assert_eq!(
        post_bytes, pre_bytes,
        ".kdbx unchanged — no merge/save occurred"
    );
    assert_eq!(
        std::fs::read(&bak).unwrap(),
        pre_bytes,
        ".kdbx.bak == original"
    );

    // The vault still opens and the merge did NOT fold in device B's entry.
    let vault = dev.open();
    assert_eq!(current_title(&vault, uuid).as_deref(), Some("base"));
    let titles = common::sync_env::vault_entry_titles(&vault);
    assert!(
        titles.contains(&"from-a".to_string()),
        "local edit survived"
    );
    assert!(
        !titles.contains(&"from-b".to_string()),
        "remote edit NOT yet merged"
    );
}

// ---------------------------------------------------------------------------
// TC-FAULT-002 — panic after the merge + save, before the PUT. The live
// `.kdbx` holds the merged state; `.kdbx.bak` holds the pre-merge state.
// ---------------------------------------------------------------------------
#[test]
fn panic_after_merge_before_put_leaves_bak_intact_and_local_merged() {
    let (dev, _uuid, mut transport, last_remote, last_sha) = diverged_setup();
    let pre_bytes = std::fs::read(dev.vault_path()).unwrap();

    transport.set_panic_after(FaultBoundary::AfterMergeBeforePut);
    let panicked = run_expecting_panic(&dev, &mut transport, &last_remote, &last_sha);
    assert!(panicked, "the injected boundary must panic");

    let bak = backup_path_for(dev.vault_path());
    assert!(bak.exists(), ".kdbx.bak must exist");

    // The backup is the pre-merge state; the live vault is the merged state
    // (the post-merge atomic save completed before the panic).
    assert_eq!(
        std::fs::read(&bak).unwrap(),
        pre_bytes,
        ".kdbx.bak == pre-merge"
    );

    let merged = dev.open();
    let titles = common::sync_env::vault_entry_titles(&merged);
    for want in ["base", "from-a", "from-b"] {
        assert!(
            titles.contains(&want.to_string()),
            "merged .kdbx missing {want}: {titles:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// TC-FAULT-003 — the documented recovery path: after the TC-FAULT-002 state,
// `cp .kdbx.bak .kdbx` yields a vault that opens with the original password
// and contains the pre-merge entries (the recovery rolls back the merge).
// ---------------------------------------------------------------------------
#[test]
fn manual_bak_restore_recovers_pre_merge_state() {
    let (dev, uuid, mut transport, last_remote, last_sha) = diverged_setup();

    transport.set_panic_after(FaultBoundary::AfterMergeBeforePut);
    let panicked = run_expecting_panic(&dev, &mut transport, &last_remote, &last_sha);
    assert!(panicked, "the injected boundary must panic");

    // Recovery: restore the pre-merge backup over the live vault.
    let bak = backup_path_for(dev.vault_path());
    std::fs::copy(&bak, dev.vault_path()).expect("cp .kdbx.bak .kdbx");

    // The recovered vault opens cleanly with the original password and holds
    // the pre-merge entries — base + from-a, but NOT the merged-in from-b.
    let recovered = dev.open();
    let titles = common::sync_env::vault_entry_titles(&recovered);
    assert!(titles.contains(&"base".to_string()));
    assert!(titles.contains(&"from-a".to_string()));
    assert!(
        !titles.contains(&"from-b".to_string()),
        "restore rolls back the merge — from-b must be absent: {titles:?}"
    );
    // History helper exercised so the recovered vault's shape is sound.
    let _ = entry_history_titles(&recovered, uuid);
}
