//! US-042 — conditional PUT on save (FR-042; impl plan §8.4.3). When the
//! local vault changed but the remote did not, the orchestrator uploads via a
//! conditional PUT against the last-synced ETag (the `Pushed` outcome).

#![allow(clippy::doc_markdown)]

mod common;

use common::sync_env::{open_vault, SyncTestEnv};
use falach_sync::sync::run_state_machine;
use falach_sync::transport::memory::MemoryTransport;
use falach_sync::transport::SyncTransport;
use falach_sync::{SyncOptions, SyncOutcome};

#[test]
fn local_changed_remote_unchanged_pushes_conditionally() {
    let dev = SyncTestEnv::new("work");
    dev.add_entry("base");

    // Seed the remote with the synced state.
    let mut transport = MemoryTransport::new();
    let synced_etag = {
        let bytes = std::fs::read(dev.vault_path()).unwrap();
        transport
            .put_conditional(&bytes, None)
            .expect("seed remote")
    };
    let synced_sha = dev.local_sha();

    // Local edit; remote untouched.
    dev.add_entry("local-edit");

    let mut vault = open_vault(&dev);
    let (outcome, pointers) = run_state_machine(
        &mut vault,
        &dev.master(),
        None,
        &mut transport,
        Some(synced_etag.clone().0),
        Some(&synced_sha),
        SyncOptions::default(),
    )
    .expect("push sync ok");

    assert!(
        matches!(
            outcome,
            SyncOutcome::Pushed {
                is_first_seed: false
            }
        ),
        "steady-state push expected, got {outcome:?}"
    );

    // The remote advanced past the last-synced version (the conditional PUT
    // landed) and the new pointer was recorded.
    let head = transport.head().expect("head ok").expect("remote present");
    assert_ne!(
        head, synced_etag,
        "conditional PUT must advance the remote ETag"
    );
    assert_eq!(pointers.remote_etag.as_deref(), Some(head.0.as_str()));
}

#[test]
fn conditional_put_against_stale_etag_is_rejected() {
    // Sanity that the transport enforces If-Match: a PUT claiming a stale
    // version is rejected (the precondition primitive the orchestrator relies
    // on). MemoryTransport mirrors S3's 412 here.
    let mut transport = MemoryTransport::new();
    let v1 = transport.put_conditional(b"v1", None).expect("seed");
    let _v2 = transport
        .put_conditional(b"v2", Some(&v1))
        .expect("advance");
    let err = transport
        .put_conditional(b"v3", Some(&v1))
        .expect_err("stale If-Match must be rejected");
    assert!(matches!(
        err,
        falach_sync::MemoryTransportError::PreconditionFailed
    ));
}
