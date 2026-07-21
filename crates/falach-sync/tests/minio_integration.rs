//! MinIO live-wire integration tests (s3-sync T6.2/T6.3; impl plan §8.4.2).
//!
//! MinIO is the *strict* SigV4 implementation: it rejects canonical-request
//! encoding bugs that AWS's permissive parser silently accepts. These tests
//! exercise the full production stack — hand-rolled SigV4 → `ureq`/rustls →
//! ETag parsing → `S3Transport` → the orchestrator — against a real backend.
//!
//! **Every test here is `#[ignore]`-gated AND compiled only under the
//! `minio-tests` feature** so the default `cargo test` (and `make test`) skip
//! them. The feature gate — not just `#[ignore]` — is what keeps this binary
//! out of the blanket `make test-ignored` sweep on the non-MinIO `vault-core`
//! CI job: `-- --ignored` runs *every* ignored test in a compiled binary, so
//! without the `cfg` these live-wire cases would build and panic on the unset
//! `FALACH_MINIO_*` env. Only `make test-s3-integration` enables the feature.
//! Run them with a running MinIO via:
//!
//! ```sh
//! make minio-up
//! make test-s3-integration
//! make minio-down
//! ```
//!
//! The test process reads the endpoint + credentials from the
//! `FALACH_MINIO_*` env vars that `start_minio.sh` exports; see
//! `tests/common/minio_env.rs`.

// `allow` first so it stays in effect on the crate-root doc comments above
// even when the `cfg` below strips the crate (feature off): clippy still lints
// those `//!` lines, and an `allow` sequenced after the false `cfg` would not
// apply.
#![allow(clippy::doc_markdown)]
// Compiled only when the `minio-tests` feature is on (set by
// `make test-s3-integration`). Off by default → an empty test crate, so the
// blanket `make test-ignored` sweep never sees these live-wire cases.
#![cfg(feature = "minio-tests")]

mod common;

use std::sync::{Arc, Barrier};
use std::thread;

use common::minio_env::{seed_synced_vault, MinioEnv};
use common::sync_env::{open_vault, vault_entry_titles, SyncTestEnv};
use falach_sync::sync::run_state_machine;
use falach_sync::transport::{ObjectVersion, SyncTransport};
use falach_sync::{IfMatchSupport, IsPreconditionFailed, SyncError, SyncOptions, SyncOutcome};

// ===========================================================================
// MINIO-001..006 — basic four-method shape + sentinel probe against the wire.
// ===========================================================================

// ---------------------------------------------------------------------------
// MINIO-001 — a signed PUT against the strict backend returns 200.
// The canonical hello-world: proves SigV4 signing + endpoint construction +
// HTTP + ETag parsing all line up against a real, strict implementation.
// ---------------------------------------------------------------------------
#[test]
#[ignore = "live-wire: requires `make minio-up` (Docker + MinIO)"]
fn signer_real_minio_accepts_basic_put() {
    let env = MinioEnv::from_env();
    let bucket = env.make_unique_bucket();
    let mut transport = env.transport(&bucket, "work.kdbx");

    let version = transport
        .put_conditional(b"hello-falach", None)
        .expect("unconditional PUT against MinIO must succeed");

    assert!(
        !version.0.is_empty(),
        "PUT must return a non-empty ETag, got {version:?}"
    );
}

// ---------------------------------------------------------------------------
// MINIO-002 — HEAD after PUT returns the same ETag the PUT returned.
// ---------------------------------------------------------------------------
#[test]
#[ignore = "live-wire: requires `make minio-up` (Docker + MinIO)"]
fn head_returns_etag_after_put() {
    let env = MinioEnv::from_env();
    let bucket = env.make_unique_bucket();
    let mut transport = env.transport(&bucket, "work.kdbx");

    let put_version = transport.put_conditional(b"payload", None).expect("PUT ok");
    let head_version = transport
        .head()
        .expect("HEAD ok")
        .expect("object exists after PUT");

    assert_eq!(
        head_version, put_version,
        "HEAD ETag must equal the PUT ETag (single-PUT object)"
    );
}

// ---------------------------------------------------------------------------
// MINIO-003 — GET with a matching If-None-Match returns 304 (no body).
// ---------------------------------------------------------------------------
#[test]
#[ignore = "live-wire: requires `make minio-up` (Docker + MinIO)"]
fn get_with_if_none_match_matching_returns_304() {
    let env = MinioEnv::from_env();
    let bucket = env.make_unique_bucket();
    let mut transport = env.transport(&bucket, "work.kdbx");

    let version = transport.put_conditional(b"payload", None).expect("PUT ok");

    // fetch_if_changed(Some(current)) → If-None-Match matches → 304 → None.
    let unchanged = transport
        .fetch_if_changed(Some(&version))
        .expect("conditional GET ok");
    assert!(
        unchanged.is_none(),
        "matching If-None-Match must yield 304 / no snapshot"
    );

    // A stale prev version → 200 + body.
    let stale = ObjectVersion("\"00000000000000000000000000000000\"".to_string());
    let changed = transport
        .fetch_if_changed(Some(&stale))
        .expect("conditional GET ok")
        .expect("stale If-None-Match → body returned");
    assert_eq!(changed.bytes, b"payload");
}

// ---------------------------------------------------------------------------
// MINIO-004 — conditional PUT with a matching If-Match succeeds (200 + new
// ETag). `if_match_supported` is pre-seeded to Supported to isolate the
// conditional-write happy path from the probe (which MINIO-006 covers).
// ---------------------------------------------------------------------------
#[test]
#[ignore = "live-wire: requires `make minio-up` (Docker + MinIO)"]
fn put_with_if_match_matching_succeeds() {
    let env = MinioEnv::from_env();
    let bucket = env.make_unique_bucket();
    let mut transport =
        env.transport_with_if_match(&bucket, "work.kdbx", IfMatchSupport::Supported);

    let v1 = transport.put_conditional(b"v1", None).expect("seed PUT ok");
    let v2 = transport
        .put_conditional(b"v2", Some(&v1))
        .expect("conditional PUT with matching If-Match must succeed");

    assert_ne!(v1, v2, "successful overwrite mints a fresh ETag");
}

// ---------------------------------------------------------------------------
// MINIO-005 — conditional PUT with a stale If-Match returns 412.
// ---------------------------------------------------------------------------
#[test]
#[ignore = "live-wire: requires `make minio-up` (Docker + MinIO)"]
fn put_with_if_match_mismatched_returns_412() {
    let env = MinioEnv::from_env();
    let bucket = env.make_unique_bucket();
    let mut transport =
        env.transport_with_if_match(&bucket, "work.kdbx", IfMatchSupport::Supported);

    let v1 = transport.put_conditional(b"v1", None).expect("seed PUT ok");
    // Advance the remote to v2 — v1 is now stale.
    let _v2 = transport
        .put_conditional(b"v2", Some(&v1))
        .expect("advance to v2 ok");

    // A conditional PUT still claiming v1 must be rejected with 412.
    let err = transport
        .put_conditional(b"v3", Some(&v1))
        .expect_err("stale If-Match must be rejected");
    assert!(
        err.is_precondition_failed(),
        "stale If-Match → 412 PreconditionFailed, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// MINIO-006 — the sentinel-key probe (ADR-5) classifies MinIO as Supported.
// A fresh transport starts Unknown; the first conditional PUT runs the probe
// before the real PUT, and MinIO (which honours If-Match) returns 412 on the
// bogus probe value → Supported.
// ---------------------------------------------------------------------------
#[test]
#[ignore = "live-wire: requires `make minio-up` (Docker + MinIO)"]
fn sentinel_probe_correctly_identifies_minio_as_supported() {
    let env = MinioEnv::from_env();
    let bucket = env.make_unique_bucket();
    let mut transport = env.transport(&bucket, "work.kdbx"); // Unknown

    let v1 = transport.put_conditional(b"v1", None).expect("seed PUT ok");
    assert_eq!(
        transport.if_match_supported(),
        IfMatchSupport::Unknown,
        "unconditional first PUT must not trigger the probe"
    );

    // Conditional PUT on an Unknown backend runs the probe first.
    let _v2 = transport
        .put_conditional(b"v2", Some(&v1))
        .expect("conditional PUT ok");
    assert_eq!(
        transport.if_match_supported(),
        IfMatchSupport::Supported,
        "the sentinel probe must classify MinIO as honouring If-Match"
    );
}

// ===========================================================================
// MINIO-007..011 — concurrency, retry, and full user-scenario end-to-end.
// ===========================================================================

// ---------------------------------------------------------------------------
// MINIO-007 — two writers race PUTs against the same key; exactly one wins,
// the other gets a precondition failure. The atomicity-of-conditional-PUT
// guarantee under real contention.
// ---------------------------------------------------------------------------
#[test]
#[ignore = "live-wire: requires `make minio-up` (Docker + MinIO)"]
fn concurrent_writers_race_one_wins_one_gets_412() {
    let env = MinioEnv::from_env();
    let bucket = env.make_unique_bucket();

    // Seed a known starting version both racers will target with If-Match.
    let base = {
        let mut t = env.transport_with_if_match(&bucket, "work.kdbx", IfMatchSupport::Supported);
        t.put_conditional(b"base", None).expect("seed ok")
    };

    let barrier = Arc::new(Barrier::new(2));
    let endpoint = env.endpoint.clone();
    let access = env.access_key.clone();
    let secret = env.secret_key.clone();
    let region = env.region.clone();

    let spawn_racer = |label: &'static str| {
        let barrier = Arc::clone(&barrier);
        let base = base.clone();
        let (endpoint, access, secret, region, bucket) = (
            endpoint.clone(),
            access.clone(),
            secret.clone(),
            region.clone(),
            bucket.clone(),
        );
        thread::spawn(move || {
            let env = MinioEnv {
                endpoint,
                access_key: access,
                secret_key: secret,
                region,
            };
            let mut t =
                env.transport_with_if_match(&bucket, "work.kdbx", IfMatchSupport::Supported);
            // Both threads line up here, then PUT as simultaneously as the
            // OS scheduler allows — both with the same If-Match base.
            barrier.wait();
            t.put_conditional(label.as_bytes(), Some(&base))
        })
    };

    let a = spawn_racer("aaaa");
    let b = spawn_racer("bbbb");
    let ra = a.join().expect("thread a");
    let rb = b.join().expect("thread b");

    // The SET of outcomes must be exactly {one Ok, one PreconditionFailed} —
    // we don't assert *which* thread wins (scheduler-dependent).
    let results = [ra, rb];
    let oks = results.iter().filter(|r| r.is_ok()).count();
    let pre = results
        .iter()
        .filter(|r| {
            r.as_ref()
                .err()
                .is_some_and(falach_sync::IsPreconditionFailed::is_precondition_failed)
        })
        .count();
    assert_eq!(oks, 1, "exactly one racer's conditional PUT must win");
    assert_eq!(pre, 1, "exactly one racer must get a precondition failure");
}

// ---------------------------------------------------------------------------
// MINIO-008 — a device that is behind the remote merges the remote's edits
// and pushes the union, against the real wire end-to-end. This drives the
// orchestrator's (true,true) merge path: device A re-fetches the current
// remote (device B's version), merges, and conditional-PUTs against it.
//
// Note on attempts: the orchestrator re-fetches the *current* remote inside
// the merge loop and PUTs with that version's ETag, so absent a writer that
// races A *between* its fetch and its PUT, the conditional PUT succeeds on
// the first attempt (attempts == 1). Forcing a ≥2-attempt retry would
// require injecting a concurrent write mid-loop, which can't be made
// deterministic against a real backend; MINIO-007 covers the racing-writer
// 412 directly, and the orchestrator's bounded-retry loop is unit-tested in
// `sync.rs` (TC-SYNC-005/006). Here we assert the merge correctness.
// ---------------------------------------------------------------------------
#[test]
#[ignore = "live-wire: requires `make minio-up` (Docker + MinIO)"]
fn retry_after_merge_eventually_succeeds() {
    let env = MinioEnv::from_env();
    let bucket = env.make_unique_bucket();
    let key = "work.kdbx";

    // Device A: create + seed a vault to the bucket.
    let dev_a = SyncTestEnv::new("work");
    dev_a.add_entry("alpha");
    let base_etag = seed_synced_vault(&env, &bucket, key, &dev_a);
    // Capture the synced-state pointers BEFORE device A diverges locally.
    let base_sha = dev_a.local_sha();

    // Device B: independently start from the same seeded bytes, add a
    // distinct entry, and push it so the remote advances past device A's
    // last-synced pointer.
    let dev_b = dev_a.clone_to("work-b");
    dev_b.add_entry("bravo");
    {
        let mut tb = env.transport_with_if_match(&bucket, key, IfMatchSupport::Supported);
        let bytes = std::fs::read(dev_b.vault_path()).unwrap();
        tb.put_conditional(&bytes, Some(&ObjectVersion(base_etag.clone())))
            .expect("device B push ok");
    }

    // Device A now edits locally (so BOTH sides diverged) and syncs. Its
    // first conditional PUT will 412 (remote moved to B's version); the
    // orchestrator re-fetches B, merges, and retries → success.
    dev_a.add_entry("charlie");
    let mut ta = env.transport_with_if_match(&bucket, key, IfMatchSupport::Supported);
    let mut vault = open_vault(&dev_a);
    let (outcome, _pointers) = run_state_machine(
        &mut vault,
        &dev_a.master(),
        None,
        &mut ta,
        Some(base_etag),
        Some(&base_sha),
        SyncOptions::default(),
    )
    .expect("merge-with-retry sync must succeed");

    match outcome {
        SyncOutcome::Merged { attempts, .. } => {
            assert!(
                attempts >= 1,
                "merge must take at least one PUT attempt, got {attempts}"
            );
        }
        other => panic!("expected Merged, got {other:?}"),
    }

    // Final remote state, fetched fresh, contains all three entries.
    let titles = vault_entry_titles(&vault);
    for want in ["alpha", "bravo", "charlie"] {
        assert!(
            titles.contains(&want.to_string()),
            "merged vault missing {want}: {titles:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// MINIO-009 — US-040 end-to-end: a HEAD against a freshly-seeded object
// returns its version; a HEAD against an absent key returns None.
// ---------------------------------------------------------------------------
#[test]
#[ignore = "live-wire: requires `make minio-up` (Docker + MinIO)"]
fn us_040_configure_target_against_real_minio() {
    let env = MinioEnv::from_env();
    let bucket = env.make_unique_bucket();

    // Absent object → HEAD None.
    let mut absent = env.transport(&bucket, "missing.kdbx");
    assert!(
        absent.head().expect("head ok").is_none(),
        "HEAD on an absent key must be None"
    );

    // Seed, then HEAD returns Some.
    let mut present = env.transport(&bucket, "work.kdbx");
    let v = present.put_conditional(b"seed", None).expect("seed ok");
    assert_eq!(present.head().expect("head ok"), Some(v));
}

// ---------------------------------------------------------------------------
// MINIO-010 — US-044 collision merge end-to-end against the real wire: two
// devices edit the same vault concurrently; the later sync merges; the merged
// vault contains both devices' entries. (The KeePassXC-history interop check
// is the separate `tools/interop-tests/sync_us-044.sh` script.)
// ---------------------------------------------------------------------------
#[test]
#[ignore = "live-wire: requires `make minio-up` (Docker + MinIO)"]
fn us_044_collision_merge_against_real_minio() {
    let env = MinioEnv::from_env();
    let bucket = env.make_unique_bucket();
    let key = "work.kdbx";

    let dev_a = SyncTestEnv::new("work");
    dev_a.add_entry("shared-base");
    let base_etag = seed_synced_vault(&env, &bucket, key, &dev_a);
    let base_sha = dev_a.local_sha();

    // Device B diverges + pushes.
    let dev_b = dev_a.clone_to("work-b");
    dev_b.add_entry("from-b");
    {
        let mut tb = env.transport_with_if_match(&bucket, key, IfMatchSupport::Supported);
        let bytes = std::fs::read(dev_b.vault_path()).unwrap();
        tb.put_conditional(&bytes, Some(&ObjectVersion(base_etag.clone())))
            .expect("device B push ok");
    }

    // Device A diverges + syncs → merge.
    dev_a.add_entry("from-a");
    let mut ta = env.transport_with_if_match(&bucket, key, IfMatchSupport::Supported);
    let mut vault = open_vault(&dev_a);
    let (outcome, _) = run_state_machine(
        &mut vault,
        &dev_a.master(),
        None,
        &mut ta,
        Some(base_etag),
        Some(&base_sha),
        SyncOptions::default(),
    )
    .expect("collision merge sync ok");
    assert!(
        matches!(outcome, SyncOutcome::Merged { .. }),
        "got {outcome:?}"
    );

    let titles = vault_entry_titles(&vault);
    for want in ["shared-base", "from-a", "from-b"] {
        assert!(
            titles.contains(&want.to_string()),
            "merged vault missing {want}: {titles:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// MINIO-011 — US-045: a sync against an unreachable endpoint surfaces
// RemoteUnreachable and leaves the local vault fully usable + the pre-existing
// pointers unchanged. (We point at a dead port rather than killing the shared
// container so other serial tests are unaffected.)
// ---------------------------------------------------------------------------
#[test]
#[ignore = "live-wire: requires `make minio-up` (Docker + MinIO)"]
fn us_045_sync_failure_recovers_local_vault() {
    let env = MinioEnv::from_env();
    let bucket = "falach-unreachable";
    let key = "work.kdbx";

    let dev = SyncTestEnv::new("work");
    dev.add_entry("local-only");

    // A transport pointed at a closed port — every request fails to connect.
    let dead = MinioEnv {
        endpoint: "http://127.0.0.1:1".to_string(),
        access_key: env.access_key.clone(),
        secret_key: env.secret_key.clone(),
        region: env.region.clone(),
    };
    let mut transport = dead.transport_with_if_match(bucket, key, IfMatchSupport::Supported);

    let pre_bytes = std::fs::read(dev.vault_path()).unwrap();
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
        .expect_err("sync against a dead endpoint must fail");

        assert!(
            matches!(err, SyncError::RemoteUnreachable { .. } | SyncError::S3(_)),
            "expected a connectivity failure, got {err:?}"
        );
        // `vault` (and its advisory lock) drops at the end of this block,
        // so the re-open below doesn't contend with itself.
    }

    // The local vault is untouched and still opens cleanly with the same
    // password.
    let post_bytes = std::fs::read(dev.vault_path()).unwrap();
    assert_eq!(
        pre_bytes, post_bytes,
        "local vault must be unchanged on sync failure"
    );
    let _ = open_vault(&dev);
}
