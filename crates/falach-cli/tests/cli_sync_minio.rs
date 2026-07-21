//! `MinIO`-gated end-to-end `falach sync` happy-path (plan §7.3.2).
//!
//! A spawned `falach` process builds a real `S3Transport` from registry
//! config — there is no way to inject `MemoryTransport` across the process
//! boundary — so the CLI's own responsibility (correctly invoking
//! `sync_now` and rendering/exit-mapping the result) can only be shown
//! end-to-end against a real S3 endpoint. The sync **state machine** is
//! already exhaustively unit-tested in `falach-sync`, so this is kept to a
//! single representative case: first-seed push, then idempotent
//! already-in-sync.
//!
//! Gated by `#![cfg(feature = "minio-tests")]` + `#[ignore]`, run only by
//! `make test-s3-integration` after `make minio-up` (which exports the
//! `FALACH_MINIO_*` env this reads). The blanket `make test` never compiles
//! this file.
#![allow(clippy::doc_markdown)]
#![cfg(feature = "minio-tests")]

mod common;

use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use common::{run_with_stdin, seed_vault, VaultsToml};

/// MinIO connection info exported by `start_minio.sh`.
struct MinioEnv {
    endpoint: String,
    access_key: String,
    secret_key: String,
    region: String,
}

impl MinioEnv {
    fn from_env() -> Self {
        fn var(name: &str) -> String {
            std::env::var(name).unwrap_or_else(|_| {
                panic!(
                    "{name} unset — run `make minio-up` and invoke via \
                     `make test-s3-integration` (which sources the env file)."
                )
            })
        }
        Self {
            endpoint: var("FALACH_MINIO_ENDPOINT"),
            access_key: var("FALACH_MINIO_ACCESS_KEY"),
            secret_key: var("FALACH_MINIO_SECRET_KEY"),
            region: var("FALACH_MINIO_REGION"),
        }
    }

    /// Create a fresh, uniquely-suffixed bucket via the shared
    /// `make_bucket.sh` fixture (same script the `falach-sync` MinIO suite
    /// uses).
    fn make_unique_bucket(&self) -> String {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let pid = std::process::id();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let bucket = format!("falach-cli-test-{pid}-{n}-{nanos}");
        let script = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tools/sync-tests/fixtures/make_bucket.sh"
        );
        let status = Command::new(script)
            .arg(&bucket)
            .status()
            .expect("spawn make_bucket.sh");
        assert!(status.success(), "make_bucket.sh failed for {bucket}");
        bucket
    }
}

#[test]
#[ignore = "requires a live MinIO (make minio-up); run via make test-s3-integration"]
fn cli_sync_first_seed_then_already_in_sync_exit_0() {
    let minio = MinioEnv::from_env();
    let bucket = minio.make_unique_bucket();
    let key = "personal.kdbx";
    let master = "master-pw";

    let reg = VaultsToml::new();
    seed_vault(&reg, "personal", master);

    // Configure the vault against MinIO. The prompt credential-source seals
    // the MinIO secret via RST-CRED-1; stdin = akid, secret, master.
    let set_sync_stdin = format!("{}\n{}\n{}\n", minio.access_key, minio.secret_key, master);
    let (code, _out, stderr) = run_with_stdin(
        &reg,
        &[
            "vault",
            "set-sync",
            "--id",
            "personal",
            "--s3-endpoint",
            &minio.endpoint,
            "--s3-bucket",
            &bucket,
            "--s3-key",
            key,
            "--s3-region",
            &minio.region,
            "--s3-path-style",
        ],
        &set_sync_stdin,
    );
    assert_eq!(code, 0, "set-sync should succeed; stderr: {stderr}");

    // First sync: the remote is empty → first-seed push.
    let (code, stdout, stderr) = run_with_stdin(
        &reg,
        &["--format", "json", "sync", "--vault", "personal"],
        &format!("{master}\n"),
    );
    assert_eq!(code, 0, "first sync should succeed; stderr: {stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json outcome on stdout");
    assert_eq!(v["outcome"], "pushed", "first sync = push; got {stdout}");
    assert_eq!(
        v["first_seed"], true,
        "first sync = first seed; got {stdout}"
    );

    // Second sync: nothing changed → already-in-sync (idempotent).
    let (code, stdout, stderr) = run_with_stdin(
        &reg,
        &["--format", "json", "sync", "--vault", "personal"],
        &format!("{master}\n"),
    );
    assert_eq!(code, 0, "second sync should succeed; stderr: {stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json outcome on stdout");
    assert_eq!(
        v["outcome"], "already-in-sync",
        "second sync must be idempotent; got {stdout}"
    );

    // Human mode uses the canonical sync-log line on stderr and keeps stdout
    // empty for scripts. Hostname and elapsed duration are dynamic, so assert
    // the stable structure rather than an exact string.
    let (code, stdout, stderr) = run_with_stdin(
        &reg,
        &["sync", "--vault", "personal"],
        &format!("{master}\n"),
    );
    assert_eq!(code, 0, "human sync should succeed; stderr: {stderr}");
    assert!(
        stdout.is_empty(),
        "human sync must keep stdout empty: {stdout}"
    );
    let outcome_line = stderr.lines().last().expect("sync outcome line on stderr");
    assert!(
        outcome_line.starts_with("falach sync: already-in-sync [host="),
        "human sync must use the canonical format: {stderr}"
    );
    assert!(
        outcome_line.contains("] [duration=") && outcome_line.ends_with("ms]"),
        "canonical human line must include duration: {stderr}"
    );
}
