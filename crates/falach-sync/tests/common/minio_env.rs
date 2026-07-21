//! Live-wire MinIO test environment helper (s3-sync T6.2).
//!
//! Reads the MinIO endpoint + credentials that `start_minio.sh` exported
//! (`FALACH_MINIO_ENDPOINT` etc.), creates per-test buckets via
//! `make_bucket.sh`, and constructs real [`falach_sync::S3Transport`]
//! instances over [`falach_sync::s3::Client`] — the full production stack,
//! no mocks. Used only by `tests/minio_integration.rs`, whose cases are
//! `#[ignore]`-gated.

// Each integration test file compiles `common` on its own and uses a
// different subset of these helpers (dead_code). The docs are acronym-heavy
// (S3/MinIO/ETag/SigV4) so doc_markdown is allowed like the production
// modules. Some helpers are ergonomic methods on the env that don't read a
// field yet (unused_self) — kept as methods for call-site readability.
#![allow(dead_code, clippy::doc_markdown, clippy::unused_self)]

use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use falach_sync::s3::{
    Client, EndpointBuilder, EndpointConfig, HttpClient, ResolvedCredentials, Signer,
};
use falach_sync::transport::s3::S3Transport;
use falach_sync::transport::SyncTransport;
use falach_sync::IfMatchSupport;

use super::sync_env::SyncTestEnv;

/// Connection parameters sourced from the environment `start_minio.sh` set.
pub struct MinioEnv {
    pub endpoint: String,
    pub access_key: String,
    pub secret_key: String,
    pub region: String,
}

impl MinioEnv {
    /// Read the MinIO connection info from the environment. Panics with an
    /// actionable message when the env vars are missing — the MINIO-* tests
    /// are `#[ignore]`-gated, so reaching this without `make minio-up` is a
    /// usage error, not a flake.
    pub fn from_env() -> Self {
        fn var(name: &str) -> String {
            std::env::var(name).unwrap_or_else(|_| {
                panic!(
                    "{name} unset — run `make minio-up` and invoke the tests via \
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

    /// Create a fresh, uniquely-suffixed bucket via `make_bucket.sh` and
    /// return its name. Unique suffix → parallel-safe (though the Makefile
    /// target runs serially) and re-run-safe.
    pub fn make_unique_bucket(&self) -> String {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let pid = std::process::id();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        // S3 bucket names: lowercase alnum + hyphens, 3..=63 chars.
        let bucket = format!("falach-test-{pid}-{n}-{nanos}");

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

    /// Build a real `S3Transport` (production stack) pointed at `bucket`/`key`
    /// in this MinIO. Path-style addressing — MinIO does not bind buckets to
    /// DNS. `if_match_supported` starts `Unknown` so the first conditional
    /// PUT runs the sentinel probe (exercising ADR-5 against the real wire).
    pub fn transport(&self, bucket: &str, key: &str) -> S3Transport<Client<HttpClient>> {
        let client = self.client(bucket);
        S3Transport::new(client, bucket.to_string(), key.to_string())
    }

    /// Same as [`Self::transport`] but seeds the `If-Match` classification
    /// (skips the probe) — used by tests that want to drive a known path.
    pub fn transport_with_if_match(
        &self,
        bucket: &str,
        key: &str,
        support: IfMatchSupport,
    ) -> S3Transport<Client<HttpClient>> {
        let client = self.client(bucket);
        S3Transport::with_if_match_state(
            client,
            bucket.to_string(),
            key.to_string(),
            support,
            Box::new(|_| {}),
        )
    }

    /// Construct the production [`Client`] over the real `ureq`/rustls HTTP
    /// stack, signing with the MinIO test credentials.
    pub fn client(&self, bucket: &str) -> Client<HttpClient> {
        let endpoint = EndpointBuilder::from_config(&EndpointConfig {
            endpoint: Some(&self.endpoint),
            region: &self.region,
            bucket,
            force_path_style: true,
        })
        .expect("endpoint builds");
        let signer = Signer::new(self.region.clone());
        let http = HttpClient::new("falach-sync-test/0").expect("http client builds");
        let creds = ResolvedCredentials {
            access_key_id: self.access_key.clone(),
            secret_access_key: self.secret_key.clone(),
            session_token: None,
        };
        Client::new(http, signer, endpoint, creds)
    }
}

/// Seed `dev`'s current on-disk vault bytes to `bucket`/`key` in `minio` via
/// an unconditional PUT, returning the remote ETag. Establishes the shared
/// "base" both simulated devices diverge from in the merge scenarios
/// (MINIO-008 / MINIO-010).
pub fn seed_synced_vault(minio: &MinioEnv, bucket: &str, key: &str, dev: &SyncTestEnv) -> String {
    let mut transport = minio.transport_with_if_match(bucket, key, IfMatchSupport::Supported);
    let bytes = std::fs::read(dev.vault_path()).expect("read seed vault bytes");
    let version = transport
        .put_conditional(&bytes, None)
        .expect("seed PUT ok");
    version.0
}
