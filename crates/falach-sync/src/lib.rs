// The crate docs name many acronyms / product names (S3, KDBX, ETag, SigV4,
// MinIO, AWS, FR-0xx, ADR-n) that read worse backticked than plain; allow the
// lint at the crate root, matching the per-module posture. Intra-doc links
// are still validated by rustdoc.
#![allow(clippy::doc_markdown)]
//! Falach sync layer — per-vault sync over S3-compatible object storage.
//!
//! This crate owns FR-040..048: per-vault sync configuration, a
//! transport-agnostic [`SyncTransport`] trait (FR-046), an
//! S3-compatible [`S3Transport`] implementation of it, a two-way KDBX
//! [`merge`] adapter (FR-043) that reconciles a local and remote vault by
//! entry UUID — preserving the loser of a collision as a KDBX history
//! entry — and the [`Sync`] orchestrator that wires them together.
//!
//! Per ADR-1 the dependency arrow points only into `falach-core`: this
//! crate consumes [`falach_core::Vault`] / [`falach_core::Database`] but
//! `falach-core` never depends on sync, keeping transport dependencies
//! (the `ureq`/`rustls` HTTP stack) out of every non-syncing consumer's
//! tree.
//!
//! # Public surface
//!
//! Frontends (CLI / TUI / a future agent) use only these types; they never
//! reach into [`s3`] or name `ureq`:
//!
//! - [`Sync`] — the orchestrator. [`Sync::configure_remote`] writes a
//!   vault's S3 target into the registry; [`Sync::sync_now`] runs the
//!   four-state truth table (already-in-sync / push / fast-replace /
//!   merge-then-conditional-PUT) and returns a [`SyncOutcome`].
//! - [`SyncOutcome`] — what a successful sync did (`AlreadyInSync`,
//!   `Pushed`, `FastReplaced`, `Merged`).
//! - [`SyncError`] — every failure mode, each naming the offending input;
//!   a sync failure always leaves the local vault usable (FR-044).
//! - [`S3Config`] / [`CredentialSource`] — the per-vault configuration
//!   persisted to `vaults.toml` (the `[vault.sync.s3]` block). `CredentialSource`
//!   is the FR-045 per-vault credential isolation: RST-CRED-1 (encrypted at
//!   rest), a named AWS profile, prefixed env vars, or an IAM instance role.
//! - [`SyncTransport`] / [`ObjectVersion`] / [`ObjectSnapshot`] — the
//!   transport abstraction (FR-046). [`S3Transport`] is the production impl;
//!   a Phase-4 NFS / WebDAV transport implements the same three methods.
//!
//! Sync is layered *above* `vault-core`: `Vault::save` never calls into this
//! crate (ADR-4). Frontends decide *when* to sync (e.g. after
//! [`falach_core::Vault::save`]).
//!
//! # Quickstart
//!
//! ```no_run
//! use falach_sync::{CredentialSource, S3Config, Sync, SyncOptions, SyncOutcome};
//! use falach_core::{MasterPassword, FalachPaths, Vault, VaultRegistry};
//! # fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let password = MasterPassword::new("…from a secure prompt…".to_string());
//! let mut registry = VaultRegistry::load(FalachPaths::with_state_dir("/state".into()))?;
//!
//! // 1. Configure the vault's S3 target once (persists to vaults.toml).
//! let s3 = S3Config::new(
//!     "my-bucket".to_string(),
//!     "work.kdbx".to_string(),
//!     "us-east-1".to_string(),
//!     // Reads MY_AWS_ACCESS_KEY_ID / MY_AWS_SECRET_ACCESS_KEY (FR-045:
//!     // an explicit per-vault prefix, never the ambient shell env).
//!     CredentialSource::EnvVars { prefix: "MY_".to_string() },
//! );
//! Sync::configure_remote(&mut registry, "work", s3, &password)?;
//!
//! // 2. Sync on demand (e.g. after opening or saving the vault).
//! let mut vault = Vault::open(std::path::Path::new("/state/work.kdbx"), &password, None)?;
//! match Sync::sync_now(&mut vault, "work", &mut registry, &password, None, SyncOptions::default())? {
//!     SyncOutcome::AlreadyInSync => {}
//!     SyncOutcome::Pushed { .. } | SyncOutcome::FastReplaced => {}
//!     SyncOutcome::Merged { attempts, .. } => eprintln!("merged in {attempts} attempt(s)"),
//!     _ => {} // SyncOutcome is #[non_exhaustive]
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Design
//!
//! The seven ADRs (see `crates/falach-sync/README.md` and the feature
//! `design.md`): **ADR-1** hand-rolled SigV4 + `ureq` over `rustls`
//! (no AWS SDK); **ADR-2** RST-CRED-1 as the credential floor (no OS
//! keychain in Phase 0); **ADR-3** the four-method [`SyncTransport`] trait;
//! **ADR-4** `Vault::save` stays sync-ignorant; **ADR-5** per-backend
//! `If-Match` support detected by a sentinel-key probe and cached in
//! `vaults.toml`; **ADR-6** registry-side `(endpoint, bucket, key)`
//! uniqueness check ([`SyncError::DuplicateTarget`]); **ADR-7**
//! `falach-sync/<version>` User-Agent.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod activity;
pub mod auth;
pub mod backup;
pub mod config;
pub mod error;
pub mod merge;
pub mod s3;
pub mod sync;
pub mod sync_log;
pub mod transport;

pub use auth::{
    encrypt_credential, AuthError, CredentialSource, EnvSource, ResolvedCredentials,
    SystemEnvSource,
};
pub use config::{canonicalize_target, IfMatchSupport, S3Config, SyncConfig, TransportKind};
pub use error::SyncError;
pub use merge::{reconcile, EntryDelta, MergeError, MergeSummary};
pub use sync::{Sync, SyncOptions, SyncOutcome};
pub use sync_log::format as format_sync_log;
pub use transport::s3::S3Transport;
pub use transport::{IsPreconditionFailed, ObjectSnapshot, ObjectVersion, SyncTransport};

#[cfg(any(test, feature = "test-helpers"))]
pub use auth::MockEnvSource;
#[cfg(any(test, feature = "test-helpers"))]
pub use transport::memory::{FaultBoundary, MemoryTransport, MemoryTransportError};
