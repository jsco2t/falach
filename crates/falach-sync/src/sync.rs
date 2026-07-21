// Domain acronyms saturate the orchestrator's docs; see the same note on
// `crate::s3::mod` for the rationale on suppressing `clippy::doc_markdown`.
#![allow(clippy::doc_markdown)]

//! The sync orchestrator: [`Sync::sync_now`] implements the four-state
//! truth table that drives a vault through a sync cycle (design.md §2.2.8
//! + impl plan §4.7).
//!
//! # T5.2 — the four-state machine
//!
//! Given the persisted divergence pointers `(last_synced_remote_etag,
//! last_synced_local_sha256)` carried in [`crate::SyncConfig`], every
//! sync sees one of four states:
//!
//! ```text
//!                            local_changed?
//!                  ┌─────────────┬───────────────────────┐
//!                  │   false     │         true          │
//! remote_changed?  ├─────────────┼───────────────────────┤
//!         false    │ AlreadyInSync│ Pushed                │
//!         true     │ FastReplaced │ Merged (+ retries)    │
//!                  └─────────────┴───────────────────────┘
//! ```
//!
//! - **`AlreadyInSync`** — both pointers match the current state; HEAD
//!   is the only network call.
//! - **`Pushed`** — local diverged; remote unchanged. Conditional PUT
//!   against `last_synced_remote_etag` (or unconditional first-seed
//!   when the remote object doesn't exist).
//! - **`FastReplaced`** — remote diverged; local unchanged. GET, decrypt,
//!   replace, save. `.kdbx.bak` is taken as a belt-and-suspenders
//!   safeguard even though no merge runs.
//! - **`Merged`** — both diverged. `.kdbx.bak` → fetch → merge → save →
//!   conditional PUT → maybe retry. Bounded by `opts.max_retries`
//!   (default 3); on exhaustion → [`SyncError::ConditionalPutExhausted`].
//!
//! # KDF-parameter mismatch (carryover)
//!
//! Before merging, the orchestrator compares
//! `vault.database().config.kdf_config` against the just-fetched
//! remote's `kdf_config`. A mismatch is the canonical
//! master-password-change-on-another-device signal, and
//! [`SyncError::MasterPasswordMismatch`] short-circuits before any merge
//! work — no `.kdbx.bak` is written in this case (per design §2.5).
//! Per follow-ups OQ-14, the existing `keepass-rs::KdfConfig: Eq` is
//! sufficient — no `falach-core` helper needed.
//!
//! # Activity-pong
//!
//! [`SyncOptions::on_activity`] is invoked at every network boundary
//! and after the merge call. The full `falach-security`
//! `AutoLockController` integration is deferred (see `crate::activity`);
//! a closure-shaped callback locks in the *contract* without committing
//! to the controller's borrow/ownership shape.
//!
//! # Registry I/O
//!
//! [`Sync::sync_now`] mutates `registry` to update the divergence
//! pointers at the end of a successful sync — atomically, via the same
//! clone-deregister-register-save pattern `falach-cli`'s
//! `vault set-lock` uses. The atomic-write guarantee comes from
//! `VaultRegistry::save` (under the hood: write-temp + rename(2)).

use std::time::Duration;

use chrono::Utc;
use falach_core::{Keyfile, MasterPassword, Vault, VaultError, VaultRegistry};
use gethostname::gethostname;
use sha2::{Digest, Sha256};

use crate::auth::{self, SystemEnvSource};
use crate::backup;
use crate::config::{S3Config, SyncConfig, TransportKind};
use crate::error::SyncError;
use crate::merge::{self, EntryDelta};
use crate::s3::{Client, EndpointBuilder, EndpointConfig, HttpClient, Signer};
use crate::transport::s3::S3Transport;
use crate::transport::{ObjectSnapshot, ObjectVersion, SyncTransport};

/// The crate version, used for the SigV4 client's `User-Agent` header
/// per design ADR-7.
const USER_AGENT_PREFIX: &str = "falach-sync/";

/// Default conditional-PUT retry budget when [`SyncOptions::max_retries`]
/// is unset.
pub const DEFAULT_MAX_RETRIES: usize = 3;

// ===========================================================================
// SyncOptions
// ===========================================================================

/// Caller-supplied options for [`Sync::sync_now`].
///
/// Defaults: `max_retries = 3`; no activity pinger; no clock override.
pub struct SyncOptions {
    /// Conditional-PUT retry budget. The orchestrator's `Merged` path
    /// re-fetches and re-merges on each precondition failure up to this
    /// many times; on exhaustion → `SyncError::ConditionalPutExhausted`.
    pub max_retries: usize,

    /// Activity pinger called at every network boundary (HEAD, GET, PUT)
    /// and after the merge engine returns. Wired through to a future
    /// `falach_security::AutoLockController` once that crate's borrow
    /// shape is settled; the closure shape lets us lock in the *contract*
    /// without committing to the controller's ownership model. `None` is
    /// the appropriate value for headless / one-shot CLI contexts.
    pub on_activity: Option<Box<dyn FnMut()>>,
}

impl Default for SyncOptions {
    fn default() -> Self {
        Self {
            max_retries: DEFAULT_MAX_RETRIES,
            on_activity: None,
        }
    }
}

impl std::fmt::Debug for SyncOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncOptions")
            .field("max_retries", &self.max_retries)
            .field("on_activity", &self.on_activity.is_some())
            .finish()
    }
}

// ===========================================================================
// SyncPointers
// ===========================================================================

/// The two divergence pointers the orchestrator maintains across syncs
/// (design §2.3.2): `last_synced_remote_etag` + `last_synced_local_sha256`.
///
/// Returned by [`run_state_machine`] so the caller can write them back
/// to the registry atomically — the state machine itself never touches
/// the registry, keeping it pure-function-shaped for tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncPointers {
    /// The strong ETag of the just-synced remote object (or, on
    /// `AlreadyInSync`, the unchanged prior pointer).
    pub remote_etag: Option<String>,
    /// Hex-encoded SHA-256 of the just-synced local bytes (or, on
    /// `AlreadyInSync`, the unchanged prior pointer).
    pub local_sha256: Option<String>,
}

// ===========================================================================
// SyncOutcome
// ===========================================================================

/// The outcome of a successful [`Sync::sync_now`].
///
/// `#[non_exhaustive]` so future Phase-1 outcomes (e.g. a dry-run variant)
/// don't break existing exhaustive matches.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SyncOutcome {
    /// Both `(remote, local)` pointers matched the current state; HEAD
    /// was the only network call.
    AlreadyInSync,

    /// Local diverged from the last-synced state; remote did not. A
    /// (possibly conditional) PUT uploaded the new local bytes.
    Pushed {
        /// `true` for the first-ever sync against an empty target —
        /// the unconditional first-seed PUT path. `false` for
        /// steady-state pushes.
        is_first_seed: bool,
    },

    /// Remote advanced; local did not. The remote bytes replaced the
    /// local in-memory database and were saved to disk; the merge
    /// engine was NOT invoked. `.kdbx.bak` was still written as a
    /// belt-and-suspenders safeguard.
    FastReplaced,

    /// Both sides diverged. A merge folded the remote into the local
    /// database, the result was saved, and a conditional PUT uploaded
    /// the merged state. `attempts` reports how many conditional-PUT
    /// attempts were needed (1 = no contention; ≥2 = at least one
    /// `PreconditionFailed` triggered a re-fetch + re-merge).
    Merged {
        /// How the local database changed.
        delta: EntryDelta,
        /// Conditional-PUT attempts consumed (≥1; bounded by
        /// `opts.max_retries`).
        attempts: usize,
    },
}

// ===========================================================================
// Sync
// ===========================================================================

/// The sync orchestrator (design.md §2.2.8).
///
/// Provides two operations:
///
/// - [`Sync::configure_remote`] — writes a fresh [`SyncConfig`] for a
///   vault, after checking for `(endpoint, bucket, key)` collisions
///   with other registered vaults (ADR-6).
/// - [`Sync::sync_now`] — runs the four-state truth table against the
///   configured target.
pub struct Sync;

impl Sync {
    /// Configure a registered vault for S3 sync (design ADR-6 +
    /// `Sync::configure_remote` per the design's public surface).
    ///
    /// Walks `registry` for any other vault configured against the same
    /// canonicalized `(endpoint, bucket, key)` triple; on collision
    /// returns [`SyncError::DuplicateTarget`] without modifying the
    /// registry. On success writes a fresh `SyncConfig::s3(s3)` into the
    /// vault's `[sync]` block (clearing any prior `last_synced_*`
    /// pointers — the new target's HEAD will be sampled by the first
    /// sync) and persists the registry via `VaultRegistry::save`.
    ///
    /// `master_password` is currently unused (the credentials are
    /// already encrypted inside the supplied `S3Config`'s `RstCred1`
    /// variant, or come from a non-encrypted source). It is part of the
    /// signature for design symmetry with the design.md committed
    /// surface and for forward-compat with a future "encrypt-on-configure"
    /// flow.
    ///
    /// # Errors
    ///
    /// - [`SyncError::S3`] — the endpoint or region configuration is
    ///   malformed.
    /// - [`SyncError::DuplicateTarget`] — another vault is already
    ///   configured against the same canonicalized target.
    /// - [`SyncError::Vault`] — registry mutation or persistence failed.
    pub fn configure_remote(
        registry: &mut VaultRegistry,
        vault_name: &str,
        s3: S3Config,
        _master_password: &MasterPassword,
    ) -> Result<(), SyncError> {
        // Confirm the vault is registered before any other work.
        if registry.get(vault_name).is_none() {
            return Err(SyncError::Vault(VaultError::NotRegistered {
                name: vault_name.to_string(),
            }));
        }

        // Configuration validity is a core invariant, not a UI concern.
        // Validate before duplicate detection or persistence so every caller
        // (CLI, TUI, and future agent/FFI surfaces) gets the same guarantee.
        EndpointBuilder::from_config(&EndpointConfig {
            endpoint: s3.endpoint(),
            region: s3.region(),
            bucket: s3.bucket(),
            force_path_style: s3.path_style(),
        })
        .map_err(|e| {
            SyncError::S3(crate::s3::S3Error::Unexpected {
                status: 0,
                reason: format!("malformed endpoint: {e}"),
            })
        })?;

        // ADR-6 — registry-side uniqueness check.
        if let Some(existing) = SyncConfig::find_duplicate_target(
            registry,
            s3.endpoint(),
            s3.bucket(),
            s3.key(),
            Some(vault_name),
        ) {
            return Err(SyncError::DuplicateTarget {
                endpoint: s3.endpoint().map(str::to_string),
                bucket: s3.bucket().to_string(),
                key: s3.key().to_string(),
                existing_vault: existing,
            });
        }

        let cfg = SyncConfig::s3(s3);
        update_registry_sync_block(registry, vault_name, &cfg)?;
        registry.save()?;
        Ok(())
    }

    /// Run the four-state truth table against the vault's configured
    /// remote.
    ///
    /// On success, updates `registry`'s `last_synced_*` pointers
    /// atomically and returns a [`SyncOutcome`]. On error the registry
    /// is left untouched (the next sync runs from the same pre-state).
    ///
    /// # Errors
    ///
    /// Every variant of [`SyncError`] except the "no transport"
    /// scaffolding is reachable here; the specific failure mode is
    /// named in the error variant.
    pub fn sync_now(
        vault: &mut Vault,
        vault_name: &str,
        registry: &mut VaultRegistry,
        master_password: &MasterPassword,
        keyfile: Option<&Keyfile>,
        opts: SyncOptions,
    ) -> Result<SyncOutcome, SyncError> {
        let entry = registry.get(vault_name).ok_or_else(|| {
            SyncError::Vault(VaultError::NotRegistered {
                name: vault_name.to_string(),
            })
        })?;
        let cfg = SyncConfig::from_vault_entry(entry).ok_or(SyncError::NotConfigured)?;

        match cfg.kind {
            TransportKind::S3 => {
                let s3_cfg = cfg.s3.clone().ok_or(SyncError::NotConfigured)?;
                let mut transport = build_s3_transport(&s3_cfg, master_password)?;
                sync_now_with_transport(
                    vault,
                    vault_name,
                    registry,
                    master_password,
                    keyfile,
                    &mut transport,
                    cfg,
                    opts,
                    // Pull the transport's `If-Match` classification back
                    // into the config so a fresh probe result (ADR-5) is
                    // persisted to vaults.toml even if the wider sync
                    // errored after the probe ran. Losing the probe result
                    // on every error would defeat the purpose of the
                    // per-backend cache.
                    |cfg, transport| {
                        if let Some(s3) = cfg.s3.as_mut() {
                            s3.set_if_match_supported(transport.if_match_supported());
                        }
                    },
                )
            }
        }
    }
}

/// The transport-generic body of [`Sync::sync_now`]: run the state
/// machine, fold any transport-specific config updates in via
/// `update_cfg_after_run` (runs on success AND failure), then persist
/// the sync pointers — atomically on success, best-effort on failure.
///
/// Extracted from `sync_now` so unit tests can exercise the *production*
/// persistence logic with a `MemoryTransport` instead of re-implementing
/// it in a test helper that would drift.
#[allow(clippy::too_many_arguments)] // Mirrors `run_state_machine`'s genuine input surface.
pub fn sync_now_with_transport<T: SyncTransport>(
    vault: &mut Vault,
    vault_name: &str,
    registry: &mut VaultRegistry,
    master_password: &MasterPassword,
    keyfile: Option<&Keyfile>,
    transport: &mut T,
    mut cfg: SyncConfig,
    opts: SyncOptions,
    update_cfg_after_run: impl FnOnce(&mut SyncConfig, &T),
) -> Result<SyncOutcome, SyncError>
where
    T::Error: Into<SyncError>,
{
    let result = run_state_machine(
        vault,
        master_password,
        keyfile,
        transport,
        cfg.last_synced_remote_etag.clone(),
        cfg.last_synced_local_sha256.as_deref(),
        opts,
    );

    update_cfg_after_run(&mut cfg, transport);

    match result {
        Ok((outcome, pointers)) => {
            cfg.last_synced_remote_etag = pointers.remote_etag;
            cfg.last_synced_local_sha256 = pointers.local_sha256;
            update_registry_sync_block(registry, vault_name, &cfg)?;
            registry.save()?;
            Ok(outcome)
        }
        Err(err) => {
            // Best-effort persist of any in-memory cfg mutations on the
            // failure path. A registry save failure here is intentionally
            // swallowed so the original `err` is what the caller sees —
            // the user wants the root cause, not a cascading "I also
            // couldn't write vaults.toml" surface.
            if let Ok(()) = update_registry_sync_block(registry, vault_name, &cfg) {
                let _ = registry.save();
            }
            Err(err)
        }
    }
}

// ===========================================================================
// State-machine entry point (testable; generic over the transport)
// ===========================================================================

/// Run the four-state truth table over `(remote_changed?, local_changed?)`.
///
/// Returns `(outcome, new_pointers)` on success: the caller writes
/// `new_pointers` into [`SyncConfig`] and persists to the registry
/// atomically. The state machine itself never touches the registry,
/// keeping it pure-function-shaped for tests.
///
/// Generic over the transport: production passes an [`S3Transport`];
/// tests pass a `MemoryTransport`. The
/// orchestrator never touches network or signer code directly; the
/// transport hides those details behind the four trait methods.
#[allow(clippy::too_many_arguments)] // The state machine genuinely needs every input.
#[allow(clippy::too_many_lines)] // The four-state truth table reads best as one cohesive function.
pub fn run_state_machine<T: SyncTransport>(
    vault: &mut Vault,
    master_password: &MasterPassword,
    keyfile: Option<&Keyfile>,
    transport: &mut T,
    last_synced_remote_etag: Option<String>,
    last_synced_local_sha256: Option<&str>,
    mut opts: SyncOptions,
) -> Result<(SyncOutcome, SyncPointers), SyncError>
where
    T::Error: Into<SyncError>,
{
    let prev_remote = last_synced_remote_etag.clone().map(ObjectVersion);
    let prev_sha = last_synced_local_sha256.map(str::to_string);

    // 1. HEAD the remote
    let remote_now = transport
        .head()
        .map_err(<T::Error as Into<SyncError>>::into)?;
    ping(&mut opts);

    // 2. Read the local vault file ONCE and hash it. Reading twice
    // (once for the SHA, once for the eventual PUT body) would open a
    // window where an external process (advisory locks are advisory)
    // edits the file between reads and we PUT one byte stream while
    // recording the SHA of another. Holding the bytes in memory is
    // cheap — KDBX vaults are typically <5 MiB.
    let local_bytes = read_vault_bytes(vault.path())?;
    let local_sha = sha256_of(&local_bytes);

    // 3. Compare against the last-synced pointers
    let remote_changed = remote_now.as_ref() != prev_remote.as_ref();
    let local_changed = Some(local_sha.as_str()) != last_synced_local_sha256;

    match (remote_changed, local_changed) {
        // -----------------------------------------------------------------
        // (false, false) — nothing to do; pointers unchanged.
        // -----------------------------------------------------------------
        (false, false) => Ok((
            SyncOutcome::AlreadyInSync,
            SyncPointers {
                remote_etag: last_synced_remote_etag,
                local_sha256: prev_sha,
            },
        )),

        // -----------------------------------------------------------------
        // (false, true) — push only
        // -----------------------------------------------------------------
        (false, true) => {
            let new_version = transport
                .put_conditional(&local_bytes, prev_remote.as_ref())
                .map_err(<T::Error as Into<SyncError>>::into)?;
            ping(&mut opts);
            let is_first_seed = prev_remote.is_none();
            Ok((
                SyncOutcome::Pushed { is_first_seed },
                SyncPointers {
                    remote_etag: Some(new_version.0),
                    local_sha256: Some(local_sha),
                },
            ))
        }

        // -----------------------------------------------------------------
        // (true, false) — fast-replace
        // -----------------------------------------------------------------
        (true, false) => {
            let snapshot = transport
                .fetch_if_changed(prev_remote.as_ref())
                .map_err(<T::Error as Into<SyncError>>::into)?;
            ping(&mut opts);
            let Some(ObjectSnapshot { version, bytes }) = snapshot else {
                // The transport reported no change despite our HEAD
                // having said the version moved — typically a race
                // where the remote rolled back between HEAD and GET.
                // Treat as `AlreadyInSync` per impl plan §4.7 pseudocode.
                return Ok((
                    SyncOutcome::AlreadyInSync,
                    SyncPointers {
                        remote_etag: last_synced_remote_etag,
                        local_sha256: prev_sha,
                    },
                ));
            };

            // Decrypt + KDF-mismatch sanity check
            let remote_db = Vault::open_from_bytes(&bytes, master_password, keyfile)?;
            if vault.database().config.kdf_config != remote_db.config.kdf_config {
                return Err(SyncError::MasterPasswordMismatch);
            }

            // .kdbx.bak even on fast-replace (TC-SYNC-003 acceptance)
            backup::snapshot_pre_merge(vault.path())?;
            ping(&mut opts);

            vault.replace_database(remote_db)?;
            vault.save()?;
            // Re-hash the on-disk bytes — Vault::save re-encrypts with a
            // fresh AES IV + KDF seed, so the saved bytes have a SHA
            // distinct from the snapshot's `bytes`.
            let new_local_sha = sha256_of(&read_vault_bytes(vault.path())?);
            Ok((
                SyncOutcome::FastReplaced,
                SyncPointers {
                    remote_etag: Some(version.0),
                    local_sha256: Some(new_local_sha),
                },
            ))
        }

        // -----------------------------------------------------------------
        // (true, true) — diverged → merge → conditional-PUT → maybe retry
        // -----------------------------------------------------------------
        (true, true) => {
            // .kdbx.bak BEFORE any merge work. Keep the returned path: the
            // orchestrator is the only place that has it, and an
            // unresolvable merge must carry it to the caller.
            let backup_path = backup::snapshot_pre_merge(vault.path())?;

            let mut attempts: usize = 0;
            let mut total_delta: EntryDelta;
            let max = opts.max_retries.max(1);
            loop {
                attempts += 1;

                // (Re-)fetch the remote unconditionally — we need the
                // bytes AND the version every iteration.
                let snapshot = transport
                    .fetch_if_changed(None)
                    .map_err(<T::Error as Into<SyncError>>::into)?
                    .ok_or_else(|| SyncError::RemoteUnreachable {
                        endpoint: "<transport>".to_string(),
                        source: "transport returned no snapshot during merge".into(),
                    })?;
                ping(&mut opts);

                let remote_db = Vault::open_from_bytes(&snapshot.bytes, master_password, keyfile)?;
                if vault.database().config.kdf_config != remote_db.config.kdf_config {
                    return Err(SyncError::MasterPasswordMismatch);
                }

                // Merge in place. An unresolvable merge (same-second
                // divergence with differing content) must surface as the
                // user-facing `SyncError::Unresolvable` carrying the
                // pre-merge backup path — NOT the generic
                // `SyncError::Merge(_)` the `?`-`#[from]` would produce.
                // The CLI maps `Unresolvable` to exit 3 and the TUI renders
                // it prominently with the `.kdbx.bak` pointer; both are dead
                // paths if this stays `Merge(_)`.
                // `MergeError` is `#[non_exhaustive]` but currently has the
                // single `Unresolvable` variant, so this intra-crate match is
                // exhaustive without a wildcard; a future variant would fail
                // to compile here, forcing an explicit exit-code decision
                // rather than silently defaulting to internal.
                let summary = match merge::reconcile(vault.database_mut(), &remote_db) {
                    Ok(summary) => summary,
                    Err(merge::MergeError::Unresolvable { reason }) => {
                        return Err(SyncError::Unresolvable {
                            reason,
                            backup_path: backup_path.clone(),
                        });
                    }
                };
                total_delta = summary.delta;
                ping(&mut opts);

                vault.save()?;

                let merged_bytes = read_vault_bytes(vault.path())?;
                match transport.put_conditional(&merged_bytes, Some(&snapshot.version)) {
                    Ok(new_version) => {
                        ping(&mut opts);
                        let merged_sha = sha256_of(&merged_bytes);
                        return Ok((
                            SyncOutcome::Merged {
                                delta: total_delta,
                                attempts,
                            },
                            SyncPointers {
                                remote_etag: Some(new_version.0),
                                local_sha256: Some(merged_sha),
                            },
                        ));
                    }
                    Err(e) => {
                        let mapped: SyncError = e.into();
                        if !is_precondition_failure(&mapped) {
                            return Err(mapped);
                        }
                        if attempts >= max {
                            return Err(SyncError::ConditionalPutExhausted { attempts: max });
                        }
                        // else: precondition failed → loop and refetch.
                    }
                }
            }
        }
    }
}

/// Identify the precondition-failure case from a [`SyncError`]. The
/// orchestrator's retry loop catches this via the `IsPreconditionFailed`
/// marker on the transport's error type; once mapped to `SyncError` the
/// signal is carried in the wrapped `S3Error::PreconditionFailed` /
/// `ConcurrentWriteDetected` variant (for the production transport) or
/// in a `MemoryTransport`-shaped wrapper for tests.
fn is_precondition_failure(err: &SyncError) -> bool {
    if let SyncError::S3(s3) = err {
        use crate::transport::IsPreconditionFailed;
        s3.is_precondition_failed()
    } else {
        // Every other variant is a hard failure — no retry available.
        // `MemoryTransport`'s precondition error round-trips here through
        // its `From<MemoryTransportError> for SyncError` mapping below,
        // which lands in `SyncError::S3(_)` so the `if let` above fires.
        false
    }
}

// ===========================================================================
// Helpers
// ===========================================================================

/// Read the on-disk vault bytes. Distinct error variant
/// ([`SyncError::VaultIo`]) so the caller can distinguish "I/O during
/// sync" from "vault-layer logical error" without parsing strings.
fn read_vault_bytes(path: &std::path::Path) -> Result<Vec<u8>, SyncError> {
    std::fs::read(path).map_err(|source| SyncError::VaultIo {
        path: path.to_path_buf(),
        source,
    })
}

/// Hex-encoded SHA-256 of `bytes`. Used for the `last_synced_local_sha256`
/// pointer.
fn sha256_of(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

/// Call the activity pinger if one is registered.
fn ping(opts: &mut SyncOptions) {
    if let Some(p) = opts.on_activity.as_mut() {
        p();
    }
}

/// Update a registered vault's `[sync]` sub-table to match `cfg`. Uses
/// the established clone-deregister-register pattern (matches
/// `falach-cli`'s `vault set-lock` flow) because [`VaultRegistry`] has
/// no `get_mut` accessor.
fn update_registry_sync_block(
    registry: &mut VaultRegistry,
    vault_name: &str,
    cfg: &SyncConfig,
) -> Result<(), SyncError> {
    let original = registry
        .get(vault_name)
        .ok_or_else(|| {
            SyncError::Vault(VaultError::NotRegistered {
                name: vault_name.to_string(),
            })
        })?
        .clone();
    let mut updated = original;
    cfg.to_vault_entry(&mut updated);
    registry.deregister(vault_name, false)?;
    registry.register(updated)?;
    Ok(())
}

// ===========================================================================
// Production-transport construction
// ===========================================================================

/// Build a production [`S3Transport`] backed by [`Client`] for the given
/// `S3Config`. Resolves credentials via [`auth::resolve`] with a
/// [`SystemEnvSource`] for `EnvVars`-variant lookups.
///
/// The transport is wired with a `with_if_match_state` constructor so
/// the sentinel-key probe result (ADR-5) can be persisted via the
/// `on_if_match_change` callback. The callback shape here is a no-op —
/// the higher-level [`Sync::sync_now`] re-reads the cache from the
/// freshly-mutated `S3Config` *after* `run_state_machine` returns,
/// then persists via `update_registry_sync_block`.
///
/// # Errors
///
/// Returns [`SyncError::Auth`] when the credential discovery layer
/// fails, [`SyncError::S3`] when the endpoint URL is malformed
/// (`EndpointError`).
fn build_s3_transport(
    cfg: &S3Config,
    master_password: &MasterPassword,
) -> Result<S3Transport<Client<HttpClient>>, SyncError> {
    let env = SystemEnvSource;
    let resolved = auth::resolve(cfg.credentials(), master_password, &env)?;

    let endpoint_cfg = EndpointConfig {
        endpoint: cfg.endpoint(),
        region: cfg.region(),
        bucket: cfg.bucket(),
        force_path_style: cfg.path_style(),
    };
    let endpoint = EndpointBuilder::from_config(&endpoint_cfg).map_err(|e| {
        SyncError::S3(crate::s3::S3Error::Unexpected {
            status: 0,
            reason: format!("malformed endpoint: {e}"),
        })
    })?;

    let signer = Signer::new(cfg.region().to_string());

    let user_agent = format!("{USER_AGENT_PREFIX}{}", env!("CARGO_PKG_VERSION"));
    let http =
        HttpClient::new(&user_agent).map_err(|e| SyncError::S3(crate::s3::S3Error::Http(e)))?;

    // Bridge from auth::ResolvedCredentials to signer::ResolvedCredentials.
    let signer_creds = signer_credentials_from(&resolved);

    let client = Client::new(http, signer, endpoint, signer_creds);

    Ok(S3Transport::with_if_match_state(
        client,
        cfg.bucket().to_string(),
        cfg.key().to_string(),
        cfg.if_match_supported(),
        // The probe-result callback is no-op here; the high-level
        // sync_now reads `transport.if_match_supported()` after the
        // state machine returns and writes it back to the registry.
        // Capturing a `&mut SyncConfig` here would require unsafe
        // lifetime-extension trickery; the read-back approach is
        // cleaner.
        Box::new(|_| {}),
    ))
}

/// Bridge from the (auth) `ResolvedCredentials` shape — which uses
/// `SecretString` for zeroize-on-drop discipline — to the (signer)
/// `ResolvedCredentials` shape, which holds raw `String`s (also
/// zeroized on drop, but lacking the `ExposeSecret` discipline).
///
/// The bridge is a controlled, single-call leak point: we extract the
/// secret bytes from `SecretString` once, copy into a `String`, and
/// drop both at the end of the sync. Both copies are zeroized via
/// their respective `Drop` impls.
fn signer_credentials_from(resolved: &auth::ResolvedCredentials) -> crate::s3::ResolvedCredentials {
    use secrecy::ExposeSecret;
    crate::s3::ResolvedCredentials {
        access_key_id: resolved.access_key_id.clone(),
        secret_access_key: resolved.secret_access_key.expose_secret().to_string(),
        session_token: resolved
            .session_token
            .as_ref()
            .map(|t| t.expose_secret().to_string()),
    }
}

// ===========================================================================
// Public helpers for tests in other modules (and the eventual CLI hand-off)
// ===========================================================================

/// Format a one-line summary of `outcome` for human-readable stderr
/// emission. Convenience pass-through to [`crate::sync_log::format`];
/// re-exported here so call sites that already imported `Sync` don't
/// need a second `use`.
#[must_use]
pub fn format_outcome(outcome: &SyncOutcome, duration: Duration) -> String {
    let hostname = gethostname().to_string_lossy().to_string();
    crate::sync_log::format(outcome, &hostname, duration)
}

/// The Utc now-helper, broken out for symmetry with the
/// design-committed surface. Currently unused inside the orchestrator
/// (no clock-derived state lives in the state machine), kept here for
/// the eventual auto-lock activity-pong integration.
#[doc(hidden)]
pub fn _now() -> chrono::DateTime<chrono::Utc> {
    Utc::now()
}

// ===========================================================================
// MemoryTransport → SyncError mapping (for tests)
// ===========================================================================

#[cfg(any(test, feature = "test-helpers"))]
impl From<crate::transport::memory::MemoryTransportError> for SyncError {
    fn from(err: crate::transport::memory::MemoryTransportError) -> Self {
        use crate::transport::memory::MemoryTransportError;
        match err {
            // Map the precondition variant into an S3Error::PreconditionFailed
            // so the orchestrator's `is_precondition_failure` check fires.
            // This is the test-only bridge that keeps the orchestrator's
            // retry-loop logic exercised against MemoryTransport.
            MemoryTransportError::PreconditionFailed => {
                SyncError::S3(crate::s3::S3Error::PreconditionFailed)
            }
            MemoryTransportError::NotFound => SyncError::RemoteUnreachable {
                endpoint: "<memory-transport>".to_string(),
                source: "MemoryTransport: object not found".into(),
            },
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::CredentialSource;
    use crate::transport::memory::MemoryTransport;
    use falach_core::{FalachPaths, KdfParams, NoRecoveryConfirmed, RegisteredVault};
    use tempfile::TempDir;

    // -----------------------------------------------------------------------
    // Test fixtures
    // -----------------------------------------------------------------------

    fn master() -> MasterPassword {
        MasterPassword::new("correct horse battery staple".to_string())
    }

    fn weak_kdf() -> KdfParams {
        // Speed for tests — KDF correctness is in vault-core's suite,
        // not here. CLAUDE.md ban on "no exceptions for tests" doesn't
        // apply: this is purely a CPU-budget concession.
        KdfParams {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        }
    }

    /// A fresh tempdir with a registered vault. Returns (TempDir,
    /// paths, registry, vault_name, vault_path) — caller holds the
    /// TempDir to keep the directory alive.
    fn seed_vault() -> (
        TempDir,
        FalachPaths,
        VaultRegistry,
        String,
        std::path::PathBuf,
    ) {
        let tmp = TempDir::new().expect("tempdir");
        let paths = FalachPaths::with_state_dir(tmp.path().join("state"));
        paths.ensure_exists().expect("state dir");

        let vault_name = "work".to_string();
        let vault_path = tmp.path().join("work.kdbx");

        // Create the vault file on disk.
        let pw = master();
        Vault::create(
            &vault_path,
            &pw,
            None,
            weak_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create vault");

        // Register it.
        let mut registry = VaultRegistry::with_paths(paths.clone());
        registry
            .register(RegisteredVault {
                name: vault_name.clone(),
                path: vault_path.clone(),
                created_at: "2026-05-28T10:00:00Z".to_string(),
                keyfile_path: None,
                extra: toml::Table::new(),
            })
            .expect("register");
        registry.save().expect("save");

        (tmp, paths, registry, vault_name, vault_path)
    }

    /// Configure the vault with a fresh SyncConfig holding a sample S3
    /// stub — the tests using MemoryTransport never touch S3, but the
    /// `SyncConfig` is the contract used to look up `last_synced_*`.
    fn configure_sync(registry: &mut VaultRegistry, vault_name: &str) {
        let s3 = S3Config::new(
            "bucket".to_string(),
            "key".to_string(),
            "us-east-1".to_string(),
            CredentialSource::RstCred1 {
                access_key_id: "AKIA".to_string(),
                secret_access_key_encrypted: "UkMwMSDV".to_string(),
            },
        );
        let cfg = SyncConfig::s3(s3);
        update_registry_sync_block(registry, vault_name, &cfg).expect("update sync block");
        registry.save().expect("save");
    }

    /// Read the (currently-stored) `(last_synced_remote_etag,
    /// last_synced_local_sha256)` pair from the registry.
    fn read_pointers(
        registry: &VaultRegistry,
        vault_name: &str,
    ) -> (Option<String>, Option<String>) {
        let entry = registry.get(vault_name).expect("vault present");
        let cfg = SyncConfig::from_vault_entry(entry).expect("sync config");
        (cfg.last_synced_remote_etag, cfg.last_synced_local_sha256)
    }

    /// Helper that drives the *production* persistence path
    /// ([`sync_now_with_transport`]) with a test-owned transport. A thin
    /// wrapper only — reading the config from the registry is the sole
    /// thing it does that the production function doesn't.
    fn run_and_persist(
        vault: &mut Vault,
        registry: &mut VaultRegistry,
        vault_name: &str,
        master_password: &MasterPassword,
        transport: &mut MemoryTransport,
        opts: SyncOptions,
    ) -> Result<SyncOutcome, SyncError> {
        let cfg = SyncConfig::from_vault_entry(registry.get(vault_name).unwrap()).unwrap();
        sync_now_with_transport(
            vault,
            vault_name,
            registry,
            master_password,
            None,
            transport,
            cfg,
            opts,
            |_, _| {},
        )
    }

    // -----------------------------------------------------------------------
    // TC-SYNC-007 — first-ever sync against an empty target
    // -----------------------------------------------------------------------
    #[test]
    fn first_ever_sync_unconditionally_puts() {
        let (_tmp, _paths, mut registry, name, vault_path) = seed_vault();
        configure_sync(&mut registry, &name);

        let mut transport = MemoryTransport::new();
        let mut vault = Vault::open(&vault_path, &master(), None).expect("open vault");

        let outcome = run_and_persist(
            &mut vault,
            &mut registry,
            &name,
            &master(),
            &mut transport,
            SyncOptions::default(),
        )
        .expect("first sync ok");

        assert!(
            matches!(
                outcome,
                SyncOutcome::Pushed {
                    is_first_seed: true
                }
            ),
            "first sync = first-seed PUT, got: {outcome:?}"
        );
        let (etag, sha) = read_pointers(&registry, &name);
        assert!(etag.is_some(), "last_synced_remote_etag populated");
        assert!(sha.is_some(), "last_synced_local_sha256 populated");
    }

    // -----------------------------------------------------------------------
    // TC-SYNC-001 — both pointers match → AlreadyInSync
    // -----------------------------------------------------------------------
    #[test]
    fn state_nothing_to_do_returns_already_in_sync() {
        let (_tmp, _paths, mut registry, name, vault_path) = seed_vault();
        configure_sync(&mut registry, &name);
        let mut transport = MemoryTransport::new();
        let mut vault = Vault::open(&vault_path, &master(), None).expect("open");

        // First sync seeds the remote + pointers.
        run_and_persist(
            &mut vault,
            &mut registry,
            &name,
            &master(),
            &mut transport,
            SyncOptions::default(),
        )
        .expect("seed");

        // Second sync sees identical state.
        let outcome = run_and_persist(
            &mut vault,
            &mut registry,
            &name,
            &master(),
            &mut transport,
            SyncOptions::default(),
        )
        .expect("second sync");
        assert!(
            matches!(outcome, SyncOutcome::AlreadyInSync),
            "got: {outcome:?}"
        );
    }

    // -----------------------------------------------------------------------
    // TC-SYNC-002 — local-only change → Pushed
    // -----------------------------------------------------------------------
    #[test]
    fn state_local_changed_only_pushes() {
        let (_tmp, _paths, mut registry, name, vault_path) = seed_vault();
        configure_sync(&mut registry, &name);
        let mut transport = MemoryTransport::new();

        // Seed + close.
        {
            let mut v = Vault::open(&vault_path, &master(), None).unwrap();
            run_and_persist(
                &mut v,
                &mut registry,
                &name,
                &master(),
                &mut transport,
                SyncOptions::default(),
            )
            .expect("seed");
        }

        // Mutate the local: open, save (which rewrites the file with a
        // fresh AES IV + KDF seed → fresh ciphertext, even with no
        // semantic edits, which is good enough for the sha256 to differ).
        let mut v = Vault::open(&vault_path, &master(), None).unwrap();
        v.save().unwrap();

        let outcome = run_and_persist(
            &mut v,
            &mut registry,
            &name,
            &master(),
            &mut transport,
            SyncOptions::default(),
        )
        .expect("push");
        assert!(
            matches!(
                outcome,
                SyncOutcome::Pushed {
                    is_first_seed: false
                }
            ),
            "expected steady-state Pushed, got: {outcome:?}"
        );
    }

    // -----------------------------------------------------------------------
    // TC-SYNC-003 — remote-only change → FastReplaced
    //
    // Simulates "device B pushed a new version" by re-saving the SAME
    // logical vault (so the root-group UUID survives Vault::replace_database)
    // to obtain a fresh-ciphertext byte stream, then PUTting those bytes
    // through the transport. From device A's perspective the remote has
    // moved while the local has not.
    // -----------------------------------------------------------------------
    #[test]
    fn state_remote_changed_only_fast_replaces() {
        let (_tmp, _paths, mut registry, name, vault_path) = seed_vault();
        configure_sync(&mut registry, &name);
        let mut transport = MemoryTransport::new();

        // Device A: seed (pushes initial local bytes to the transport).
        {
            let mut v = Vault::open(&vault_path, &master(), None).unwrap();
            run_and_persist(
                &mut v,
                &mut registry,
                &name,
                &master(),
                &mut transport,
                SyncOptions::default(),
            )
            .expect("seed");
        }

        // Device B (simulated): clone the same vault file to a sibling
        // path, open + save it to mint a fresh-ciphertext byte stream,
        // then PUT those bytes to the transport. The root-group UUID is
        // preserved (it's the SAME logical vault), so
        // Vault::replace_database accepts the snapshot on device A.
        let device_b_path = vault_path.with_extension("kdbx.deviceB");
        std::fs::copy(&vault_path, &device_b_path).unwrap();
        {
            let mut vb = Vault::open(&device_b_path, &master(), None).unwrap();
            vb.save().unwrap(); // fresh KDF salt + IV → different ciphertext
        }
        let b_bytes = std::fs::read(&device_b_path).unwrap();
        let prev = transport.head().unwrap();
        let _new_v = transport.put_conditional(&b_bytes, prev.as_ref()).unwrap();

        // Device A: now sees the moved remote ETag with its local
        // unchanged → FastReplaced.
        let mut va = Vault::open(&vault_path, &master(), None).unwrap();
        let outcome = run_and_persist(
            &mut va,
            &mut registry,
            &name,
            &master(),
            &mut transport,
            SyncOptions::default(),
        )
        .expect("fast-replace");
        assert!(
            matches!(outcome, SyncOutcome::FastReplaced),
            "got: {outcome:?}"
        );

        // .kdbx.bak was written.
        let bak = backup::backup_path_for(&vault_path);
        assert!(bak.exists(), ".kdbx.bak written even on fast-replace");
    }

    // -----------------------------------------------------------------------
    // FR-044 partial: a successful Pushed sync does not modify the
    // on-disk local vault bytes (the local file is what gets PUT, then
    // left in place). The full TC-SYNC-009 (HEAD-returns-error →
    // SyncError::RemoteUnreachable + no .kdbx.bak) is covered by
    // `head_error_surfaces_remote_unreachable_without_backup` below.
    // -----------------------------------------------------------------------
    #[test]
    fn pushed_path_does_not_modify_local_vault_bytes() {
        let (_tmp, _paths, mut registry, name, vault_path) = seed_vault();
        configure_sync(&mut registry, &name);

        // Empty transport whose `fetch_if_changed(None)` returns NotFound.
        // For HEAD we get Ok(None) which would mean "first seed", not an
        // error — to model "remote unreachable" we drive the state machine
        // through a path where fetch_if_changed errors. Use the local-side
        // pointers to force the path that needs a fetch_if_changed.
        //
        // Simpler approach: confirm the vault file is untouched in the
        // first-seed PUT path on a fresh transport — fetch is never called,
        // and the test is effectively redundant with TC-SYNC-007. Instead,
        // force the Pushed path with a stale pointer pointing at an
        // existing-but-different remote, and inject the precondition
        // failure path; verify the vault on-disk bytes don't change.
        let mut transport = MemoryTransport::new();
        let other = b"random-bytes-pretending-to-be-encrypted-kdbx";
        let v0 = transport.put_conditional(other, None).unwrap();

        // Save a stale (mismatched) etag pointer + a fresh local sha so
        // the local-changed axis fires.
        let mut cfg = SyncConfig::from_vault_entry(registry.get(&name).unwrap()).unwrap();
        cfg.last_synced_remote_etag = Some(v0.0.clone());
        cfg.last_synced_local_sha256 = Some("0".repeat(64));
        update_registry_sync_block(&mut registry, &name, &cfg).unwrap();
        registry.save().unwrap();

        // Capture vault bytes before — they must NOT change since this is
        // a push-only path and the transport happily accepts the PUT.
        // To force a `RemoteUnreachable`-shaped error we'd need a
        // failing transport; the MemoryTransport doesn't have an "error
        // injection" mode. Instead, this test pins the FR-044 property
        // by asserting that a successful Pushed leaves the local bytes
        // unchanged — that's what the impl plan §1.4 acceptance lists
        // (FR-044: "sync failures don't damage local").
        let pre = std::fs::read(&vault_path).unwrap();
        let mut v = Vault::open(&vault_path, &master(), None).unwrap();
        let _ = run_and_persist(
            &mut v,
            &mut registry,
            &name,
            &master(),
            &mut transport,
            SyncOptions::default(),
        );
        drop(v);
        let post = std::fs::read(&vault_path).unwrap();
        // The local file is the same — sync wrote no merged state, only
        // PUT (Pushed path); the local-side .kdbx is unchanged.
        assert_eq!(pre, post, "FR-044: local vault unchanged through push");

        // .kdbx.bak is NOT written on a non-merge sync.
        let bak = backup::backup_path_for(&vault_path);
        assert!(!bak.exists(), "no .kdbx.bak written on Pushed");
    }

    // -----------------------------------------------------------------------
    // TC-SYNC-011 — activity-pong fires at network boundaries
    // -----------------------------------------------------------------------
    #[test]
    fn activity_pong_called_at_each_network_boundary() {
        let (_tmp, _paths, mut registry, name, vault_path) = seed_vault();
        configure_sync(&mut registry, &name);

        let mut transport = MemoryTransport::new();

        // Use a shared counter through interior mutability.
        let counter = std::rc::Rc::new(std::cell::Cell::new(0u32));
        let counter_clone = counter.clone();
        let opts = SyncOptions {
            max_retries: 3,
            on_activity: Some(Box::new(move || {
                counter_clone.set(counter_clone.get() + 1);
            })),
        };

        let mut v = Vault::open(&vault_path, &master(), None).unwrap();
        run_and_persist(
            &mut v,
            &mut registry,
            &name,
            &master(),
            &mut transport,
            opts,
        )
        .expect("first-seed sync");

        // First-seed path pings at: HEAD, after the unconditional PUT
        // = 2 pings minimum.
        let n = counter.get();
        assert!(
            n >= 2,
            "expected ≥2 pings (HEAD + PUT) on first-seed path, got {n}"
        );
    }

    // -----------------------------------------------------------------------
    // TC-SYNC-012 — `on_activity = None` is safe
    // -----------------------------------------------------------------------
    #[test]
    fn activity_pong_safe_with_none() {
        let (_tmp, _paths, mut registry, name, vault_path) = seed_vault();
        configure_sync(&mut registry, &name);
        let mut transport = MemoryTransport::new();
        let mut v = Vault::open(&vault_path, &master(), None).unwrap();
        let _ = run_and_persist(
            &mut v,
            &mut registry,
            &name,
            &master(),
            &mut transport,
            SyncOptions {
                max_retries: 3,
                on_activity: None,
            },
        )
        .expect("None pinger is fine");
    }

    // -----------------------------------------------------------------------
    // TC-SYNC-014 — atomic pointer-update on success
    // -----------------------------------------------------------------------
    #[test]
    fn successful_sync_updates_both_last_synced_pointers_atomically() {
        let (_tmp, _paths, mut registry, name, vault_path) = seed_vault();
        configure_sync(&mut registry, &name);
        let mut transport = MemoryTransport::new();

        let mut v = Vault::open(&vault_path, &master(), None).unwrap();
        run_and_persist(
            &mut v,
            &mut registry,
            &name,
            &master(),
            &mut transport,
            SyncOptions::default(),
        )
        .expect("first sync");

        let (etag, sha) = read_pointers(&registry, &name);
        assert!(etag.is_some(), "remote ETag pointer set");
        assert!(sha.is_some(), "local SHA pointer set");

        // Reload the registry from disk to confirm the write happened —
        // not just an in-memory mutation.
        let fresh = VaultRegistry::load(registry.paths().clone()).unwrap();
        let (e2, s2) = read_pointers(&fresh, &name);
        assert_eq!(e2, etag);
        assert_eq!(s2, sha);
    }

    // -----------------------------------------------------------------------
    // TC-SYNC-008 — KDF param mismatch short-circuits, no .kdbx.bak
    // -----------------------------------------------------------------------
    #[test]
    fn kdf_param_mismatch_aborts_before_merge() {
        let (_tmp, _paths, mut registry, name, vault_path) = seed_vault();
        configure_sync(&mut registry, &name);
        let mut transport = MemoryTransport::new();

        // Construct a vault with DIFFERENT KDF params at a sibling path
        // — this becomes the "remote" we PUT to the transport.
        let tmp_remote = TempDir::new().unwrap();
        let remote_path = tmp_remote.path().join("remote.kdbx");
        Vault::create(
            &remote_path,
            &master(),
            None,
            KdfParams {
                memory_kib: 2048, // DIFFERENT from weak_kdf's 1024
                iterations: 2,
                parallelism: 1,
            },
            NoRecoveryConfirmed::yes(),
        )
        .unwrap();
        let remote_bytes = std::fs::read(&remote_path).unwrap();
        transport.put_conditional(&remote_bytes, None).unwrap();

        // Seed our pointers to mark "remote unseen, local unchanged"
        // — wait, we need (true, false) i.e. remote-changed only. The
        // pointers must claim the remote was at some prior etag.
        let mut cfg = SyncConfig::from_vault_entry(registry.get(&name).unwrap()).unwrap();
        cfg.last_synced_remote_etag = Some("stale-etag".to_string());
        let local_sha = sha256_of(&std::fs::read(&vault_path).unwrap());
        cfg.last_synced_local_sha256 = Some(local_sha);
        update_registry_sync_block(&mut registry, &name, &cfg).unwrap();
        registry.save().unwrap();

        let mut v = Vault::open(&vault_path, &master(), None).unwrap();
        let err = run_state_machine(
            &mut v,
            &master(),
            None,
            &mut transport,
            cfg.last_synced_remote_etag.clone(),
            cfg.last_synced_local_sha256.as_deref(),
            SyncOptions::default(),
        )
        .expect_err("KDF mismatch must surface");
        assert!(
            matches!(err, SyncError::MasterPasswordMismatch),
            "got: {err:?}"
        );

        let bak = backup::backup_path_for(&vault_path);
        assert!(
            !bak.exists(),
            "no .kdbx.bak written on KDF mismatch (short-circuit before backup)"
        );
    }

    /// Test transport that reports `PreconditionFailed` on the first
    /// `puts_to_fail` conditional PUTs, then succeeds. Setting
    /// `puts_to_fail = u32::MAX` models the "always-fails" remote that
    /// drives the orchestrator into bounded exhaustion. Defined at
    /// module scope so clippy's `items_after_statements` lint stays
    /// clean.
    struct FlakyPutTransport {
        puts_to_fail: u32,
        attempts_seen: u32,
        cur_version: ObjectVersion,
        cur_bytes: Vec<u8>,
    }

    impl SyncTransport for FlakyPutTransport {
        type Error = crate::transport::memory::MemoryTransportError;
        fn head(&mut self) -> Result<Option<ObjectVersion>, Self::Error> {
            Ok(Some(self.cur_version.clone()))
        }
        fn fetch_if_changed(
            &mut self,
            _prev_version: Option<&ObjectVersion>,
        ) -> Result<Option<ObjectSnapshot>, Self::Error> {
            Ok(Some(ObjectSnapshot {
                version: self.cur_version.clone(),
                bytes: self.cur_bytes.clone(),
            }))
        }
        fn put_conditional(
            &mut self,
            bytes: &[u8],
            _if_match: Option<&ObjectVersion>,
        ) -> Result<ObjectVersion, Self::Error> {
            self.attempts_seen += 1;
            if self.attempts_seen <= self.puts_to_fail {
                // Advance the version so the next fetch returns
                // something "new" → next conditional PUT also fails
                // under `If-Match` semantics.
                self.cur_version = ObjectVersion(format!("racer-{}", self.attempts_seen));
                self.cur_bytes = bytes.to_vec();
                Err(crate::transport::memory::MemoryTransportError::PreconditionFailed)
            } else {
                // Success on this attempt: install the bytes, mint a
                // post-race version, return it.
                self.cur_version = ObjectVersion(format!("winning-{}", self.attempts_seen));
                self.cur_bytes = bytes.to_vec();
                Ok(self.cur_version.clone())
            }
        }
    }

    /// Common setup for the FlakyPutTransport-driven merge-retry tests:
    /// register + configure a vault, return everything the test needs to
    /// drive `run_state_machine` through the (true, true) branch.
    fn flaky_merge_fixture() -> (
        TempDir,
        VaultRegistry,
        String,
        std::path::PathBuf,
        FlakyPutTransport,
    ) {
        let (tmp, _paths, mut registry, name, vault_path) = seed_vault();
        configure_sync(&mut registry, &name);

        let initial_bytes = std::fs::read(&vault_path).unwrap();
        let transport = FlakyPutTransport {
            puts_to_fail: 0, // overwrite per-test
            attempts_seen: 0,
            cur_version: ObjectVersion("v0".to_string()),
            cur_bytes: initial_bytes,
        };

        let mut cfg = SyncConfig::from_vault_entry(registry.get(&name).unwrap()).unwrap();
        cfg.last_synced_remote_etag = Some("stale".to_string());
        cfg.last_synced_local_sha256 = Some("0".repeat(64));
        update_registry_sync_block(&mut registry, &name, &cfg).unwrap();

        (tmp, registry, name, vault_path, transport)
    }

    // -----------------------------------------------------------------------
    // TC-SYNC-006 — exhausted retries → ConditionalPutExhausted
    // -----------------------------------------------------------------------
    #[test]
    fn conditional_put_exhausted_when_remote_keeps_advancing() {
        let (_tmp, registry, name, vault_path, mut transport) = flaky_merge_fixture();
        transport.puts_to_fail = u32::MAX; // never succeed

        let (prev_etag, prev_sha) = read_pointers(&registry, &name);
        let mut v = Vault::open(&vault_path, &master(), None).unwrap();
        let err = run_state_machine(
            &mut v,
            &master(),
            None,
            &mut transport,
            prev_etag,
            prev_sha.as_deref(),
            SyncOptions {
                max_retries: 3,
                on_activity: None,
            },
        )
        .expect_err("exhaustion expected");
        assert!(
            matches!(err, SyncError::ConditionalPutExhausted { attempts: 3 }),
            "got: {err:?}"
        );
        assert_eq!(
            transport.attempts_seen, 3,
            "orchestrator must consume exactly max_retries attempts before giving up"
        );

        // The local vault's `.kdbx.bak` IS present — the (true, true)
        // path snapshots before the retry loop. The next sync resumes
        // from the same state machine state.
        let bak = backup::backup_path_for(&vault_path);
        assert!(
            bak.exists(),
            ".kdbx.bak written before the retry loop, retained on exhaustion"
        );
        let _ = registry; // silence unused-mut without dropping the reload assertions if added later.
    }

    // -----------------------------------------------------------------------
    // TC-SYNC-005 — retries up to N, then succeed → outcome carries the
    // correct attempts count, pointers advance.
    // -----------------------------------------------------------------------
    #[test]
    fn merge_with_precondition_failed_retries_then_succeeds() {
        let (_tmp, registry, name, vault_path, mut transport) = flaky_merge_fixture();
        // Fail twice, succeed on attempt 3.
        transport.puts_to_fail = 2;

        let (prev_etag, prev_sha) = read_pointers(&registry, &name);
        let mut v = Vault::open(&vault_path, &master(), None).unwrap();
        let (outcome, pointers) = run_state_machine(
            &mut v,
            &master(),
            None,
            &mut transport,
            prev_etag,
            prev_sha.as_deref(),
            SyncOptions {
                max_retries: 3,
                on_activity: None,
            },
        )
        .expect("third attempt should succeed");

        match outcome {
            SyncOutcome::Merged { attempts, delta: _ } => {
                assert_eq!(
                    attempts, 3,
                    "expected exactly three conditional-PUT attempts (2 failures + 1 success)"
                );
            }
            other => panic!("expected Merged, got {other:?}"),
        }
        assert_eq!(transport.attempts_seen, 3);
        assert!(
            pointers.remote_etag.is_some(),
            "successful merge must advance the remote_etag pointer"
        );
        assert!(
            pointers.local_sha256.is_some(),
            "successful merge must advance the local_sha256 pointer"
        );

        // `.kdbx.bak` was written before the retry loop.
        let bak = backup::backup_path_for(&vault_path);
        assert!(bak.exists());
        let _ = registry;
    }

    // -----------------------------------------------------------------------
    // Sync::configure_remote — DuplicateTarget rejection
    // -----------------------------------------------------------------------
    #[test]
    fn configure_remote_rejects_duplicate_target() {
        let (_tmp, _paths, mut registry, work_name, _) = seed_vault();

        // Register a second vault.
        let other_path = registry
            .paths()
            .vaults_toml()
            .parent()
            .unwrap()
            .join("other.kdbx");
        Vault::create(
            &other_path,
            &master(),
            None,
            weak_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .unwrap();
        registry
            .register(RegisteredVault {
                name: "personal".to_string(),
                path: other_path,
                created_at: "2026-05-28T11:00:00Z".to_string(),
                keyfile_path: None,
                extra: toml::Table::new(),
            })
            .unwrap();
        registry.save().unwrap();

        // Configure `work` against bucket=X, key=Y.
        let s3a = S3Config::new(
            "shared-bucket".to_string(),
            "shared.kdbx".to_string(),
            "us-east-1".to_string(),
            CredentialSource::RstCred1 {
                access_key_id: "AKIA".to_string(),
                secret_access_key_encrypted: "UkMwMSDV".to_string(),
            },
        );
        Sync::configure_remote(&mut registry, &work_name, s3a, &master())
            .expect("first configure ok");

        // Try to configure `personal` against the same triple → DuplicateTarget.
        let s3b = S3Config::new(
            "shared-bucket".to_string(),
            "shared.kdbx".to_string(),
            "us-east-1".to_string(),
            CredentialSource::RstCred1 {
                access_key_id: "AKIA-other".to_string(),
                secret_access_key_encrypted: "UkMwMSDV".to_string(),
            },
        );
        let err = Sync::configure_remote(&mut registry, "personal", s3b, &master())
            .expect_err("collision must reject");
        assert!(
            matches!(err, SyncError::DuplicateTarget { ref existing_vault, .. } if existing_vault == &work_name),
            "got: {err:?}"
        );

        // The `personal` vault entry was NOT modified by the rejected
        // configure call.
        let personal = registry.get("personal").expect("personal still registered");
        assert!(SyncConfig::from_vault_entry(personal).is_none());
    }

    // -----------------------------------------------------------------------
    // configure_remote allows re-configuring the same vault (self-collision exclude)
    // -----------------------------------------------------------------------
    #[test]
    fn configure_remote_allows_re_configuring_same_vault() {
        let (_tmp, _paths, mut registry, name, _) = seed_vault();

        let s3 = S3Config::new(
            "bucket".to_string(),
            "key".to_string(),
            "us-east-1".to_string(),
            CredentialSource::RstCred1 {
                access_key_id: "AKIA".to_string(),
                secret_access_key_encrypted: "UkMwMSDV".to_string(),
            },
        );
        Sync::configure_remote(&mut registry, &name, s3.clone(), &master())
            .expect("first configure");
        Sync::configure_remote(&mut registry, &name, s3, &master())
            .expect("re-configure same vault, same target");
    }

    #[test]
    fn configure_remote_rejects_malformed_endpoint_without_modifying_registry() {
        let (_tmp, _paths, mut registry, name, _) = seed_vault();

        let mut s3 = S3Config::new(
            "bucket".to_string(),
            "key".to_string(),
            "us-east-1".to_string(),
            CredentialSource::RstCred1 {
                access_key_id: "AKIA".to_string(),
                secret_access_key_encrypted: "UkMwMSDV".to_string(),
            },
        );
        s3.set_endpoint(Some("missing-scheme.example".to_string()));

        let err = Sync::configure_remote(&mut registry, &name, s3, &master())
            .expect_err("malformed endpoint must reject");
        assert!(matches!(err, SyncError::S3(_)), "got: {err:?}");
        let record = registry.get(&name).expect("vault remains registered");
        assert!(
            SyncConfig::from_vault_entry(record).is_none(),
            "invalid configuration must not modify the registry"
        );
    }

    // -----------------------------------------------------------------------
    // configure_remote rejects unregistered vault
    // -----------------------------------------------------------------------
    #[test]
    fn configure_remote_rejects_unregistered_vault() {
        let (_tmp, paths, _registry, _, _) = seed_vault();
        let mut empty = VaultRegistry::with_paths(paths);

        let s3 = S3Config::new(
            "b".to_string(),
            "k".to_string(),
            "us-east-1".to_string(),
            CredentialSource::RstCred1 {
                access_key_id: "AKIA".to_string(),
                secret_access_key_encrypted: "UkMwMSDV".to_string(),
            },
        );
        let err = Sync::configure_remote(&mut empty, "no-such-vault", s3, &master())
            .expect_err("must reject unknown vault");
        assert!(
            matches!(err, SyncError::Vault(VaultError::NotRegistered { .. })),
            "got: {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // sync_now surfaces NotConfigured for an unconfigured vault
    // -----------------------------------------------------------------------
    #[test]
    fn sync_now_returns_not_configured_when_unconfigured() {
        let (_tmp, _paths, mut registry, name, vault_path) = seed_vault();
        // NOTE: we do NOT call `configure_sync` — the vault has no
        // [sync] block.

        let mut v = Vault::open(&vault_path, &master(), None).unwrap();
        let err = Sync::sync_now(
            &mut v,
            &name,
            &mut registry,
            &master(),
            None,
            SyncOptions::default(),
        )
        .expect_err("unconfigured vault must surface NotConfigured");
        assert!(matches!(err, SyncError::NotConfigured), "got: {err:?}");
    }

    // -----------------------------------------------------------------------
    // Regression: run_state_machine MUST return a fresh `SyncPointers`
    // for every successful outcome so the orchestrator's persist step
    // can advance the on-disk pointers. A returned `SyncPointers`
    // equalling the input would re-trigger the same state machine
    // branch on the next sync — silently wasting bandwidth + (in the
    // Merged path) re-running the merge engine on the same divergence
    // every time.
    // -----------------------------------------------------------------------
    #[test]
    fn run_state_machine_returns_advanced_pointers_on_pushed() {
        let (_tmp, _paths, mut registry, name, vault_path) = seed_vault();
        configure_sync(&mut registry, &name);
        let mut transport = MemoryTransport::new();
        let mut v = Vault::open(&vault_path, &master(), None).unwrap();

        let (_outcome, pointers) = run_state_machine(
            &mut v,
            &master(),
            None,
            &mut transport,
            None, // first-ever sync
            None,
            SyncOptions::default(),
        )
        .expect("first-seed succeeds");

        assert!(
            pointers.remote_etag.is_some(),
            "first-seed PUT must advance the remote_etag pointer"
        );
        assert!(
            pointers.local_sha256.is_some(),
            "first-seed PUT must advance the local_sha256 pointer"
        );
    }

    /// Test transport whose every operation returns an error of the
    /// caller's choosing. Used by `head_error_surfaces_remote_unreachable_*`
    /// to drive the FR-044 / TC-SYNC-009 path that `MemoryTransport`'s
    /// always-Ok semantics can't reach.
    struct AlwaysErrTransport;

    impl SyncTransport for AlwaysErrTransport {
        type Error = crate::transport::memory::MemoryTransportError;
        fn head(&mut self) -> Result<Option<ObjectVersion>, Self::Error> {
            // Reuse NotFound as a stand-in for "wire-level failure":
            // its `From<MemoryTransportError> for SyncError` mapping
            // (above) produces `SyncError::RemoteUnreachable`, which is
            // exactly the variant we want to assert.
            Err(crate::transport::memory::MemoryTransportError::NotFound)
        }
        fn fetch_if_changed(
            &mut self,
            _prev: Option<&ObjectVersion>,
        ) -> Result<Option<ObjectSnapshot>, Self::Error> {
            Err(crate::transport::memory::MemoryTransportError::NotFound)
        }
        fn put_conditional(
            &mut self,
            _bytes: &[u8],
            _if_match: Option<&ObjectVersion>,
        ) -> Result<ObjectVersion, Self::Error> {
            Err(crate::transport::memory::MemoryTransportError::NotFound)
        }
    }

    // -----------------------------------------------------------------------
    // TC-SYNC-009 — HEAD fails → SyncError::RemoteUnreachable, local
    // vault file untouched, no .kdbx.bak created.
    // -----------------------------------------------------------------------
    #[test]
    fn head_error_surfaces_remote_unreachable_without_backup() {
        let (_tmp, _paths, mut registry, name, vault_path) = seed_vault();
        configure_sync(&mut registry, &name);
        let mut transport = AlwaysErrTransport;

        let pre = std::fs::read(&vault_path).expect("pre-read");

        let mut v = Vault::open(&vault_path, &master(), None).expect("open");
        let err = run_state_machine(
            &mut v,
            &master(),
            None,
            &mut transport,
            None,
            None,
            SyncOptions::default(),
        )
        .expect_err("HEAD failure must surface");
        assert!(
            matches!(err, SyncError::RemoteUnreachable { .. }),
            "got: {err:?}"
        );

        // Local vault untouched.
        let post = std::fs::read(&vault_path).expect("post-read");
        assert_eq!(pre, post, "FR-044: HEAD failure does not damage local");

        // No backup written — the failure short-circuited before any
        // .kdbx.bak step.
        let bak = backup::backup_path_for(&vault_path);
        assert!(!bak.exists(), "no .kdbx.bak on HEAD failure");
    }

    // -----------------------------------------------------------------------
    // TC-SYNC-004 — both pointers diverged, merge succeeds on the first
    // conditional-PUT attempt → SyncOutcome::Merged { attempts: 1 }.
    // -----------------------------------------------------------------------
    #[test]
    fn state_both_changed_triggers_merge_on_first_attempt() {
        let (_tmp, _paths, mut registry, name, vault_path) = seed_vault();
        configure_sync(&mut registry, &name);
        let mut transport = MemoryTransport::new();

        // Seed (both A and B start from the same vault).
        {
            let mut v = Vault::open(&vault_path, &master(), None).unwrap();
            run_and_persist(
                &mut v,
                &mut registry,
                &name,
                &master(),
                &mut transport,
                SyncOptions::default(),
            )
            .expect("seed");
        }

        // Device B (simulated): clone the same logical vault to a
        // sibling path, save (mints fresh ciphertext), PUT.
        let device_b_path = vault_path.with_extension("kdbx.deviceB");
        std::fs::copy(&vault_path, &device_b_path).unwrap();
        {
            let mut vb = Vault::open(&device_b_path, &master(), None).unwrap();
            vb.save().unwrap();
        }
        let b_bytes = std::fs::read(&device_b_path).unwrap();
        let prev = transport.head().unwrap();
        transport.put_conditional(&b_bytes, prev.as_ref()).unwrap();

        // Device A: also mutate locally (so local SHA diverges too).
        {
            let mut va = Vault::open(&vault_path, &master(), None).unwrap();
            va.save().unwrap();
        }

        let mut va = Vault::open(&vault_path, &master(), None).unwrap();
        let outcome = run_and_persist(
            &mut va,
            &mut registry,
            &name,
            &master(),
            &mut transport,
            SyncOptions::default(),
        )
        .expect("merge ok");

        match outcome {
            SyncOutcome::Merged { attempts, delta: _ } => {
                assert_eq!(
                    attempts, 1,
                    "no contention → single conditional-PUT attempt"
                );
            }
            other => panic!("expected Merged, got {other:?}"),
        }

        // .kdbx.bak was written.
        let bak = backup::backup_path_for(&vault_path);
        assert!(bak.exists(), ".kdbx.bak written before merge");

        // Pointers advanced.
        let (etag, sha) = read_pointers(&registry, &name);
        assert!(etag.is_some());
        assert!(sha.is_some());
    }

    #[test]
    fn run_state_machine_already_in_sync_preserves_pointers() {
        let (_tmp, _paths, mut registry, name, vault_path) = seed_vault();
        configure_sync(&mut registry, &name);
        let mut transport = MemoryTransport::new();
        let mut v = Vault::open(&vault_path, &master(), None).unwrap();

        // Seed (advances pointers).
        run_and_persist(
            &mut v,
            &mut registry,
            &name,
            &master(),
            &mut transport,
            SyncOptions::default(),
        )
        .expect("seed");

        // Second sync from the same state: AlreadyInSync; pointers preserved.
        let (prev_etag, prev_sha) = read_pointers(&registry, &name);
        let (outcome, pointers) = run_state_machine(
            &mut v,
            &master(),
            None,
            &mut transport,
            prev_etag.clone(),
            prev_sha.as_deref(),
            SyncOptions::default(),
        )
        .expect("second sync ok");
        assert!(matches!(outcome, SyncOutcome::AlreadyInSync));
        assert_eq!(pointers.remote_etag, prev_etag);
        assert_eq!(pointers.local_sha256, prev_sha);
    }
}
