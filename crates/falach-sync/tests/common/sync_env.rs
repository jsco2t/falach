//! `SyncTestEnv` — the shared integration-test fixture (impl plan §8.5).
//!
//! Provides a `TempDir`-backed [`FalachPaths`] + [`VaultRegistry`] + an
//! on-disk KDBX vault, plus the small set of mutation/read helpers the
//! `us_04*` and `minio_integration` tests need. Every fs-touching test owns
//! its own `TempDir`; nothing writes to the developer's real environment.

// Each integration test file uses a subset (dead_code). Docs reference type
// names heavily (doc_markdown); `master()` and friends are ergonomic methods
// that don't read a field (unused_self) — kept as methods for call-site flow.
#![allow(dead_code, clippy::doc_markdown, clippy::unused_self)]

use std::cell::Cell;
use std::path::{Path, PathBuf};

use falach_core::{
    fields, FalachPaths, KdfParams, MasterPassword, NoRecoveryConfirmed, RegisteredVault, Uuid,
    Vault, VaultRegistry,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

/// The shared test master password. Deterministic; tests aren't about
/// password strength.
pub const TEST_PASSWORD: &str = "correct horse battery staple";

/// Fast KDF for tests — KDF correctness is vault-core's concern, not the
/// sync suite's. A CPU-budget concession only (matches `sync.rs`'s unit
/// tests).
fn weak_kdf() -> KdfParams {
    KdfParams {
        memory_kib: 1024,
        iterations: 1,
        parallelism: 1,
    }
}

/// A self-contained vault + registry rooted in one `TempDir`.
pub struct SyncTestEnv {
    _tmp: TempDir,
    paths: FalachPaths,
    registry: VaultRegistry,
    name: String,
    vault_path: PathBuf,
    /// Monotonic clock for entry `last_modification` stamps so merge
    /// ordering is deterministic across `add_entry` calls.
    clock: Cell<i64>,
}

impl SyncTestEnv {
    /// Create a fresh tempdir, a vault on disk, and register it.
    #[must_use]
    pub fn new(name: &str) -> Self {
        let tmp = TempDir::new().expect("tempdir");
        let paths = FalachPaths::with_state_dir(tmp.path().join("state"));
        paths.ensure_exists().expect("state dir");

        let vault_path = tmp.path().join(format!("{name}.kdbx"));
        Vault::create(
            &vault_path,
            &MasterPassword::new(TEST_PASSWORD.to_string()),
            None,
            weak_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create vault");

        let mut registry = VaultRegistry::with_paths(paths.clone());
        registry
            .register(RegisteredVault {
                name: name.to_string(),
                path: vault_path.clone(),
                created_at: "2026-05-29T00:00:00Z".to_string(),
                keyfile_path: None,
                extra: toml::Table::new(),
            })
            .expect("register");
        registry.save().expect("save registry");

        Self {
            _tmp: tmp,
            paths,
            registry,
            name: name.to_string(),
            vault_path,
            clock: Cell::new(1_700_000_000),
        }
    }

    /// The configured master password.
    #[must_use]
    pub fn master(&self) -> MasterPassword {
        MasterPassword::new(TEST_PASSWORD.to_string())
    }

    /// The registered vault name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Path to the on-disk `.kdbx`.
    #[must_use]
    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    /// Mutable access to the registry (US-040 configures sync here).
    pub fn registry_mut(&mut self) -> &mut VaultRegistry {
        &mut self.registry
    }

    /// Immutable access to the registry.
    #[must_use]
    pub fn registry(&self) -> &VaultRegistry {
        &self.registry
    }

    /// Add a root-level entry titled `title` (with a monotonic
    /// `last_modification` stamp) and save. Re-encrypts the file → fresh
    /// ciphertext, so the on-disk SHA changes on every call.
    pub fn add_entry(&self, title: &str) {
        let mut vault = self.open();
        let at = self.next_time();
        {
            let db = vault.database_mut();
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, title);
            entry.times.last_modification = Some(at);
        }
        vault.save().expect("save after add_entry");
    }

    /// Add a root-level entry and return its UUID — used by collision /
    /// disjoint-merge scenarios that later edit the *same* entry on two
    /// devices.
    pub fn seed_entry(&self, title: &str) -> Uuid {
        let mut vault = self.open();
        let at = self.next_time();
        let uuid = {
            let db = vault.database_mut();
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, title);
            entry.times.last_modification = Some(at);
            entry.id().uuid()
        };
        vault.save().expect("save after seed_entry");
        uuid
    }

    /// Edit an existing entry's title with history tracking (the prior value
    /// is pushed to history, as a real edit does), stamping
    /// `last_modification` from the env clock, and save.
    pub fn edit_entry(&self, uuid: Uuid, title: &str) {
        let at = self.next_time().and_utc().timestamp();
        self.edit_entry_at(uuid, title, at);
    }

    /// Like [`Self::edit_entry`] but with an explicit Unix-second timestamp,
    /// so collision tests can deterministically control which side is
    /// "newer" (newer-modified wins per the merge engine, ADR-008).
    pub fn edit_entry_at(&self, uuid: Uuid, title: &str, unix_secs: i64) {
        let at = chrono::DateTime::from_timestamp(unix_secs, 0)
            .expect("valid timestamp")
            .naive_utc();
        let mut vault = self.open();
        {
            let db = vault.database_mut();
            let id = db
                .root()
                .entries()
                .find(|e| e.id().uuid() == uuid)
                .map(|e| e.id())
                .expect("entry exists");
            db.entry_mut(id)
                .expect("entry exists")
                .edit_tracking(|e| e.set_unprotected(fields::TITLE, title));
            db.entry_mut(id)
                .expect("entry exists")
                .times
                .last_modification = Some(at);
        }
        vault.save().expect("save after edit_entry");
    }

    /// Copy this vault to a new `SyncTestEnv` under `new_name`, modelling a
    /// second device holding the *same* logical vault (identical root-group
    /// UUID + master password), so merges and `replace_database` accept it.
    #[must_use]
    pub fn clone_to(&self, new_name: &str) -> SyncTestEnv {
        let other = SyncTestEnv::new(new_name);
        std::fs::copy(&self.vault_path, &other.vault_path).expect("copy vault to device B");
        // Carry the clock forward so device B's edits sort after device A's.
        other.clock.set(self.clock.get() + 1_000);
        other
    }

    /// Open the vault.
    #[must_use]
    pub fn open(&self) -> Vault {
        Vault::open(&self.vault_path, &self.master(), None).expect("open vault")
    }

    /// Hex-encoded SHA-256 of the current on-disk bytes — identical to the
    /// orchestrator's `last_synced_local_sha256` computation.
    #[must_use]
    pub fn local_sha(&self) -> String {
        let bytes = std::fs::read(&self.vault_path).expect("read vault bytes");
        hex::encode(Sha256::digest(&bytes))
    }

    fn next_time(&self) -> chrono::NaiveDateTime {
        let t = self.clock.get();
        self.clock.set(t + 1);
        chrono::DateTime::from_timestamp(t, 0)
            .expect("valid timestamp")
            .naive_utc()
    }
}

/// Open `env`'s vault (free-function form for call sites that already hold a
/// `&SyncTestEnv`).
#[must_use]
pub fn open_vault(env: &SyncTestEnv) -> Vault {
    env.open()
}

/// Collect the current titles of every entry in `vault` (recursively),
/// modulo ordering.
#[must_use]
pub fn vault_entry_titles(vault: &Vault) -> Vec<String> {
    fn walk(group: &falach_core::GroupRef<'_>, out: &mut Vec<String>) {
        for entry in group.entries() {
            out.push(entry.get(fields::TITLE).unwrap_or_default().to_string());
        }
        for sub in group.groups() {
            walk(&sub, out);
        }
    }
    let mut out = Vec::new();
    walk(&vault.database().root(), &mut out);
    out
}

/// The current title of the entry with `uuid`, or `None` if absent
/// (recursive walk; UUID-keyed so it survives a merge).
#[must_use]
pub fn current_title(vault: &Vault, uuid: Uuid) -> Option<String> {
    fn walk(group: &falach_core::GroupRef<'_>, uuid: Uuid) -> Option<String> {
        for entry in group.entries() {
            if entry.id().uuid() == uuid {
                return Some(entry.get(fields::TITLE).unwrap_or_default().to_string());
            }
        }
        for sub in group.groups() {
            if let Some(found) = walk(&sub, uuid) {
                return Some(found);
            }
        }
        None
    }
    walk(&vault.database().root(), uuid)
}

/// The titles recorded in the *history* of the entry with `uuid` — the loser
/// of a collision merge must appear here (FR-043 "no data loss").
#[must_use]
pub fn entry_history_titles(vault: &Vault, uuid: Uuid) -> Vec<String> {
    fn walk(group: &falach_core::GroupRef<'_>, uuid: Uuid) -> Option<Vec<String>> {
        for entry in group.entries() {
            if entry.id().uuid() == uuid {
                let values = entry
                    .history
                    .as_ref()
                    .map(|h| {
                        h.get_entries()
                            .iter()
                            .map(|he| he.get(fields::TITLE).unwrap_or_default().to_string())
                            .collect()
                    })
                    .unwrap_or_default();
                return Some(values);
            }
        }
        for sub in group.groups() {
            if let Some(found) = walk(&sub, uuid) {
                return Some(found);
            }
        }
        None
    }
    walk(&vault.database().root(), uuid).unwrap_or_default()
}
