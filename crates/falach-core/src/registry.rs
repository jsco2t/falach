//! Vault registry — load and save `vaults.toml`.
//!
//! Per design §2.2.8 and §2.3.1, the registry tracks the user's named
//! KDBX vaults. The on-disk schema is TOML at
//! `$HOME/.local/state/falach/vaults.toml`:
//!
//! ```toml
//! version = 1
//!
//! [[vault]]
//! name = "personal"
//! path = "/Users/jason/.local/state/falach/personal.kdbx"
//! created_at = "2026-05-16T22:00:00-06:00"
//! # keyfile_path = "..."     # optional
//! ```
//!
//! ## Forward compatibility
//!
//! Future features (sync, per-vault auto-lock) will add `[[vault.sync]]`
//! / `[vault.lock]` style sub-tables to each `[[vault]]` entry. The
//! registry preserves any unknown TOML keys verbatim via
//! `#[serde(flatten)] extra: toml::Table` at both the top level and the
//! per-vault level. This is the same forward-compat principle KDBX uses
//! internally — never drop data we don't understand.
//!
//! ## Durability
//!
//! [`VaultRegistry::save`] routes through [`crate::atomic::write_atomic`],
//! inheriting the same crash-durability guarantees as KDBX vault saves
//! (FR-054 / NFR-006). The file is created with POSIX mode `0600`.
//!
//! ## Concurrency
//!
//! Writes are serialized with a sibling advisory lock. Field-level updates use
//! [`VaultRegistry::update_registered_extra`] to reload under that lock before
//! applying the mutation, preventing stale snapshots from losing another
//! process's completed registry edit.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::atomic::write_atomic;
use crate::error::VaultError;
use crate::paths::FalachPaths;

/// The only schema version this build understands. Loading a registry
/// with a different `version` returns [`VaultError::RegistryMalformed`].
pub const SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single registered vault.
///
/// Fields beyond `name`, `path`, `created_at`, and `keyfile_path` are
/// captured in `extra` and round-tripped verbatim on save (forward-compat
/// for sync / auto-lock features that will add their own sub-tables).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredVault {
    /// Unique human-readable name for the vault.
    pub name: String,

    /// Absolute path to the `.kdbx` file on disk.
    pub path: PathBuf,

    /// RFC 3339 timestamp string recording when this vault was
    /// registered. Stored as `String` rather than a typed timestamp so
    /// the registry stays human-editable and round-trips unknown
    /// timezone offsets.
    pub created_at: String,

    /// Optional path to a keyfile required to open this vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyfile_path: Option<PathBuf>,

    /// Unknown TOML keys belonging to this vault entry, preserved
    /// verbatim across load/save. Future features (sync, auto-lock)
    /// write into and read out of this map.
    #[serde(default, flatten)]
    pub extra: toml::Table,
}

/// In-memory representation of `vaults.toml`.
///
/// Construct via [`Self::load`] (production) or [`Self::with_paths`]
/// (tests). Mutate via [`Self::register`]. Persist via [`Self::save`].
///
/// The registry intentionally does not enforce that the underlying
/// `.kdbx` files exist on disk — `Vault::open` is where missing-file
/// errors surface (design §2.2.8, decision #9).
#[derive(Debug)]
pub struct VaultRegistry {
    paths: FalachPaths,
    /// Schema version of this in-memory registry. Always
    /// [`SCHEMA_VERSION`] on save; this field exists so that load can
    /// verify the on-disk file's version.
    version: u32,
    vaults: Vec<RegisteredVault>,
    /// Unknown top-level TOML keys preserved verbatim across save.
    extra_top_level: toml::Table,
    /// Exact bytes read (or `None` for a missing registry), used for optimistic
    /// conflict detection under the write lock.
    baseline: Option<String>,
}

// ---------------------------------------------------------------------------
// Internal serde shape
//
// Kept private so the public API can evolve independently of the TOML
// surface. Note the `#[serde(rename = "vault")]` on the array — the
// TOML uses `[[vault]]` (singular), which is the conventional spelling
// for arrays of tables.
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct OnDisk {
    version: u32,

    #[serde(default, rename = "vault")]
    vaults: Vec<RegisteredVault>,

    #[serde(default, flatten)]
    extra: toml::Table,
}

// ---------------------------------------------------------------------------
// VaultRegistry — public API
// ---------------------------------------------------------------------------

impl VaultRegistry {
    /// Load the registry from `paths.vaults_toml()`.
    ///
    /// Returns an **empty** registry (no error) when the file does not
    /// yet exist — first-run UX requires that creating the very first
    /// vault works without a pre-existing `vaults.toml`.
    ///
    /// # Errors
    ///
    /// - [`VaultError::Io`] for filesystem failures other than
    ///   "file not found".
    /// - [`VaultError::RegistryMalformed`] when the file is not valid
    ///   TOML or its `version` is not [`SCHEMA_VERSION`].
    pub fn load(paths: FalachPaths) -> Result<Self, VaultError> {
        let file = paths.vaults_toml();
        let contents = match std::fs::read_to_string(&file) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::with_paths(paths));
            }
            Err(source) => {
                return Err(VaultError::Io { source, path: file });
            }
        };

        let on_disk: OnDisk =
            toml::from_str(&contents).map_err(|source| VaultError::RegistryMalformed {
                source: Some(source),
            })?;

        if on_disk.version != SCHEMA_VERSION {
            // A registry written by a newer version of Falach is
            // surfaced as malformed rather than parsed loosely. Refusing
            // to read a newer file protects users who downgrade from
            // having their richer registry silently truncated on
            // re-save.
            return Err(VaultError::RegistryMalformed { source: None });
        }

        Ok(Self {
            paths,
            version: on_disk.version,
            vaults: on_disk.vaults,
            extra_top_level: on_disk.extra,
            baseline: Some(contents),
        })
    }

    /// Construct an empty registry rooted at `paths`. Used internally
    /// by [`Self::load`] when `vaults.toml` is missing, and by tests.
    pub fn with_paths(paths: FalachPaths) -> Self {
        Self {
            paths,
            version: SCHEMA_VERSION,
            vaults: Vec::new(),
            extra_top_level: toml::Table::new(),
            baseline: None,
        }
    }

    /// Serialize the registry to `paths.vaults_toml()` via the atomic
    /// write helper. Creates the state directory if needed.
    ///
    /// # Errors
    ///
    /// - [`VaultError::Io`] for filesystem failures (parent-dir
    ///   creation, temp-file write, rename, parent-dir fsync).
    /// - [`VaultError::RegistrySerializationFailed`] if the in-memory
    ///   registry cannot be expressed as TOML. Nearly impossible in
    ///   practice — values that came from a valid load always
    ///   re-serialize, and the registry's own typed fields are
    ///   trivially serializable.
    /// - [`VaultError::Contended`] if another process currently holds the
    ///   registry write lock.
    /// - [`VaultError::RegistryChanged`] if the file changed since this
    ///   snapshot was loaded; reload, reapply the edit, and retry.
    pub fn save(&mut self) -> Result<(), VaultError> {
        self.paths.ensure_exists()?;
        let _guard = crate::locking::acquire_exclusive(&self.paths.vaults_toml())?;
        let current = match std::fs::read_to_string(self.paths.vaults_toml()) {
            Ok(contents) => Some(contents),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(source) => {
                return Err(VaultError::Io {
                    source,
                    path: self.paths.vaults_toml(),
                })
            }
        };
        if current != self.baseline {
            return Err(VaultError::RegistryChanged);
        }
        self.save_unlocked()
    }

    fn save_unlocked(&mut self) -> Result<(), VaultError> {
        let on_disk = OnDisk {
            version: SCHEMA_VERSION,
            vaults: self.vaults.clone(),
            extra: self.extra_top_level.clone(),
        };

        let body = toml::to_string(&on_disk)
            .map_err(|source| VaultError::RegistrySerializationFailed { source })?;

        write_atomic(&self.paths.vaults_toml(), body.as_bytes())?;
        self.baseline = Some(body);
        Ok(())
    }

    /// Transactionally update one registered vault. The latest registry is
    /// reloaded while holding the write lock, so unrelated concurrent changes
    /// survive. `self` is replaced only after the atomic save succeeds.
    pub fn update_registered_extra(
        &mut self,
        name: &str,
        update: impl FnOnce(&mut toml::Table),
    ) -> Result<(), VaultError> {
        self.paths.ensure_exists()?;
        let path = self.paths.vaults_toml();
        let _guard = crate::locking::acquire_exclusive(&path)?;
        let mut latest = Self::load(self.paths.clone())?;
        let vault = latest
            .vaults
            .iter_mut()
            .find(|vault| vault.name == name)
            .ok_or_else(|| VaultError::NotRegistered {
                name: name.to_string(),
            })?;
        update(&mut vault.extra);
        latest.save_unlocked()?;
        *self = latest;
        Ok(())
    }

    /// Add a vault to the registry.
    ///
    /// # Errors
    ///
    /// - [`VaultError::AlreadyRegistered`] if a vault with the same
    ///   name is already present.
    pub fn register(&mut self, vault: RegisteredVault) -> Result<(), VaultError> {
        if self.vaults.iter().any(|v| v.name == vault.name) {
            return Err(VaultError::AlreadyRegistered { name: vault.name });
        }
        self.vaults.push(vault);
        Ok(())
    }

    /// Remove a vault registration by name.
    ///
    /// When `delete_file` is `false`, only the registry entry is
    /// removed and the `.kdbx` file remains untouched. When
    /// `delete_file` is `true`, the registered file is unlinked before
    /// the in-memory entry is removed. A missing file is treated as
    /// already deleted; other I/O failures leave the registry unchanged.
    pub fn deregister(
        &mut self,
        name: &str,
        delete_file: bool,
    ) -> Result<RegisteredVault, VaultError> {
        let index = self
            .vaults
            .iter()
            .position(|vault| vault.name == name)
            .ok_or_else(|| VaultError::NotRegistered {
                name: name.to_string(),
            })?;

        if delete_file {
            let path = self.vaults[index].path.clone();
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => return Err(VaultError::Io { source, path }),
            }
        }

        Ok(self.vaults.remove(index))
    }

    /// Iterate over the registered vaults in insertion order.
    pub fn list(&self) -> impl Iterator<Item = &RegisteredVault> {
        self.vaults.iter()
    }

    /// Look up a vault by name.
    pub fn get(&self, name: &str) -> Option<&RegisteredVault> {
        self.vaults.iter().find(|v| v.name == name)
    }

    /// The [`FalachPaths`] this registry is rooted in.
    pub fn paths(&self) -> &FalachPaths {
        &self.paths
    }

    /// Return the schema version this registry was loaded with. Always
    /// [`SCHEMA_VERSION`] for in-memory and saved registries.
    pub fn version(&self) -> u32 {
        self.version
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    /// Build a `FalachPaths` rooted in `dir` with the state dir at `<dir>/state`.
    /// Matches the `TestEnv` shape used by integration tests but avoids the
    /// integration-test `common::mod` (this is an in-file unit test).
    fn paths_in(dir: &TempDir) -> FalachPaths {
        FalachPaths::with_state_dir(dir.path().join("state"))
    }

    /// Construct a representative [`RegisteredVault`].
    fn sample_vault(name: &str, dir: &Path) -> RegisteredVault {
        RegisteredVault {
            name: name.to_string(),
            path: dir.join(format!("{name}.kdbx")),
            created_at: "2026-05-17T10:00:00-06:00".to_string(),
            keyfile_path: None,
            extra: toml::Table::new(),
        }
    }

    // -------------------------------------------------------------------
    // Load / save / register / list / get
    // -------------------------------------------------------------------

    #[test]
    fn load_missing_file_returns_empty_registry() {
        let tmp = TempDir::new().expect("tempdir");
        let paths = paths_in(&tmp);
        let registry = VaultRegistry::load(paths).expect("load missing succeeds");
        assert_eq!(registry.list().count(), 0);
    }

    #[test]
    fn transactional_update_preserves_a_concurrent_registry_change() {
        let tmp = TempDir::new().expect("tempdir");
        let paths = paths_in(&tmp);
        let mut stale = VaultRegistry::with_paths(paths.clone());
        stale
            .register(sample_vault("personal", tmp.path()))
            .expect("register");
        stale.save().expect("initial save");

        let mut other = VaultRegistry::load(paths.clone()).expect("other load");
        other
            .register(sample_vault("work", tmp.path()))
            .expect("register work");
        other.save().expect("other save");

        stale
            .update_registered_extra("personal", |extra| {
                extra.insert(
                    "lock".to_string(),
                    toml::Value::String("changed".to_string()),
                );
            })
            .expect("transactional update");

        let reloaded = VaultRegistry::load(paths).expect("reload");
        assert!(
            reloaded.get("work").is_some(),
            "unrelated completed write survives"
        );
        assert_eq!(
            reloaded.get("personal").unwrap().extra["lock"].as_str(),
            Some("changed")
        );
    }

    #[test]
    fn stale_whole_registry_save_is_rejected_instead_of_losing_data() {
        let tmp = TempDir::new().expect("tempdir");
        let paths = paths_in(&tmp);
        let mut initial = VaultRegistry::with_paths(paths.clone());
        initial
            .register(sample_vault("personal", tmp.path()))
            .unwrap();
        initial.save().unwrap();

        let mut first = VaultRegistry::load(paths.clone()).unwrap();
        let mut stale = VaultRegistry::load(paths.clone()).unwrap();
        first.register(sample_vault("work", tmp.path())).unwrap();
        first.save().unwrap();
        stale.register(sample_vault("archive", tmp.path())).unwrap();

        assert!(matches!(stale.save(), Err(VaultError::RegistryChanged)));
        let reloaded = VaultRegistry::load(paths).unwrap();
        assert!(reloaded.get("work").is_some());
        assert!(reloaded.get("archive").is_none());
    }

    #[test]
    fn contended_registry_save_is_non_destructive() {
        let tmp = TempDir::new().expect("tempdir");
        let paths = paths_in(&tmp);
        let mut registry = VaultRegistry::with_paths(paths.clone());
        registry
            .register(sample_vault("personal", tmp.path()))
            .unwrap();
        registry.save().unwrap();
        let path = paths.vaults_toml();
        let before = std::fs::read(&path).unwrap();
        let _guard = crate::locking::acquire_exclusive(&path).unwrap();
        registry.register(sample_vault("work", tmp.path())).unwrap();
        assert!(matches!(registry.save(), Err(VaultError::Contended { .. })));
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    #[test]
    fn register_then_get_returns_record() {
        let tmp = TempDir::new().expect("tempdir");
        let mut registry = VaultRegistry::with_paths(paths_in(&tmp));

        let vault = sample_vault("personal", tmp.path());
        registry.register(vault.clone()).expect("register succeeds");

        let got = registry.get("personal").expect("get returns the vault");
        assert_eq!(got.name, "personal");
        assert_eq!(got.path, vault.path);
    }

    #[test]
    fn register_then_save_then_load_round_trips() {
        let tmp = TempDir::new().expect("tempdir");
        let paths = paths_in(&tmp);

        // Phase 1: write.
        {
            let mut registry = VaultRegistry::with_paths(paths.clone());
            registry
                .register(sample_vault("personal", tmp.path()))
                .expect("register");
            registry
                .register(sample_vault("work", tmp.path()))
                .expect("register");
            registry.save().expect("save succeeds");
        }

        // Phase 2: read in a fresh registry instance.
        let reloaded = VaultRegistry::load(paths).expect("reload succeeds");
        let names: Vec<&str> = reloaded.list().map(|v| v.name.as_str()).collect();
        assert_eq!(names, vec!["personal", "work"]);
        assert_eq!(reloaded.version(), SCHEMA_VERSION);
    }

    #[test]
    fn register_duplicate_name_returns_already_registered() {
        let tmp = TempDir::new().expect("tempdir");
        let mut registry = VaultRegistry::with_paths(paths_in(&tmp));

        registry
            .register(sample_vault("personal", tmp.path()))
            .expect("first register");
        let err = registry
            .register(sample_vault("personal", tmp.path()))
            .expect_err("duplicate register should fail");
        assert!(matches!(err, VaultError::AlreadyRegistered { ref name } if name == "personal"));
    }

    // -------------------------------------------------------------------
    // Forward-compat — unknown-key preservation. The two highest-value
    // tests in the module: a regression here would silently clobber the
    // sync / auto-lock features' future config when vault-core re-saves.
    // -------------------------------------------------------------------

    /// Hand-craft a fixture matching `tests/fixtures/v1_registry.toml`
    /// but inline so the test stays self-contained. The fixture includes:
    /// - a known top-level key (`version`)
    /// - an unknown top-level key (`[future_feature]`)
    /// - one `[[vault]]` entry with a known field set
    /// - an unknown per-vault key (`note = "x"`)
    /// - an unknown per-vault sub-table (`[[vault.sync]]` style)
    fn v1_fixture_toml() -> &'static str {
        r#"
version = 1

[future_feature]
foo = 1
bar = "two"

[[vault]]
name = "personal"
path = "/tmp/personal.kdbx"
created_at = "2026-05-17T10:00:00-06:00"
note = "unknown per-vault key — should survive"

[vault.sync]
remote = "git@example:vault.git"
branch = "main"
"#
    }

    #[test]
    fn unknown_top_level_keys_preserved_across_roundtrip() {
        let tmp = TempDir::new().expect("tempdir");
        let paths = paths_in(&tmp);
        paths.ensure_exists().expect("ensure state dir");
        std::fs::write(paths.vaults_toml(), v1_fixture_toml()).expect("seed fixture");

        // Load, then save unchanged.
        let mut registry = VaultRegistry::load(paths.clone()).expect("load fixture");
        registry.save().expect("save unchanged");

        // Re-read the raw file and verify the unknown top-level table
        // is intact.
        let raw = std::fs::read_to_string(paths.vaults_toml()).expect("read saved");
        let table: toml::Table = toml::from_str(&raw).expect("parse saved");
        let future = table
            .get("future_feature")
            .and_then(toml::Value::as_table)
            .expect("future_feature top-level table preserved");
        assert_eq!(
            future.get("foo").and_then(toml::Value::as_integer),
            Some(1),
            "foo value preserved"
        );
        assert_eq!(
            future.get("bar").and_then(toml::Value::as_str),
            Some("two"),
            "bar value preserved"
        );
    }

    #[test]
    fn unknown_per_vault_keys_preserved_across_roundtrip() {
        let tmp = TempDir::new().expect("tempdir");
        let paths = paths_in(&tmp);
        paths.ensure_exists().expect("ensure state dir");
        std::fs::write(paths.vaults_toml(), v1_fixture_toml()).expect("seed fixture");

        let mut registry = VaultRegistry::load(paths.clone()).expect("load fixture");
        registry.save().expect("save unchanged");

        // Re-read the raw file and inspect the [[vault]] entry.
        let raw = std::fs::read_to_string(paths.vaults_toml()).expect("read saved");
        let table: toml::Table = toml::from_str(&raw).expect("parse saved");
        let vaults = table
            .get("vault")
            .and_then(toml::Value::as_array)
            .expect("[[vault]] array present");
        assert_eq!(vaults.len(), 1, "exactly one vault");
        let vault = vaults[0].as_table().expect("vault entry is a table");

        // Known field still there.
        assert_eq!(
            vault.get("name").and_then(toml::Value::as_str),
            Some("personal")
        );

        // Unknown scalar field preserved.
        assert_eq!(
            vault.get("note").and_then(toml::Value::as_str),
            Some("unknown per-vault key — should survive"),
            "unknown per-vault scalar key preserved"
        );

        // Unknown sub-table preserved.
        let sync = vault
            .get("sync")
            .and_then(toml::Value::as_table)
            .expect("sync sub-table preserved");
        assert_eq!(
            sync.get("remote").and_then(toml::Value::as_str),
            Some("git@example:vault.git"),
            "sync.remote preserved"
        );
        assert_eq!(
            sync.get("branch").and_then(toml::Value::as_str),
            Some("main"),
            "sync.branch preserved"
        );
    }

    // -------------------------------------------------------------------
    // Error paths
    // -------------------------------------------------------------------

    #[test]
    fn load_with_unsupported_version_errors() {
        let tmp = TempDir::new().expect("tempdir");
        let paths = paths_in(&tmp);
        paths.ensure_exists().expect("ensure state dir");
        let fixture = r#"
version = 99

[[vault]]
name = "future"
path = "/tmp/future.kdbx"
created_at = "2026-05-17T10:00:00-06:00"
"#;
        std::fs::write(paths.vaults_toml(), fixture).expect("seed v99 fixture");

        let err = VaultRegistry::load(paths).expect_err("v99 should error");
        assert!(
            matches!(err, VaultError::RegistryMalformed { source: None }),
            "expected RegistryMalformed with no toml source for version mismatch, got {err:?}"
        );
    }

    #[test]
    fn load_malformed_toml_errors() {
        let tmp = TempDir::new().expect("tempdir");
        let paths = paths_in(&tmp);
        paths.ensure_exists().expect("ensure state dir");
        // Unclosed string literal — guaranteed parser failure.
        std::fs::write(paths.vaults_toml(), "version = \"unterminated").expect("seed malformed");

        let err = VaultRegistry::load(paths).expect_err("malformed toml should error");
        assert!(
            matches!(err, VaultError::RegistryMalformed { source: Some(_) }),
            "expected RegistryMalformed with toml::de::Error source, got {err:?}"
        );
    }

    // -------------------------------------------------------------------
    // Permissions
    // -------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn save_creates_file_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().expect("tempdir");
        let paths = paths_in(&tmp);
        let mut registry = VaultRegistry::with_paths(paths.clone());
        registry
            .register(sample_vault("personal", tmp.path()))
            .expect("register");
        registry.save().expect("save");

        let mode = std::fs::metadata(paths.vaults_toml())
            .expect("stat vaults.toml")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "vaults.toml must be created with mode 0600");
    }

    // -------------------------------------------------------------------
    // Fixture-file tests — confirms hand-crafted fixtures parse correctly.
    // Mirror of v1_fixture_toml above but loaded from disk; protects
    // against accidental fixture-file mutations.
    // -------------------------------------------------------------------

    #[test]
    fn fixture_v1_registry_toml_loads_and_preserves_extras() {
        let tmp = TempDir::new().expect("tempdir");
        let paths = paths_in(&tmp);
        paths.ensure_exists().expect("ensure state dir");

        let fixture_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1_registry.toml");
        let body = std::fs::read_to_string(&fixture_path)
            .unwrap_or_else(|e| panic!("read fixture {}: {e}", fixture_path.display()));
        std::fs::write(paths.vaults_toml(), body).expect("seed fixture");

        let mut registry = VaultRegistry::load(paths.clone()).expect("load fixture");
        assert!(
            registry.get("personal").is_some(),
            "fixture should contain the 'personal' vault"
        );
        // Save + reload: the fixture's unknown keys should survive.
        registry.save().expect("save fixture");
        let reloaded = VaultRegistry::load(paths.clone()).expect("reload fixture");
        assert!(reloaded.get("personal").is_some());

        let raw = std::fs::read_to_string(paths.vaults_toml()).expect("read saved fixture");
        let table: toml::Table = toml::from_str(&raw).expect("parse saved fixture");

        let future = table
            .get("future_feature")
            .and_then(toml::Value::as_table)
            .expect("future_feature top-level table preserved");
        assert_eq!(future.get("foo").and_then(toml::Value::as_integer), Some(1));
        assert_eq!(future.get("bar").and_then(toml::Value::as_str), Some("two"));

        let vaults = table
            .get("vault")
            .and_then(toml::Value::as_array)
            .expect("[[vault]] array preserved");
        let vault = vaults
            .first()
            .and_then(toml::Value::as_table)
            .expect("first vault table preserved");
        assert_eq!(
            vault.get("note").and_then(toml::Value::as_str),
            Some("an unknown per-vault key — should survive load/save")
        );
        let sync = vault
            .get("sync")
            .and_then(toml::Value::as_table)
            .expect("vault.sync table preserved");
        assert_eq!(
            sync.get("remote").and_then(toml::Value::as_str),
            Some("git@example:vault.git")
        );
        assert_eq!(
            sync.get("branch").and_then(toml::Value::as_str),
            Some("main")
        );
    }

    #[test]
    fn fixture_v99_registry_toml_is_rejected() {
        let tmp = TempDir::new().expect("tempdir");
        let paths = paths_in(&tmp);
        paths.ensure_exists().expect("ensure state dir");

        let fixture_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v99_registry.toml");
        let body = std::fs::read_to_string(&fixture_path).expect("read v99 fixture");
        std::fs::write(paths.vaults_toml(), body).expect("seed v99 fixture");

        let err = VaultRegistry::load(paths).expect_err("v99 fixture should error");
        assert!(matches!(
            err,
            VaultError::RegistryMalformed { source: None }
        ));
    }

    #[test]
    fn fixture_malformed_toml_is_rejected() {
        let tmp = TempDir::new().expect("tempdir");
        let paths = paths_in(&tmp);
        paths.ensure_exists().expect("ensure state dir");

        let fixture_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/malformed.toml");
        let body = std::fs::read_to_string(&fixture_path).expect("read malformed fixture");
        std::fs::write(paths.vaults_toml(), body).expect("seed malformed fixture");

        let err = VaultRegistry::load(paths).expect_err("malformed fixture should error");
        assert!(matches!(
            err,
            VaultError::RegistryMalformed { source: Some(_) }
        ));
    }
}
