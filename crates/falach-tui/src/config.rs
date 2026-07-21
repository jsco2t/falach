//! `TuiConfig` — the TUI's own **machine state** persistence in `tui.toml`
//! (T4.1 / ADR-T3).
//!
//! The TUI owns `$HOME/.local/state/falach/tui.toml` (resolved via
//! [`FalachPaths`]): a per-vault `[vaults.<name>]` table holding that vault's
//! **pinned entry UUIDs** and **recents list**. It is written through
//! vault-core's atomic-write helper (temp + rename; never truncate the live
//! file).
//!
//! **State only** (TUI enhancements config/state split, design §2.2.5): user
//! *preferences* (default sort, sync toggles, keymap, theme, …) moved to
//! `config.toml` ([`crate::user_config`]) — `tui.toml` no longer carries them.
//! Stray legacy pref keys in an existing `tui.toml` are inert (they round-trip
//! through the lenient `extra` mechanism; A-5: no migration).
//!
//! **Non-secret only** (CLAUDE.md): no passwords, no S3 keys, no master
//! password — only entry UUIDs (which are not secret). Sync secrets live in
//! `vaults.toml` via `configure_remote`; vault contents only in the KDBX itself.
//!
//! **Lenient by design** (U.5 / R-14): unlike the vault registry, a missing,
//! unparsable, or newer-version `tui.toml` is never fatal. Load always yields a
//! usable config — falling back to defaults and returning a human warning the
//! caller surfaces in the status bar — because losing pins/recents is merely
//! cosmetic. Unknown keys (top-level and per-vault) round-trip via a flattened
//! `extra` table so a config written by a newer Falach is preserved, not
//! truncated, on re-save.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use falach_core::atomic::write_atomic;
use falach_core::FalachPaths;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::TuiError;

/// Current `tui.toml` schema version. Persisted for future migrations; **not**
/// gated on load (a mismatch is lenient — see the module docs), unlike the
/// registry's strict `SCHEMA_VERSION` check.
const CONFIG_VERSION: u64 = 1;

/// The TUI config file name within the state directory.
const CONFIG_FILE: &str = "tui.toml";

/// Resolve `<state_dir>/tui.toml` from the shared [`FalachPaths`].
pub(crate) fn config_path(paths: &FalachPaths) -> PathBuf {
    paths.state_dir().join(CONFIG_FILE)
}

/// In-memory TUI configuration (the persisted mirror of `tui.toml`).
#[derive(Debug, Clone, Default)]
pub(crate) struct TuiConfig {
    vaults: BTreeMap<String, VaultUiState>,
    /// Unknown top-level keys, preserved across saves (forward-compat). Legacy
    /// pref keys (`[global]`, `default-sort`, …) that moved to `config.toml`
    /// land here inertly (A-5: no migration).
    extra: toml::Table,
}

/// Per-vault UI state: pinned-tab UUIDs and the recents (MRU) list.
#[derive(Debug, Clone, Default)]
pub(crate) struct VaultUiState {
    pub(crate) pinned: Vec<Uuid>,
    pub(crate) recents: Vec<Uuid>,
    extra: toml::Table,
}

impl TuiConfig {
    /// The persisted UI state for `vault`, or `None` if this vault has no
    /// `[vaults.<name>]` table yet.
    pub(crate) fn vault_state(&self, vault: &str) -> Option<&VaultUiState> {
        self.vaults.get(vault)
    }

    /// Replace `vault`'s pinned + recents lists (the in-memory mirror), creating
    /// the per-vault table if absent and preserving any unknown keys already in
    /// it. Call before [`Self::save`].
    pub(crate) fn set_vault_state(&mut self, vault: &str, pinned: Vec<Uuid>, recents: Vec<Uuid>) {
        let entry = self.vaults.entry(vault.to_string()).or_default();
        entry.pinned = pinned;
        entry.recents = recents;
    }

    /// Load from `path`. **Never fails**: a missing file yields defaults
    /// silently; an unreadable or unparsable file yields defaults plus a
    /// human-readable warning (no file contents — only prefs + UUIDs live here)
    /// for the caller to surface in the status bar.
    pub(crate) fn load(path: &Path) -> (Self, Option<String>) {
        let contents = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return (Self::default(), None),
            Err(_) => {
                return (
                    Self::default(),
                    Some("Could not read tui.toml; using defaults.".to_string()),
                );
            }
        };

        match toml::from_str::<OnDisk>(&contents) {
            Ok(on_disk) => (on_disk.into(), None),
            Err(_) => (
                Self::default(),
                Some("Could not parse tui.toml; using defaults.".to_string()),
            ),
        }
    }

    /// Serialize to `path` via the atomic-write helper, creating the state
    /// directory if needed. Failures are returned for the caller to surface
    /// non-fatally (the UI keeps running on in-memory state; U.5).
    ///
    /// # Errors
    /// [`TuiError::ConfigParse`] if the in-memory config cannot be expressed as
    /// TOML (near-impossible); [`TuiError::ConfigIo`] for filesystem failures.
    pub(crate) fn save(&self, paths: &FalachPaths, path: &Path) -> Result<(), TuiError> {
        paths
            .ensure_exists()
            .map_err(|e| TuiError::ConfigIo(io::Error::other(e)))?;
        let on_disk = OnDisk::from(self);
        let body = toml::to_string(&on_disk).map_err(|e| TuiError::ConfigParse(e.to_string()))?;
        write_atomic(path, body.as_bytes()).map_err(|e| TuiError::ConfigIo(io::Error::other(e)))
    }
}

// ---------------------------------------------------------------------------
// On-disk (serde) representation. Kept separate from the in-memory type so the
// wire format is explicit and `#[serde(default)]` makes every field optional —
// a partial or older file loads cleanly, a newer file's unknown keys survive in
// `extra`.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct OnDisk {
    #[serde(default = "default_version")]
    version: u64,
    #[serde(default)]
    vaults: BTreeMap<String, OnDiskVault>,
    #[serde(flatten)]
    extra: toml::Table,
}

fn default_version() -> u64 {
    CONFIG_VERSION
}

#[derive(Serialize, Deserialize, Default)]
struct OnDiskVault {
    #[serde(default)]
    pinned: Vec<Uuid>,
    #[serde(default)]
    recents: Vec<Uuid>,
    #[serde(flatten)]
    extra: toml::Table,
}

impl From<OnDisk> for TuiConfig {
    fn from(d: OnDisk) -> Self {
        TuiConfig {
            vaults: d
                .vaults
                .into_iter()
                .map(|(name, v)| {
                    (
                        name,
                        VaultUiState {
                            pinned: v.pinned,
                            recents: v.recents,
                            extra: v.extra,
                        },
                    )
                })
                .collect(),
            extra: d.extra,
        }
    }
}

impl From<&TuiConfig> for OnDisk {
    fn from(c: &TuiConfig) -> Self {
        OnDisk {
            version: CONFIG_VERSION,
            vaults: c
                .vaults
                .iter()
                .map(|(name, v)| {
                    (
                        name.clone(),
                        OnDiskVault {
                            pinned: v.pinned.clone(),
                            recents: v.recents.clone(),
                            extra: v.extra.clone(),
                        },
                    )
                })
                .collect(),
            extra: c.extra.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuids(n: usize) -> Vec<Uuid> {
        (0..n).map(|_| Uuid::new_v4()).collect()
    }

    fn paths_in(dir: &Path) -> FalachPaths {
        FalachPaths::with_state_dir(dir.join("state"))
    }

    #[test]
    fn missing_file_loads_defaults_without_warning() {
        let dir = tempfile::tempdir().unwrap();
        let (config, warning) = TuiConfig::load(&config_path(&paths_in(dir.path())));
        assert!(warning.is_none(), "absent file is not a warning condition");
        assert!(config.vault_state("anything").is_none());
    }

    #[test]
    fn save_then_load_round_trips_pins_and_recents() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths_in(dir.path());
        let path = config_path(&paths);

        let pins = uuids(2);
        let recents = uuids(3);
        let mut config = TuiConfig::default();
        config.set_vault_state("personal", pins.clone(), recents.clone());
        config.save(&paths, &path).expect("save");

        let (loaded, warning) = TuiConfig::load(&path);
        assert!(warning.is_none());
        let state = loaded.vault_state("personal").expect("vault state present");
        assert_eq!(state.pinned, pins);
        assert_eq!(state.recents, recents);
    }

    #[test]
    fn save_failure_returns_configio_not_panic() {
        // Make the state dir uncreatable so `ensure_exists` (create_dir_all)
        // fails: its would-be parent is a regular file. The save must surface a
        // non-fatal `ConfigIo` error (U.5), never panic.
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let paths = FalachPaths::with_state_dir(blocker.join("state"));
        let path = config_path(&paths);

        let mut config = TuiConfig::default();
        config.set_vault_state("personal", uuids(1), Vec::new());
        let result = config.save(&paths, &path);
        assert!(
            matches!(result, Err(TuiError::ConfigIo(_))),
            "a save failure is a non-fatal ConfigIo error, got {result:?}"
        );
    }

    #[test]
    fn unparsable_file_falls_back_to_defaults_with_warning() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths_in(dir.path());
        let path = config_path(&paths);
        paths.ensure_exists().unwrap();
        std::fs::write(&path, b"this is = = not valid toml [[[").unwrap();

        let (config, warning) = TuiConfig::load(&path);
        assert!(warning.is_some(), "a parse failure must warn (R-14)");
        assert!(
            config.vault_state("anything").is_none(),
            "defaults despite the corrupt file"
        );
    }

    #[test]
    fn unknown_keys_survive_a_save_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths_in(dir.path());
        let path = config_path(&paths);
        paths.ensure_exists().unwrap();
        // A config written by a hypothetical newer Falach: unknown top-level
        // and per-vault keys we must not drop on re-save (forward-compat).
        std::fs::write(
            &path,
            "version = 1\nfuture_top = \"keep\"\n\n[vaults.personal]\npinned = []\nrecents = []\nfuture_vault = 42\n",
        )
        .unwrap();

        let (config, _) = TuiConfig::load(&path);
        config.save(&paths, &path).expect("save");

        // Re-load and assert the unknown keys round-trip to the SAME place, not
        // merely that the bytes survive somewhere. A flattened `extra` emitted
        // after the `[vaults.*]` tables would silently re-parse a top-level key
        // *into* `vaults.personal`; this check discriminates that corruption.
        let (reloaded, _) = TuiConfig::load(&path);
        assert!(
            reloaded.extra.contains_key("future_top"),
            "unknown top-level key stays top-level: {:?}",
            reloaded.extra
        );
        let personal = reloaded
            .vaults
            .get("personal")
            .expect("personal vault table preserved");
        assert!(
            personal.extra.contains_key("future_vault"),
            "unknown per-vault key stays under its vault: {:?}",
            personal.extra
        );
        assert!(
            !reloaded.extra.contains_key("future_vault"),
            "per-vault key must not leak to top-level"
        );
        assert!(
            !personal.extra.contains_key("future_top"),
            "top-level key must not be relocated into the vault table"
        );
    }

    #[test]
    fn tui_toml_no_longer_carries_prefs() {
        // A-5 (no migration): preferences moved to config.toml. tui.toml must
        // NOT emit them on save, and loading a legacy tui.toml that still has
        // them must treat those keys as inert (round-tripped in `extra`) while
        // keeping pins/recents intact.
        let dir = tempfile::tempdir().unwrap();
        let paths = paths_in(dir.path());
        let path = config_path(&paths);

        // Save a fresh config: no pref keys should appear on disk.
        let mut config = TuiConfig::default();
        let pins = uuids(1);
        config.set_vault_state("personal", pins.clone(), Vec::new());
        config.save(&paths, &path).expect("save");
        let on_disk = std::fs::read_to_string(&path).unwrap();
        for pref in ["default-sort", "sync-on-unlock", "sync-on-lock-quit"] {
            assert!(
                !on_disk.contains(pref),
                "moved pref `{pref}` must not be written to tui.toml: {on_disk}"
            );
        }

        // Load a legacy tui.toml that still carries the moved prefs: they must
        // be inert (ignored, not influential) and pins/recents preserved.
        paths.ensure_exists().unwrap();
        std::fs::write(
            &path,
            "version = 1\n\n[global]\ndefault-sort = \"title\"\nsync-on-unlock = true\n\n[vaults.personal]\npinned = []\nrecents = []\n",
        )
        .unwrap();
        let (loaded, warning) = TuiConfig::load(&path);
        assert!(
            warning.is_none(),
            "legacy pref keys are inert, not a parse error: {warning:?}"
        );
        assert!(
            loaded.vault_state("personal").is_some(),
            "pins/recents table still loads alongside legacy pref keys"
        );
        // The legacy `[global]` table survives verbatim in `extra` (round-trip),
        // never re-interpreted as a live preference.
        assert!(
            loaded.extra.contains_key("global"),
            "legacy [global] table round-trips inertly in extra: {:?}",
            loaded.extra
        );
    }
}
