//! Per-vault `[vault.lock]` TOML schema.
//!
//! `falach-core::registry::RegisteredVault::extra` is a `toml::Table`
//! preserved verbatim across load/save cycles via `serde(flatten)`. We
//! use that forward-compat slot to store `[vault.lock]` overrides
//! without modifying `falach-core`:
//!
//! ```toml
//! [[vault]]
//! name = "personal"
//! path = "/home/user/personal.kdbx"
//!
//!   [vault.lock]                  # owned by falach-security
//!   idle_timeout_seconds = 300    # override the global default (600s)
//! ```
//!
//! [`VaultLockConfig::from_extra`] reads the `lock` sub-table off
//! `RegisteredVault::extra`. [`VaultLockConfig::to_auto_lock_config`]
//! converts it into an [`crate::auto_lock::AutoLockConfig`] suitable
//! for `AutoLockController::new`.
//!
//! The schema is intentionally minimal: only `idle_timeout_seconds`
//! today. Future fields are forward-compat by construction —
//! `#[serde(default)]` on the field means an old vault with only this
//! field still parses after we add new ones.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::auto_lock::AutoLockConfig;
use crate::error::SecurityError;

/// Sub-table name inside `RegisteredVault::extra` that this crate owns
/// (`[vault.lock]` in `vaults.toml`). Writers in other crates (the
/// CLI's `vault set-lock`) must go through [`VaultLockConfig`]'s
/// helpers so the on-disk schema has exactly one definition.
pub const LOCK_TABLE_KEY: &str = "lock";

/// Field name inside the lock sub-table. Must match the serde field
/// name on [`VaultLockConfig`] (asserted by test
/// `idle_timeout_key_matches_serde_field`).
pub const IDLE_TIMEOUT_KEY: &str = "idle_timeout_seconds";

/// Per-vault auto-lock override loaded from `vaults.toml`'s
/// `[vault.lock]` sub-table.
///
/// When present, this overrides the frontend's global
/// [`AutoLockConfig`]; when absent (the common case), the frontend
/// falls back to its default (600s, see
/// [`crate::auto_lock::DEFAULT_IDLE_TIMEOUT`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultLockConfig {
    /// Idle timeout in seconds. Defaults to 600 (10 min) when the
    /// field is missing — see `default_idle_timeout_seconds`.
    #[serde(default = "default_idle_timeout_seconds")]
    pub idle_timeout_seconds: u64,
}

/// Default returned by `serde(default)` when `idle_timeout_seconds`
/// is missing from a `[vault.lock]` sub-table. Matches
/// [`crate::auto_lock::DEFAULT_IDLE_TIMEOUT`] (600s).
fn default_idle_timeout_seconds() -> u64 {
    600
}

impl VaultLockConfig {
    /// Parse a [`VaultLockConfig`] out of a `toml::Table` (typically
    /// `RegisteredVault::extra`).
    ///
    /// - `Ok(None)` — the table has no `lock` key. The most common
    ///   case; the caller should fall back to its global default.
    /// - `Ok(Some(cfg))` — the table has a well-formed `lock`
    ///   sub-table.
    /// - `Err(SecurityError::InvalidVaultLockConfig)` — the `lock`
    ///   sub-table exists but contains malformed values (e.g.,
    ///   `idle_timeout_seconds = "not-a-number"`).
    ///
    /// # Errors
    ///
    /// Returns [`SecurityError::InvalidVaultLockConfig`] with a
    /// human-readable `detail` when the sub-table is present but
    /// can't be parsed. A user editing `vaults.toml` by hand gets a
    /// clear error rather than a silent fallback to the default.
    pub fn from_extra(extra: &toml::Table) -> Result<Option<Self>, SecurityError> {
        let Some(value) = extra.get(LOCK_TABLE_KEY) else {
            return Ok(None);
        };
        let cfg: VaultLockConfig = value.clone().try_into().map_err(|e: toml::de::Error| {
            SecurityError::InvalidVaultLockConfig {
                detail: e.to_string(),
            }
        })?;
        Ok(Some(cfg))
    }

    /// Read just the `idle_timeout_seconds` override, leniently: an
    /// absent `lock` sub-table, an absent key, or a malformed value all
    /// read as `None`. For display paths (e.g. `vault list`) that must
    /// not fail on hand-edited registries; unlock paths that want a
    /// hard error on malformed data use [`Self::from_extra`].
    #[must_use]
    pub fn idle_timeout_seconds_from_extra(extra: &toml::Table) -> Option<u64> {
        extra
            .get(LOCK_TABLE_KEY)
            .and_then(toml::Value::as_table)
            .and_then(|t| t.get(IDLE_TIMEOUT_KEY))
            .and_then(toml::Value::as_integer)
            .and_then(|v| u64::try_from(v).ok())
    }

    /// Set (`Some`) or remove (`None`) the `idle_timeout_seconds` key in
    /// `extra`'s `[lock]` sub-table, creating the sub-table on demand and
    /// dropping it again when it empties so the registry stays clean. A
    /// non-table value under the `lock` key is replaced with a fresh
    /// table (forward-compat tolerance — better than panicking).
    ///
    /// Values above `i64::MAX` are clamped: TOML integers are `i64`, and
    /// ~9e18 seconds is not a real-world idle timeout.
    pub fn apply_idle_timeout(extra: &mut toml::Table, timeout: Option<u64>) {
        let lock = extra
            .entry(LOCK_TABLE_KEY.to_string())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        if !lock.is_table() {
            *lock = toml::Value::Table(toml::Table::new());
        }
        if let toml::Value::Table(lock) = lock {
            match timeout {
                Some(s) => {
                    let as_i64 = i64::try_from(s).unwrap_or(i64::MAX);
                    lock.insert(IDLE_TIMEOUT_KEY.to_string(), toml::Value::Integer(as_i64));
                }
                None => {
                    lock.remove(IDLE_TIMEOUT_KEY);
                }
            }
        }

        // Tidy up: if the lock table is now empty, drop it from `extra`.
        if extra
            .get(LOCK_TABLE_KEY)
            .and_then(toml::Value::as_table)
            .is_some_and(toml::Table::is_empty)
        {
            extra.remove(LOCK_TABLE_KEY);
        }
    }

    /// Convert this per-vault override into an [`AutoLockConfig`]
    /// suitable for [`crate::auto_lock::AutoLockController::new`].
    ///
    /// # Errors
    ///
    /// Returns [`SecurityError::InvalidAutoLockConfig`] when
    /// `idle_timeout_seconds == 0` — a zero timeout would lock the
    /// vault on the very next `tick` after construction. The
    /// validation duplicates `AutoLockConfig::validate`'s check at
    /// the *parse* layer so the error surfaces at vault-load time
    /// rather than at controller-construction time.
    pub fn to_auto_lock_config(self) -> Result<AutoLockConfig, SecurityError> {
        let cfg = AutoLockConfig {
            idle_timeout: Duration::from_secs(self.idle_timeout_seconds),
        };
        cfg.validate()?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: parse a TOML string into a `toml::Table` for the tests
    /// below.
    fn table(toml_str: &str) -> toml::Table {
        toml_str.parse().expect("test TOML fixture should parse")
    }

    #[test]
    fn from_extra_returns_none_when_no_lock_key() {
        // The common case: a vault registered without per-vault
        // override. A regression to `Err` here would force every
        // legacy vault to be edited before it could be opened.
        let extra = toml::Table::new();
        let result = VaultLockConfig::from_extra(&extra).expect("no `lock` key should be Ok(None)");
        assert!(result.is_none(), "absent `lock` key must yield Ok(None)");
    }

    #[test]
    fn from_extra_returns_config_when_valid() {
        let extra = table("lock = { idle_timeout_seconds = 300 }");
        let result = VaultLockConfig::from_extra(&extra)
            .expect("valid lock sub-table should parse")
            .expect("present sub-table should yield Some");
        assert_eq!(result.idle_timeout_seconds, 300);
    }

    #[test]
    fn from_extra_returns_error_when_malformed() {
        // A hand-edited `vaults.toml` with a typo should surface a
        // clear error, not silently fall through to the default.
        let extra = table(r#"lock = { idle_timeout_seconds = "not-a-number" }"#);
        match VaultLockConfig::from_extra(&extra) {
            Err(SecurityError::InvalidVaultLockConfig { detail }) => {
                assert!(
                    !detail.is_empty(),
                    "InvalidVaultLockConfig detail should be non-empty",
                );
            }
            Err(other) => panic!("expected InvalidVaultLockConfig, got {other:?}"),
            Ok(other) => panic!("expected Err, got Ok({other:?})"),
        }
    }

    #[test]
    fn from_extra_uses_default_for_missing_field() {
        // `lock = {}` parses to a `VaultLockConfig` whose
        // `idle_timeout_seconds` comes from the serde default. This
        // is the forward-compat seam: a future field addition won't
        // break vaults that only set the original field.
        let extra = table("lock = {}");
        let cfg = VaultLockConfig::from_extra(&extra)
            .expect("empty lock sub-table should parse")
            .expect("present sub-table should yield Some");
        assert_eq!(cfg.idle_timeout_seconds, 600);
    }

    #[test]
    fn to_auto_lock_config_returns_valid_config() {
        let cfg = VaultLockConfig {
            idle_timeout_seconds: 300,
        }
        .to_auto_lock_config()
        .expect("300s is a valid timeout");
        assert_eq!(cfg.idle_timeout, Duration::from_secs(300));
    }

    #[test]
    fn to_auto_lock_config_rejects_zero_timeout() {
        // Zero would lock the vault on the next tick. Validation must
        // fire at the parse layer so the user sees the error when
        // loading `vaults.toml`, not when constructing the controller.
        let result = VaultLockConfig {
            idle_timeout_seconds: 0,
        }
        .to_auto_lock_config();
        match result {
            Err(SecurityError::InvalidAutoLockConfig { detail }) => {
                assert!(
                    !detail.is_empty(),
                    "InvalidAutoLockConfig detail should be non-empty",
                );
            }
            Err(other) => panic!("expected InvalidAutoLockConfig, got {other:?}"),
            Ok(other) => panic!("expected Err, got Ok({other:?})"),
        }
    }

    #[test]
    fn idle_timeout_key_matches_serde_field() {
        // The exported `IDLE_TIMEOUT_KEY` constant and the serde field
        // name must agree — a `#[serde(rename)]` that forgets the
        // constant would silently split the write path (constant-based)
        // from the read path (serde-based).
        let cfg = VaultLockConfig {
            idle_timeout_seconds: 42,
        };
        let serialised = toml::to_string(&cfg).expect("serialise should succeed");
        assert!(
            serialised.contains(IDLE_TIMEOUT_KEY),
            "serde output {serialised:?} must use IDLE_TIMEOUT_KEY"
        );
    }

    #[test]
    fn apply_idle_timeout_sets_and_reads_back() {
        let mut extra = toml::Table::new();
        VaultLockConfig::apply_idle_timeout(&mut extra, Some(300));
        assert_eq!(
            VaultLockConfig::idle_timeout_seconds_from_extra(&extra),
            Some(300)
        );
        // And the strict reader sees the same value.
        let cfg = VaultLockConfig::from_extra(&extra)
            .expect("valid table")
            .expect("lock table present");
        assert_eq!(cfg.idle_timeout_seconds, 300);
    }

    #[test]
    fn apply_idle_timeout_clear_drops_empty_table() {
        let mut extra = toml::Table::new();
        VaultLockConfig::apply_idle_timeout(&mut extra, Some(300));
        VaultLockConfig::apply_idle_timeout(&mut extra, None);
        assert!(
            !extra.contains_key(LOCK_TABLE_KEY),
            "an emptied lock sub-table must be removed from extra"
        );
    }

    #[test]
    fn apply_idle_timeout_replaces_non_table_lock_value() {
        let mut extra = table(r#"lock = "corrupted""#);
        VaultLockConfig::apply_idle_timeout(&mut extra, Some(120));
        assert_eq!(
            VaultLockConfig::idle_timeout_seconds_from_extra(&extra),
            Some(120)
        );
    }

    #[test]
    fn lenient_reader_returns_none_on_malformed_value() {
        let extra = table(r#"lock = { idle_timeout_seconds = "not-a-number" }"#);
        assert_eq!(
            VaultLockConfig::idle_timeout_seconds_from_extra(&extra),
            None
        );
    }

    #[test]
    fn serde_round_trip_via_toml_string() {
        // A vault hand-edited by the user must round-trip through
        // load/save unchanged. A future `#[serde(rename)]` on the
        // field would break compat with existing vaults; this test
        // catches it.
        let original = VaultLockConfig {
            idle_timeout_seconds: 300,
        };
        let serialised = toml::to_string(&original).expect("serialise should succeed");
        let parsed: VaultLockConfig =
            toml::from_str(&serialised).expect("deserialise should succeed");
        assert_eq!(parsed, original);
    }
}
