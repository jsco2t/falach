//! Vault subcommand view structs — the JSON-schema contract for
//! `falach vault {create, open, list, set-lock}`.
//!
//! ## Schema stability
//!
//! Each `#[derive(serde::Serialize)]` struct here is the public JSON
//! contract for one subcommand. Field renames or type changes are
//! breaking; new optional fields are additive (use
//! `#[serde(skip_serializing_if = "Option::is_none")]`).
//!
//! ## Lifetimes
//!
//! Views borrow from already-loaded registry / vault data — they're
//! cheap to construct, zero-allocate at the view boundary, and the
//! borrow checker prevents the underlying state from changing
//! mid-write. The CLI dispatchers in `commands/vault.rs` are the only
//! callers.
//!
//! ## Note on `created_at`
//!
//! The design (§2.2.4) calls for `chrono::DateTime<chrono::Utc>`. The
//! registry stores `created_at` as a `String` to preserve arbitrary
//! timezone offsets (see `falach_core::registry`); a typed conversion
//! would lose that information. We pass through the registry's
//! `String` value verbatim instead — honest, lossless, no parse-failure
//! mode.

use std::path::Path;

use serde::Serialize;

use crate::format::HumanFormat;

// ---------------------------------------------------------------------------
// vault list
// ---------------------------------------------------------------------------

/// JSON envelope for `falach vault list`.
#[derive(Serialize, Debug)]
pub struct VaultListView<'a> {
    /// Vaults registered in the loaded registry, in insertion order
    /// (which is also the order `VaultRegistry::list()` returns).
    pub vaults: Vec<VaultListEntry<'a>>,
}

/// One row of [`VaultListView::vaults`].
#[derive(Serialize, Debug)]
pub struct VaultListEntry<'a> {
    /// Registry name for the vault (unique within the registry).
    pub id: &'a str,
    /// Absolute path to the `.kdbx` file.
    pub path: &'a Path,
    /// Optional keyfile path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyfile: Option<&'a Path>,
    /// RFC 3339 timestamp string the registry stored at create time.
    pub created_at: &'a str,
    /// Idle-timeout (seconds) before auto-lock fires. Omitted from JSON
    /// when unset (registry's `[vault.lock]` sub-table is absent or has
    /// no `idle_timeout_seconds` key).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_timeout_seconds: Option<u64>,
}

impl HumanFormat for VaultListView<'_> {
    fn write_human(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        if self.vaults.is_empty() {
            return writeln!(out, "no vaults registered");
        }
        // Sorted-by-id is the human-output stability choice (see
        // task-doc §technical-notes). JSON output uses insertion order.
        let mut entries: Vec<&VaultListEntry<'_>> = self.vaults.iter().collect();
        entries.sort_by_key(|e| e.id);

        // Compute column widths so id / path align even with long
        // entries. Cap at sensible upper bounds so a 1000-char path
        // doesn't blow out the layout.
        let id_w = entries
            .iter()
            .map(|e| e.id.len())
            .max()
            .unwrap_or(2)
            .min(40);
        let path_w = entries
            .iter()
            .map(|e| e.path.display().to_string().len())
            .max()
            .unwrap_or(4)
            .min(60);

        writeln!(
            out,
            "{:<id_w$}  {:<path_w$}  IDLE-TIMEOUT",
            "ID",
            "PATH",
            id_w = id_w,
            path_w = path_w,
        )?;
        for e in entries {
            let timeout = e
                .idle_timeout_seconds
                .map_or_else(|| "default".to_string(), |s| format!("{s}s"));
            writeln!(
                out,
                "{:<id_w$}  {:<path_w$}  {timeout}",
                e.id,
                e.path.display(),
                id_w = id_w,
                path_w = path_w,
            )?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// vault create
// ---------------------------------------------------------------------------

/// JSON output for `falach vault create`.
#[derive(Serialize, Debug)]
pub struct VaultCreateView<'a> {
    /// Registry name assigned to the new vault.
    pub id: &'a str,
    /// On-disk path of the created `.kdbx` file.
    pub path: &'a Path,
    /// Keyfile path used (when supplied).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyfile: Option<&'a Path>,
    /// KDF parameters the vault was created with.
    pub kdf: VaultCreateKdfView,
}

/// KDF parameters the new vault uses. Argon2id only in Phase 0.
#[derive(Serialize, Debug)]
pub struct VaultCreateKdfView {
    /// Always `"argon2id"` in Phase 0.
    pub algorithm: &'static str,
    /// Memory cost (KiB).
    pub memory_kib: u64,
    /// Iteration count.
    pub iterations: u64,
    /// Parallel lane count.
    pub parallelism: u32,
}

impl HumanFormat for VaultCreateView<'_> {
    fn write_human(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(
            out,
            "created vault '{}' at {}",
            self.id,
            self.path.display()
        )?;
        if let Some(kf) = self.keyfile {
            writeln!(out, "  keyfile: {}", kf.display())?;
        }
        writeln!(
            out,
            "  kdf: {} (memory={} KiB, iterations={}, parallelism={})",
            self.kdf.algorithm, self.kdf.memory_kib, self.kdf.iterations, self.kdf.parallelism,
        )
    }
}

// ---------------------------------------------------------------------------
// vault open
// ---------------------------------------------------------------------------

/// JSON output for `falach vault open`.
#[derive(Serialize, Debug)]
pub struct VaultOpenView<'a> {
    /// Registry name of the vault.
    pub id: &'a str,
    /// `"unlocked-ok"` in MVP. When the agent ships post-MVP, may
    /// become `"agent-cached"` for vaults the agent now holds.
    pub status: &'static str,
}

impl HumanFormat for VaultOpenView<'_> {
    fn write_human(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(out, "vault '{}' unlocked ({})", self.id, self.status)
    }
}

// ---------------------------------------------------------------------------
// vault set-lock
// ---------------------------------------------------------------------------

/// JSON output for `falach vault set-lock`.
#[derive(Serialize, Debug)]
pub struct VaultSetLockView<'a> {
    /// Registry name of the vault.
    pub id: &'a str,
    /// New idle-timeout (seconds). `None` means the override was
    /// cleared and the default applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_timeout_seconds: Option<u64>,
}

impl HumanFormat for VaultSetLockView<'_> {
    fn write_human(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        match self.idle_timeout_seconds {
            Some(s) => writeln!(out, "vault '{}' idle-timeout set to {}s", self.id, s),
            None => writeln!(out, "vault '{}' idle-timeout override cleared", self.id),
        }
    }
}

// ---------------------------------------------------------------------------
// vault set-sync
// ---------------------------------------------------------------------------

/// JSON output for `falach vault set-sync`.
///
/// **Secret-free by construction.** The struct carries only the S3
/// *target* coordinates plus a structural `credentials_source` kind tag
/// (`"prompt"` / `"iam-role"` / `"aws-profile"` / `"env-vars"`). It never
/// carries the sealed secret, the access-key-id, a profile name, or an
/// env prefix — so `--format json` output can never leak credential
/// material (guarded by `set_sync_json_schema_omits_secret`).
#[derive(Serialize, Debug)]
pub struct VaultSetSyncView<'a> {
    /// Registry name of the configured vault.
    pub id: &'a str,
    /// S3 bucket the vault syncs to.
    pub bucket: &'a str,
    /// S3 object key (the `.kdbx` on the remote).
    pub key: &'a str,
    /// Custom endpoint URL, when one was supplied. Omitted (not `null`)
    /// when the vault uses the default AWS regional endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<&'a str>,
    /// Structural kind tag for the resolved credential source — never
    /// the secret, access-key-id, profile name, or env prefix.
    pub credentials_source: &'static str,
}

impl HumanFormat for VaultSetSyncView<'_> {
    fn write_human(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        write!(
            out,
            "configured sync for vault '{}' → bucket '{}' key '{}'",
            self.id, self.bucket, self.key
        )?;
        if let Some(endpoint) = self.endpoint {
            write!(out, " endpoint '{endpoint}'")?;
        }
        writeln!(out, " (credentials: {})", self.credentials_source)
    }
}

// ---------------------------------------------------------------------------
// Tests — JSON-schema regression gate for each view.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::path::PathBuf;

    /// Serialize `view` and parse the result back to a `serde_json::Value`.
    /// Comparing `Value`s ignores field-ordering noise; the *shape* of
    /// the JSON is what the contract guarantees, not the byte sequence.
    fn json_of<V: serde::Serialize>(view: &V) -> Value {
        let s = serde_json::to_string(view).expect("serialize succeeds");
        serde_json::from_str(&s).expect("parses back")
    }

    // ---- list ----

    #[test]
    fn vault_list_view_empty_serializes_to_empty_vaults_array() {
        let view = VaultListView { vaults: Vec::new() };
        assert_eq!(json_of(&view), json!({ "vaults": [] }));
    }

    #[test]
    fn vault_list_entry_schema_with_all_optional_fields_present() {
        let path = PathBuf::from("/tmp/personal.kdbx");
        let kf = PathBuf::from("/tmp/personal.keyx");
        let view = VaultListView {
            vaults: vec![VaultListEntry {
                id: "personal",
                path: &path,
                keyfile: Some(&kf),
                created_at: "2026-05-17T10:00:00-06:00",
                idle_timeout_seconds: Some(300),
            }],
        };
        assert_eq!(
            json_of(&view),
            json!({
                "vaults": [{
                    "id": "personal",
                    "path": "/tmp/personal.kdbx",
                    "keyfile": "/tmp/personal.keyx",
                    "created_at": "2026-05-17T10:00:00-06:00",
                    "idle_timeout_seconds": 300,
                }],
            })
        );
    }

    #[test]
    fn vault_list_entry_omits_optional_fields_when_none() {
        let path = PathBuf::from("/tmp/x.kdbx");
        let view = VaultListView {
            vaults: vec![VaultListEntry {
                id: "x",
                path: &path,
                keyfile: None,
                created_at: "2026-05-17T10:00:00-06:00",
                idle_timeout_seconds: None,
            }],
        };
        let v = json_of(&view);
        let entry = &v["vaults"][0];
        assert!(entry.get("keyfile").is_none(), "keyfile must be absent");
        assert!(
            entry.get("idle_timeout_seconds").is_none(),
            "idle_timeout_seconds must be absent"
        );
    }

    #[test]
    fn vault_list_view_human_sorts_by_id() {
        let p1 = PathBuf::from("/tmp/b.kdbx");
        let p2 = PathBuf::from("/tmp/a.kdbx");
        // Insertion order: b, a. Human output must sort to a, b.
        let view = VaultListView {
            vaults: vec![
                VaultListEntry {
                    id: "b",
                    path: &p1,
                    keyfile: None,
                    created_at: "x",
                    idle_timeout_seconds: None,
                },
                VaultListEntry {
                    id: "a",
                    path: &p2,
                    keyfile: None,
                    created_at: "x",
                    idle_timeout_seconds: None,
                },
            ],
        };
        let mut buf = Vec::new();
        view.write_human(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let a_pos = s.find("\na ").expect("a line present");
        let b_pos = s.find("\nb ").expect("b line present");
        assert!(
            a_pos < b_pos,
            "human output should sort 'a' before 'b': {s}"
        );
    }

    #[test]
    fn vault_list_view_human_empty_says_no_vaults() {
        let view = VaultListView { vaults: Vec::new() };
        let mut buf = Vec::new();
        view.write_human(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("no vaults registered"), "{s}");
    }

    // ---- create ----

    #[test]
    fn vault_create_view_schema_with_keyfile() {
        let path = PathBuf::from("/tmp/new.kdbx");
        let kf = PathBuf::from("/tmp/new.keyx");
        let view = VaultCreateView {
            id: "new",
            path: &path,
            keyfile: Some(&kf),
            kdf: VaultCreateKdfView {
                algorithm: "argon2id",
                memory_kib: 65_536,
                iterations: 3,
                parallelism: 2,
            },
        };
        assert_eq!(
            json_of(&view),
            json!({
                "id": "new",
                "path": "/tmp/new.kdbx",
                "keyfile": "/tmp/new.keyx",
                "kdf": {
                    "algorithm": "argon2id",
                    "memory_kib": 65536,
                    "iterations": 3,
                    "parallelism": 2,
                },
            })
        );
    }

    #[test]
    fn vault_create_view_omits_keyfile_when_none() {
        let path = PathBuf::from("/tmp/new.kdbx");
        let view = VaultCreateView {
            id: "new",
            path: &path,
            keyfile: None,
            kdf: VaultCreateKdfView {
                algorithm: "argon2id",
                memory_kib: 65_536,
                iterations: 3,
                parallelism: 2,
            },
        };
        let v = json_of(&view);
        assert!(v.get("keyfile").is_none(), "keyfile must be absent");
    }

    // ---- open ----

    #[test]
    fn vault_open_view_schema() {
        let view = VaultOpenView {
            id: "personal",
            status: "unlocked-ok",
        };
        assert_eq!(
            json_of(&view),
            json!({ "id": "personal", "status": "unlocked-ok" })
        );
    }

    // ---- set-lock ----

    #[test]
    fn vault_set_lock_view_schema_with_timeout() {
        let view = VaultSetLockView {
            id: "personal",
            idle_timeout_seconds: Some(600),
        };
        assert_eq!(
            json_of(&view),
            json!({ "id": "personal", "idle_timeout_seconds": 600 })
        );
    }

    #[test]
    fn vault_set_lock_view_schema_cleared_omits_field() {
        let view = VaultSetLockView {
            id: "personal",
            idle_timeout_seconds: None,
        };
        let v = json_of(&view);
        assert_eq!(v["id"], "personal");
        assert!(
            v.get("idle_timeout_seconds").is_none(),
            "cleared override must omit the field, not emit null"
        );
    }

    // ---- set-sync ----

    #[test]
    fn vault_set_sync_view_schema_with_endpoint() {
        let view = VaultSetSyncView {
            id: "personal",
            bucket: "my-bucket",
            key: "personal.kdbx",
            endpoint: Some("https://minio.internal"),
            credentials_source: "iam-role",
        };
        assert_eq!(
            json_of(&view),
            json!({
                "id": "personal",
                "bucket": "my-bucket",
                "key": "personal.kdbx",
                "endpoint": "https://minio.internal",
                "credentials_source": "iam-role",
            })
        );
    }

    #[test]
    fn vault_set_sync_view_omits_endpoint_when_none() {
        let view = VaultSetSyncView {
            id: "personal",
            bucket: "b",
            key: "k",
            endpoint: None,
            credentials_source: "prompt",
        };
        let v = json_of(&view);
        assert!(
            v.get("endpoint").is_none(),
            "default endpoint must be omitted, not null"
        );
    }

    #[test]
    fn vault_set_sync_view_carries_no_secret_fields() {
        // Defence-in-depth: the view is the JSON contract for the output
        // channel; it must never grow a secret-bearing field. Pin the
        // exact key set so a future edit that adds `access_key_id` or the
        // sealed container gets caught here.
        let view = VaultSetSyncView {
            id: "personal",
            bucket: "b",
            key: "k",
            endpoint: None,
            credentials_source: "prompt",
        };
        let v = json_of(&view);
        let obj = v.as_object().expect("view serializes to a JSON object");
        for forbidden in [
            "access_key_id",
            "secret_access_key",
            "secret_access_key_encrypted",
        ] {
            assert!(
                obj.get(forbidden).is_none(),
                "set-sync view must not expose `{forbidden}`"
            );
        }
    }
}
