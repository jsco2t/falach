// Domain acronyms (S3, SigV4, ETag, KDBX, FR-040..048, ADR-n …) saturate
// this module's docs; backticking each one is more noise than signal.
#![allow(clippy::doc_markdown)]

//! Per-vault sync configuration (design.md §2.3) and its `vaults.toml`
//! integration.
//!
//! Each vault entry in `vaults.toml` may carry a `[vault.sync]` sub-table
//! whose shape is defined by [`SyncConfig`]:
//!
//! ```toml
//! [vault.sync]
//! kind = "s3"
//! last_synced_remote_etag = "..."
//! last_synced_local_sha256 = "..."
//!
//! [vault.sync.s3]
//! bucket = "jason-falach-vaults"
//! key = "work.kdbx"
//! endpoint = "https://s3.us-east-1.amazonaws.com"   # optional
//! region = "us-east-1"
//! path_style = false
//! if_match_supported = "supported"
//!
//! [vault.sync.s3.credentials]
//! kind = "rst_cred1"
//! access_key_id = "AKIA..."
//! secret_access_key_encrypted = "UkMwMSDV..."
//! ```
//!
//! `falach-core`'s [`RegisteredVault::extra`] field stores the `[vault.sync]`
//! sub-table verbatim; this module's helpers read/write it without
//! `falach-core` knowing the sync schema.
//!
//! # T5.1 — schema rewrite
//!
//! Replaces the carryover git-shaped fields (`remote_url`, `branch`,
//! `last_synced_commit`) with the design-§2.3 shape:
//!
//! - [`SyncConfig`] carries a `kind` tag, the divergence pointers
//!   (`last_synced_remote_etag` + `last_synced_local_sha256`), an optional
//!   [`S3Config`] sub-table, and a `serde(flatten) extra: toml::Table` for
//!   forward-compat with unknown top-level keys under `[sync]`.
//! - [`S3Config`] gains a [`CredentialSource`] field per design §2.3.1; the
//!   cache-invalidating setters from T3.4 carry forward; an `extra` slot is
//!   added for `[sync.s3]`-level forward-compat (impl plan §5.2 #8 / T5.1
//!   technical note).
//! - [`TransportKind`] is the `kind = "..."` enum tag — only `s3` is wired
//!   in Phase 0; future Phase-4 transports add variants without breaking
//!   the schema.
//!
//! Two ADRs land their on-disk pieces here:
//!
//! - **ADR-5** — `[sync.s3] if_match_supported = "..."` caches the per-backend
//!   conditional-PUT enforcement classification across process restarts; the
//!   setters in [`S3Config`] invalidate it back to `Unknown` whenever
//!   `(endpoint, bucket, key)` changes.
//! - **ADR-6** — [`canonicalize_target`] + [`SyncConfig::find_duplicate_target`]
//!   detect two vault entries configured against the same canonicalized S3
//!   target so [`crate::Sync::configure_remote`] can refuse the collision
//!   (`SyncError::DuplicateTarget`).
//!
//! Forward-compat: any pre-T5.1 `[sync]` block (e.g. the git-shaped
//! `remote_url`/`branch` carryover) lands in [`SyncConfig::extra`] without
//! erroring — `SyncConfig::from_vault_entry` returns `None` when the
//! `kind` tag is absent (the pre-T5.1 git-shape carryover had no `kind`
//! field), so the vault simply has no usable sync config until the user
//! re-runs `falach vault set-sync`.

use falach_core::{RegisteredVault, VaultRegistry};
use serde::{Deserialize, Serialize};

use crate::auth::CredentialSource;
use crate::s3::endpoint::canonicalize_endpoint;

/// The `vaults.toml` key under which a vault's sync config is stored.
const SYNC_KEY: &str = "sync";

// ===========================================================================
// IfMatchSupport — per-backend conditional-PUT enforcement cache (ADR-5)
// ===========================================================================

/// Per-backend `If-Match` enforcement classification, persisted in
/// `[vault.sync.s3] if_match_supported = "..."` after the T3.4 sentinel-key
/// probe runs (design.md §2.2.3 / ADR-5).
///
/// `Unknown` is the default; the probe transitions to either `Supported`
/// (412 on bogus `If-Match`) or `Degraded` (200 silent-accept). The cache
/// invalidates back to `Unknown` whenever any of `(endpoint, bucket, key)`
/// on the parent [`S3Config`] changes — they identify the target, and a
/// change means we may be talking to a different backend instance whose
/// capabilities are unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IfMatchSupport {
    /// The probe has not yet run for this `(endpoint, bucket, key)` target;
    /// the next `S3Transport::put_conditional`
    /// will run it before the real PUT.
    #[default]
    Unknown,
    /// The backend honors `If-Match` (returns 412 on a bogus value).
    Supported,
    /// The backend silently accepts `If-Match` without enforcement; the
    /// orchestrator falls back to the read-then-PUT-then-HEAD-compare
    /// degradation path.
    Degraded,
}

impl IfMatchSupport {
    /// Serde helper: omit the field when serializing the default `Unknown`
    /// so freshly-configured vaults don't carry noisy `if_match_supported
    /// = "unknown"` into `vaults.toml`. The first sync runs the probe and
    /// writes the real classification back.
    ///
    /// `&self` (not `self`) matches the `serde(skip_serializing_if =
    /// "...")` predicate's required signature; clippy's
    /// `trivially_copy_pass_by_ref` lint flags this but the trait shape
    /// is fixed.
    #[must_use]
    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn is_unknown(&self) -> bool {
        matches!(self, IfMatchSupport::Unknown)
    }
}

// ===========================================================================
// TransportKind — the `kind = "..."` schema tag
// ===========================================================================

/// Which sync transport a vault is configured against.
///
/// `#[non_exhaustive]` so Phase-4 transports (`Nfs`, `WebDav`, …) add
/// variants without breaking existing configs. Currently only `S3` is
/// wired; the design's `SyncConfig.s3: Option<S3Config>` carries the
/// transport-specific sub-table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TransportKind {
    /// S3-compatible object storage (FR-040..048). The corresponding
    /// `[sync.s3]` sub-table is present.
    S3,
}

// ===========================================================================
// S3Config — the per-vault S3 target
// ===========================================================================

/// Per-vault S3 target (design.md §2.3.1).
///
/// Fields are private; callers mutate through the setter pair so the
/// `if_match_supported` cache-invalidation invariant (ADR-5) is enforced
/// at the type boundary rather than relying on every call site to
/// remember it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct S3Config {
    bucket: String,
    key: String,
    /// `None` defaults to `https://s3.<region>.amazonaws.com`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    endpoint: Option<String>,
    region: String,
    #[serde(default, skip_serializing_if = "is_false")]
    path_style: bool,
    /// Per-vault credentials. Distinct types per variant (e.g. RST-CRED-1
    /// stores access_key_id + ciphertext; AwsProfile stores a profile
    /// name); see [`CredentialSource`].
    credentials: CredentialSource,
    /// Cached probe classification (ADR-5). Defaults to `Unknown`; the
    /// first conditional PUT runs the probe and writes the real
    /// classification back via the orchestrator's persist hook.
    #[serde(default, skip_serializing_if = "IfMatchSupport::is_unknown")]
    if_match_supported: IfMatchSupport,
    /// Forward-compat for unknown keys at the `[sync.s3]` level. Same
    /// posture as [`SyncConfig::extra`]; the only `#[serde(flatten)]`
    /// on this struct.
    #[serde(default, flatten, skip_serializing_if = "toml::Table::is_empty")]
    extra: toml::Table,
}

/// `serde(skip_serializing_if = "is_false")` helper — keeps the default-
/// `false` `path_style` field out of the on-disk TOML. The `&bool`
/// argument is required by serde's predicate-signature contract; the
/// `clippy::trivially_copy_pass_by_ref` allow matches the same rationale
/// as [`IfMatchSupport::is_unknown`].
#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(b: &bool) -> bool {
    !*b
}

impl S3Config {
    /// Build a fresh [`S3Config`]. `if_match_supported` starts as
    /// [`IfMatchSupport::Unknown`] so the first PUT runs the probe.
    #[must_use]
    pub fn new(bucket: String, key: String, region: String, credentials: CredentialSource) -> Self {
        Self {
            bucket,
            key,
            endpoint: None,
            region,
            path_style: false,
            credentials,
            if_match_supported: IfMatchSupport::Unknown,
            extra: toml::Table::new(),
        }
    }

    /// The bucket name.
    #[must_use]
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// The object key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The optional custom endpoint URL (`None` → AWS default for region).
    #[must_use]
    pub fn endpoint(&self) -> Option<&str> {
        self.endpoint.as_deref()
    }

    /// The region (required for SigV4 — the signing key is region-scoped).
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }

    /// Whether path-style addressing is in use.
    #[must_use]
    pub fn path_style(&self) -> bool {
        self.path_style
    }

    /// The per-vault credentials source.
    #[must_use]
    pub fn credentials(&self) -> &CredentialSource {
        &self.credentials
    }

    /// The cached `If-Match` enforcement classification.
    #[must_use]
    pub fn if_match_supported(&self) -> IfMatchSupport {
        self.if_match_supported
    }

    /// Replace the endpoint. Resets `if_match_supported` to `Unknown` —
    /// the endpoint identifies the target, so a change may put us in
    /// front of a different backend instance whose capabilities are
    /// unknown.
    pub fn set_endpoint(&mut self, endpoint: Option<String>) {
        self.endpoint = endpoint;
        self.if_match_supported = IfMatchSupport::Unknown;
    }

    /// Replace the bucket. Resets `if_match_supported` (same rationale
    /// as [`Self::set_endpoint`]).
    pub fn set_bucket(&mut self, bucket: String) {
        self.bucket = bucket;
        self.if_match_supported = IfMatchSupport::Unknown;
    }

    /// Replace the key. Resets `if_match_supported`.
    pub fn set_key(&mut self, key: String) {
        self.key = key;
        self.if_match_supported = IfMatchSupport::Unknown;
    }

    /// Replace the path-style flag. Does NOT reset `if_match_supported`
    /// — path-style is a request-encoding choice, not a backend identity,
    /// so the cached classification stays valid.
    pub fn set_path_style(&mut self, path_style: bool) {
        self.path_style = path_style;
    }

    /// Replace the credentials. Does NOT reset `if_match_supported` —
    /// rotating an access-key against the same bucket/endpoint doesn't
    /// change the backend's protocol-level behavior.
    pub fn set_credentials(&mut self, credentials: CredentialSource) {
        self.credentials = credentials;
    }

    /// Persist a probe classification. Called via the transport's
    /// `on_if_match_change` callback (`with_if_match_state` constructor).
    pub fn set_if_match_supported(&mut self, support: IfMatchSupport) {
        self.if_match_supported = support;
    }
}

// ===========================================================================
// SyncConfig — the per-vault sync block
// ===========================================================================

/// Per-vault sync configuration, serialized under `[vault.sync]` (design
/// §2.3.2).
///
/// `Eq` is deliberately NOT derived — `extra` is a `toml::Table` whose
/// values may contain `f64`, which is not `Eq`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncConfig {
    /// The configured transport kind (`kind = "s3"` currently). Drives
    /// dispatch in the orchestrator.
    pub kind: TransportKind,

    /// S3 target, present iff `kind == TransportKind::S3`. Serialized as
    /// `[sync.s3]` nested sub-table. **NOT** `#[serde(flatten)]` — only
    /// [`SyncConfig::extra`] is flattened; flattening both would collide.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s3: Option<S3Config>,

    /// Strong ETag the last successful sync observed on the remote. The
    /// orchestrator compares this against the current remote HEAD to
    /// detect the "remote changed" axis of the four-state truth table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_synced_remote_etag: Option<String>,

    /// Hex-encoded SHA-256 of the local KDBX bytes the last successful
    /// sync wrote. The orchestrator compares this against a fresh
    /// `sha256(read(vault.path()))` to detect the "local changed" axis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_synced_local_sha256: Option<String>,

    /// Forward-compat — unknown top-level keys under `[sync]` are
    /// preserved verbatim across save+load. Matches the `toml::Table`
    /// pattern used by [`RegisteredVault::extra`]. This is the lone
    /// `#[serde(flatten)]` on this struct.
    #[serde(default, flatten)]
    pub extra: toml::Table,
}

impl SyncConfig {
    /// Build a fresh [`SyncConfig`] for an S3 target. Sets `kind = "s3"`,
    /// wraps the supplied [`S3Config`], leaves `last_synced_*` as `None`
    /// (first sync writes them).
    #[must_use]
    pub fn s3(config: S3Config) -> Self {
        Self {
            kind: TransportKind::S3,
            s3: Some(config),
            last_synced_remote_etag: None,
            last_synced_local_sha256: None,
            extra: toml::Table::new(),
        }
    }

    /// Read the `[sync]` sub-table out of a registered vault entry.
    ///
    /// Returns `None` when the entry has no `sync` sub-table **or** when
    /// the sub-table fails to deserialize (e.g. a malformed hand-edit, or
    /// a pre-T5.1 git-shape `[sync]` block missing the `kind` tag). The
    /// caller treats `None` as "no usable sync config; the user must
    /// (re-)run `falach vault set-sync`."
    #[must_use]
    pub fn from_vault_entry(entry: &RegisteredVault) -> Option<SyncConfig> {
        entry
            .extra
            .get(SYNC_KEY)
            .cloned()
            .and_then(|value| value.try_into().ok())
    }

    /// Write this config into a registered vault entry's `[sync]`
    /// sub-table, overwriting any existing one.
    ///
    /// # Panics
    ///
    /// Never in practice. The `expect` guards a `toml::Value` serialization
    /// that cannot fail for `SyncConfig`'s field types.
    pub fn to_vault_entry(&self, entry: &mut RegisteredVault) {
        let value = toml::Value::try_from(self)
            .expect("SyncConfig is always representable as a TOML value");
        entry.extra.insert(SYNC_KEY.to_string(), value);
    }

    /// Walk the registry for any other vault configured against the same
    /// canonicalized S3 target — `(canonicalize_endpoint, bucket, key)`.
    /// Returns the colliding vault's name, or `None` if no collision.
    ///
    /// Per design ADR-6, `Sync::configure_remote` calls this before
    /// writing the new config and rejects with `SyncError::DuplicateTarget`
    /// on a match. `exclude_vault` is the vault being configured (so
    /// re-configuring the same vault doesn't self-collide).
    ///
    /// This only reads the S3 variant; non-S3 transports (none yet) and
    /// vaults without a `[sync]` block are skipped.
    #[must_use]
    pub fn find_duplicate_target(
        registry: &VaultRegistry,
        target_endpoint: Option<&str>,
        target_bucket: &str,
        target_key: &str,
        exclude_vault: Option<&str>,
    ) -> Option<String> {
        let target_canonical = canonicalize_target(target_endpoint, target_bucket, target_key);

        registry
            .list()
            .filter(|entry| match exclude_vault {
                Some(name) => entry.name != name,
                None => true,
            })
            .find_map(|entry| {
                let cfg = SyncConfig::from_vault_entry(entry)?;
                let s3 = cfg.s3.as_ref()?;
                let existing_canonical = canonicalize_target(s3.endpoint(), s3.bucket(), s3.key());
                if existing_canonical == target_canonical {
                    Some(entry.name.clone())
                } else {
                    None
                }
            })
    }
}

// ===========================================================================
// canonicalize_target — ADR-6 normalization
// ===========================================================================

/// Normalize an `(endpoint, bucket, key)` triple to a single comparable
/// string. Used by [`SyncConfig::find_duplicate_target`] to detect two
/// vault entries configured against the same S3 target across cosmetic
/// differences (case, trailing slash, `https://` prefix).
///
/// The canonical form is `"<endpoint>|<bucket>|<key>"` where `endpoint`
/// is normalized via [`canonicalize_endpoint`] (lowercase, scheme-stripped,
/// trailing-slash-stripped). `None` endpoint canonicalizes to a fixed
/// sentinel so an explicit `None` matches another `None` but not an
/// explicit AWS-default URL.
///
/// Bucket and key are NOT lower-cased: S3 bucket names ARE case-sensitive
/// (and AWS prohibits uppercase in v2-API bucket names anyway), and
/// object keys are emphatically case-sensitive.
#[must_use]
pub fn canonicalize_target(endpoint: Option<&str>, bucket: &str, key: &str) -> String {
    let endpoint_part = match endpoint {
        Some(s) => canonicalize_endpoint(s),
        // Sentinel for "no explicit endpoint = AWS default for region";
        // distinct from any real URL canonical form because real URLs
        // canonicalize to host-and-path strings that never start with
        // `<aws-default>`.
        None => "<aws-default>".to_string(),
    };
    format!("{endpoint_part}|{bucket}|{key}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use falach_core::{FalachPaths, RegisteredVault, VaultRegistry};
    use std::path::PathBuf;
    use tempfile::TempDir;

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    fn rst_cred1_source() -> CredentialSource {
        CredentialSource::RstCred1 {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key_encrypted: "UkMwMSDV-fake-base64".to_string(),
        }
    }

    fn sample_s3_config() -> S3Config {
        S3Config::new(
            "my-bucket".to_string(),
            "work.kdbx".to_string(),
            "us-east-1".to_string(),
            rst_cred1_source(),
        )
    }

    fn sample_sync_config() -> SyncConfig {
        SyncConfig::s3(sample_s3_config())
    }

    fn paths_in(dir: &TempDir) -> FalachPaths {
        FalachPaths::with_state_dir(dir.path().join("state"))
    }

    fn seed_vaults_toml(paths: &FalachPaths, body: &str) {
        paths.ensure_exists().expect("ensure state dir");
        std::fs::write(paths.vaults_toml(), body).expect("seed vaults.toml");
    }

    // -- TC-CONFIG-001 ------------------------------------------------------
    #[test]
    fn sync_config_round_trips_s3_kind() {
        let cfg = sample_sync_config();
        let serialized = toml::to_string(&cfg).expect("serialize");
        let back: SyncConfig = toml::from_str(&serialized).expect("deserialize");
        assert_eq!(cfg, back);
        assert!(matches!(back.kind, TransportKind::S3));
        assert!(back.s3.is_some());
    }

    // -- TC-CONFIG-002 ------------------------------------------------------
    #[test]
    fn sync_config_default_if_match_supported_is_unknown() {
        let toml_without_field = r#"
kind = "s3"

[s3]
bucket = "b"
key = "k"
region = "us-east-1"

[s3.credentials]
kind = "rst_cred1"
access_key_id = "AKIA"
secret_access_key_encrypted = "UkMwMSDV"
"#;
        let cfg: SyncConfig = toml::from_str(toml_without_field).expect("deserialize");
        let s3 = cfg.s3.expect("s3 sub-table");
        assert_eq!(s3.if_match_supported(), IfMatchSupport::Unknown);
    }

    // -- TC-CONFIG-002b -----------------------------------------------------
    // The `Unknown` default must serde-omit so freshly-configured vaults
    // don't carry a noisy `if_match_supported = "unknown"` into the TOML.
    #[test]
    fn sync_config_if_match_unknown_is_omitted_when_serializing() {
        let cfg = sample_sync_config();
        let serialized = toml::to_string(&cfg).expect("serialize");
        assert!(
            !serialized.contains("if_match_supported"),
            "Unknown must be omitted; got:\n{serialized}"
        );
    }

    // -- TC-CONFIG-003 ------------------------------------------------------
    #[test]
    fn sync_config_extra_preserves_unknown_top_level_keys() {
        let with_unknown = r#"
kind = "s3"
crazy_future_field = "x"

[s3]
bucket = "b"
key = "k"
region = "us-east-1"

[s3.credentials]
kind = "rst_cred1"
access_key_id = "AKIA"
secret_access_key_encrypted = "UkMwMSDV"
"#;
        let cfg: SyncConfig = toml::from_str(with_unknown).expect("deserialize");
        assert_eq!(
            cfg.extra
                .get("crazy_future_field")
                .and_then(toml::Value::as_str),
            Some("x"),
            "unknown top-level key captured in extra"
        );

        let serialized = toml::to_string(&cfg).expect("serialize");
        let reparsed: toml::Table = toml::from_str(&serialized).expect("reparse");
        assert_eq!(
            reparsed
                .get("crazy_future_field")
                .and_then(toml::Value::as_str),
            Some("x"),
            "unknown top-level key survives the round-trip"
        );
    }

    // -- TC-CONFIG-004 ------------------------------------------------------
    // The advisor caught a draft schema that `#[serde(flatten)]`-ed both
    // `s3` AND `extra` — flattening dissolved `[s3]` into `[sync]` and
    // collided with `extra`. This test pins the corrected shape: the S3
    // sub-table is a NESTED block, not flattened.
    #[test]
    fn sync_config_nested_s3_block_serializes_as_subtable() {
        let cfg = sample_sync_config();
        let serialized = toml::to_string(&cfg).expect("serialize");
        // `[s3]` MUST appear as a nested sub-table header.
        assert!(
            serialized.contains("[s3]") || serialized.contains("s3.bucket"),
            "S3 config must serialize as a nested sub-table, got:\n{serialized}"
        );
        // Bucket should NOT appear at the top level (which would be the
        // flattened-bug shape).
        let top_level_lines: Vec<&str> = serialized
            .lines()
            .take_while(|line| !line.starts_with('['))
            .collect();
        for line in &top_level_lines {
            assert!(
                !line.starts_with("bucket"),
                "S3.bucket leaked to the top level (flatten bug); got:\n{serialized}"
            );
        }
    }

    // -- TC-CONFIG-005 ------------------------------------------------------
    #[test]
    fn sync_config_credentials_round_trip_rstcred1() {
        let cfg = sample_sync_config();
        let serialized = toml::to_string(&cfg).expect("serialize");
        let back: SyncConfig = toml::from_str(&serialized).expect("deserialize");
        match back.s3.expect("s3").credentials() {
            CredentialSource::RstCred1 {
                access_key_id,
                secret_access_key_encrypted,
            } => {
                assert_eq!(access_key_id, "AKIAIOSFODNN7EXAMPLE");
                assert_eq!(secret_access_key_encrypted, "UkMwMSDV-fake-base64");
            }
            other => panic!("expected RstCred1, got {other:?}"),
        }
    }

    // -- TC-CONFIG-006 ------------------------------------------------------
    #[test]
    fn sync_config_credentials_round_trip_aws_profile() {
        let mut s3 = sample_s3_config();
        s3.set_credentials(CredentialSource::AwsProfile {
            profile: "personal-vaults".to_string(),
            credentials_file: Some(PathBuf::from("/path/to/creds")),
        });
        let cfg = SyncConfig::s3(s3);
        let serialized = toml::to_string(&cfg).expect("serialize");
        let back: SyncConfig = toml::from_str(&serialized).expect("deserialize");
        match back.s3.expect("s3").credentials() {
            CredentialSource::AwsProfile {
                profile,
                credentials_file,
            } => {
                assert_eq!(profile, "personal-vaults");
                assert_eq!(
                    credentials_file.as_deref(),
                    Some(std::path::Path::new("/path/to/creds"))
                );
            }
            other => panic!("expected AwsProfile, got {other:?}"),
        }
    }

    // -- TC-CONFIG-007 ------------------------------------------------------
    #[test]
    fn sync_config_credentials_round_trip_env_vars() {
        let mut s3 = sample_s3_config();
        s3.set_credentials(CredentialSource::EnvVars {
            prefix: "MY_".to_string(),
        });
        let cfg = SyncConfig::s3(s3);
        let serialized = toml::to_string(&cfg).expect("serialize");
        let back: SyncConfig = toml::from_str(&serialized).expect("deserialize");
        match back.s3.expect("s3").credentials() {
            CredentialSource::EnvVars { prefix } => assert_eq!(prefix, "MY_"),
            other => panic!("expected EnvVars, got {other:?}"),
        }
    }

    // -- TC-CONFIG-008 ------------------------------------------------------
    #[test]
    fn sync_config_credentials_round_trip_iam_role() {
        let mut s3 = sample_s3_config();
        s3.set_credentials(CredentialSource::IamInstanceRole {
            imds_endpoint: Some("http://169.254.169.254".to_string()),
        });
        let cfg = SyncConfig::s3(s3);
        let serialized = toml::to_string(&cfg).expect("serialize");
        let back: SyncConfig = toml::from_str(&serialized).expect("deserialize");
        match back.s3.expect("s3").credentials() {
            CredentialSource::IamInstanceRole { imds_endpoint } => {
                assert_eq!(imds_endpoint.as_deref(), Some("http://169.254.169.254"));
            }
            other => panic!("expected IamInstanceRole, got {other:?}"),
        }
    }

    // -- TC-CONFIG-009 ------------------------------------------------------
    #[test]
    fn sync_config_invalid_credential_kind_errors() {
        let bad = r#"
kind = "s3"

[s3]
bucket = "b"
key = "k"
region = "us-east-1"

[s3.credentials]
kind = "telepathy"
"#;
        let result: Result<SyncConfig, _> = toml::from_str(bad);
        assert!(
            result.is_err(),
            "unknown `kind = \"telepathy\"` must fail to deserialize"
        );
    }

    // -- TC-CONFIG-010 ------------------------------------------------------
    #[test]
    fn sync_config_last_synced_etag_omitted_when_none() {
        let cfg = sample_sync_config();
        assert!(cfg.last_synced_remote_etag.is_none());
        let serialized = toml::to_string(&cfg).expect("serialize");
        assert!(
            !serialized.contains("last_synced_remote_etag"),
            "None must be omitted; got:\n{serialized}"
        );
        assert!(
            !serialized.contains("last_synced_local_sha256"),
            "None must be omitted; got:\n{serialized}"
        );
    }

    // -- TC-CONFIG-011 ------------------------------------------------------
    #[test]
    fn sync_config_last_synced_sha256_round_trips_as_hex() {
        let mut cfg = sample_sync_config();
        cfg.last_synced_remote_etag = Some("d41d8cd98f00b204e9800998ecf8427e".to_string());
        cfg.last_synced_local_sha256 =
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string());
        let serialized = toml::to_string(&cfg).expect("serialize");
        let back: SyncConfig = toml::from_str(&serialized).expect("deserialize");
        assert_eq!(
            back.last_synced_remote_etag.as_deref(),
            Some("d41d8cd98f00b204e9800998ecf8427e")
        );
        assert_eq!(
            back.last_synced_local_sha256.as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    // -- TC-CONFIG-012 ------------------------------------------------------
    #[test]
    fn vaults_toml_load_with_sync_s3_block_succeeds() {
        let tmp = TempDir::new().expect("tempdir");
        let paths = paths_in(&tmp);
        seed_vaults_toml(
            &paths,
            r#"
version = 1

[[vault]]
name = "work"
path = "/tmp/work.kdbx"
created_at = "2026-05-27T22:30:00Z"

[vault.sync]
kind = "s3"
last_synced_remote_etag = "d41d8cd98f00b204e9800998ecf8427e"

[vault.sync.s3]
bucket = "jason-falach-vaults"
key = "work.kdbx"
region = "us-east-1"

[vault.sync.s3.credentials]
kind = "rst_cred1"
access_key_id = "AKIAIOSFODNN7EXAMPLE"
secret_access_key_encrypted = "UkMwMSDV"
"#,
        );

        let registry = VaultRegistry::load(paths).expect("load registry");
        let entry = registry.get("work").expect("work vault present");
        let cfg = SyncConfig::from_vault_entry(entry).expect("sync config present");
        assert!(matches!(cfg.kind, TransportKind::S3));
        let s3 = cfg.s3.expect("s3 sub-table");
        assert_eq!(s3.bucket(), "jason-falach-vaults");
        assert_eq!(s3.key(), "work.kdbx");
        assert_eq!(s3.region(), "us-east-1");
        assert_eq!(
            cfg.last_synced_remote_etag.as_deref(),
            Some("d41d8cd98f00b204e9800998ecf8427e")
        );
    }

    // -- TC-CONFIG-013 ------------------------------------------------------
    #[test]
    fn vaults_toml_save_then_load_preserves_sync_block() {
        let tmp = TempDir::new().expect("tempdir");
        let paths = paths_in(&tmp);

        // Carry a non-empty `extra` so this also proves the forward-compat
        // guarantee through the write path (`to_vault_entry`'s
        // `Value::try_from` serializer + registry save).
        let mut cfg = sample_sync_config();
        cfg.extra.insert(
            "future_feature".to_string(),
            toml::Value::Table({
                let mut t = toml::Table::new();
                t.insert("enabled".to_string(), toml::Value::Boolean(true));
                t
            }),
        );

        {
            let mut registry = VaultRegistry::with_paths(paths.clone());
            let mut entry = RegisteredVault {
                name: "personal".to_string(),
                path: PathBuf::from("/tmp/personal.kdbx"),
                created_at: "2026-05-27T22:30:00Z".to_string(),
                keyfile_path: None,
                extra: toml::Table::new(),
            };
            cfg.to_vault_entry(&mut entry);
            registry.register(entry).expect("register");
            registry.save().expect("save");
        }

        let registry = VaultRegistry::load(paths).expect("reload");
        let entry = registry.get("personal").expect("personal vault present");
        let loaded = SyncConfig::from_vault_entry(entry).expect("sync config present");
        assert_eq!(loaded, cfg, "sync block survives save + reload");
    }

    // -- TC-CONFIG-014 ------------------------------------------------------
    #[test]
    fn vaults_toml_without_sync_block_returns_none() {
        let tmp = TempDir::new().expect("tempdir");
        let paths = paths_in(&tmp);
        seed_vaults_toml(
            &paths,
            r#"
version = 1

[[vault]]
name = "plain"
path = "/tmp/plain.kdbx"
created_at = "2026-05-27T22:30:00Z"
"#,
        );
        let registry = VaultRegistry::load(paths).expect("load registry");
        let entry = registry.get("plain").expect("plain vault present");
        assert!(SyncConfig::from_vault_entry(entry).is_none());
    }

    // -- TC-CONFIG-014b -----------------------------------------------------
    // Pre-T5.1 git-shape `[sync]` blocks (with `remote_url`/`branch` but no
    // `kind` tag) parse as `None` — the user must re-run `vault set-sync`.
    #[test]
    fn pre_t5_1_git_shape_sync_block_returns_none() {
        let tmp = TempDir::new().expect("tempdir");
        let paths = paths_in(&tmp);
        seed_vaults_toml(
            &paths,
            r#"
version = 1

[[vault]]
name = "legacy"
path = "/tmp/legacy.kdbx"
created_at = "2026-05-27T22:30:00Z"

[vault.sync]
remote_url = "git@github.com:me/vault.git"
branch = "main"
"#,
        );
        let registry = VaultRegistry::load(paths).expect("load registry");
        let entry = registry.get("legacy").expect("legacy vault present");
        // No `kind` tag → deserialization to SyncConfig fails →
        // from_vault_entry returns None (the user re-configures).
        assert!(SyncConfig::from_vault_entry(entry).is_none());
    }

    // -- TC-CONFIG-015 ------------------------------------------------------
    // Cache-invalidation invariant from ADR-5 (carry-forward from T3.4):
    // setters on (endpoint, bucket, key) reset `if_match_supported` to
    // `Unknown`. Re-pinned here in the post-T5.1 schema.
    #[test]
    fn if_match_supported_resets_when_endpoint_changes() {
        let mut s3 = sample_s3_config();
        s3.set_if_match_supported(IfMatchSupport::Supported);
        s3.set_endpoint(Some("https://minio.example.com".to_string()));
        assert_eq!(s3.if_match_supported(), IfMatchSupport::Unknown);
    }

    #[test]
    fn if_match_supported_resets_when_bucket_changes() {
        let mut s3 = sample_s3_config();
        s3.set_if_match_supported(IfMatchSupport::Supported);
        s3.set_bucket("other-bucket".to_string());
        assert_eq!(s3.if_match_supported(), IfMatchSupport::Unknown);
    }

    #[test]
    fn if_match_supported_resets_when_key_changes() {
        let mut s3 = sample_s3_config();
        s3.set_if_match_supported(IfMatchSupport::Supported);
        s3.set_key("other.kdbx".to_string());
        assert_eq!(s3.if_match_supported(), IfMatchSupport::Unknown);
    }

    #[test]
    fn if_match_supported_preserved_when_path_style_changes() {
        let mut s3 = sample_s3_config();
        s3.set_if_match_supported(IfMatchSupport::Supported);
        s3.set_path_style(true);
        assert_eq!(s3.if_match_supported(), IfMatchSupport::Supported);
    }

    // -- TC-CONFIG-016 ------------------------------------------------------
    // The DuplicateTarget check: two vault entries with the same
    // canonicalized (endpoint, bucket, key) → find_duplicate_target
    // returns the existing vault's name.
    #[test]
    fn duplicate_target_uniqueness_check_at_configure_time() {
        let tmp = TempDir::new().expect("tempdir");
        let paths = paths_in(&tmp);

        let mut registry = VaultRegistry::with_paths(paths);
        let cfg = sample_sync_config();
        let mut entry = RegisteredVault {
            name: "work".to_string(),
            path: PathBuf::from("/tmp/work.kdbx"),
            created_at: "2026-05-27T22:30:00Z".to_string(),
            keyfile_path: None,
            extra: toml::Table::new(),
        };
        cfg.to_vault_entry(&mut entry);
        registry.register(entry).expect("register work");

        // Same (endpoint=None, bucket="my-bucket", key="work.kdbx") as
        // sample_sync_config() — must surface as a duplicate.
        let collision = SyncConfig::find_duplicate_target(
            &registry,
            None,
            "my-bucket",
            "work.kdbx",
            Some("personal"),
        );
        assert_eq!(collision.as_deref(), Some("work"));

        // Re-configuring the same vault under its own name does NOT
        // self-collide.
        let self_check = SyncConfig::find_duplicate_target(
            &registry,
            None,
            "my-bucket",
            "work.kdbx",
            Some("work"),
        );
        assert!(
            self_check.is_none(),
            "exclude_vault prevents self-collision"
        );

        // A different key in the same bucket is not a duplicate.
        let no_collision = SyncConfig::find_duplicate_target(
            &registry,
            None,
            "my-bucket",
            "other.kdbx",
            Some("personal"),
        );
        assert!(no_collision.is_none());
    }

    // -- TC-CONFIG-017 ------------------------------------------------------
    // canonicalize_target normalizes endpoint case, scheme, and trailing
    // slash — `https://S3.AMAZONAWS.com/` and `https://s3.amazonaws.com`
    // are the same target.
    #[test]
    fn target_canonicalization_handles_trailing_slash_and_case() {
        let cases = [
            (
                Some("https://S3.AMAZONAWS.com/"),
                Some("https://s3.amazonaws.com"),
            ),
            (Some("HTTP://Example.COM/"), Some("http://example.com")),
            (Some("https://example.com"), Some("example.com")),
        ];
        for (a, b) in cases {
            let ca = canonicalize_target(a, "bucket", "key");
            let cb = canonicalize_target(b, "bucket", "key");
            assert_eq!(
                ca, cb,
                "endpoints {a:?} and {b:?} must canonicalize the same"
            );
        }
        // None and Some are NOT equivalent — None means "AWS default for
        // region"; a user who writes `https://s3.us-east-1.amazonaws.com`
        // is being explicit and must collide with another explicit user
        // of the same URL, not with the implicit-default user.
        let implicit = canonicalize_target(None, "bucket", "key");
        let explicit =
            canonicalize_target(Some("https://s3.us-east-1.amazonaws.com"), "bucket", "key");
        assert_ne!(implicit, explicit);
    }

    // -- TC-CONFIG-018 ------------------------------------------------------
    // `S3Config.extra` forward-compat: an unknown key at the `[sync.s3]`
    // level round-trips opaquely.
    #[test]
    fn s3_config_extra_preserves_unknown_subtable_keys() {
        let with_unknown = r#"
kind = "s3"

[s3]
bucket = "b"
key = "k"
region = "us-east-1"
future_s3_option = true

[s3.credentials]
kind = "rst_cred1"
access_key_id = "AKIA"
secret_access_key_encrypted = "UkMwMSDV"
"#;
        let cfg: SyncConfig = toml::from_str(with_unknown).expect("deserialize");
        let s3 = cfg.s3.as_ref().expect("s3 sub-table");
        assert_eq!(
            s3.extra
                .get("future_s3_option")
                .and_then(toml::Value::as_bool),
            Some(true),
            "unknown [s3]-level key captured in S3Config.extra"
        );
        let serialized = toml::to_string(&cfg).expect("serialize");
        assert!(
            serialized.contains("future_s3_option"),
            "unknown [s3]-level key survives the round-trip; got:\n{serialized}"
        );
    }
}
