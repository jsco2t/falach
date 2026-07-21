//! [`CliExit`] — the stable CLI exit-code contract (FR-063).
//!
//! Every consumed-library error enum maps into one of six variants via
//! a `From` impl. Each impl `match` enumerates every variant known at
//! this crate's build time; because the sibling error enums are
//! `#[non_exhaustive]`, the impls also carry a documented catch-all arm
//! that surfaces unmapped variants as [`CliExit::Internal`] with the
//! upstream `Display` text. The catch-all means new variants are
//! reported but not silently dropped — and a quick search for
//! `unexpected vault error:` in logs flags drift.
//!
//! Documented codes (frozen at MVP merge — see design §2.4.2):
//!
//! | Code | Variant          | When                                                |
//! | ---- | ---------------- | --------------------------------------------------- |
//! | 0    | `Success`        | Command completed normally.                         |
//! | 1    | `UserError`      | Malformed input, missing vault, parse failure, ...  |
//! | 2    | `VaultLocked`    | Wrong master password / contended write lock.       |
//! | 3    | `SyncConflict`   | Unresolvable sync merge requiring user resolution. |
//! | 10   | `Internal`       | I/O / KDBX / unexpected upstream failure.           |
//! | 11   | `NotImplemented` | Known slot commands, currently the `ssh` family.     |
//!
//! `From<falach_security::SecurityError>` joins the exhaustiveness
//! battery in Phase 3 — `falach-security` ships its clipboard +
//! auto-lock + OS-event surface via the security-behaviors MVP.
//!
//! `From<falach_sync::SyncError>` maps `Unresolvable` to
//! `SyncConflict` (exit 3). The `falach sync` command supplies the
//! vault context and is the runtime producer of that stable exit code.

use std::io::Write;

use falach_core::VaultError;
use falach_genpw::GenError;
use falach_security::SecurityError;
use falach_sync::SyncError;

/// CLI exit code carrying enough context to render a human or JSON
/// diagnostic. Variant order matches the documented exit-code table.
#[derive(Debug)]
pub enum CliExit {
    /// Exit code 0.
    Success,
    /// Exit code 1.
    UserError(String),
    /// Exit code 2 — authentication or write-contention failure.
    VaultLocked(String),
    /// Exit code 3 — unresolvable sync merge requiring user resolution
    /// (maps from `falach_sync::SyncError::Unresolvable`).
    SyncConflict {
        /// Vault name whose sync needs user resolution.
        vault: String,
        /// Free-text detail (non-secret).
        detail: String,
    },
    /// Exit code 10 — internal / unexpected failure.
    Internal(String),
    /// Exit code 11 — known unimplemented surface (slot subcommand or
    /// phase-stub body).
    NotImplemented(&'static str),
}

impl CliExit {
    /// Numeric exit code (frozen contract).
    #[must_use]
    pub const fn code(&self) -> i32 {
        match self {
            Self::Success => 0,
            Self::UserError(_) => 1,
            Self::VaultLocked(_) => 2,
            Self::SyncConflict { .. } => 3,
            Self::Internal(_) => 10,
            Self::NotImplemented(_) => 11,
        }
    }

    /// Stable, dotted error-kind string. Suitable for `error.kind` in
    /// JSON output and for log-aggregation filters.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::UserError(_) => "user.error",
            Self::VaultLocked(_) => "vault.locked",
            Self::SyncConflict { .. } => "sync.conflict",
            Self::Internal(_) => "internal",
            Self::NotImplemented(_) => "not.implemented",
        }
    }

    /// Free-text message component. Never includes secret material.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Success => String::new(),
            Self::UserError(m) | Self::VaultLocked(m) | Self::Internal(m) => m.clone(),
            // The `From<SyncError>` conversion cannot know the vault name
            // (`SyncError::Unresolvable` does not carry it), so it leaves
            // `vault` empty; the `falach sync` command boundary attaches it
            // when it has it. Omit the `vault '…':` prefix when empty rather
            // than rendering a bare `vault '':`.
            Self::SyncConflict { vault, detail } if vault.is_empty() => detail.clone(),
            Self::SyncConflict { vault, detail } => format!("vault '{vault}': {detail}"),
            Self::NotImplemented(m) => (*m).to_string(),
        }
    }

    /// Render a human-readable diagnostic to the given writer. Used by
    /// `lib.rs`'s top-level dispatcher to emit a final stderr line when
    /// a command fails.
    ///
    /// # Errors
    ///
    /// Returns any `std::io::Error` produced by the writer.
    pub fn render_human(&self, out: &mut dyn Write) -> std::io::Result<()> {
        match self {
            Self::Success => Ok(()),
            other => writeln!(out, "error: {}: {}", other.kind(), other.message()),
        }
    }
}

// ---------------------------------------------------------------------------
// From<VaultError> for CliExit.
//
// vault-core folded what the original planning called `EntryError` /
// `RegistryError` into a single `VaultError` (see `falach-core/src/error.rs`).
// This impl is the one place that takes the entire known surface and
// produces the CLI's exit-code mapping. `VaultError` is `#[non_exhaustive]`,
// so the trailing `other => ...` arm is required by the compiler; new
// variants surface as `Internal` with the upstream Display until they
// are mapped explicitly.
// ---------------------------------------------------------------------------

impl From<VaultError> for CliExit {
    fn from(e: VaultError) -> Self {
        match e {
            VaultError::HomeUnresolvable => {
                Self::UserError("$HOME is not set or not resolvable".to_string())
            }
            VaultError::PathExists { path } => {
                Self::UserError(format!("path already exists: {}", path.display()))
            }
            VaultError::FileNotFound { path } => {
                Self::UserError(format!("vault file not found: {}", path.display()))
            }
            VaultError::AuthenticationFailed => {
                Self::VaultLocked("master password incorrect".to_string())
            }
            VaultError::Contended { holder } => Self::VaultLocked(holder.map_or_else(
                || "vault held by another process".to_string(),
                |pid| format!("vault held by another process (pid {pid})"),
            )),
            VaultError::InvalidFormat { source } => {
                Self::Internal(format!("invalid KDBX format: {source}"))
            }
            VaultError::Io { source, path } => {
                Self::Internal(format!("I/O error on {}: {source}", path.display()))
            }
            VaultError::WriteFailed { source } => {
                Self::Internal(format!("KDBX write failed: {source}"))
            }
            VaultError::RegistryMalformed { source } => {
                let detail =
                    source.map_or_else(|| "structural check failed".to_string(), |e| e.to_string());
                Self::Internal(format!("vault registry file is malformed: {detail}"))
            }
            VaultError::RegistrySerializationFailed { source } => {
                Self::Internal(format!("vault registry serialization failed: {source}"))
            }
            VaultError::NotRegistered { name } => {
                Self::UserError(format!("vault not registered: {name}"))
            }
            VaultError::AlreadyRegistered { name } => {
                Self::UserError(format!("vault already registered: {name}"))
            }
            VaultError::NoRecoveryNotConfirmed => Self::UserError(
                "vault creation requires the no-recovery warning to be confirmed".to_string(),
            ),
            VaultError::EntryNotFound { uuid } => {
                Self::UserError(format!("entry not found: {uuid}"))
            }
            VaultError::GroupNotFound { uuid } => {
                Self::UserError(format!("group not found: {uuid}"))
            }
            VaultError::EntryHasNoTotp { uuid } => {
                Self::UserError(format!("entry has no TOTP/HOTP otp field: {uuid}"))
            }
            VaultError::AttachmentTooLarge { actual, limit } => Self::UserError(format!(
                "attachment too large: {actual} bytes exceeds limit of {limit} bytes"
            )),
            VaultError::AttachmentNotFound { name } => {
                Self::UserError(format!("attachment not found: {name}"))
            }
            VaultError::InvalidOtpUri { source } => {
                Self::UserError(format!("invalid otpauth URI: {source}"))
            }
            VaultError::InvalidAttachmentCap => {
                Self::UserError("invalid attachment cap (must be 1..=104857600 bytes)".to_string())
            }
            VaultError::GroupNotEmpty { uuid } => Self::UserError(format!(
                "group not empty: {uuid}; pass recursive flag to delete with children"
            )),
            VaultError::InvalidTag { value } => {
                Self::UserError(format!("invalid tag: {value} (tags cannot contain ';')"))
            }
            VaultError::CannotModifyRoot => {
                Self::UserError("the root group cannot be moved or deleted".to_string())
            }
            VaultError::InvalidGroupTarget { reason } => {
                Self::UserError(format!("invalid group target: {reason}"))
            }
            // `VaultError` is `#[non_exhaustive]`. A future variant
            // landing in vault-core falls through here and is reported
            // as `Internal` with the upstream Display. This is the
            // intentional safety valve; the per-variant `match` arms
            // above are the design contract for known variants.
            other => Self::Internal(format!("unexpected vault error: {other}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Exhaustive From<GenError> for CliExit.
//
// falach-genpw exposes `GenError` (the planning doc called it
// `PasswordGenError`; the crate landed under the shorter name).
// ---------------------------------------------------------------------------

impl From<GenError> for CliExit {
    fn from(e: GenError) -> Self {
        match e {
            GenError::InvalidLength => {
                Self::UserError("requested password length must be at least 1".to_string())
            }
            GenError::NoClassesEnabled => Self::UserError(
                "at least one character class (lowercase/uppercase/digits/symbols) must be enabled"
                    .to_string(),
            ),
            GenError::LengthTooShort { length, classes } => Self::UserError(format!(
                "length {length} is too short for {classes} enabled character classes"
            )),
            GenError::AlphabetEmpty => Self::UserError(
                "the requested alphabet is empty after applying the ambiguous-character filter"
                    .to_string(),
            ),
            GenError::InvalidWordCount => {
                Self::UserError("requested word count must be at least 1".to_string())
            }
            GenError::Csprng(source) => Self::Internal(format!("OS CSPRNG failure: {source}")),
        }
    }
}

// ---------------------------------------------------------------------------
// From<SecurityError> for CliExit.
//
// `falach-security` ships clipboard + auto-lock + OS-event surface.
// The CLI consumes only the clipboard hand-off in MVP (`entry get --copy`
// / `gen --copy`); other variants surface either via the controller
// (CLI's `master_password` agent path) or via vault-side propagation.
// `SecurityError` is `#[non_exhaustive]`, so the trailing arm catches
// future variants as `Internal`.
// ---------------------------------------------------------------------------

impl From<SecurityError> for CliExit {
    fn from(e: SecurityError) -> Self {
        match e {
            SecurityError::ClipboardUnavailable(detail) => {
                Self::Internal(format!("clipboard backend unavailable: {detail}"))
            }
            SecurityError::ClipboardIo { detail } => {
                Self::Internal(format!("clipboard I/O error: {detail}"))
            }
            SecurityError::EventSourceStart { name, detail } => Self::Internal(format!(
                "OS event source '{name}' failed to start: {detail}"
            )),
            SecurityError::EventChannelClosed { name } => Self::Internal(format!(
                "OS event source '{name}' lost its channel (controller dropped)"
            )),
            SecurityError::InvalidVaultLockConfig { detail } => {
                Self::UserError(format!("invalid per-vault lock config: {detail}"))
            }
            SecurityError::InvalidAutoLockConfig { detail } => {
                Self::UserError(format!("invalid auto-lock config: {detail}"))
            }
            // `SecurityError` is `#[non_exhaustive]`. A new variant
            // falls through here and is reported as `Internal`.
            other => Self::Internal(format!("unexpected security error: {other}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Exhaustive From<SyncError> for CliExit.
//
// `falach-sync` ships the sync-transport surface consumed by
// `falach sync` and `falach vault set-sync` (features/cli-sync-wiring/).
// The CLI maps every `SyncError` variant onto the frozen exit-code
// contract (FR-063):
//
//   3 — `SyncConflict`  : `Unresolvable` (same-second divergence)
//   2 — `VaultLocked`   : `MasterPasswordMismatch`
//   1 — `UserError`     : `NotConfigured`, `DuplicateTarget`, `Auth`,
//                          `AuthFailed`, `S3(AuthFailed)` (remote 403 — see
//                          "Option B" below)
//   10+ — `Internal`    : `RemoteUnreachable`, `S3` (non-auth), `BackupFailed`,
//                          `ConditionalPutExhausted`, `VaultIo`, `Vault`,
//                          `Merge`, `CredentialDecryption`, `UnsupportedBackend`
//
// Option B (2026-07-19): a REMOTE authentication/authorization failure —
// the top-level `AuthFailed` and an S3 403 (`S3(S3Error::AuthFailed)`) — is
// a user error (exit 1), not internal. Its dominant causes (bad/expired
// credentials, bucket-policy denial) are user-fixable; the rarer
// signature-rejection sub-case is guarded by the SigV4 test-vector suite,
// not by reserving exit 10. Local vault auth (`MasterPasswordMismatch`)
// stays at exit 2.
//
// `SyncError` is `#[non_exhaustive]`, so the trailing arm catches
// future variants as `Internal` (with the upstream Display text).
//
// Exit 3 (`SyncConflict`) gets its mapping here: `SyncError::Unresolvable`
// converts to `CliExit::SyncConflict`. The `falach sync` command invokes
// this mapping at runtime and attaches the selected vault name before
// rendering the exit-3 diagnostic.
// ---------------------------------------------------------------------------

impl From<SyncError> for CliExit {
    fn from(e: SyncError) -> Self {
        use SyncError as E;
        match e {
            // 3 — conflict requiring the user (same-second unresolvable merge)
            E::Unresolvable {
                reason,
                backup_path,
            } => Self::SyncConflict {
                vault: String::new(),
                detail: format!(
                    "merge cannot proceed: {}; pre-merge backup at {}",
                    reason,
                    backup_path.display()
                ),
            },

            // 2 — auth failure (master-password / KDF mismatch between
            // local and remote vaults)
            E::MasterPasswordMismatch => Self::VaultLocked(
                "master password or KDF parameters differ between local and remote vault"
                    .to_string(),
            ),

            // 1 — user-config error (not configured, duplicate target, bad creds)
            E::NotConfigured => Self::UserError(
                "sync is not configured for this vault (run `falach vault set-sync ...`)"
                    .to_string(),
            ),
            E::DuplicateTarget {
                endpoint,
                bucket,
                key,
                existing_vault,
            } => Self::UserError(format!(
                "two vaults configured to the same S3 target \
                     (endpoint={endpoint:?} bucket={bucket} key={key}); \
                     existing vault: `{existing_vault}`"
            )),
            // Forward the specific discovery failure (missing file / profile /
            // env-var / IMDS) — `AuthError` names the offending source but
            // never the credential value, so this is safe to surface.
            E::Auth(inner) => Self::UserError(format!("credential discovery failed: {inner}")),

            // Remote authentication/authorization failure → user error, NOT
            // internal (feature decision "Option B", 2026-07-19). An S3 403
            // (or a top-level auth failure) is dominated by user-fixable
            // causes — wrong/expired credentials or a bucket-policy denial —
            // so exit 1 (`user.error`) is the honest signal: fix it and
            // re-run. The rarer "server rejected our signature" sub-case is
            // guarded by the SigV4 test-vector suite rather than by reserving
            // exit 10 for it. Both `endpoint` and `reason` are documented
            // non-secret; a 403 carries no credential value. This arm precedes
            // the general `E::S3(_)` arm below so `AuthFailed` is not swept
            // into `Internal`.
            E::AuthFailed { endpoint, reason } => Self::UserError(format!(
                "S3 authentication failed for {endpoint}: {reason} \
                 (check your credentials and bucket policy)"
            )),
            E::S3(falach_sync::s3::S3Error::AuthFailed) => Self::UserError(
                "S3 authentication or authorization failed (HTTP 403) — \
                 check your credentials and bucket policy"
                    .to_string(),
            ),

            // 10+ — transport / internal / unexpected failures
            E::RemoteUnreachable { endpoint, source } => {
                Self::Internal(format!("S3 endpoint unreachable: {endpoint} ({source})"))
            }
            E::ConditionalPutExhausted { attempts } => Self::Internal(format!(
                "conditional PUT exhausted after {attempts} retries; \
                 remote has advanced concurrently; retry `falach sync`"
            )),
            E::UnsupportedBackend { feature } => {
                Self::Internal(format!("S3 backend lacks required feature `{feature}`"))
            }
            E::BackupFailed { source } => {
                Self::Internal(format!("pre-merge backup creation failed: {source}"))
            }
            E::CredentialDecryption => Self::Internal(
                "invalid credential container (corrupt or wrong master password)".to_string(),
            ),
            E::S3(source) => Self::Internal(format!("S3 protocol error: {source}")),
            E::Merge(source) => Self::Internal(format!("merge engine error: {source}")),
            E::VaultIo { path, source } => Self::Internal(format!(
                "vault I/O during sync: {}: {source}",
                path.display()
            )),
            E::Vault(v) => CliExit::from(v),

            // `SyncError` is `#[non_exhaustive]`. A future variant
            // falls through here and is reported as `Internal`.
            other => Self::Internal(format!("unexpected sync error: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_code_table_matches_design() {
        assert_eq!(CliExit::Success.code(), 0);
        assert_eq!(CliExit::UserError(String::new()).code(), 1);
        assert_eq!(CliExit::VaultLocked(String::new()).code(), 2);
        assert_eq!(
            CliExit::SyncConflict {
                vault: String::new(),
                detail: String::new(),
            }
            .code(),
            3
        );
        assert_eq!(CliExit::Internal(String::new()).code(), 10);
        assert_eq!(CliExit::NotImplemented("x").code(), 11);
    }

    #[test]
    fn kind_strings_are_stable() {
        assert_eq!(CliExit::Success.kind(), "success");
        assert_eq!(CliExit::UserError(String::new()).kind(), "user.error");
        assert_eq!(CliExit::VaultLocked(String::new()).kind(), "vault.locked");
        assert_eq!(
            CliExit::SyncConflict {
                vault: String::new(),
                detail: String::new(),
            }
            .kind(),
            "sync.conflict"
        );
        assert_eq!(CliExit::Internal(String::new()).kind(), "internal");
        assert_eq!(CliExit::NotImplemented("x").kind(), "not.implemented");
    }

    #[test]
    fn message_never_panics_for_any_variant() {
        // Exhaustive constructor pass — every variant builds and the
        // `message()` accessor returns a String (smoke-only; semantics
        // are checked in render_human_tests below).
        for exit in [
            CliExit::Success,
            CliExit::UserError("u".into()),
            CliExit::VaultLocked("v".into()),
            CliExit::SyncConflict {
                vault: "x".into(),
                detail: "y".into(),
            },
            CliExit::Internal("i".into()),
            CliExit::NotImplemented("n"),
        ] {
            let _ = exit.message();
        }
    }

    #[test]
    fn render_human_includes_kind_and_message() {
        let mut buf = Vec::new();
        CliExit::UserError("missing flag".into())
            .render_human(&mut buf)
            .unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("error: user.error"), "{s:?}");
        assert!(s.contains("missing flag"), "{s:?}");
        assert!(s.ends_with('\n'), "expected trailing newline: {s:?}");
    }

    #[test]
    fn render_human_for_success_writes_nothing() {
        let mut buf = Vec::new();
        CliExit::Success.render_human(&mut buf).unwrap();
        assert!(buf.is_empty());
    }

    // ---- VaultError mapping -----------------------------------------

    #[test]
    fn vault_error_authentication_failed_maps_to_code_2() {
        let exit: CliExit = VaultError::AuthenticationFailed.into();
        assert_eq!(exit.code(), 2);
        assert_eq!(exit.kind(), "vault.locked");
    }

    #[test]
    fn vault_error_contended_with_pid_includes_pid_in_message() {
        let exit: CliExit = VaultError::Contended { holder: Some(4242) }.into();
        assert_eq!(exit.code(), 2);
        assert!(exit.message().contains("4242"), "{}", exit.message());
    }

    #[test]
    fn vault_error_not_registered_maps_to_user_error() {
        let exit: CliExit = VaultError::NotRegistered {
            name: "personal".into(),
        }
        .into();
        assert_eq!(exit.code(), 1);
        assert!(exit.message().contains("personal"));
    }

    #[test]
    fn vault_error_invalid_tag_maps_to_user_error() {
        let exit: CliExit = VaultError::InvalidTag {
            value: "a;b".into(),
        }
        .into();
        assert_eq!(exit.code(), 1);
        assert!(exit.message().contains("a;b"));
    }

    #[test]
    fn vault_error_attachment_too_large_maps_to_user_error_with_numbers() {
        let exit: CliExit = VaultError::AttachmentTooLarge {
            actual: 10_000,
            limit: 5_000,
        }
        .into();
        assert_eq!(exit.code(), 1);
        assert!(exit.message().contains("10000"), "{}", exit.message());
        assert!(exit.message().contains("5000"), "{}", exit.message());
    }

    #[test]
    fn vault_error_io_maps_to_internal_with_path() {
        let source = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let exit: CliExit = VaultError::Io {
            source,
            path: "/tmp/x.kdbx".into(),
        }
        .into();
        assert_eq!(exit.code(), 10);
        assert!(exit.message().contains("/tmp/x.kdbx"));
    }

    #[test]
    fn vault_error_home_unresolvable_maps_to_user_error() {
        let exit: CliExit = VaultError::HomeUnresolvable.into();
        assert_eq!(exit.code(), 1);
    }

    // ---- GenError mapping -------------------------------------------

    #[test]
    fn gen_error_invalid_length_maps_to_user_error() {
        let exit: CliExit = GenError::InvalidLength.into();
        assert_eq!(exit.code(), 1);
    }

    #[test]
    fn gen_error_no_classes_enabled_maps_to_user_error() {
        let exit: CliExit = GenError::NoClassesEnabled.into();
        assert_eq!(exit.code(), 1);
    }

    #[test]
    fn gen_error_length_too_short_includes_numbers() {
        let exit: CliExit = GenError::LengthTooShort {
            length: 2,
            classes: 4,
        }
        .into();
        assert_eq!(exit.code(), 1);
        assert!(exit.message().contains('2'));
        assert!(exit.message().contains('4'));
    }

    #[test]
    fn gen_error_alphabet_empty_maps_to_user_error() {
        let exit: CliExit = GenError::AlphabetEmpty.into();
        assert_eq!(exit.code(), 1);
    }

    #[test]
    fn gen_error_invalid_word_count_maps_to_user_error() {
        let exit: CliExit = GenError::InvalidWordCount.into();
        assert_eq!(exit.code(), 1);
    }

    // ---- SecurityError mapping -------------------------------------

    #[test]
    fn security_clipboard_unavailable_maps_to_internal() {
        let exit: CliExit = SecurityError::ClipboardUnavailable("no DISPLAY".into()).into();
        assert_eq!(exit.code(), 10);
        assert!(exit.message().contains("no DISPLAY"), "{}", exit.message());
    }

    #[test]
    fn security_clipboard_io_maps_to_internal() {
        let exit: CliExit = SecurityError::ClipboardIo {
            detail: "x11 down".into(),
        }
        .into();
        assert_eq!(exit.code(), 10);
        assert!(exit.message().contains("x11 down"), "{}", exit.message());
    }

    #[test]
    fn security_invalid_vault_lock_config_maps_to_user_error() {
        let exit: CliExit = SecurityError::InvalidVaultLockConfig {
            detail: "idle_timeout must be >= 1".into(),
        }
        .into();
        assert_eq!(exit.code(), 1);
    }

    #[test]
    fn security_invalid_auto_lock_config_maps_to_user_error() {
        let exit: CliExit = SecurityError::InvalidAutoLockConfig {
            detail: "zero".into(),
        }
        .into();
        assert_eq!(exit.code(), 1);
    }

    // ---- SyncError mapping ------------------------------------------
    //
    // `falach sync` is the only producer of exit 3 in the whole CLI, so
    // these are the sole guard on the `Unresolvable` -> 3 contract
    // (FR-063). Plan §7.2.1 / §7.6 step 1: highest-value, no-dependency
    // tests that anchor the T1.3 mapping.

    #[test]
    fn sync_error_unresolvable_maps_to_exit_3() {
        let exit: CliExit = SyncError::Unresolvable {
            reason: "same-second divergence".into(),
            backup_path: "/tmp/vault.kdbx.bak".into(),
        }
        .into();
        assert_eq!(exit.code(), 3);
        assert_eq!(exit.kind(), "sync.conflict");
        assert!(
            exit.message().contains("/tmp/vault.kdbx.bak"),
            "{}",
            exit.message()
        );
    }

    #[test]
    fn sync_error_master_password_mismatch_maps_to_exit_2() {
        let exit: CliExit = SyncError::MasterPasswordMismatch.into();
        assert_eq!(exit.code(), 2);
        assert_eq!(exit.kind(), "vault.locked");
    }

    #[test]
    fn sync_error_not_configured_maps_to_exit_1() {
        let exit: CliExit = SyncError::NotConfigured.into();
        assert_eq!(exit.code(), 1);
        assert_eq!(exit.kind(), "user.error");
    }

    #[test]
    fn sync_error_duplicate_target_maps_to_exit_1_with_detail() {
        let exit: CliExit = SyncError::DuplicateTarget {
            endpoint: None,
            bucket: "shared-bucket".into(),
            key: "vault.kdbx".into(),
            existing_vault: "work".into(),
        }
        .into();
        assert_eq!(exit.code(), 1);
        assert!(exit.message().contains("work"), "{}", exit.message());
        assert!(
            exit.message().contains("shared-bucket"),
            "{}",
            exit.message()
        );
    }

    #[test]
    fn sync_error_auth_maps_to_exit_1_and_names_the_source() {
        // A credential-*discovery* failure is a user/config error, and the
        // mapping must forward which source failed (never the value).
        let exit: CliExit = SyncError::Auth(falach_sync::AuthError::MissingEnvVar {
            name: "PERSONAL_AWS_ACCESS_KEY_ID".into(),
        })
        .into();
        assert_eq!(exit.code(), 1);
        assert!(
            exit.message().contains("PERSONAL_AWS_ACCESS_KEY_ID"),
            "auth mapping should name the failing source: {}",
            exit.message()
        );
    }

    #[test]
    fn sync_error_vault_delegates_to_vault_error_mapping() {
        // `Vault(v)` must produce the identical code to `From<VaultError>`
        // so the two impls never drift.
        assert_eq!(
            CliExit::from(SyncError::Vault(VaultError::AuthenticationFailed)).code(),
            CliExit::from(VaultError::AuthenticationFailed).code(),
        );
        assert_eq!(
            CliExit::from(SyncError::Vault(VaultError::NotRegistered {
                name: "personal".into(),
            }))
            .code(),
            CliExit::from(VaultError::NotRegistered {
                name: "personal".into(),
            })
            .code(),
        );
    }

    #[test]
    fn sync_error_transport_variants_map_to_internal() {
        let cases: Vec<CliExit> = vec![
            SyncError::RemoteUnreachable {
                endpoint: "https://s3.example".into(),
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timed out",
                )),
            }
            .into(),
            SyncError::ConditionalPutExhausted { attempts: 5 }.into(),
            SyncError::BackupFailed {
                source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
            }
            .into(),
            SyncError::S3(falach_sync::s3::S3Error::NotFound).into(),
        ];
        for exit in cases {
            assert!(
                exit.code() >= 10,
                "expected internal (>=10): {}",
                exit.message()
            );
            assert_eq!(exit.kind(), "internal");
        }
    }

    #[test]
    fn sync_error_remote_auth_maps_to_exit_1() {
        // Feature decision "Option B": a remote S3 authentication/authorization
        // failure (HTTP 403, or a top-level auth failure) is a USER error —
        // the dominant cause is wrong/expired credentials or a bucket-policy
        // denial, all user-fixable — NOT an internal (exit 10) failure.
        let s3_403: CliExit = SyncError::S3(falach_sync::s3::S3Error::AuthFailed).into();
        assert_eq!(
            s3_403.code(),
            1,
            "S3 403 must be a user error: {}",
            s3_403.message()
        );
        assert_eq!(s3_403.kind(), "user.error");

        let top_level: CliExit = SyncError::AuthFailed {
            endpoint: "https://s3.example".into(),
            reason: "signature mismatch".into(),
        }
        .into();
        assert_eq!(top_level.code(), 1, "{}", top_level.message());
        assert_eq!(top_level.kind(), "user.error");
        assert!(
            top_level.message().contains("https://s3.example"),
            "should name the endpoint: {}",
            top_level.message()
        );

        // Other S3 errors (e.g. NotFound) remain internal — only the auth
        // family moved.
        let not_found: CliExit = SyncError::S3(falach_sync::s3::S3Error::NotFound).into();
        assert_eq!(not_found.code(), 10, "non-auth S3 errors stay internal");
    }

    #[test]
    fn every_sync_error_variant_maps_and_message_leaks_no_secret() {
        // Representative of every SyncError variant. `SyncError` is
        // `#[non_exhaustive]` with a wildcard arm, so this guards that (1)
        // no known variant is routed to an unexpected code, and (2) no
        // mapped message carries secret material (mirrors falach-sync's
        // display_and_debug_never_leak_secret_markers).
        //
        // None of the non-secret fields constructed below contain these
        // markers, so any hit means a mapping interpolated something it
        // must not.
        const SECRET_MARKERS: [&str; 3] =
            ["-----begin", "secret_access_key", "aws_secret_access_key"];

        let all: Vec<SyncError> = vec![
            SyncError::NotConfigured,
            SyncError::RemoteUnreachable {
                endpoint: "https://s3.example".into(),
                source: Box::new(std::io::Error::other("boom")),
            },
            SyncError::AuthFailed {
                endpoint: "https://s3.example".into(),
                reason: "signature mismatch".into(),
            },
            SyncError::ConditionalPutExhausted { attempts: 3 },
            SyncError::DuplicateTarget {
                endpoint: Some("https://s3.example".into()),
                bucket: "b".into(),
                key: "k".into(),
                existing_vault: "other".into(),
            },
            SyncError::UnsupportedBackend {
                feature: "conditional-put".into(),
            },
            SyncError::MasterPasswordMismatch,
            SyncError::Unresolvable {
                reason: "same-second divergence".into(),
                backup_path: "/tmp/v.kdbx.bak".into(),
            },
            SyncError::BackupFailed {
                source: std::io::Error::other("io"),
            },
            SyncError::CredentialDecryption,
            SyncError::Auth(falach_sync::AuthError::HomeUnresolvable),
            SyncError::Merge(falach_sync::MergeError::Unresolvable {
                reason: "conflict".into(),
            }),
            SyncError::S3(falach_sync::s3::S3Error::NotFound),
            SyncError::Vault(VaultError::AuthenticationFailed),
            SyncError::VaultIo {
                path: "/tmp/v.kdbx".into(),
                source: std::io::Error::other("io"),
            },
        ];

        for err in all {
            let exit: CliExit = err.into();
            assert!(
                matches!(exit.code(), 1 | 2 | 3 | 10),
                "unexpected exit code {} / kind {}",
                exit.code(),
                exit.kind()
            );
            let msg = exit.message();
            assert!(!msg.is_empty(), "mapped message must be non-empty");
            let lowered = msg.to_ascii_lowercase();
            for marker in SECRET_MARKERS {
                assert!(
                    !lowered.contains(marker),
                    "message leaked secret marker {marker:?}: {msg}"
                );
            }
        }
    }
}
