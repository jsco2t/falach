use falach_core::VaultError;
use falach_genpw::GenError;
use falach_security::SecurityError;
use falach_sync::auth::AuthError;
use falach_sync::s3::S3Error;
use falach_sync::SyncError;

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FalachApiError {
    #[error("authentication failed")]
    AuthenticationFailed,

    #[error("vault is locked")]
    VaultLocked,

    #[error("vault is busy syncing")]
    VaultBusySyncing,

    #[error("vault is held by another process")]
    VaultContended { holder_pid: Option<u32> },

    #[error("path already exists: {path}")]
    PathExists { path: String },

    #[error("file not found: {path}")]
    FileNotFound { path: String },

    #[error("keyfile is required")]
    KeyfileRequired,

    #[error("vault registry changed concurrently; reload and retry")]
    RegistryChanged,

    #[error("invalid vault format")]
    InvalidFormat,

    #[error("vault registry is malformed")]
    RegistryMalformed,

    #[error("sync is not configured")]
    SyncNotConfigured,

    #[error("sync endpoint unreachable")]
    SyncRemoteUnreachable { endpoint: Option<String> },

    #[error("sync authentication failed")]
    SyncAuthFailed,

    #[error("sync conflict cannot be auto-resolved; backup at {backup_path}")]
    SyncConflictUnresolvable { backup_path: String },

    #[error("another vault already syncs to this target: {existing_vault}")]
    SyncDuplicateTarget { existing_vault: String },

    #[error("invalid input: {field}: {reason}")]
    InvalidInput { field: String, reason: String },

    #[error("I/O error: {context}")]
    Io { context: String },

    #[error("internal error: {context}")]
    Internal { context: String },
}

impl From<VaultError> for FalachApiError {
    fn from(err: VaultError) -> Self {
        match err {
            VaultError::AuthenticationFailed => Self::AuthenticationFailed,
            VaultError::Contended { holder } => Self::VaultContended { holder_pid: holder },
            VaultError::PathExists { path } => Self::PathExists {
                path: path.display().to_string(),
            },
            VaultError::FileNotFound { path } => Self::FileNotFound {
                path: path.display().to_string(),
            },
            VaultError::RegistryChanged => Self::RegistryChanged,
            VaultError::InvalidFormat { .. } => Self::InvalidFormat,
            VaultError::RegistryMalformed { .. } => Self::RegistryMalformed,
            VaultError::HomeUnresolvable => Self::Io {
                context: "HOME is not set or not resolvable".to_string(),
            },
            VaultError::Io { path, .. } => Self::Io {
                context: format!("on {}", path.display()),
            },
            VaultError::WriteFailed { .. } => Self::Io {
                context: "KDBX write failed".to_string(),
            },
            VaultError::RegistrySerializationFailed { .. } => Self::Io {
                context: "registry serialization failed".to_string(),
            },
            VaultError::NotRegistered { name } => Self::FileNotFound { path: name },
            VaultError::AlreadyRegistered { name } => Self::PathExists { path: name },
            VaultError::NoRecoveryNotConfirmed => Self::InvalidInput {
                field: "confirmed_no_recovery".to_string(),
                reason: "no-recovery warning must be confirmed before vault creation".to_string(),
            },
            VaultError::EntryNotFound { uuid } => Self::InvalidInput {
                field: "uuid".to_string(),
                reason: format!("entry not found: {uuid}"),
            },
            VaultError::GroupNotFound { uuid } => Self::InvalidInput {
                field: "group".to_string(),
                reason: format!("group not found: {uuid}"),
            },
            VaultError::EntryHasNoTotp { uuid } => Self::InvalidInput {
                field: "uuid".to_string(),
                reason: format!("entry has no TOTP: {uuid}"),
            },
            VaultError::AttachmentTooLarge { actual, limit } => Self::InvalidInput {
                field: "attachment".to_string(),
                reason: format!("{actual} bytes exceeds limit of {limit} bytes"),
            },
            VaultError::AttachmentNotFound { .. } => Self::InvalidInput {
                field: "attachment".to_string(),
                reason: "attachment not found".to_string(),
            },
            VaultError::InvalidOtpUri { .. } => Self::InvalidInput {
                field: "totp_uri".to_string(),
                reason: "invalid otpauth URI".to_string(),
            },
            VaultError::InvalidAttachmentCap => Self::InvalidInput {
                field: "attachment_cap".to_string(),
                reason: "invalid attachment cap".to_string(),
            },
            VaultError::GroupNotEmpty { uuid } => Self::InvalidInput {
                field: "group".to_string(),
                reason: format!("group is not empty: {uuid}"),
            },
            VaultError::InvalidTag { .. } => Self::InvalidInput {
                field: "tag".to_string(),
                reason: "tag contains the forbidden ';' delimiter".to_string(),
            },
            VaultError::CannotModifyRoot => Self::InvalidInput {
                field: "group".to_string(),
                reason: "cannot move or delete the root group".to_string(),
            },
            VaultError::InvalidGroupTarget { reason } => Self::InvalidInput {
                field: "group".to_string(),
                reason: reason.to_string(),
            },
            VaultError::DatabaseIdentityMismatch { expected, found } => Self::Internal {
                context: format!("database identity mismatch: {found} vs {expected}"),
            },
            _ => Self::Internal {
                context: "unrecognized vault error".to_string(),
            },
        }
    }
}

impl From<SyncError> for FalachApiError {
    fn from(err: SyncError) -> Self {
        match err {
            SyncError::NotConfigured => Self::SyncNotConfigured,
            SyncError::RemoteUnreachable { endpoint, .. } => Self::SyncRemoteUnreachable {
                endpoint: Some(endpoint),
            },
            SyncError::Auth(AuthError::RstCred1Decryption) => Self::AuthenticationFailed,
            SyncError::Auth(AuthError::RstCred1Malformed { .. }) => Self::InvalidInput {
                field: "credential_source".to_string(),
                reason: "encrypted credential container is malformed".to_string(),
            },
            SyncError::Auth(
                AuthError::AwsProfileNotFound { .. }
                | AuthError::AwsProfileMissingKey { .. }
                | AuthError::EmptyEnvPrefix
                | AuthError::MissingEnvVar { .. }
                | AuthError::NoIamRole,
            ) => Self::InvalidInput {
                field: "credential_source".to_string(),
                reason: "configured credential source is unavailable or incomplete".to_string(),
            },
            SyncError::Auth(AuthError::AwsCredentialsFileNotFound { path }) => Self::FileNotFound {
                path: path.display().to_string(),
            },
            SyncError::Auth(AuthError::AwsCredentialsFileReadFailed { path, .. }) => Self::Io {
                context: format!("AWS credentials file could not be read: {}", path.display()),
            },
            SyncError::Auth(AuthError::HomeUnresolvable) => Self::Io {
                context: "HOME is not set or not resolvable".to_string(),
            },
            SyncError::Auth(AuthError::ImdsUnreachable { endpoint, .. }) => {
                Self::SyncRemoteUnreachable {
                    endpoint: Some(endpoint),
                }
            }
            SyncError::Auth(
                AuthError::ImdsMalformedResponse { .. } | AuthError::ImdsUnexpectedStatus { .. },
            ) => Self::Internal {
                context: "IMDS credential response error".to_string(),
            },
            SyncError::AuthFailed { .. } | SyncError::S3(S3Error::AuthFailed) => {
                Self::SyncAuthFailed
            }
            SyncError::ConditionalPutExhausted { .. } => Self::Internal {
                context: "conditional PUT exhausted; retry sync".to_string(),
            },
            SyncError::DuplicateTarget { existing_vault, .. } => {
                Self::SyncDuplicateTarget { existing_vault }
            }
            SyncError::UnsupportedBackend { feature } => Self::Internal {
                context: format!("unsupported backend feature: {feature}"),
            },
            SyncError::MasterPasswordMismatch | SyncError::CredentialDecryption => {
                Self::AuthenticationFailed
            }
            SyncError::Unresolvable { backup_path, .. } => Self::SyncConflictUnresolvable {
                backup_path: backup_path.display().to_string(),
            },
            SyncError::BackupFailed { .. } => Self::Io {
                context: "pre-merge backup creation failed".to_string(),
            },
            SyncError::Merge(_) => Self::Internal {
                context: "merge engine error".to_string(),
            },
            SyncError::S3(S3Error::RemoteUnreachable { .. } | S3Error::Http(_)) => {
                Self::SyncRemoteUnreachable { endpoint: None }
            }
            SyncError::S3(_) => Self::Internal {
                context: "S3 protocol error".to_string(),
            },
            SyncError::Vault(ve) => Self::from(ve),
            SyncError::VaultIo { path, .. } => Self::Io {
                context: format!("vault I/O during sync: {}", path.display()),
            },
            _ => Self::Internal {
                context: "unrecognized sync error".to_string(),
            },
        }
    }
}

impl From<SecurityError> for FalachApiError {
    fn from(err: SecurityError) -> Self {
        match err {
            SecurityError::ClipboardUnavailable(_) => Self::Io {
                context: "clipboard unavailable".to_string(),
            },
            SecurityError::ClipboardIo { .. } => Self::Io {
                context: "clipboard operation failed".to_string(),
            },
            SecurityError::EventSourceStart { name, .. } => Self::Io {
                context: format!("OS event source '{name}' failed"),
            },
            SecurityError::EventChannelClosed { name } => Self::Io {
                context: format!("OS event source '{name}' channel closed"),
            },
            SecurityError::InvalidVaultLockConfig { .. } => Self::InvalidInput {
                field: "lock_config".to_string(),
                reason: "invalid per-vault lock configuration".to_string(),
            },
            SecurityError::InvalidAutoLockConfig { .. } => Self::InvalidInput {
                field: "auto_lock_config".to_string(),
                reason: "invalid auto-lock configuration".to_string(),
            },
            _ => Self::Internal {
                context: "unrecognized security error".to_string(),
            },
        }
    }
}

impl From<GenError> for FalachApiError {
    fn from(err: GenError) -> Self {
        match err {
            GenError::InvalidLength => Self::InvalidInput {
                field: "length".to_string(),
                reason: "must be at least 1".to_string(),
            },
            GenError::NoClassesEnabled => Self::InvalidInput {
                field: "classes".to_string(),
                reason: "at least one character class must be enabled".to_string(),
            },
            GenError::LengthTooShort { length, classes } => Self::InvalidInput {
                field: "length".to_string(),
                reason: format!(
                    "length {length} cannot satisfy at-least-one-of-each for {classes} classes"
                ),
            },
            GenError::AlphabetEmpty => Self::InvalidInput {
                field: "classes".to_string(),
                reason: "alphabet is empty after ambiguous filter".to_string(),
            },
            GenError::InvalidWordCount => Self::InvalidInput {
                field: "words".to_string(),
                reason: "must be at least 1".to_string(),
            },
            GenError::Csprng(_) => Self::Internal {
                context: "OS CSPRNG failure".to_string(),
            },
            // GenError is not #[non_exhaustive] today, but defensive:
            #[allow(unreachable_patterns)]
            _ => Self::Internal {
                context: "unrecognized password-generation error".to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARKER_SECRET: &str = "MARKER-p@ss-S3CR3T";

    fn assert_no_secret(err: &FalachApiError) {
        let display = format!("{err}");
        let debug = format!("{err:?}");
        assert!(
            !display.contains(MARKER_SECRET),
            "Display contains secret: {display}"
        );
        assert!(
            !debug.contains(MARKER_SECRET),
            "Debug contains secret: {debug}"
        );
    }

    fn invalid_input(field: &str, reason: impl Into<String>) -> FalachApiError {
        FalachApiError::InvalidInput {
            field: field.to_string(),
            reason: reason.into(),
        }
    }

    fn assert_vault_mappings(cases: Vec<(VaultError, FalachApiError)>) {
        for (upstream, expected) in cases {
            let case = format!("{upstream:?}");
            assert_eq!(FalachApiError::from(upstream), expected, "case: {case}");
        }
    }

    #[test]
    fn vault_filesystem_registry_and_auth_errors_map_exactly() {
        use std::path::PathBuf;

        assert_vault_mappings(vec![
            (
                VaultError::HomeUnresolvable,
                FalachApiError::Io {
                    context: "HOME is not set or not resolvable".to_string(),
                },
            ),
            (
                VaultError::PathExists {
                    path: PathBuf::from("/test"),
                },
                FalachApiError::PathExists {
                    path: "/test".to_string(),
                },
            ),
            (
                VaultError::FileNotFound {
                    path: PathBuf::from("/test"),
                },
                FalachApiError::FileNotFound {
                    path: "/test".to_string(),
                },
            ),
            (
                VaultError::AuthenticationFailed,
                FalachApiError::AuthenticationFailed,
            ),
            (
                VaultError::Contended { holder: Some(1234) },
                FalachApiError::VaultContended {
                    holder_pid: Some(1234),
                },
            ),
            (VaultError::RegistryChanged, FalachApiError::RegistryChanged),
            (
                VaultError::RegistryMalformed { source: None },
                FalachApiError::RegistryMalformed,
            ),
            (
                VaultError::Io {
                    source: std::io::Error::other("source detail"),
                    path: PathBuf::from("/test"),
                },
                FalachApiError::Io {
                    context: "on /test".to_string(),
                },
            ),
            (
                VaultError::NotRegistered {
                    name: "test".to_string(),
                },
                FalachApiError::FileNotFound {
                    path: "test".to_string(),
                },
            ),
            (
                VaultError::AlreadyRegistered {
                    name: "test".to_string(),
                },
                FalachApiError::PathExists {
                    path: "test".to_string(),
                },
            ),
        ]);
    }

    #[test]
    fn vault_entry_and_group_errors_map_exactly() {
        use falach_core::Uuid;

        let nil = Uuid::nil();
        assert_vault_mappings(vec![
            (
                VaultError::NoRecoveryNotConfirmed,
                invalid_input(
                    "confirmed_no_recovery",
                    "no-recovery warning must be confirmed before vault creation",
                ),
            ),
            (
                VaultError::EntryNotFound { uuid: nil },
                invalid_input("uuid", format!("entry not found: {nil}")),
            ),
            (
                VaultError::GroupNotFound { uuid: nil },
                invalid_input("group", format!("group not found: {nil}")),
            ),
            (
                VaultError::EntryHasNoTotp { uuid: nil },
                invalid_input("uuid", format!("entry has no TOTP: {nil}")),
            ),
            (
                VaultError::AttachmentTooLarge {
                    actual: 10,
                    limit: 5,
                },
                invalid_input("attachment", "10 bytes exceeds limit of 5 bytes"),
            ),
            (
                VaultError::AttachmentNotFound {
                    name: "x".to_string(),
                },
                invalid_input("attachment", "attachment not found"),
            ),
            (
                VaultError::InvalidAttachmentCap,
                invalid_input("attachment_cap", "invalid attachment cap"),
            ),
            (
                VaultError::GroupNotEmpty { uuid: nil },
                invalid_input("group", format!("group is not empty: {nil}")),
            ),
            (
                VaultError::InvalidTag {
                    value: "a;b".to_string(),
                },
                invalid_input("tag", "tag contains the forbidden ';' delimiter"),
            ),
            (
                VaultError::CannotModifyRoot,
                invalid_input("group", "cannot move or delete the root group"),
            ),
            (
                VaultError::InvalidGroupTarget { reason: "test" },
                invalid_input("group", "test"),
            ),
            (
                VaultError::DatabaseIdentityMismatch {
                    expected: nil,
                    found: nil,
                },
                FalachApiError::Internal {
                    context: format!("database identity mismatch: {nil} vs {nil}"),
                },
            ),
        ]);

        let invalid_otp = falach_core::Totp::from_otpauth_uri("not-an-otpauth-uri")
            .expect_err("malformed URI should fail");
        assert_eq!(
            FalachApiError::from(invalid_otp),
            invalid_input("totp_uri", "invalid otpauth URI")
        );
    }

    #[test]
    fn constructible_sync_errors_map_to_exact_api_categories() {
        use std::path::PathBuf;

        let cases: Vec<(SyncError, FalachApiError)> = vec![
            (SyncError::NotConfigured, FalachApiError::SyncNotConfigured),
            (
                SyncError::RemoteUnreachable {
                    endpoint: "https://s3.test".to_string(),
                    source: Box::new(std::io::Error::other("timeout")),
                },
                FalachApiError::SyncRemoteUnreachable {
                    endpoint: Some("https://s3.test".to_string()),
                },
            ),
            (
                SyncError::AuthFailed {
                    endpoint: "https://s3.test".to_string(),
                    reason: "forbidden".to_string(),
                },
                FalachApiError::SyncAuthFailed,
            ),
            (
                SyncError::ConditionalPutExhausted { attempts: 3 },
                FalachApiError::Internal {
                    context: "conditional PUT exhausted; retry sync".to_string(),
                },
            ),
            (
                SyncError::DuplicateTarget {
                    endpoint: Some("https://s3.test".to_string()),
                    bucket: "b".to_string(),
                    key: "k".to_string(),
                    existing_vault: "other".to_string(),
                },
                FalachApiError::SyncDuplicateTarget {
                    existing_vault: "other".to_string(),
                },
            ),
            (
                SyncError::UnsupportedBackend {
                    feature: "conditional-put".to_string(),
                },
                FalachApiError::Internal {
                    context: "unsupported backend feature: conditional-put".to_string(),
                },
            ),
            (
                SyncError::MasterPasswordMismatch,
                FalachApiError::AuthenticationFailed,
            ),
            (
                SyncError::Unresolvable {
                    reason: "same-second".to_string(),
                    backup_path: PathBuf::from("/test.bak"),
                },
                FalachApiError::SyncConflictUnresolvable {
                    backup_path: "/test.bak".to_string(),
                },
            ),
            (
                SyncError::BackupFailed {
                    source: std::io::Error::other("test"),
                },
                FalachApiError::Io {
                    context: "pre-merge backup creation failed".to_string(),
                },
            ),
            (
                SyncError::CredentialDecryption,
                FalachApiError::AuthenticationFailed,
            ),
            (
                SyncError::Merge(falach_sync::MergeError::Unresolvable {
                    reason: "conflict".to_string(),
                }),
                FalachApiError::Internal {
                    context: "merge engine error".to_string(),
                },
            ),
            (
                SyncError::Vault(VaultError::AuthenticationFailed),
                FalachApiError::AuthenticationFailed,
            ),
            (
                SyncError::VaultIo {
                    path: PathBuf::from("/test"),
                    source: std::io::Error::other("test"),
                },
                FalachApiError::Io {
                    context: "vault I/O during sync: /test".to_string(),
                },
            ),
        ];

        for (upstream, expected) in cases {
            let case = format!("{upstream:?}");
            assert_eq!(FalachApiError::from(upstream), expected, "case: {case}");
        }
    }

    #[test]
    fn every_current_auth_error_maps_to_the_exact_actionable_category() {
        use std::path::PathBuf;

        let unavailable_source = FalachApiError::InvalidInput {
            field: "credential_source".to_string(),
            reason: "configured credential source is unavailable or incomplete".to_string(),
        };
        let cases = vec![
            (
                AuthError::RstCred1Decryption,
                FalachApiError::AuthenticationFailed,
            ),
            (
                AuthError::RstCred1Malformed {
                    reason: "bad magic".to_string(),
                },
                FalachApiError::InvalidInput {
                    field: "credential_source".to_string(),
                    reason: "encrypted credential container is malformed".to_string(),
                },
            ),
            (
                AuthError::AwsProfileNotFound {
                    profile: "missing".to_string(),
                    path: PathBuf::from("/credentials"),
                },
                unavailable_source.clone(),
            ),
            (
                AuthError::AwsCredentialsFileNotFound {
                    path: PathBuf::from("/credentials"),
                },
                FalachApiError::FileNotFound {
                    path: "/credentials".to_string(),
                },
            ),
            (
                AuthError::AwsProfileMissingKey {
                    profile: "profile".to_string(),
                    key: "aws_secret_access_key".to_string(),
                },
                unavailable_source.clone(),
            ),
            (
                AuthError::AwsCredentialsFileReadFailed {
                    path: PathBuf::from("/credentials"),
                    source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
                },
                FalachApiError::Io {
                    context: "AWS credentials file could not be read: /credentials".to_string(),
                },
            ),
            (AuthError::EmptyEnvPrefix, unavailable_source.clone()),
            (
                AuthError::MissingEnvVar {
                    name: "APP_ACCESS_KEY_ID".to_string(),
                },
                unavailable_source.clone(),
            ),
            (
                AuthError::HomeUnresolvable,
                FalachApiError::Io {
                    context: "HOME is not set or not resolvable".to_string(),
                },
            ),
            (
                AuthError::ImdsUnreachable {
                    endpoint: "http://169.254.169.254".to_string(),
                    reason: "timeout".to_string(),
                },
                FalachApiError::SyncRemoteUnreachable {
                    endpoint: Some("http://169.254.169.254".to_string()),
                },
            ),
            (AuthError::NoIamRole, unavailable_source),
            (
                AuthError::ImdsMalformedResponse {
                    reason: "bad JSON".to_string(),
                },
                FalachApiError::Internal {
                    context: "IMDS credential response error".to_string(),
                },
            ),
            (
                AuthError::ImdsUnexpectedStatus { status: 500 },
                FalachApiError::Internal {
                    context: "IMDS credential response error".to_string(),
                },
            ),
        ];

        for (upstream, expected) in cases {
            let case = format!("{upstream:?}");
            assert_eq!(
                FalachApiError::from(SyncError::Auth(upstream)),
                expected,
                "case: {case}"
            );
        }
    }

    #[test]
    fn every_current_security_error_maps_to_the_exact_api_category() {
        let cases = vec![
            (
                SecurityError::ClipboardUnavailable("no DISPLAY".to_string()),
                FalachApiError::Io {
                    context: "clipboard unavailable".to_string(),
                },
            ),
            (
                SecurityError::ClipboardIo {
                    detail: "test".to_string(),
                },
                FalachApiError::Io {
                    context: "clipboard operation failed".to_string(),
                },
            ),
            (
                SecurityError::EventSourceStart {
                    name: "test",
                    detail: "test".to_string(),
                },
                FalachApiError::Io {
                    context: "OS event source 'test' failed".to_string(),
                },
            ),
            (
                SecurityError::EventChannelClosed { name: "test" },
                FalachApiError::Io {
                    context: "OS event source 'test' channel closed".to_string(),
                },
            ),
            (
                SecurityError::InvalidVaultLockConfig {
                    detail: "test".to_string(),
                },
                FalachApiError::InvalidInput {
                    field: "lock_config".to_string(),
                    reason: "invalid per-vault lock configuration".to_string(),
                },
            ),
            (
                SecurityError::InvalidAutoLockConfig {
                    detail: "test".to_string(),
                },
                FalachApiError::InvalidInput {
                    field: "auto_lock_config".to_string(),
                    reason: "invalid auto-lock configuration".to_string(),
                },
            ),
        ];

        for (upstream, expected) in cases {
            let case = format!("{upstream:?}");
            assert_eq!(FalachApiError::from(upstream), expected, "case: {case}");
        }
    }

    #[test]
    fn every_constructible_generation_error_maps_to_the_exact_api_category() {
        let cases = vec![
            (
                GenError::InvalidLength,
                FalachApiError::InvalidInput {
                    field: "length".to_string(),
                    reason: "must be at least 1".to_string(),
                },
            ),
            (
                GenError::NoClassesEnabled,
                FalachApiError::InvalidInput {
                    field: "classes".to_string(),
                    reason: "at least one character class must be enabled".to_string(),
                },
            ),
            (
                GenError::LengthTooShort {
                    length: 2,
                    classes: 4,
                },
                FalachApiError::InvalidInput {
                    field: "length".to_string(),
                    reason: "length 2 cannot satisfy at-least-one-of-each for 4 classes"
                        .to_string(),
                },
            ),
            (
                GenError::AlphabetEmpty,
                FalachApiError::InvalidInput {
                    field: "classes".to_string(),
                    reason: "alphabet is empty after ambiguous filter".to_string(),
                },
            ),
            (
                GenError::InvalidWordCount,
                FalachApiError::InvalidInput {
                    field: "words".to_string(),
                    reason: "must be at least 1".to_string(),
                },
            ),
        ];

        for (upstream, expected) in cases {
            let case = format!("{upstream:?}");
            assert_eq!(FalachApiError::from(upstream), expected, "case: {case}");
        }
    }

    #[test]
    fn rendered_messages_never_contain_secret_material() {
        let marker_vault_err = VaultError::Io {
            source: std::io::Error::other(MARKER_SECRET),
            path: std::path::PathBuf::from("/vaults/test.kdbx"),
        };
        let api_err = FalachApiError::from(marker_vault_err);
        let display = format!("{api_err}");
        assert!(
            !display.contains(MARKER_SECRET),
            "VaultError::Io source error message leaked: {display}"
        );

        for marker_vault_err in [
            VaultError::AttachmentNotFound {
                name: MARKER_SECRET.to_string(),
            },
            VaultError::InvalidTag {
                value: MARKER_SECRET.to_string(),
            },
        ] {
            assert_no_secret(&FalachApiError::from(marker_vault_err));
        }

        for marker_security_err in [
            SecurityError::ClipboardUnavailable(MARKER_SECRET.to_string()),
            SecurityError::ClipboardIo {
                detail: MARKER_SECRET.to_string(),
            },
            SecurityError::EventSourceStart {
                name: "test",
                detail: MARKER_SECRET.to_string(),
            },
            SecurityError::InvalidVaultLockConfig {
                detail: MARKER_SECRET.to_string(),
            },
            SecurityError::InvalidAutoLockConfig {
                detail: MARKER_SECRET.to_string(),
            },
        ] {
            assert_no_secret(&FalachApiError::from(marker_security_err));
        }

        let marker_s3_err = SyncError::S3(S3Error::Unexpected {
            status: 500,
            reason: MARKER_SECRET.to_string(),
        });
        assert_no_secret(&FalachApiError::from(marker_s3_err));

        let marker_auth_err = SyncError::Auth(AuthError::RstCred1Malformed {
            reason: MARKER_SECRET.to_string(),
        });
        assert_no_secret(&FalachApiError::from(marker_auth_err));
    }

    #[test]
    fn nested_s3_errors_keep_actionable_api_categories() {
        assert!(matches!(
            FalachApiError::from(SyncError::S3(S3Error::AuthFailed)),
            FalachApiError::SyncAuthFailed
        ));
        assert!(matches!(
            FalachApiError::from(SyncError::S3(S3Error::RemoteUnreachable {
                reason: "server unavailable".to_string(),
            })),
            FalachApiError::SyncRemoteUnreachable { endpoint: None }
        ));
        assert!(matches!(
            FalachApiError::from(SyncError::S3(S3Error::Http(
                falach_sync::s3::HttpError::Io("timeout".to_string()),
            ))),
            FalachApiError::SyncRemoteUnreachable { endpoint: None }
        ));

        let protocol = FalachApiError::from(SyncError::S3(S3Error::Unexpected {
            status: 418,
            reason: "unexpected response".to_string(),
        }));
        assert_eq!(
            protocol,
            FalachApiError::Internal {
                context: "S3 protocol error".to_string(),
            }
        );
    }

    #[test]
    fn authentication_failure_is_indistinct_between_password_and_keyfile() {
        let from_password = FalachApiError::from(VaultError::AuthenticationFailed);
        let from_sync_mismatch = FalachApiError::from(SyncError::MasterPasswordMismatch);
        let from_cred_decrypt = FalachApiError::from(SyncError::CredentialDecryption);

        assert!(matches!(
            from_password,
            FalachApiError::AuthenticationFailed
        ));
        assert!(matches!(
            from_sync_mismatch,
            FalachApiError::AuthenticationFailed
        ));
        assert!(matches!(
            from_cred_decrypt,
            FalachApiError::AuthenticationFailed
        ));
    }
}
