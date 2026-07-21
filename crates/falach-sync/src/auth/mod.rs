// Domain acronyms saturate auth's docs; see the same note on
// `crate::s3::mod` for the rationale.
#![allow(clippy::doc_markdown)]

//! Per-vault S3 credential discovery (FR-045; design.md §2.2.7).
//!
//! The orchestrator (T5.2) calls [`resolve`] with the vault's configured
//! [`CredentialSource`], the user's `MasterPassword`, and an
//! [`env::EnvSource`] (`SystemEnvSource` in production, `MockEnvSource`
//! in tests). The four resolvers — RST-CRED-1, AWS-profile, EnvVars,
//! IAM-instance-role — each have distinct mechanics and failure modes;
//! [`AuthError`] enumerates them.
//!
//! **Design ADR-2 (RST-CRED-1 floor).** OS keychain integration is a
//! Phase-1 follow-on; Phase 0 ships only the four variants above. The
//! `#[non_exhaustive]` posture on [`CredentialSource`] keeps the
//! eventual `OsKeychain` addition non-breaking.
//!
//! **No implicit shell-env fallback.** Per FR-045, the configured
//! `CredentialSource` is the ONLY source consulted. The orchestrator
//! never reads `AWS_PROFILE` / `AWS_ACCESS_KEY_ID` from the shell
//! unless the vault explicitly declared an [`CredentialSource::EnvVars`]
//! source with a matching prefix.

pub mod env;
pub mod envvars;
pub mod error;
pub mod iam;
pub mod profile;
pub mod rstcred1;
pub mod source;

#[cfg(any(test, feature = "test-helpers"))]
pub use env::MockEnvSource;
pub use env::{EnvSource, SystemEnvSource};
pub use error::AuthError;
pub use rstcred1::encrypt_credential;
pub use source::{CredentialSource, ResolvedCredentials};

use falach_core::MasterPassword;

/// Dispatch on a [`CredentialSource`] variant and resolve to
/// [`ResolvedCredentials`]. Each variant has a separate resolver module
/// (`rstcred1`, `profile`, `envvars`, `iam`) — this function is a thin
/// pattern-match plus the prefix-emptiness defensive check.
///
/// # Errors
///
/// Returns [`AuthError`] with a variant that names the specific failure
/// mode (missing file, missing env var, decryption failure, etc.). The
/// orchestrator's `SyncError::AuthFailed` wraps this for the user-facing
/// message.
pub fn resolve(
    source: &CredentialSource,
    master_password: &MasterPassword,
    env: &dyn EnvSource,
) -> Result<ResolvedCredentials, AuthError> {
    match source {
        CredentialSource::RstCred1 {
            access_key_id,
            secret_access_key_encrypted,
        } => {
            rstcred1::resolve_rstcred1(access_key_id, secret_access_key_encrypted, master_password)
        }

        CredentialSource::AwsProfile {
            profile,
            credentials_file,
        } => profile::resolve_profile(profile, credentials_file.as_deref(), env),

        CredentialSource::EnvVars { prefix } => envvars::resolve_env_vars(prefix, env),

        CredentialSource::IamInstanceRole { imds_endpoint } => {
            iam::resolve_iam_instance_role(imds_endpoint.as_deref())
        }
    }
}
