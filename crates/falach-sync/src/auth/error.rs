// Domain acronyms (RST-CRED-1, IMDSv2, AWS, IAM, STS, ChaCha20-Poly1305,
// etc.) saturate the auth module's docs; backticking every one harms
// readability without catching real intra-doc-link bugs.
#![allow(clippy::doc_markdown)]

//! Errors surfaced by the [`crate::auth`] credential-resolution layer
//! (FR-045; design.md §2.2.7).
//!
//! Every resolution failure mode has a named variant so the orchestrator
//! (T5.2) can craft a user-facing message that names the credential
//! source the failure came from ("credentials from `[personal]` profile
//! in `~/.aws/credentials`: secret-access-key missing"). No variant
//! carries plaintext credentials — variants name the offending key,
//! profile, env-var, or endpoint, never the value behind it.

use std::path::PathBuf;

/// Errors returned by the four [`crate::auth::CredentialSource`] resolvers
/// (RST-CRED-1, AWS-profile, EnvVars, IAM-instance-role).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// The encrypted RST-CRED-1 container failed to decrypt. Could be wrong
    /// master password, corrupted ciphertext, or a tampered MAC tag — the
    /// three cases are deliberately indistinguishable (defense against
    /// timing-side-channels on which-bit-flipped).
    #[error(
        "RST-CRED-1 container decryption failed (wrong master password or corrupt ciphertext)"
    )]
    RstCred1Decryption,

    /// The RST-CRED-1 container had an invalid format (wrong magic bytes,
    /// truncated bytes, bad base64). Distinguished from `RstCred1Decryption`
    /// so the operator-facing message can suggest "your vaults.toml was
    /// edited by hand" instead of "wrong master password".
    #[error("RST-CRED-1 container is malformed: {reason}")]
    RstCred1Malformed {
        /// Non-secret reason string naming the format violation.
        reason: String,
    },

    /// The named AWS-profile section is absent from the credentials file.
    /// Names the profile so the user can fix the typo.
    #[error("AWS profile `{profile}` not found in {path}")]
    AwsProfileNotFound {
        /// The profile name that was requested.
        profile: String,
        /// The credentials-file path that was searched.
        path: PathBuf,
    },

    /// The AWS-credentials file does not exist at the resolved path.
    /// Distinct from `AwsProfileNotFound` so the operator-facing message
    /// can suggest "create `~/.aws/credentials`" instead of "fix the
    /// profile name typo".
    #[error("AWS credentials file not found: {path}")]
    AwsCredentialsFileNotFound {
        /// The path that was searched.
        path: PathBuf,
    },

    /// The AWS-credentials file exists but a required key is missing from
    /// the named profile section.
    #[error("AWS profile `{profile}` is missing required key `{key}`")]
    AwsProfileMissingKey {
        /// The profile name.
        profile: String,
        /// The missing key (e.g. `aws_secret_access_key`).
        key: String,
    },

    /// The credentials file could not be read (permissions, I/O error).
    #[error("AWS credentials file {path} could not be read: {source}")]
    AwsCredentialsFileReadFailed {
        /// The path that failed to read.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// `CredentialSource::EnvVars { prefix }` was constructed with an
    /// empty prefix string. This is the FR-045 footgun mitigation: an
    /// empty prefix would let a personal vault inherit
    /// `AWS_ACCESS_KEY_ID` from the user's shell-default profile.
    /// `Sync::configure_remote` rejects empty prefixes at config time
    /// (T5.1) so this error only surfaces from the resolver as a defense
    /// in depth.
    #[error("EnvVars credential source requires a non-empty prefix (FR-045 footgun mitigation)")]
    EmptyEnvPrefix,

    /// A required environment variable is missing for the EnvVars
    /// resolver. Names the variable so the user can populate it.
    #[error("environment variable `{name}` is not set (required by EnvVars credential source)")]
    MissingEnvVar {
        /// The full env-var name (prefix + suffix).
        name: String,
    },

    /// `HOME` cannot be resolved when expanding the default
    /// `~/.aws/credentials` path. Distinct from `AwsCredentialsFileNotFound`
    /// so the message can suggest setting `HOME` instead of creating the
    /// file.
    #[error("HOME environment variable is not set; cannot resolve default AWS credentials path")]
    HomeUnresolvable,

    /// The IMDS endpoint refused our connection. Common on non-EC2 boxes
    /// where the metadata service simply doesn't exist.
    #[error("IMDS endpoint {endpoint} unreachable: {reason}")]
    ImdsUnreachable {
        /// The IMDS endpoint URL.
        endpoint: String,
        /// Non-secret diagnostic from the underlying transport error.
        reason: String,
    },

    /// IMDS returned a response but no IAM role is attached to this
    /// instance.
    #[error("no IAM role attached to this instance (IMDS returned 404)")]
    NoIamRole,

    /// IMDS returned a credentials payload we could not parse (unexpected
    /// JSON shape, missing field, etc.).
    #[error("IMDS credentials response is malformed: {reason}")]
    ImdsMalformedResponse {
        /// Non-secret reason naming the format violation.
        reason: String,
    },

    /// IMDS returned an unexpected HTTP status.
    #[error("IMDS returned unexpected status {status}")]
    ImdsUnexpectedStatus {
        /// The HTTP status code that was received.
        status: u16,
    },
}
