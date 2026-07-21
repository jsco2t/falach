// Domain acronyms saturate this module; see `crate::s3::mod` for the
// rationale on suppressing `clippy::doc_markdown` at the module
// boundary.
#![allow(clippy::doc_markdown)]

//! [`CredentialSource`] (the per-vault declaration of how to obtain
//! S3 credentials, FR-045) and [`ResolvedCredentials`] (the
//! `ZeroizeOnDrop` result of resolving that declaration), per design.md
//! §2.2.7.
//!
//! The four variants of `CredentialSource` cover the Phase-0 set:
//! - [`CredentialSource::RstCred1`] — static access key + RST-CRED-1-encrypted
//!   secret stored in `vaults.toml`. The portability floor (ADR-2).
//! - [`CredentialSource::AwsProfile`] — named profile from `~/.aws/credentials`.
//! - [`CredentialSource::EnvVars`] — prefix-required env vars. The prefix is
//!   the FR-045 footgun mitigation that prevents personal vaults from
//!   inheriting `AWS_*` defaults set by the user's work shell.
//! - [`CredentialSource::IamInstanceRole`] — IMDSv2 metadata service for
//!   headless EC2 / ECS hosts.
//!
//! `OsKeychain` is deliberately absent in Phase 0 per ADR-2.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The per-vault declaration of how the orchestrator obtains S3
/// credentials. Serialized into `vaults.toml`'s
/// `[vaults.<name>.sync.s3.credentials]` sub-table in T5.1; the
/// `kind = "..."` tag drives the dispatch in [`crate::auth::resolve`].
///
/// `#[non_exhaustive]` so an `OsKeychain` variant added in Phase 1 is a
/// non-breaking change (per design ADR-2 deferral).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum CredentialSource {
    /// Static access key + RST-CRED-1-encrypted secret access key. The
    /// encrypted secret is decrypted with the master password the user
    /// supplied to unlock the vault; same trust model as the KDBX file
    /// itself.
    RstCred1 {
        /// Public AWS access-key identifier (e.g. `AKIA...`). Not secret
        /// per AWS posture (`access_key_id` appears in CloudTrail logs
        /// and IAM policies as cleartext).
        access_key_id: String,
        /// Base64-encoded RST-CRED-1 container holding the secret access
        /// key. Format: `RC01 + salt[16] + nonce[12] + ciphertext + tag[16]`,
        /// Argon2id-derived key, ChaCha20-Poly1305 AEAD.
        secret_access_key_encrypted: String,
    },

    /// Named profile from `~/.aws/credentials` (or a custom file path).
    /// `~/.aws/config` (with its `[profile name]` sections) is NOT read —
    /// only the credentials file with `[name]` sections.
    AwsProfile {
        /// The profile name (e.g. `"personal-vaults"`).
        profile: String,
        /// Optional override for the credentials file path. `None`
        /// resolves to `$HOME/.aws/credentials` via the [`crate::auth::env::EnvSource`]
        /// passed into the resolver.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        credentials_file: Option<PathBuf>,
    },

    /// Environment variables with a vault-specific prefix. The vault
    /// declares `prefix = "PERSONAL_"` and the resolver reads
    /// `PERSONAL_AWS_ACCESS_KEY_ID`, `PERSONAL_AWS_SECRET_ACCESS_KEY`,
    /// and (optionally) `PERSONAL_AWS_SESSION_TOKEN`. Empty prefix is
    /// rejected at `Sync::configure_remote` time (T5.1); the resolver
    /// also rejects defensively.
    EnvVars {
        /// Required non-empty per-vault prefix. The footgun this exists
        /// to prevent: a user's `AWS_PROFILE=work` shell shouldn't
        /// authenticate their personal vault to the work account.
        prefix: String,
    },

    /// IMDSv2 instance-metadata-service credentials for EC2 / ECS hosts
    /// running with an instance profile. Credentials rotate on the
    /// AWS-managed schedule (typically 6h); the orchestrator re-resolves
    /// when the cached `ResolvedCredentials::expiry` lapses.
    IamInstanceRole {
        /// Optional override for the IMDS endpoint URL (rare; default
        /// is the standard `http://169.254.169.254` link-local address).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        imds_endpoint: Option<String>,
    },
}

/// Resolved AWS credentials, ready to feed into the SigV4 signer
/// (`crate::s3::signer`) for request signing.
///
/// Secret material is held inside [`SecretString`] (from the `secrecy`
/// crate) so accidental `Debug` / `Display` / `serde::Serialize` paths
/// don't leak the value. The whole struct is `ZeroizeOnDrop` for
/// defense in depth.
///
/// The `Debug` derive masks every secret-bearing field; the `Clone`
/// derive duplicates secrets to a new `SecretString` (zeroized
/// independently on drop).
pub struct ResolvedCredentials {
    /// Public access-key identifier. Not secret per AWS posture; logged
    /// and shown in error messages.
    pub access_key_id: String,
    /// Secret access key. Held as [`SecretString`] so accidental logging
    /// / debug-printing surfaces `[REDACTED]`; access via
    /// `expose_secret()` for the signer.
    pub secret_access_key: SecretString,
    /// Optional session token for STS / IAM-instance-role temporary
    /// credentials. `None` for static long-lived credentials.
    pub session_token: Option<SecretString>,
    /// Credentials expiry. `None` for static credentials (RST-CRED-1,
    /// AWS-profile static, EnvVars). `Some(_)` for IAM-instance-role
    /// (and any future STS-derived source). The orchestrator (T5.2)
    /// re-resolves when `expiry < now + safety_margin`.
    pub expiry: Option<DateTime<Utc>>,
}

impl Zeroize for ResolvedCredentials {
    fn zeroize(&mut self) {
        // `access_key_id` is documented-non-secret per AWS posture but
        // we wipe it anyway as defense-in-depth (a memory dump that
        // finds an `AKIA...` is a signal worth denying).
        self.access_key_id.zeroize();
        // `SecretString` is `SecretBox<str>` and `SecretBox<S: Zeroize>`
        // implements `Zeroize` directly (vendor `secrecy/src/lib.rs:62`).
        // Call the trait method in place — no allocation, no
        // intermediate plaintext buffer.
        self.secret_access_key.zeroize();
        if let Some(t) = self.session_token.as_mut() {
            t.zeroize();
        }
        // DateTime is not secret material; nothing to zeroize.
        self.expiry = None;
    }
}

impl ZeroizeOnDrop for ResolvedCredentials {}

impl Drop for ResolvedCredentials {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for ResolvedCredentials {
    /// Mask every secret-bearing field. `access_key_id` is shown
    /// verbatim because it's documented-non-secret per AWS posture (it
    /// appears in `CloudTrail` logs and IAM policies as cleartext);
    /// masking it would block legitimate debugging.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expiry", &self.expiry)
            .finish()
    }
}

impl Clone for ResolvedCredentials {
    fn clone(&self) -> Self {
        // Critical: use `SecretString`'s native `Clone` (clones the
        // inner `Box<str>` directly). The naive
        // `SecretString::from(self.x.expose_secret().to_string())`
        // pattern would allocate an intermediate plaintext `String`
        // that gets freed without zeroization — exactly the leak
        // pattern CLAUDE.md's "Zeroize on drop for every type holding
        // sensitive bytes" rule exists to prevent.
        Self {
            access_key_id: self.access_key_id.clone(),
            secret_access_key: self.secret_access_key.clone(),
            session_token: self.session_token.clone(),
            expiry: self.expiry,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn resolved_credentials_debug_masks_secret_and_token() {
        let creds = ResolvedCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: SecretString::from("wJal...EKEY".to_string()),
            session_token: Some(SecretString::from("FQoG...token".to_string())),
            expiry: None,
        };
        let formatted = format!("{creds:?}");
        assert!(
            formatted.contains("AKIAIOSFODNN7EXAMPLE"),
            "access_key_id is documented-non-secret; show verbatim"
        );
        assert!(
            !formatted.contains("wJal"),
            "secret_access_key must NEVER appear in Debug output"
        );
        assert!(
            !formatted.contains("FQoG"),
            "session_token must NEVER appear in Debug output"
        );
        assert!(formatted.contains("<redacted>"));
    }

    #[test]
    fn resolved_credentials_zeroize_clears_observable_fields() {
        // Locks down the manual `Zeroize` impl: `access_key_id` is the
        // only field a test can observe post-zeroize without UB (the
        // others are inside `SecretString` whose internals are opaque).
        // Combined with the compile-time `ZeroizeOnDrop` bound check
        // (asserted in `resolve_profile_returns_zeroize_on_drop_credentials`
        // and the `impl ZeroizeOnDrop` itself), this pins the contract.
        let mut creds = ResolvedCredentials {
            access_key_id: "AKIA-DONT-PERSIST".to_string(),
            secret_access_key: SecretString::from("secret".to_string()),
            session_token: Some(SecretString::from("token".to_string())),
            expiry: Some(chrono::DateTime::<Utc>::MIN_UTC),
        };
        Zeroize::zeroize(&mut creds);
        assert!(
            creds.access_key_id.is_empty(),
            "access_key_id must be wiped on zeroize"
        );
        assert!(creds.expiry.is_none(), "expiry must be cleared on zeroize");
    }

    #[test]
    fn resolved_credentials_clone_duplicates_secret_independently() {
        let creds = ResolvedCredentials {
            access_key_id: "AKIA".to_string(),
            secret_access_key: SecretString::from("secret-value".to_string()),
            session_token: None,
            expiry: None,
        };
        let cloned = creds.clone();
        assert_eq!(cloned.access_key_id, "AKIA");
        assert_eq!(cloned.secret_access_key.expose_secret(), "secret-value");
    }
}
