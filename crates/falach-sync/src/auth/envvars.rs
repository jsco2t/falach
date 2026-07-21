// Domain acronyms saturate this module's docs.
#![allow(clippy::doc_markdown)]

//! Prefix-required environment-variable credential resolver
//! (FR-045; design.md §2.2.7).
//!
//! **The FR-045 footgun mitigation.** A user with `AWS_PROFILE=work` in
//! their shell environment must not be able to authenticate a personal
//! vault to the work account by accident. The mechanism: the per-vault
//! `CredentialSource::EnvVars { prefix }` requires a non-empty prefix
//! and reads `<prefix>AWS_ACCESS_KEY_ID` + `<prefix>AWS_SECRET_ACCESS_KEY`
//! (+ optional `<prefix>AWS_SESSION_TOKEN`). The user must explicitly
//! populate the per-vault variables; the shell-default `AWS_*` are
//! never read.
//!
//! `Sync::configure_remote` (T5.1) rejects empty prefixes at config
//! time; this resolver also rejects defensively to keep the invariant
//! intact even if someone hand-edits `vaults.toml`.

use secrecy::SecretString;

use crate::auth::env::EnvSource;
use crate::auth::error::AuthError;
use crate::auth::source::ResolvedCredentials;

/// Resolve a [`crate::auth::CredentialSource::EnvVars`] to
/// [`ResolvedCredentials`] by reading prefixed environment variables
/// via the [`EnvSource`].
///
/// # Errors
///
/// - [`AuthError::EmptyEnvPrefix`] — `prefix` is empty.
/// - [`AuthError::MissingEnvVar`] — required env var (with the prefix
///   applied) is not set in the env source.
pub fn resolve_env_vars(
    prefix: &str,
    env: &dyn EnvSource,
) -> Result<ResolvedCredentials, AuthError> {
    if prefix.is_empty() {
        return Err(AuthError::EmptyEnvPrefix);
    }

    let access_key_name = format!("{prefix}AWS_ACCESS_KEY_ID");
    let secret_key_name = format!("{prefix}AWS_SECRET_ACCESS_KEY");
    let session_token_name = format!("{prefix}AWS_SESSION_TOKEN");

    let access_key_id = env
        .get(&access_key_name)
        .ok_or_else(|| AuthError::MissingEnvVar {
            name: access_key_name.clone(),
        })?;
    let secret_access_key = env
        .get(&secret_key_name)
        .ok_or_else(|| AuthError::MissingEnvVar {
            name: secret_key_name.clone(),
        })?;
    let session_token = env.get(&session_token_name);

    Ok(ResolvedCredentials {
        access_key_id,
        secret_access_key: SecretString::from(secret_access_key),
        session_token: session_token.map(SecretString::from),
        expiry: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::env::MockEnvSource;
    use secrecy::ExposeSecret;

    // -- TC-AUTH-EV1 --------------------------------------------------------
    #[test]
    fn resolve_env_with_prefix_reads_prefixed_vars() {
        let env = MockEnvSource::with([
            ("MY_AWS_ACCESS_KEY_ID", "AKEX"),
            ("MY_AWS_SECRET_ACCESS_KEY", "secret-MY"),
        ]);
        let creds = resolve_env_vars("MY_", &env).expect("resolve");
        assert_eq!(creds.access_key_id, "AKEX");
        assert_eq!(creds.secret_access_key.expose_secret(), "secret-MY");
        assert!(creds.session_token.is_none());
    }

    // -- TC-AUTH-EV2 --------------------------------------------------------
    #[test]
    fn resolve_env_with_empty_prefix_returns_empty_env_prefix_error() {
        let env = MockEnvSource::with([("AWS_ACCESS_KEY_ID", "leak")]);
        let err = resolve_env_vars("", &env).expect_err("empty prefix");
        assert!(matches!(err, AuthError::EmptyEnvPrefix));
    }

    // -- TC-AUTH-EV3 --------------------------------------------------------
    #[test]
    fn resolve_env_with_missing_access_key_returns_missing_env_var() {
        let env = MockEnvSource::with([("MY_AWS_SECRET_ACCESS_KEY", "x")]);
        let err = resolve_env_vars("MY_", &env).expect_err("missing access key");
        match err {
            AuthError::MissingEnvVar { name } => assert_eq!(name, "MY_AWS_ACCESS_KEY_ID"),
            other => panic!("expected MissingEnvVar, got {other:?}"),
        }
    }

    // -- TC-AUTH-EV4 --------------------------------------------------------
    #[test]
    fn resolve_env_with_missing_secret_key_returns_missing_env_var() {
        let env = MockEnvSource::with([("MY_AWS_ACCESS_KEY_ID", "x")]);
        let err = resolve_env_vars("MY_", &env).expect_err("missing secret key");
        match err {
            AuthError::MissingEnvVar { name } => {
                assert_eq!(name, "MY_AWS_SECRET_ACCESS_KEY");
            }
            other => panic!("expected MissingEnvVar, got {other:?}"),
        }
    }

    // -- TC-AUTH-EV5 --------------------------------------------------------
    #[test]
    fn resolve_env_with_session_token_returns_session_token() {
        let env = MockEnvSource::with([
            ("PERSONAL_AWS_ACCESS_KEY_ID", "ASIA"),
            ("PERSONAL_AWS_SECRET_ACCESS_KEY", "temp"),
            ("PERSONAL_AWS_SESSION_TOKEN", "session-token-bytes"),
        ]);
        let creds = resolve_env_vars("PERSONAL_", &env).expect("resolve");
        assert_eq!(
            creds
                .session_token
                .as_ref()
                .map(secrecy::ExposeSecret::expose_secret),
            Some("session-token-bytes")
        );
    }

    // -- TC-AUTH-EV6 --------------------------------------------------------
    // The FR-045 footgun mitigation in action: a MockEnvSource holding
    // the unprefixed `AWS_*` triple plus NO prefixed equivalents → the
    // resolver returns an error, not a leak.
    #[test]
    fn resolve_env_does_not_read_unprefixed_vars() {
        let env = MockEnvSource::with([
            ("AWS_ACCESS_KEY_ID", "WORK-LEAK"),
            ("AWS_SECRET_ACCESS_KEY", "WORK-SECRET-LEAK"),
            ("AWS_SESSION_TOKEN", "WORK-SESSION-LEAK"),
        ]);
        let err = resolve_env_vars("PERSONAL_", &env).expect_err("must NOT read unprefixed");
        match err {
            AuthError::MissingEnvVar { name } => {
                assert_eq!(
                    name, "PERSONAL_AWS_ACCESS_KEY_ID",
                    "the error names the PREFIXED var the resolver looked for"
                );
            }
            other => panic!("expected MissingEnvVar, got {other:?}"),
        }
    }
}
