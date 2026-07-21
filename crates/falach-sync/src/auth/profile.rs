// Domain acronyms saturate this module's docs.
#![allow(clippy::doc_markdown)]

//! AWS-profile resolver (FR-045 / design.md §2.2.7) — reads
//! `~/.aws/credentials` (or a custom path) and returns the named
//! profile's credentials.
//!
//! **Scope:** ONLY the credentials file. AWS distinguishes
//! `~/.aws/config` (with `[profile name]` sections, also containing
//! settings like `region` and `output`) from `~/.aws/credentials`
//! (with `[name]` sections, ONLY credentials). We read only the latter
//! because the design's `[vaults.<name>.sync.s3.credentials.profile]`
//! field is the credentials-file profile, and the region lives in
//! `S3Config::region` not in the profile.
//!
//! **INI parser shape:** hand-rolled ~50 LoC. Recognizes
//! `[section_name]` headers, `key = value` lines, comments (`#` or `;`
//! prefix), and blank lines. No multi-line continuations, no
//! `${var}` interpolation, no quoted values — AWS's own credentials
//! files use only the simple form.

use std::fs;
use std::path::{Path, PathBuf};

use secrecy::SecretString;
use zeroize::Zeroize;

use crate::auth::env::EnvSource;
use crate::auth::error::AuthError;
use crate::auth::source::ResolvedCredentials;

/// Resolve a named profile from an AWS-credentials file.
///
/// `credentials_file = None` resolves to `$HOME/.aws/credentials` via
/// the [`EnvSource`] (so tests can inject a fake `HOME`); `Some(path)`
/// uses that path verbatim.
///
/// # Errors
///
/// - [`AuthError::HomeUnresolvable`] — `HOME` is unset/empty.
/// - [`AuthError::AwsCredentialsFileNotFound`] — the resolved file
///   does not exist.
/// - [`AuthError::AwsCredentialsFileReadFailed`] — the file cannot be
///   read.
/// - [`AuthError::AwsProfileNotFound`] — the profile section is absent.
/// - [`AuthError::AwsProfileMissingKey`] — the section lacks
///   `aws_access_key_id` or `aws_secret_access_key`.
pub fn resolve_profile(
    profile: &str,
    credentials_file: Option<&Path>,
    env: &dyn EnvSource,
) -> Result<ResolvedCredentials, AuthError> {
    let path = match credentials_file {
        Some(p) => p.to_path_buf(),
        None => default_credentials_path(env)?,
    };

    if !path.exists() {
        return Err(AuthError::AwsCredentialsFileNotFound { path });
    }

    let mut contents =
        fs::read_to_string(&path).map_err(|source| AuthError::AwsCredentialsFileReadFailed {
            path: path.clone(),
            source,
        })?;

    // `find_section` returns an owned copy of the matched section; the
    // whole-file buffer (which holds every profile's secrets) is no longer
    // needed, so wipe it before it drops (CLAUDE.md "zeroize on drop for
    // every type holding sensitive bytes").
    let section = find_section(&contents, profile);
    contents.zeroize();
    let mut section = section.ok_or_else(|| AuthError::AwsProfileNotFound {
        profile: profile.to_string(),
        path: path.clone(),
    })?;

    let access_key_id = get_required_key(&section, "aws_access_key_id", profile)?.to_string();
    let secret_access_key_str =
        get_required_key(&section, "aws_secret_access_key", profile)?.to_string();
    let session_token_str = get_optional_key(&section, "aws_session_token").map(str::to_string);
    // The matched section still holds the plaintext secret; wipe it too.
    section.zeroize();

    Ok(ResolvedCredentials {
        access_key_id,
        secret_access_key: SecretString::from(secret_access_key_str),
        session_token: session_token_str.map(SecretString::from),
        expiry: None,
    })
}

/// Default `$HOME/.aws/credentials` path, with `HOME` read via the
/// injected [`EnvSource`] so tests stay deterministic.
fn default_credentials_path(env: &dyn EnvSource) -> Result<PathBuf, AuthError> {
    let home = env
        .get("HOME")
        .filter(|s| !s.is_empty())
        .ok_or(AuthError::HomeUnresolvable)?;
    let mut path = PathBuf::from(home);
    path.push(".aws");
    path.push("credentials");
    Ok(path)
}

/// Find the section body for `target` in an INI-formatted file. Returns
/// the section text (everything between the `[target]` header and the
/// next `[section]` header or EOF), or `None` if the section is absent.
fn find_section(contents: &str, target: &str) -> Option<String> {
    let header = format!("[{target}]");
    let mut in_target = false;
    let mut body = String::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            // A new section header.
            if in_target {
                // We were inside `target`; the next section ends it.
                return Some(body);
            }
            if name == target || header == trimmed {
                in_target = true;
            }
            continue;
        }
        if in_target {
            body.push_str(line);
            body.push('\n');
        }
    }
    if in_target {
        Some(body)
    } else {
        None
    }
}

/// Look up `key` in a section body; return `Some(value)` or `None`.
/// Skips comments (`#` or `;`) and blank lines.
fn get_optional_key<'sec>(section: &'sec str, key: &str) -> Option<&'sec str> {
    for line in section.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some(eq) = trimmed.find('=') {
            let (k, v) = trimmed.split_at(eq);
            let k = k.trim();
            // `v` starts with `=`; skip it and trim whitespace.
            let v = v[1..].trim();
            if k == key {
                return Some(v);
            }
        }
    }
    None
}

/// Look up `key` and error with `AwsProfileMissingKey` if absent.
fn get_required_key<'sec>(
    section: &'sec str,
    key: &str,
    profile: &str,
) -> Result<&'sec str, AuthError> {
    get_optional_key(section, key).ok_or_else(|| AuthError::AwsProfileMissingKey {
        profile: profile.to_string(),
        key: key.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::env::MockEnvSource;
    use secrecy::ExposeSecret;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Create a credentials-file with the given body in a tempfile;
    /// returns the path + the file (file is kept alive via the returned
    /// value).
    fn make_credentials_file(body: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tempfile");
        write!(f, "{body}").expect("write");
        f
    }

    fn empty_env() -> MockEnvSource {
        MockEnvSource::default()
    }

    // -- TC-AUTH-PR1 --------------------------------------------------------
    #[test]
    fn resolve_profile_reads_named_profile_from_tempfile() {
        let body = "\
[personal]
aws_access_key_id = AKIAPERSONAL
aws_secret_access_key = secret-personal
";
        let f = make_credentials_file(body);
        let creds = resolve_profile("personal", Some(f.path()), &empty_env()).expect("resolve");
        assert_eq!(creds.access_key_id, "AKIAPERSONAL");
        assert_eq!(creds.secret_access_key.expose_secret(), "secret-personal");
        assert!(creds.session_token.is_none());
        assert!(creds.expiry.is_none());
    }

    // -- TC-AUTH-PR2 --------------------------------------------------------
    #[test]
    fn resolve_profile_with_missing_profile_returns_auth_failed() {
        let body = "\
[other]
aws_access_key_id = X
aws_secret_access_key = Y
";
        let f = make_credentials_file(body);
        let err =
            resolve_profile("personal", Some(f.path()), &empty_env()).expect_err("missing profile");
        match err {
            AuthError::AwsProfileNotFound { profile, .. } => {
                assert_eq!(profile, "personal");
            }
            other => panic!("expected AwsProfileNotFound, got {other:?}"),
        }
    }

    // -- TC-AUTH-PR3 --------------------------------------------------------
    #[test]
    fn resolve_profile_with_missing_secret_key_returns_auth_failed() {
        let body = "\
[personal]
aws_access_key_id = X
";
        let f = make_credentials_file(body);
        let err =
            resolve_profile("personal", Some(f.path()), &empty_env()).expect_err("missing secret");
        match err {
            AuthError::AwsProfileMissingKey { profile, key } => {
                assert_eq!(profile, "personal");
                assert_eq!(key, "aws_secret_access_key");
            }
            other => panic!("expected AwsProfileMissingKey, got {other:?}"),
        }
    }

    // -- TC-AUTH-PR4 --------------------------------------------------------
    #[test]
    fn resolve_profile_handles_session_token_when_present() {
        let body = "\
[sts-derived]
aws_access_key_id = ASIA
aws_secret_access_key = temp
aws_session_token = FwoG...token
";
        let f = make_credentials_file(body);
        let creds = resolve_profile("sts-derived", Some(f.path()), &empty_env()).expect("resolve");
        assert_eq!(
            creds
                .session_token
                .as_ref()
                .map(secrecy::ExposeSecret::expose_secret),
            Some("FwoG...token")
        );
    }

    // -- TC-AUTH-PR5 --------------------------------------------------------
    #[test]
    fn resolve_profile_respects_custom_credentials_file_path() {
        let body = "\
[work]
aws_access_key_id = AKIAWORK
aws_secret_access_key = work-secret
";
        let f = make_credentials_file(body);
        // No HOME set in the env — proves the resolver used the
        // explicit path argument and did NOT consult HOME.
        let env = MockEnvSource::default();
        let creds = resolve_profile("work", Some(f.path()), &env).expect("resolve");
        assert_eq!(creds.access_key_id, "AKIAWORK");
    }

    // -- TC-AUTH-PR6 --------------------------------------------------------
    #[test]
    fn resolve_profile_with_missing_file_returns_auth_failed() {
        let nonexistent = PathBuf::from("/nonexistent/path/to/credentials");
        let err = resolve_profile("personal", Some(&nonexistent), &empty_env())
            .expect_err("missing file");
        match err {
            AuthError::AwsCredentialsFileNotFound { path } => {
                assert_eq!(path, nonexistent);
            }
            other => panic!("expected AwsCredentialsFileNotFound, got {other:?}"),
        }
    }

    // -- TC-AUTH-PR7 --------------------------------------------------------
    // Best-effort: assert that the `ResolvedCredentials` value is
    // `ZeroizeOnDrop` at the type level (compile-time). The actual
    // memory-zero behaviour is best-tested by the type's own unit tests
    // in `auth/source.rs`; here we just pin that the contract holds for
    // values this resolver produces.
    #[test]
    fn resolve_profile_returns_zeroize_on_drop_credentials() {
        fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}
        assert_zod::<ResolvedCredentials>();
    }

    // -- TC-AUTH-PR-default-path --------------------------------------------
    #[test]
    fn resolve_profile_uses_home_for_default_path() {
        // No HOME — the resolver must surface HomeUnresolvable rather
        // than panic.
        let env = MockEnvSource::default();
        let err = resolve_profile("personal", None, &env).expect_err("HOME unset");
        assert!(matches!(err, AuthError::HomeUnresolvable));

        // HOME set + missing file → AwsCredentialsFileNotFound.
        let env = MockEnvSource::with([("HOME", "/nonexistent/home")]);
        let err = resolve_profile("personal", None, &env).expect_err("missing file");
        match err {
            AuthError::AwsCredentialsFileNotFound { path } => {
                assert_eq!(path, PathBuf::from("/nonexistent/home/.aws/credentials"));
            }
            other => panic!("expected AwsCredentialsFileNotFound, got {other:?}"),
        }
    }

    // -- TC-AUTH-PR-parser-edges --------------------------------------------
    #[test]
    fn ini_parser_skips_comments_and_blank_lines() {
        let body = "\
# Top comment
; semicolon comment

[work]
# Inside work
aws_access_key_id = AKIA
aws_secret_access_key = secret

[other]
aws_access_key_id = OTHER
aws_secret_access_key = other
";
        let f = make_credentials_file(body);
        let creds = resolve_profile("work", Some(f.path()), &empty_env()).expect("resolve");
        assert_eq!(creds.access_key_id, "AKIA");
        assert_eq!(creds.secret_access_key.expose_secret(), "secret");
    }

    // -- TC-AUTH-PR-trailing-comment ----------------------------------------
    // Pin the documented "no trailing-comment stripping" contract with an
    // exact-equality assertion: a `;` on a value line is preserved
    // verbatim because AWS's own credentials files use the simple form
    // (key = value, no trailing comments). A future implementation that
    // adds stripping would change observable behavior and should fail
    // this test loudly.
    #[test]
    fn ini_parser_does_not_strip_trailing_comments() {
        let body = "\
[work]
aws_access_key_id = AKIA  ; looks like a comment but is NOT stripped
aws_secret_access_key = secret
";
        let f = make_credentials_file(body);
        let creds = resolve_profile("work", Some(f.path()), &empty_env()).expect("resolve");
        assert_eq!(
            creds.access_key_id, "AKIA  ; looks like a comment but is NOT stripped",
            "trailing-comment text MUST be preserved verbatim per the documented contract"
        );
    }

    #[test]
    fn ini_parser_section_boundary_terminates_search() {
        // The `[other]` section starts with `aws_access_key_id =
        // SHOULD_NOT_LEAK`. If our section-walker misses the boundary,
        // we'd return SHOULD_NOT_LEAK for [work]'s missing secret.
        let body = "\
[work]
aws_access_key_id = AKIAWORK

[other]
aws_access_key_id = SHOULD_NOT_LEAK
aws_secret_access_key = SHOULD_NOT_LEAK_SECRET
";
        let f = make_credentials_file(body);
        let err = resolve_profile("work", Some(f.path()), &empty_env())
            .expect_err("missing secret in work");
        assert!(matches!(
            err,
            AuthError::AwsProfileMissingKey { key, .. } if key == "aws_secret_access_key"
        ));
    }
}
