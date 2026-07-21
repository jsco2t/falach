//! Single public error type for the `falach-genpw` crate.
//!
//! Per design §2.2.5: every fallible operation returns [`GenError`].
//! Variants carry only structured, non-sensitive context (numeric knobs,
//! upstream CSPRNG errors). No variant ever embeds a generated password,
//! passphrase, character class set contents, or wordlist bytes.

/// Errors returned by every fallible operation in `falach-genpw`.
///
/// The five "documented" variants in design §2.2.5 are joined by
/// `Csprng`, which surfaces failures from the OS CSPRNG (the
/// `getrandom 0.4` direct call documented in the crate-level docs and
/// the implementation-plan Revision Log). `Csprng` carries the raw
/// upstream error; its `Display` defers to `getrandom`, which never
/// embeds caller-supplied bytes — only an `errno` or internal code.
#[derive(Debug, thiserror::Error)]
pub enum GenError {
    /// Requested password length was zero. Length must be at least 1.
    #[error("requested length must be at least 1")]
    InvalidLength,

    /// No character classes were enabled. At least one of lowercase,
    /// uppercase, digits, or symbols must be set.
    #[error("at least one character class must be enabled")]
    NoClassesEnabled,

    /// Requested length is too short to satisfy the
    /// at-least-one-of-each-class invariant.
    #[error(
        "requested length {length} cannot satisfy at-least-one-of-each invariant for {classes} enabled classes"
    )]
    LengthTooShort {
        /// Requested password length.
        length: usize,
        /// Number of enabled character classes.
        classes: usize,
    },

    /// The requested alphabet is empty after applying the
    /// ambiguous-character filter. Indicates either an exotic class-set
    /// + filter combination or a regression in the class constants.
    #[error("the requested alphabet is empty (all chars excluded by ambiguous filter)")]
    AlphabetEmpty,

    /// Requested passphrase word count was zero. Must be at least 1.
    #[error("requested word count must be at least 1")]
    InvalidWordCount,

    /// The OS CSPRNG (`getrandom`) returned an error. In practice this
    /// is "your platform is broken" territory — the crate does not
    /// attempt to recover.
    #[error("OS CSPRNG failure: {0}")]
    Csprng(#[from] getrandom::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_do_not_contain_sensitive_material() {
        // The five "documented" variants never carry caller-supplied
        // byte content; this test pins each variant's Display string so
        // a future refactor that interpolates extra context surfaces
        // here rather than in a downstream log line.
        assert_eq!(
            GenError::InvalidLength.to_string(),
            "requested length must be at least 1"
        );
        assert_eq!(
            GenError::NoClassesEnabled.to_string(),
            "at least one character class must be enabled"
        );
        assert_eq!(
            GenError::LengthTooShort {
                length: 2,
                classes: 4
            }
            .to_string(),
            "requested length 2 cannot satisfy at-least-one-of-each invariant for 4 enabled classes"
        );
        assert_eq!(
            GenError::AlphabetEmpty.to_string(),
            "the requested alphabet is empty (all chars excluded by ambiguous filter)"
        );
        assert_eq!(
            GenError::InvalidWordCount.to_string(),
            "requested word count must be at least 1"
        );
    }

    #[test]
    fn error_implements_std_error() {
        // Compile-time bound check — confirms `?`-propagation works for
        // downstream callers that bubble `GenError` through `Result`.
        fn assert_std_error<E: std::error::Error>() {}
        assert_std_error::<GenError>();
    }

    #[test]
    fn csprng_variant_wraps_getrandom_error_via_from() {
        // `#[from]` should let `?` convert a `getrandom::Error` into
        // `GenError::Csprng` without boilerplate. We construct a known
        // upstream error (`UNSUPPORTED`) to exercise the conversion
        // path.
        fn wrap() -> Result<(), GenError> {
            Err(getrandom::Error::UNSUPPORTED)?;
            Ok(())
        }
        let err = wrap().unwrap_err();
        assert!(matches!(err, GenError::Csprng(_)));
    }
}
