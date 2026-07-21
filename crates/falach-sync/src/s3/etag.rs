//! ETag parsing and normalization (design.md §2.2.3).
//!
//! S3 returns ETags wrapped in double quotes:
//! `ETag: "d41d8cd98f00b204e9800998ecf8427e"`. This module strips the
//! quotes, distinguishes weak (`W/"..."`) from strong, and rejects
//! malformed values.
//!
//! For single-PUT objects (≤5 GB, our only upload mode in Phase 0) the
//! ETag IS the hex-MD5 of the object bytes — useful as a content version
//! identifier in the orchestrator's four-state truth table. For multipart
//! objects the format is `"hex-N"` where N is the part count; we don't
//! produce these but a backend may return them on a GET / HEAD of a
//! pre-existing object, so the parser must accept them verbatim.
//!
//! Per design §2.2.3, the orchestrator's conditional-PUT semantics require
//! STRONG ETags only. A weak ETag (`W/"..."`) is rejected with
//! [`EtagError::Weak`] at the boundary; the orchestrator surfaces
//! [`crate::s3::S3Error::WeakEtag`].

/// Errors returned by [`Etag::parse`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EtagError {
    /// The ETag is missing its enclosing double-quote characters.
    /// Per RFC 7232 ETags are always quoted; an unquoted value is a
    /// malformed response from the server.
    #[error("ETag is missing the enclosing quotes")]
    Unquoted,

    /// The ETag is the weak form `W/"..."`. The orchestrator's
    /// conditional-PUT semantics require strong ETags.
    #[error("ETag is a weak validator (W/\"...\"); strong validator required")]
    Weak,

    /// The ETag string is empty or contains only whitespace.
    #[error("ETag is empty")]
    Empty,
}

/// A parsed, normalized strong ETag.
///
/// The stored form is the QUOTE-STRIPPED inner string. So an ETag header
/// value of `"d41d..."` becomes `Etag("d41d...".to_string())`.
///
/// `PartialEq`/`Eq` are derived for use in the orchestrator's divergence
/// detection (compare-against-`last_synced_remote_etag`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Etag(pub String);

impl Etag {
    /// Parse an ETag from its on-the-wire header value (e.g.
    /// `"d41d8cd98f00b204e9800998ecf8427e"`).
    ///
    /// # Errors
    ///
    /// - [`EtagError::Empty`] when the input is empty / whitespace-only.
    /// - [`EtagError::Weak`] when the input is a weak validator (`W/"..."`).
    /// - [`EtagError::Unquoted`] when the input does not start AND end with
    ///   a double-quote character.
    pub fn parse(s: &str) -> Result<Self, EtagError> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(EtagError::Empty);
        }
        // RFC 7232: weak validators are `W/"..."`. Reject up front.
        if let Some(rest) = trimmed.strip_prefix("W/") {
            // Validate the rest is properly quoted before returning Weak —
            // a malformed `W/foo` is "weak AND unquoted" but we choose
            // Weak as the more informative error.
            if rest.starts_with('"') && rest.ends_with('"') && rest.len() >= 2 {
                return Err(EtagError::Weak);
            }
            return Err(EtagError::Weak);
        }
        if !trimmed.starts_with('"') || !trimmed.ends_with('"') || trimmed.len() < 2 {
            return Err(EtagError::Unquoted);
        }
        let inner = &trimmed[1..trimmed.len() - 1];
        if inner.is_empty() {
            return Err(EtagError::Empty);
        }
        Ok(Self(inner.to_string()))
    }

    /// The inner (quote-stripped) ETag string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Render the ETag in its on-the-wire (quoted) form, suitable for
    /// inclusion in an `If-Match` or `If-None-Match` request header.
    #[must_use]
    pub fn to_header_value(&self) -> String {
        format!("\"{}\"", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- TC-ETAG-001 --------------------------------------------------------
    #[test]
    fn parse_strong_etag_strips_quotes() {
        let etag = Etag::parse("\"d41d8cd98f00b204e9800998ecf8427e\"").expect("parse strong ETag");
        assert_eq!(etag.as_str(), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            etag.to_header_value(),
            "\"d41d8cd98f00b204e9800998ecf8427e\""
        );
    }

    // -- TC-ETAG-002 --------------------------------------------------------
    #[test]
    fn parse_rejects_weak_etag() {
        let result = Etag::parse("W/\"d41d8cd98f00b204e9800998ecf8427e\"");
        assert!(matches!(result, Err(EtagError::Weak)));
    }

    // -- TC-ETAG-003 --------------------------------------------------------
    #[test]
    fn parse_rejects_unquoted_value() {
        let result = Etag::parse("d41d8cd98f00b204e9800998ecf8427e");
        assert!(matches!(result, Err(EtagError::Unquoted)));
    }

    // -- TC-ETAG-004 --------------------------------------------------------
    #[test]
    fn parse_accepts_multipart_format_verbatim() {
        // S3 multipart ETags look like `"<md5>-<part-count>"`. We don't
        // produce them but must accept them on GET/HEAD of pre-existing
        // multipart objects.
        let etag =
            Etag::parse("\"d41d8cd98f00b204e9800998ecf8427e-2\"").expect("parse multipart ETag");
        assert_eq!(etag.as_str(), "d41d8cd98f00b204e9800998ecf8427e-2");
    }

    // -- TC-ETAG-005 --------------------------------------------------------
    #[test]
    fn parse_rejects_empty_input() {
        assert!(matches!(Etag::parse(""), Err(EtagError::Empty)));
        assert!(matches!(Etag::parse("   "), Err(EtagError::Empty)));
        assert!(matches!(Etag::parse("\"\""), Err(EtagError::Empty)));
    }

    // -- TC-ETAG-006 --------------------------------------------------------
    #[test]
    fn parse_trims_surrounding_whitespace() {
        let etag = Etag::parse("  \"abc123\"  ").expect("parse with whitespace");
        assert_eq!(etag.as_str(), "abc123");
    }
}
