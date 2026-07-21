//! Small entry-domain value types.

use std::convert::TryFrom;

use crate::VaultError;

/// A validated KeePass-compatible tag.
///
/// Falach stores tags using `KeePassXC`'s semicolon-delimited convention, so
/// semicolons are rejected at the API boundary instead of escaped.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Tag(String);

impl Tag {
    /// Validate and construct a tag.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::InvalidTag`] when `value` contains `;`.
    pub fn from(value: impl Into<String>) -> Result<Self, VaultError> {
        Self::try_from(value.into())
    }

    /// Construct a tag from a known-valid value.
    ///
    /// # Panics
    ///
    /// Panics when `value` contains `;`. Use [`Self::from`] for user input.
    pub fn new(value: impl Into<String>) -> Self {
        Self::from(value).expect("known-valid tag should not contain ';'")
    }

    /// Return the tag as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}

impl TryFrom<String> for Tag {
    type Error = VaultError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.contains(';') {
            return Err(VaultError::InvalidTag { value });
        }
        Ok(Self(value))
    }
}

impl TryFrom<&str> for Tag {
    type Error = VaultError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from(value.to_string())
    }
}

impl AsRef<str> for Tag {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Display for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Metadata for an entry attachment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attachment {
    /// Attachment filename as stored on the entry.
    pub name: String,
    /// Attachment byte length.
    pub size_bytes: u64,
    /// SHA-256 content hash.
    pub content_hash: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_from_accepts_valid_value() {
        let tag = Tag::from("foo").expect("valid tag should parse");
        assert_eq!(tag.as_str(), "foo");
    }

    #[test]
    fn tag_from_rejects_semicolon() {
        let err = Tag::from("has;semicolon").expect_err("semicolon should fail");
        assert!(matches!(err, VaultError::InvalidTag { value } if value == "has;semicolon"));
    }

    #[test]
    fn attachment_struct_round_trips_fields() {
        let attachment = Attachment {
            name: "doc.pdf".to_string(),
            size_bytes: 1024,
            content_hash: [7; 32],
        };

        assert_eq!(attachment.name, "doc.pdf");
        assert_eq!(attachment.size_bytes, 1024);
        assert_eq!(attachment.content_hash, [7; 32]);
    }
}
