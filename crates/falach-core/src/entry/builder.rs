//! Typed construction of entry drafts.

use std::fmt;

use chrono::{DateTime, Utc};
use keepass::db::fields;
use zeroize::Zeroizing;

use crate::{Tag, VaultError};

/// High-level entry kind exposed by Falach.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
    /// Username/password-style credential.
    Credential,
    /// Notes-only entry.
    SecureNote,
    /// Entry with an `otp` custom field.
    Totp,
}

/// Builder for a new entry.
#[derive(Clone)]
#[must_use]
pub struct EntryBuilder {
    kind: EntryKind,
    title: String,
    username: Option<String>,
    password: Option<Zeroizing<String>>,
    url: Option<String>,
    notes: Option<String>,
    tags: Vec<Tag>,
    expires_at: Option<DateTime<Utc>>,
    custom_fields: Vec<CustomFieldDraft>,
    totp_uri: Option<Zeroizing<String>>,
}

/// Entry data ready for insertion into a vault.
#[derive(Clone)]
#[must_use]
pub struct EntryDraft {
    pub(crate) kind: EntryKind,
    pub(crate) title: String,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<Zeroizing<String>>,
    pub(crate) url: Option<String>,
    pub(crate) notes: Option<String>,
    pub(crate) tags: Vec<Tag>,
    pub(crate) expires_at: Option<DateTime<Utc>>,
    pub(crate) custom_fields: Vec<CustomFieldDraft>,
    pub(crate) totp_uri: Option<Zeroizing<String>>,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct CustomFieldDraft {
    pub(crate) name: String,
    pub(crate) value: Zeroizing<String>,
    pub(crate) protected: bool,
}

// Manual `Debug` impls: `Zeroizing<String>`'s derived `Debug` is
// transparent, and drafts are `pub` API types — a `dbg!`, panic message,
// or error-context format of a draft must never print the password, the
// otpauth URI (it embeds the TOTP seed), or protected custom-field
// values. Mirrors `MasterPassword`/`Keyfile` in `secret.rs`.

impl fmt::Debug for EntryBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryBuilder")
            .field("kind", &self.kind)
            .field("title", &self.title)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("url", &self.url)
            .field("notes", &self.notes)
            .field("tags", &self.tags)
            .field("expires_at", &self.expires_at)
            .field("custom_fields", &self.custom_fields)
            .field("totp_uri", &self.totp_uri.as_ref().map(|_| "***"))
            .finish()
    }
}

impl fmt::Debug for EntryDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryDraft")
            .field("kind", &self.kind)
            .field("title", &self.title)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("url", &self.url)
            .field("notes", &self.notes)
            .field("tags", &self.tags)
            .field("expires_at", &self.expires_at)
            .field("custom_fields", &self.custom_fields)
            .field("totp_uri", &self.totp_uri.as_ref().map(|_| "***"))
            .finish()
    }
}

impl fmt::Debug for CustomFieldDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Unprotected values are ordinary KDBX string fields, but a
        // draft's protection flag can be mis-set in the code path being
        // debugged — redact unconditionally rather than trust it.
        f.debug_struct("CustomFieldDraft")
            .field("name", &self.name)
            .field("value", &"***")
            .field("protected", &self.protected)
            .finish()
    }
}

impl EntryBuilder {
    /// Start a credential entry draft with a required title.
    pub fn credential(title: impl Into<String>) -> Self {
        Self::new(EntryKind::Credential, title)
    }

    /// Start a secure-note entry draft with a required title.
    pub fn secure_note(title: impl Into<String>) -> Self {
        Self::new(EntryKind::SecureNote, title)
    }

    /// Start a TOTP entry draft with a required title and otpauth URI.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::InvalidOtpUri`] when the URI is not a valid
    /// `otpauth://totp/...` URI parseable by [`crate::Totp::from_otpauth_uri`].
    pub fn totp(title: impl Into<String>, otpauth_uri: &str) -> Result<Self, VaultError> {
        crate::Totp::from_otpauth_uri(otpauth_uri)?;
        Ok(Self::new(EntryKind::Totp, title).custom_field(fields::OTP, otpauth_uri, true))
    }

    fn new(kind: EntryKind, title: impl Into<String>) -> Self {
        Self {
            kind,
            title: title.into(),
            username: None,
            password: None,
            url: None,
            notes: None,
            tags: Vec::new(),
            expires_at: None,
            custom_fields: Vec::new(),
            totp_uri: None,
        }
    }

    /// Set the username field.
    pub fn username(mut self, value: impl Into<String>) -> Self {
        self.username = Some(value.into());
        self
    }

    /// Set the protected password field.
    pub fn password(mut self, value: impl Into<String>) -> Self {
        self.password = Some(Zeroizing::new(value.into()));
        self
    }

    /// Set the URL field.
    pub fn url(mut self, value: impl Into<String>) -> Self {
        self.url = Some(value.into());
        self
    }

    /// Set the notes field.
    pub fn notes(mut self, value: impl Into<String>) -> Self {
        self.notes = Some(value.into());
        self
    }

    /// Add an already-validated tag.
    pub fn tag(mut self, value: Tag) -> Self {
        self.tags.push(value);
        self
    }

    /// Add many already-validated tags.
    pub fn tags(mut self, values: impl IntoIterator<Item = Tag>) -> Self {
        self.tags.extend(values);
        self
    }

    /// Set the expiration timestamp.
    pub fn expires_at(mut self, when: DateTime<Utc>) -> Self {
        self.expires_at = Some(when);
        self
    }

    /// Add a custom string field.
    pub fn custom_field(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
        protected: bool,
    ) -> Self {
        let name = name.into();
        let value = Zeroizing::new(value.into());
        if name == fields::OTP {
            self.totp_uri = Some(value.clone());
        }
        self.custom_fields.push(CustomFieldDraft {
            name,
            value,
            protected,
        });
        self
    }

    /// Finish the builder.
    pub fn build(self) -> EntryDraft {
        EntryDraft {
            kind: self.kind,
            title: self.title,
            username: self.username,
            password: self.password,
            url: self.url,
            notes: self.notes,
            tags: self.tags,
            expires_at: self.expires_at,
            custom_fields: self.custom_fields,
            totp_uri: self.totp_uri,
        }
    }
}

impl EntryDraft {
    /// Return the entry kind.
    pub fn kind(&self) -> EntryKind {
        self.kind
    }

    /// Return the title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Return the username when present.
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// Return the password when present.
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref().map(String::as_str)
    }

    /// Return the URL when present.
    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    /// Return the notes when present.
    pub fn notes(&self) -> Option<&str> {
        self.notes.as_deref()
    }

    /// Return tags on the draft.
    pub fn tags(&self) -> &[Tag] {
        &self.tags
    }

    /// Return the expiration timestamp when present.
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }

    /// Return the otpauth URI for TOTP drafts.
    pub fn totp_uri(&self) -> Option<&str> {
        self.totp_uri.as_deref().map(String::as_str)
    }

    /// Return a custom field value by name.
    pub fn custom_field(&self, name: &str) -> Option<&str> {
        self.custom_fields
            .iter()
            .find(|field| field.name == name)
            .map(|field| field.value.as_str())
    }

    /// Return custom field names.
    pub fn custom_field_names(&self) -> Vec<&str> {
        self.custom_fields
            .iter()
            .map(|field| field.name.as_str())
            .collect()
    }

    /// Return whether a custom field is protected.
    pub fn custom_field_is_protected(&self, name: &str) -> Option<bool> {
        self.custom_fields
            .iter()
            .find(|field| field.name == name)
            .map(|field| field.protected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_builder_sets_title_and_kind() {
        let draft = EntryBuilder::credential("Example").build();
        assert_eq!(draft.title(), "Example");
        assert_eq!(draft.kind(), EntryKind::Credential);
    }

    #[test]
    fn secure_note_builder_sets_kind() {
        let draft = EntryBuilder::secure_note("Recovery Codes").build();
        assert_eq!(draft.kind(), EntryKind::SecureNote);
    }

    #[test]
    fn totp_builder_accepts_minimal_otpauth_uri() {
        let draft = EntryBuilder::totp("GitHub", "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP")
            .expect("valid minimal otpauth URI should parse")
            .build();

        assert_eq!(draft.kind(), EntryKind::Totp);
        assert_eq!(
            draft.totp_uri(),
            Some("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP")
        );
        assert_eq!(
            draft.custom_field("otp"),
            Some("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP")
        );
        assert_eq!(draft.custom_field_is_protected("otp"), Some(true));
    }

    #[test]
    fn totp_builder_rejects_malformed_uri() {
        let err = EntryBuilder::totp("GitHub", "not a uri").expect_err("invalid URI should fail");
        assert!(matches!(err, VaultError::InvalidOtpUri { .. }));
    }

    #[test]
    fn builder_setter_chain_populates_fields() {
        let draft = EntryBuilder::credential("Example")
            .username("alice")
            .password("secret")
            .url("https://example.com")
            .notes("notes")
            .tag(Tag::new("work"))
            .build();

        assert_eq!(draft.username(), Some("alice"));
        assert_eq!(draft.password(), Some("secret"));
        assert_eq!(draft.url(), Some("https://example.com"));
        assert_eq!(draft.notes(), Some("notes"));
        assert_eq!(draft.tags(), &[Tag::new("work")]);
    }

    #[test]
    fn builder_password_wraps_in_zeroizing_internally() {
        let draft = EntryBuilder::credential("Example")
            .password("secret")
            .build();
        let password: &Zeroizing<String> = draft
            .password
            .as_ref()
            .expect("password should be stored in draft");
        assert_eq!(password.as_str(), "secret");
    }

    #[test]
    fn debug_output_redacts_secret_fields() {
        let builder =
            EntryBuilder::totp("GitHub", "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP")
                .expect("valid otpauth URI")
                .password("hunter2-secret")
                .custom_field("api-key", "protected-custom-secret", true);
        let draft = builder.clone().build();

        for dbg in [format!("{builder:?}"), format!("{draft:?}")] {
            assert!(
                !dbg.contains("hunter2-secret"),
                "Debug must not contain the password: {dbg}"
            );
            assert!(
                !dbg.contains("JBSWY3DPEHPK3PXP"),
                "Debug must not contain the TOTP seed: {dbg}"
            );
            assert!(
                !dbg.contains("protected-custom-secret"),
                "Debug must not contain protected custom-field values: {dbg}"
            );
        }
    }

    #[test]
    fn expires_at_setter_sets_expiration() {
        let when = Utc::now();
        let draft = EntryBuilder::credential("Example").expires_at(when).build();
        assert_eq!(draft.expires_at(), Some(when));
    }
}
