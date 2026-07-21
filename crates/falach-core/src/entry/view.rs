//! Entry view façades over `keepass-rs` entry references.

use chrono::{DateTime, Utc};
use keepass::db::{fields, EntryMut, EntryRef, Times, Value};
use sha2::{Digest, Sha256};

use crate::{Attachment, EntryKind, Tag};

/// Read-only view of a KDBX entry.
pub struct EntryView<'a> {
    entry: EntryRef<'a>,
}

/// Mutable view of a KDBX entry.
pub struct EntryViewMut<'a> {
    entry: EntryMut<'a>,
}

/// Read-only view of a historical entry snapshot.
pub struct HistoryView<'a> {
    entry: EntryRef<'a>,
}

impl<'a> EntryView<'a> {
    /// Wrap a `keepass-rs` entry reference.
    pub fn new(entry: EntryRef<'a>) -> Self {
        Self { entry }
    }

    /// Return the entry UUID.
    pub fn uuid(&self) -> uuid::Uuid {
        self.entry.id().uuid()
    }

    /// Return the title field, or `""` when absent.
    pub fn title(&self) -> &str {
        self.entry.get(fields::TITLE).unwrap_or("")
    }

    /// Return the username field, or `""` when absent.
    pub fn username(&self) -> &str {
        self.entry.get(fields::USERNAME).unwrap_or("")
    }

    /// Return the protected password field, or `""` when absent.
    pub fn password(&self) -> &str {
        self.entry.get(fields::PASSWORD).unwrap_or("")
    }

    /// Return the URL field, or `""` when absent.
    pub fn url(&self) -> &str {
        self.entry.get(fields::URL).unwrap_or("")
    }

    /// Return the notes field, or `""` when absent.
    pub fn notes(&self) -> &str {
        self.entry.get(fields::NOTES).unwrap_or("")
    }

    /// Return validated tags.
    ///
    /// Existing vaults may contain invalid tag values from other tools. Invalid
    /// tags are ignored here; mutation APIs validate all new tags.
    pub fn tags(&self) -> Vec<Tag> {
        tags_from_entry(&self.entry.tags)
    }

    /// Infer the entry kind from its fields.
    pub fn kind(&self) -> EntryKind {
        if self.entry.get(fields::OTP).is_some() {
            EntryKind::Totp
        } else if self.username().is_empty() && self.password().is_empty() && self.url().is_empty()
        {
            EntryKind::SecureNote
        } else {
            EntryKind::Credential
        }
    }

    /// Return the creation timestamp when present.
    pub fn creation_time(&self) -> Option<DateTime<Utc>> {
        self.entry
            .times
            .creation
            .map(|time| DateTime::from_naive_utc_and_offset(time, Utc))
    }

    /// Return the last modification timestamp when present.
    pub fn last_modification_time(&self) -> Option<DateTime<Utc>> {
        self.entry
            .times
            .last_modification
            .map(|time| DateTime::from_naive_utc_and_offset(time, Utc))
    }

    /// Return the expiration timestamp when the entry expires.
    pub fn expires(&self) -> Option<DateTime<Utc>> {
        self.entry.times.expires.unwrap_or(false).then(|| {
            self.entry
                .times
                .expiry
                .map(|time| DateTime::from_naive_utc_and_offset(time, Utc))
        })?
    }

    /// Return a custom field value by name.
    pub fn custom_field(&self, name: &str) -> Option<&str> {
        self.entry.get(name)
    }

    /// Return custom field names, excluding standard fields.
    pub fn custom_field_names(&self) -> Vec<&str> {
        self.entry
            .fields
            .keys()
            .filter(|name| !fields::KNOWN_FIELDS.contains(&name.as_str()))
            .map(String::as_str)
            .collect()
    }

    /// Return whether a custom field is stored protected.
    ///
    /// `Some(true)` for a protected field, `Some(false)` for an unprotected
    /// one, and `None` when the field is absent. The read-side mirror of the
    /// builder's `EntryDraft::custom_field_is_protected`.
    pub fn custom_field_is_protected(&self, name: &str) -> Option<bool> {
        self.entry.fields.get(name).map(Value::is_protected)
    }

    /// Return historical snapshots for this entry.
    pub fn history(&self) -> Vec<HistoryView<'_>> {
        let count = self
            .entry
            .history
            .as_ref()
            .map_or(0, |history| history.get_entries().len());
        (0..count)
            .filter_map(|index| self.entry.historical(index))
            .map(|entry| HistoryView { entry })
            .collect()
    }

    /// Return attachment metadata.
    pub fn attachments(&self) -> Vec<Attachment> {
        self.entry
            .attachments_named()
            .map(|(name, attachment)| Attachment {
                name: name.to_string(),
                size_bytes: attachment.data.as_slice().len() as u64,
                content_hash: Sha256::digest(attachment.data.as_slice()).into(),
            })
            .collect()
    }
}

impl<'a> EntryViewMut<'a> {
    /// Wrap a mutable `keepass-rs` entry reference.
    pub fn new(entry: EntryMut<'a>) -> Self {
        Self { entry }
    }

    /// Return the entry UUID.
    pub fn uuid(&self) -> uuid::Uuid {
        self.entry.id().uuid()
    }

    /// Return the title field, or `""` when absent.
    pub fn title(&self) -> &str {
        self.entry.get(fields::TITLE).unwrap_or("")
    }

    /// Return the username field, or `""` when absent.
    pub fn username(&self) -> &str {
        self.entry.get(fields::USERNAME).unwrap_or("")
    }

    /// Return the password field, or `""` when absent.
    pub fn password(&self) -> &str {
        self.entry.get(fields::PASSWORD).unwrap_or("")
    }

    /// Return the URL field, or `""` when absent.
    pub fn url(&self) -> &str {
        self.entry.get(fields::URL).unwrap_or("")
    }

    /// Return the notes field, or `""` when absent.
    pub fn notes(&self) -> &str {
        self.entry.get(fields::NOTES).unwrap_or("")
    }

    /// Return validated tags.
    pub fn tags(&self) -> Vec<Tag> {
        tags_from_entry(&self.entry.tags)
    }

    /// Infer the entry kind from its fields.
    pub fn kind(&self) -> EntryKind {
        if self.entry.get(fields::OTP).is_some() {
            EntryKind::Totp
        } else if self.username().is_empty() && self.password().is_empty() && self.url().is_empty()
        {
            EntryKind::SecureNote
        } else {
            EntryKind::Credential
        }
    }

    /// Set the title field.
    pub fn set_title(&mut self, value: impl Into<String>) {
        self.entry.set_unprotected(fields::TITLE, value);
        self.touch();
    }

    /// Set the username field.
    pub fn set_username(&mut self, value: impl Into<String>) {
        self.entry.set_unprotected(fields::USERNAME, value);
        self.touch();
    }

    /// Set the protected password field.
    pub fn set_password(&mut self, value: impl Into<String>) {
        self.entry.set_protected(fields::PASSWORD, value);
        self.touch();
    }

    /// Set the URL field.
    pub fn set_url(&mut self, value: impl Into<String>) {
        self.entry.set_unprotected(fields::URL, value);
        self.touch();
    }

    /// Set the notes field.
    pub fn set_notes(&mut self, value: impl Into<String>) {
        self.entry.set_unprotected(fields::NOTES, value);
        self.touch();
    }

    /// Add a tag if it is not already present.
    pub fn add_tag(&mut self, value: Tag) {
        if !self.entry.tags.iter().any(|tag| tag == value.as_str()) {
            self.entry.tags.push(value.into_inner());
            self.touch();
        }
    }

    /// Remove a tag.
    pub fn remove_tag(&mut self, value: &Tag) {
        let before = self.entry.tags.len();
        self.entry.tags.retain(|tag| tag != value.as_str());
        if self.entry.tags.len() != before {
            self.touch();
        }
    }

    /// Replace all tags.
    pub fn set_tags(&mut self, values: impl IntoIterator<Item = Tag>) {
        let mut tags = Vec::new();
        for value in values {
            let value = value.into_inner();
            if !tags.contains(&value) {
                tags.push(value);
            }
        }
        self.entry.tags = tags;
        self.touch();
    }

    /// Set a custom string field.
    pub fn set_custom_field(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
        protected: bool,
    ) {
        let value = value.into();
        if protected {
            self.entry.set(name, Value::protected(value));
        } else {
            self.entry.set(name, Value::unprotected(value));
        }
        self.touch();
    }

    /// Remove a custom field.
    pub fn remove_custom_field(&mut self, name: &str) {
        if self.entry.fields.remove(name).is_some() {
            self.touch();
        }
    }

    fn touch(&mut self) {
        self.entry.times.last_modification = Some(Times::now());
    }
}

impl HistoryView<'_> {
    /// Return the title field, or `""` when absent.
    pub fn title(&self) -> &str {
        self.entry.get(fields::TITLE).unwrap_or("")
    }

    /// Return the username field, or `""` when absent.
    pub fn username(&self) -> &str {
        self.entry.get(fields::USERNAME).unwrap_or("")
    }

    /// Return the password field, or `""` when absent.
    pub fn password(&self) -> &str {
        self.entry.get(fields::PASSWORD).unwrap_or("")
    }

    /// Return the URL field, or `""` when absent.
    pub fn url(&self) -> &str {
        self.entry.get(fields::URL).unwrap_or("")
    }

    /// Return the notes field, or `""` when absent.
    pub fn notes(&self) -> &str {
        self.entry.get(fields::NOTES).unwrap_or("")
    }

    /// Return the last modification timestamp when present.
    pub fn last_modification_time(&self) -> Option<DateTime<Utc>> {
        self.entry
            .times
            .last_modification
            .map(|time| DateTime::from_naive_utc_and_offset(time, Utc))
    }
}

fn tags_from_entry(tags: &[String]) -> Vec<Tag> {
    tags.iter()
        .filter_map(|tag| Tag::from(tag.clone()).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use keepass::{db::fields, Database};

    use super::*;

    fn database_with_entry() -> (Database, keepass::db::EntryId) {
        let mut db = Database::new();
        let entry_id = db
            .root_mut()
            .add_entry()
            .edit(|entry| {
                entry.set_unprotected(fields::TITLE, "Example");
                entry.set_unprotected(fields::USERNAME, "alice");
                entry.set_protected(fields::PASSWORD, "secret");
                entry.set_unprotected(fields::URL, "https://example.com");
                entry.set_unprotected(fields::NOTES, "notes");
                entry.tags.push("work".to_string());
            })
            .id();
        (db, entry_id)
    }

    #[test]
    fn entry_view_accessors_return_standard_fields() {
        let (db, entry_id) = database_with_entry();
        let view = EntryView::new(db.entry(entry_id).expect("entry should exist"));

        assert_eq!(view.title(), "Example");
        assert_eq!(view.username(), "alice");
        assert_eq!(view.password(), "secret");
        assert_eq!(view.url(), "https://example.com");
        assert_eq!(view.notes(), "notes");
        assert_eq!(view.tags(), vec![Tag::new("work")]);
        assert_eq!(view.kind(), EntryKind::Credential);
    }

    #[test]
    fn entry_view_kind_detects_secure_note() {
        let mut db = Database::new();
        let entry_id = db
            .root_mut()
            .add_entry()
            .edit(|entry| {
                entry.set_unprotected(fields::TITLE, "Recovery Codes");
                entry.set_unprotected(fields::NOTES, "one\ntwo");
            })
            .id();

        let view = EntryView::new(db.entry(entry_id).expect("entry should exist"));
        assert_eq!(view.kind(), EntryKind::SecureNote);
    }

    #[test]
    fn entry_view_kind_detects_totp() {
        let mut db = Database::new();
        let entry_id = db
            .root_mut()
            .add_entry()
            .edit(|entry| {
                entry.set_unprotected(fields::TITLE, "GitHub");
                entry.set_protected(fields::OTP, "otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP");
            })
            .id();

        let view = EntryView::new(db.entry(entry_id).expect("entry should exist"));
        assert_eq!(view.kind(), EntryKind::Totp);
    }

    #[test]
    fn entry_view_mut_setters_update_fields_and_tags() {
        let (mut db, entry_id) = database_with_entry();
        db.entry_mut(entry_id)
            .expect("entry should exist")
            .times
            .last_modification = Some(keepass::db::Times::epoch());
        let before = Some(keepass::db::Times::epoch());
        {
            let mut view = EntryViewMut::new(db.entry_mut(entry_id).expect("entry should exist"));
            view.set_title("Changed");
            view.set_username("bob");
            view.set_password("new-secret");
            view.set_url("https://changed.example");
            view.set_notes("changed notes");
            view.add_tag(Tag::new("finance"));
            view.add_tag(Tag::new("finance"));
            view.remove_tag(&Tag::new("work"));
            view.set_tags([Tag::new("finance"), Tag::new("admin"), Tag::new("admin")]);
        }

        let view = EntryView::new(db.entry(entry_id).expect("entry should exist"));
        assert_eq!(view.title(), "Changed");
        assert_eq!(view.username(), "bob");
        assert_eq!(view.password(), "new-secret");
        assert_eq!(view.url(), "https://changed.example");
        assert_eq!(view.notes(), "changed notes");
        assert_eq!(view.tags(), vec![Tag::new("finance"), Tag::new("admin")]);
        assert!(view.last_modification_time().is_some());
        assert_ne!(
            view.entry.times.last_modification, before,
            "setter mutations should refresh last_modification"
        );
    }

    #[test]
    fn custom_field_accessors_read_write_and_remove() {
        let (mut db, entry_id) = database_with_entry();
        {
            let mut view = EntryViewMut::new(db.entry_mut(entry_id).expect("entry should exist"));
            view.set_custom_field("otp", "otpauth://totp/X?secret=JBSWY3DPEHPK3PXP", true);
        }

        let view = EntryView::new(db.entry(entry_id).expect("entry should exist"));
        assert_eq!(
            view.custom_field("otp"),
            Some("otpauth://totp/X?secret=JBSWY3DPEHPK3PXP")
        );

        {
            let mut view = EntryViewMut::new(db.entry_mut(entry_id).expect("entry should exist"));
            view.remove_custom_field("otp");
        }
        let view = EntryView::new(db.entry(entry_id).expect("entry should exist"));
        assert_eq!(view.custom_field("otp"), None);
    }

    #[test]
    fn custom_field_is_protected_reports_protectedness() {
        let mut db = Database::new();
        let entry_id = db
            .root_mut()
            .add_entry()
            .edit(|entry| {
                entry.set_unprotected(fields::TITLE, "With Protected Fields");
                entry.set_protected("pin", "1234");
                entry.set_unprotected("label", "home");
            })
            .id();

        let view = EntryView::new(db.entry(entry_id).expect("entry should exist"));
        assert_eq!(view.custom_field_is_protected("pin"), Some(true));
        assert_eq!(view.custom_field_is_protected("label"), Some(false));
        assert_eq!(view.custom_field_is_protected("absent"), None);
    }

    #[test]
    fn attachments_return_size_and_content_hash() {
        let mut db = Database::new();
        let entry_id = db
            .root_mut()
            .add_entry()
            .edit(|entry| {
                entry.set_unprotected(fields::TITLE, "With Attachment");
                entry.add_attachment("doc.pdf", Value::unprotected(vec![b'A'; 1024]));
            })
            .id();

        let view = EntryView::new(db.entry(entry_id).expect("entry should exist"));
        let attachments = view.attachments();

        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].name, "doc.pdf");
        assert_eq!(attachments[0].size_bytes, 1024);
        let expected_hash: [u8; 32] = Sha256::digest(vec![b'A'; 1024]).into();
        assert_eq!(attachments[0].content_hash, expected_hash);
    }
}
