//! Entry subcommand view structs — JSON-schema contract for
//! `falach entry {add, get, edit, rm, list, search}`.
//!
//! Each `#[derive(serde::Serialize)]` struct is the public JSON shape
//! for one verb. Field renames or type changes are breaking; new
//! optional fields are additive (`#[serde(skip_serializing_if =
//! "Option::is_none")]`).
//!
//! Per design §2.3.2, every view carries the entry's UUID where one
//! exists; views borrow from already-decoded `EntryView` data so the
//! JSON emission is zero-allocate at the view boundary.

use serde::Serialize;
use uuid::Uuid;

use crate::format::HumanFormat;

// ---------------------------------------------------------------------------
// entry get
// ---------------------------------------------------------------------------

/// JSON output for `falach entry get`.
#[derive(Serialize, Debug)]
pub struct EntryGetView<'a> {
    /// Entry UUID.
    pub uuid: Uuid,
    /// Title field.
    pub title: &'a str,
    /// Username field (omitted when empty).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<&'a str>,
    /// URL field (omitted when empty).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<&'a str>,
    /// Notes field (omitted when empty).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<&'a str>,
    /// Password value — populated only when `--show-password` is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<&'a str>,
    /// Tag list (always emitted; an empty list is still meaningful).
    pub tags: Vec<&'a str>,
    /// Parent group name (top-level groups read as the group name; root
    /// reads as the database root name — typically `"Passwords"`).
    pub group: &'a str,
    /// Whether the entry has expired (`now >= expiry_time`).
    pub expired: bool,
    /// Whether the entry carries one or more attachments.
    pub has_attachments: bool,
    /// Whether the entry has a stored TOTP `otpauth://` URI.
    pub has_totp: bool,
    /// Current TOTP code — populated only when `--show-totp` is set
    /// and the entry has a TOTP URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_code: Option<String>,
}

impl HumanFormat for EntryGetView<'_> {
    fn write_human(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(out, "uuid:    {}", self.uuid)?;
        writeln!(out, "title:   {}", self.title)?;
        if let Some(u) = self.username {
            writeln!(out, "user:    {u}")?;
        }
        if let Some(u) = self.url {
            writeln!(out, "url:     {u}")?;
        }
        writeln!(out, "group:   {}", self.group)?;
        if !self.tags.is_empty() {
            writeln!(out, "tags:    {}", self.tags.join(", "))?;
        }
        if self.expired {
            writeln!(out, "expired: yes")?;
        }
        if self.has_attachments {
            writeln!(out, "attach:  yes")?;
        }
        if self.has_totp {
            writeln!(out, "totp:    yes")?;
        }
        if let Some(n) = self.notes {
            writeln!(out, "notes:   {n}")?;
        }
        if let Some(p) = self.password {
            writeln!(out, "pass:    {p}")?;
        }
        if let Some(code) = &self.totp_code {
            writeln!(out, "code:    {code}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// entry list
// ---------------------------------------------------------------------------

/// JSON envelope for `falach entry list`.
#[derive(Serialize, Debug)]
pub struct EntryListView<'a> {
    /// Matched entries, in vault iteration order (after pagination).
    pub entries: Vec<EntryListItem<'a>>,
}

/// One row of [`EntryListView::entries`]. Same shape is used by
/// [`EntrySearchView::matches`].
#[derive(Serialize, Debug, Clone)]
pub struct EntryListItem<'a> {
    /// Entry UUID.
    pub uuid: Uuid,
    /// Title field.
    pub title: &'a str,
    /// Parent group name.
    pub group: &'a str,
    /// Tag list (always emitted).
    pub tags: Vec<&'a str>,
    /// Whether the entry has expired.
    pub expired: bool,
}

impl HumanFormat for EntryListView<'_> {
    fn write_human(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        if self.entries.is_empty() {
            return writeln!(out, "no entries");
        }
        let uuid_w = 36; // UUID length is fixed
        let title_w = self
            .entries
            .iter()
            .map(|e| e.title.len())
            .max()
            .unwrap_or(5)
            .clamp(5, 40);
        writeln!(
            out,
            "{:<uuid_w$}  {:<title_w$}  GROUP",
            "UUID",
            "TITLE",
            uuid_w = uuid_w,
            title_w = title_w,
        )?;
        for e in &self.entries {
            let mark = if e.expired { " [expired]" } else { "" };
            writeln!(
                out,
                "{:<uuid_w$}  {:<title_w$}  {}{}",
                e.uuid.to_string(),
                e.title,
                e.group,
                mark,
                uuid_w = uuid_w,
                title_w = title_w,
            )?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// entry search
// ---------------------------------------------------------------------------

/// One match row of [`EntrySearchView`]. Extends the list-row shape with the
/// ranking `score` (always emitted) and, in fuzzy mode, the matched character
/// positions per field (`matched_indices`) for downstream highlighting. Both
/// fields are additive — existing consumers ignore them (schema-stable).
#[derive(Serialize, Debug, Clone)]
pub struct EntrySearchItem<'a> {
    /// Entry UUID.
    pub uuid: Uuid,
    /// Title field.
    pub title: &'a str,
    /// Parent group name.
    pub group: &'a str,
    /// Tag list (always emitted).
    pub tags: Vec<&'a str>,
    /// Whether the entry has expired.
    pub expired: bool,
    /// Field-weighted rank score (higher sorts first).
    pub score: u32,
    /// Matched character positions per field — populated only in fuzzy mode;
    /// omitted from JSON when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub matched_indices: Vec<FieldIndices>,
}

/// Matched character positions within one field (fuzzy JSON output).
#[derive(Serialize, Debug, Clone)]
pub struct FieldIndices {
    /// Field name (`title`, `username`, `url`, `notes`, `tags`).
    pub field: &'static str,
    /// Character positions (into the field value's `chars()`), strictly increasing.
    pub positions: Vec<u32>,
}

/// JSON envelope for `falach entry search`.
#[derive(Serialize, Debug)]
pub struct EntrySearchView<'a> {
    /// Query string the user passed.
    pub query: &'a str,
    /// Match rows, ordered by score descending (entry-management's
    /// ranking — title > username/tags > url > notes).
    pub matches: Vec<EntrySearchItem<'a>>,
}

impl HumanFormat for EntrySearchView<'_> {
    fn write_human(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        if self.matches.is_empty() {
            return writeln!(out, "no matches for {:?}", self.query);
        }
        writeln!(out, "matches for {:?}:", self.query)?;
        for m in &self.matches {
            let mark = if m.expired { " [expired]" } else { "" };
            writeln!(out, "  {}  {}  {}{}", m.uuid, m.title, m.group, mark)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// entry add
// ---------------------------------------------------------------------------

/// JSON output for `falach entry add`.
#[derive(Serialize, Debug)]
pub struct EntryAddView<'a> {
    /// Freshly allocated entry UUID.
    pub uuid: Uuid,
    /// Title (echoed back).
    pub title: &'a str,
    /// Parent group name.
    pub group: &'a str,
    /// Password value — populated only when `--show-password` is set
    /// AND the password was generated/captured during the call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<&'a str>,
}

impl HumanFormat for EntryAddView<'_> {
    fn write_human(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(out, "added entry '{}' ({})", self.title, self.uuid)?;
        writeln!(out, "  group: {}", self.group)?;
        if let Some(p) = self.password {
            writeln!(out, "  password: {p}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// entry edit
// ---------------------------------------------------------------------------

/// JSON output for `falach entry edit`.
#[derive(Serialize, Debug)]
pub struct EntryEditView {
    /// Entry UUID (unchanged across the edit).
    pub uuid: Uuid,
    /// Field names that were actually modified. Stable identifiers
    /// (`"title"`, `"username"`, `"url"`, `"notes"`, `"password"`,
    /// `"tags"`).
    pub modified_fields: Vec<&'static str>,
}

impl HumanFormat for EntryEditView {
    fn write_human(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        if self.modified_fields.is_empty() {
            writeln!(out, "entry {} unchanged", self.uuid)
        } else {
            writeln!(
                out,
                "edited entry {}: {}",
                self.uuid,
                self.modified_fields.join(", ")
            )
        }
    }
}

// ---------------------------------------------------------------------------
// entry rm
// ---------------------------------------------------------------------------

/// JSON output for `falach entry rm`.
#[derive(Serialize, Debug)]
pub struct EntryRmView {
    /// UUID of the removed (or recycled) entry.
    pub uuid: Uuid,
    /// `true` when the entry was moved to the recycle bin (default);
    /// `false` when `--permanent` was passed and the entry was purged.
    pub recycle_bin: bool,
}

impl HumanFormat for EntryRmView {
    fn write_human(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        if self.recycle_bin {
            writeln!(out, "moved entry {} to recycle bin", self.uuid)
        } else {
            writeln!(out, "permanently deleted entry {}", self.uuid)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests — JSON-schema regression gates per view.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn json_of<V: serde::Serialize>(view: &V) -> Value {
        let s = serde_json::to_string(view).expect("serialize");
        serde_json::from_str(&s).expect("parse")
    }

    fn sample_uuid() -> Uuid {
        Uuid::parse_str("0d36b0c5-3a7f-4c2d-8b9e-1c5e88a31a2b").unwrap()
    }

    // ---- get ----

    #[test]
    fn entry_get_view_omits_optional_fields_when_none() {
        let uuid = sample_uuid();
        let view = EntryGetView {
            uuid,
            title: "GitHub",
            username: None,
            url: None,
            notes: None,
            password: None,
            tags: vec![],
            group: "Passwords",
            expired: false,
            has_attachments: false,
            has_totp: false,
            totp_code: None,
        };
        let v = json_of(&view);
        assert_eq!(v["uuid"], uuid.to_string());
        assert_eq!(v["title"], "GitHub");
        assert!(v.get("username").is_none());
        assert!(v.get("url").is_none());
        assert!(v.get("notes").is_none());
        assert!(v.get("password").is_none());
        assert!(v.get("totp_code").is_none());
        assert_eq!(v["tags"], json!([]));
        assert_eq!(v["expired"], false);
        assert_eq!(v["has_attachments"], false);
        assert_eq!(v["has_totp"], false);
    }

    #[test]
    fn entry_get_view_emits_password_when_set() {
        let uuid = sample_uuid();
        let view = EntryGetView {
            uuid,
            title: "GitHub",
            username: Some("alice"),
            url: Some("https://github.com"),
            notes: None,
            password: Some("hunter2"),
            tags: vec!["work"],
            group: "Passwords",
            expired: false,
            has_attachments: false,
            has_totp: false,
            totp_code: None,
        };
        let v = json_of(&view);
        assert_eq!(v["password"], "hunter2");
        assert_eq!(v["tags"], json!(["work"]));
    }

    #[test]
    fn entry_get_view_emits_totp_code_when_set() {
        let uuid = sample_uuid();
        let view = EntryGetView {
            uuid,
            title: "GitHub",
            username: None,
            url: None,
            notes: None,
            password: None,
            tags: vec![],
            group: "Passwords",
            expired: false,
            has_attachments: false,
            has_totp: true,
            totp_code: Some("123456".to_string()),
        };
        let v = json_of(&view);
        assert_eq!(v["totp_code"], "123456");
        assert_eq!(v["has_totp"], true);
    }

    // ---- list ----

    #[test]
    fn entry_list_view_empty_serializes_to_empty_array() {
        let view = EntryListView { entries: vec![] };
        assert_eq!(json_of(&view), json!({ "entries": [] }));
    }

    #[test]
    fn entry_list_item_schema() {
        let uuid = sample_uuid();
        let view = EntryListView {
            entries: vec![EntryListItem {
                uuid,
                title: "GitHub",
                group: "Passwords",
                tags: vec!["work"],
                expired: false,
            }],
        };
        let v = json_of(&view);
        let row = &v["entries"][0];
        assert_eq!(row["uuid"], uuid.to_string());
        assert_eq!(row["title"], "GitHub");
        assert_eq!(row["group"], "Passwords");
        assert_eq!(row["tags"], json!(["work"]));
        assert_eq!(row["expired"], false);
    }

    #[test]
    fn entry_list_view_human_renders_table() {
        let view = EntryListView {
            entries: vec![EntryListItem {
                uuid: sample_uuid(),
                title: "GitHub",
                group: "Passwords",
                tags: vec![],
                expired: true,
            }],
        };
        let mut buf = Vec::new();
        view.write_human(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("UUID"), "header present: {s}");
        assert!(s.contains("GitHub"), "title row present: {s}");
        assert!(s.contains("[expired]"), "expired flag visible: {s}");
    }

    // ---- search ----

    #[test]
    fn entry_search_view_no_matches() {
        let view = EntrySearchView {
            query: "github",
            matches: vec![],
        };
        let v = json_of(&view);
        assert_eq!(v["query"], "github");
        assert_eq!(v["matches"], json!([]));
    }

    #[test]
    fn entry_search_view_with_matches() {
        let uuid = sample_uuid();
        let view = EntrySearchView {
            query: "git",
            matches: vec![EntrySearchItem {
                uuid,
                title: "GitHub",
                group: "Passwords",
                tags: vec![],
                expired: false,
                score: 8,
                matched_indices: vec![],
            }],
        };
        let v = json_of(&view);
        assert_eq!(v["matches"][0]["uuid"], uuid.to_string());
        assert_eq!(v["matches"][0]["title"], "GitHub");
        assert_eq!(v["matches"][0]["score"], 8, "score is always emitted");
        assert!(
            v["matches"][0].get("matched_indices").is_none(),
            "matched_indices omitted when empty (non-fuzzy)"
        );
    }

    #[test]
    fn entry_search_view_emits_fuzzy_indices() {
        let uuid = sample_uuid();
        let view = EntrySearchView {
            query: "git",
            matches: vec![EntrySearchItem {
                uuid,
                title: "GitHub",
                group: "Passwords",
                tags: vec![],
                expired: false,
                score: 42,
                matched_indices: vec![FieldIndices {
                    field: "title",
                    positions: vec![0, 1, 2],
                }],
            }],
        };
        let v = json_of(&view);
        assert_eq!(v["matches"][0]["matched_indices"][0]["field"], "title");
        assert_eq!(v["matches"][0]["matched_indices"][0]["positions"][2], 2);
    }

    // ---- add ----

    #[test]
    fn entry_add_view_omits_password_by_default() {
        let uuid = sample_uuid();
        let view = EntryAddView {
            uuid,
            title: "New",
            group: "Passwords",
            password: None,
        };
        let v = json_of(&view);
        assert_eq!(v["uuid"], uuid.to_string());
        assert_eq!(v["title"], "New");
        assert_eq!(v["group"], "Passwords");
        assert!(v.get("password").is_none(), "password absent by default");
    }

    #[test]
    fn entry_add_view_emits_password_when_show_password() {
        let view = EntryAddView {
            uuid: sample_uuid(),
            title: "New",
            group: "Passwords",
            password: Some("hunter2"),
        };
        let v = json_of(&view);
        assert_eq!(v["password"], "hunter2");
    }

    // ---- edit ----

    #[test]
    fn entry_edit_view_lists_modified_fields() {
        let uuid = sample_uuid();
        let view = EntryEditView {
            uuid,
            modified_fields: vec!["title", "tags"],
        };
        let v = json_of(&view);
        assert_eq!(v["uuid"], uuid.to_string());
        assert_eq!(v["modified_fields"], json!(["title", "tags"]));
    }

    // ---- rm ----

    #[test]
    fn entry_rm_view_recycle_bin_default() {
        let uuid = sample_uuid();
        let view = EntryRmView {
            uuid,
            recycle_bin: true,
        };
        let v = json_of(&view);
        assert_eq!(v["uuid"], uuid.to_string());
        assert_eq!(v["recycle_bin"], true);
    }

    #[test]
    fn entry_rm_view_permanent() {
        let view = EntryRmView {
            uuid: sample_uuid(),
            recycle_bin: false,
        };
        let v = json_of(&view);
        assert_eq!(v["recycle_bin"], false);
    }
}
