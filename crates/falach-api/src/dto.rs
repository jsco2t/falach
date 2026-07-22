use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::FalachApiError;

// ---------------------------------------------------------------------------
// Vault / registry
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct VaultSummary {
    pub name: String,
    pub path: String,
    pub has_keyfile: bool,
    pub has_sync: bool,
}

#[derive(Clone, Debug)]
pub struct VaultTree {
    pub root: GroupNode,
    pub entries: Vec<EntrySummary>,
}

#[derive(Clone, Debug)]
pub struct GroupNode {
    pub uuid: String,
    pub name: String,
    pub children: Vec<GroupNode>,
    pub entry_count: usize,
}

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKindDto {
    Credential,
    SecureNote,
    Totp,
}

#[derive(Clone)]
pub struct EntrySummary {
    pub uuid: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub kind: EntryKindDto,
    pub has_totp: bool,
    pub has_attachments: bool,
    pub is_expired: bool,
    pub group_uuid: String,
    pub tags: Vec<String>,
}

impl fmt::Debug for EntrySummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntrySummary")
            .field("uuid", &self.uuid)
            .field("title", &"***")
            .field("username", &"***")
            .field("url", &"***")
            .field("kind", &self.kind)
            .field("has_totp", &self.has_totp)
            .field("has_attachments", &self.has_attachments)
            .field("is_expired", &self.is_expired)
            .field("group_uuid", &self.group_uuid)
            .field("tag_count", &self.tags.len())
            .finish()
    }
}

#[derive(Clone)]
pub struct EntryDetail {
    pub uuid: String,
    pub title: String,
    pub username: String,
    pub has_password: bool,
    pub url: String,
    pub notes: String,
    pub kind: EntryKindDto,
    pub tags: Vec<String>,
    pub custom_fields: Vec<CustomFieldDto>,
    pub attachments: Vec<AttachmentMeta>,
    pub creation_time: Option<i64>,
    pub last_modification_time: Option<i64>,
    pub expiry_time: Option<i64>,
}

impl fmt::Debug for EntryDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryDetail")
            .field("uuid", &self.uuid)
            .field("title", &"***")
            .field("username", &"***")
            .field("has_password", &self.has_password)
            .field("url", &"***")
            .field("notes", &"***")
            .field("kind", &self.kind)
            .field("tag_count", &self.tags.len())
            .field("custom_field_count", &self.custom_fields.len())
            .field("attachment_count", &self.attachments.len())
            .field("creation_time", &self.creation_time)
            .field("last_modification_time", &self.last_modification_time)
            .field("expiry_time", &self.expiry_time)
            .finish()
    }
}

#[derive(Clone)]
pub struct CustomFieldDto {
    pub name: String,
    pub is_protected: bool,
}

impl fmt::Debug for CustomFieldDto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomFieldDto")
            .field("name", &"***")
            .field("is_protected", &self.is_protected)
            .finish()
    }
}

#[derive(Clone)]
pub struct AttachmentMeta {
    pub name: String,
    pub size_bytes: u64,
}

impl fmt::Debug for AttachmentMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttachmentMeta")
            .field("name", &"***")
            .field("size_bytes", &self.size_bytes)
            .finish()
    }
}

#[derive(Clone)]
pub struct HistorySummary {
    pub title: String,
    pub username: String,
    pub last_modification_time: Option<i64>,
}

impl fmt::Debug for HistorySummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistorySummary")
            .field("title", &"***")
            .field("username", &"***")
            .field("last_modification_time", &self.last_modification_time)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Entry draft / edit (inbound, secret-bearing)
// ---------------------------------------------------------------------------

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EntryDraftDto {
    #[zeroize(skip)]
    pub kind: EntryKindDto,
    pub title: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub custom_fields: Vec<CustomFieldInputDto>,
    pub totp_uri: Option<String>,
}

impl fmt::Debug for EntryDraftDto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryDraftDto")
            .field("kind", &self.kind)
            .field("title", &"***")
            .field("username", &self.username.as_ref().map(|_| "***"))
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("url", &self.url.as_ref().map(|_| "***"))
            .field("notes", &self.notes.as_ref().map(|_| "***"))
            .field("tag_count", &self.tags.len())
            .field("custom_fields", &"[redacted]")
            .field("totp_uri", &self.totp_uri.as_ref().map(|_| "***"))
            .finish()
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CustomFieldInputDto {
    pub name: String,
    pub value: String,
    pub protected: bool,
}

impl fmt::Debug for CustomFieldInputDto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomFieldInputDto")
            .field("name", &"***")
            .field("value", &"***")
            .field("protected", &self.protected)
            .finish()
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EntryEditDto {
    pub title: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub custom_fields: Option<Vec<CustomFieldInputDto>>,
    pub totp_uri: Option<String>,
}

impl fmt::Debug for EntryEditDto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryEditDto")
            .field("title", &self.title.as_ref().map(|_| "***"))
            .field("username", &self.username.as_ref().map(|_| "***"))
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("url", &self.url.as_ref().map(|_| "***"))
            .field("notes", &self.notes.as_ref().map(|_| "***"))
            .field("tag_count", &self.tags.as_ref().map(Vec::len))
            .field("custom_fields", &"[redacted]")
            .field("totp_uri", &self.totp_uri.as_ref().map(|_| "***"))
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchModeDto {
    Substring,
    Wildcard,
    Fuzzy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SearchScopeDto {
    All,
    GroupSubtree(String),
    Tag(String),
}

#[derive(Clone)]
pub struct SearchOptionsDto {
    pub query: String,
    pub mode: SearchModeDto,
    pub scope: SearchScopeDto,
    pub include_recycled: bool,
}

impl fmt::Debug for SearchOptionsDto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scope = match &self.scope {
            SearchScopeDto::All => "all",
            SearchScopeDto::GroupSubtree(_) => "group-subtree",
            SearchScopeDto::Tag(_) => "tag",
        };
        f.debug_struct("SearchOptionsDto")
            .field("query", &"***")
            .field("mode", &self.mode)
            .field("scope", &scope)
            .field("include_recycled", &self.include_recycled)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MatchedFieldDto {
    Title,
    Username,
    Url,
    Notes,
    Tags,
}

#[derive(Clone, Debug)]
pub struct SearchHit {
    pub entry: EntrySummary,
    pub matches: Vec<SearchFieldMatchDto>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchFieldMatchDto {
    pub field: MatchedFieldDto,
    pub ranges: Vec<(u32, u32)>,
}

// ---------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TotpCode {
    pub code: String,
    pub remaining_secs: u64,
    pub period: u64,
}

impl fmt::Debug for TotpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpCode")
            .field("code", &"***")
            .field("remaining_secs", &self.remaining_secs)
            .field("period", &self.period)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Password generation
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct PasswordOptionsDto {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

#[derive(Clone, Debug)]
pub struct PassphraseOptionsDto {
    pub words: usize,
    pub separator: String,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct GeneratedSecret {
    pub value: String,
    pub entropy_bits: f64,
}

impl fmt::Debug for GeneratedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedSecret")
            .field("value", &"***")
            .field("entropy_bits", &self.entropy_bits)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct S3ConfigDto {
    pub bucket: String,
    pub key: String,
    pub region: String,
    pub endpoint: Option<String>,
    pub path_style: bool,
    pub access_key_id: String,
    pub secret_access_key: String,
}

impl fmt::Debug for S3ConfigDto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3ConfigDto")
            .field("bucket", &self.bucket)
            .field("key", &self.key)
            .field("region", &self.region)
            .field("endpoint", &self.endpoint)
            .field("path_style", &self.path_style)
            .field("access_key_id", &"***")
            .field("secret_access_key", &"***")
            .finish()
    }
}

impl fmt::Display for S3ConfigDto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "S3ConfigDto {{ bucket: {}, key: {}, region: {} }}",
            self.bucket, self.key, self.region
        )
    }
}

#[derive(Clone, Debug)]
pub struct SyncStatusDto {
    pub configured: bool,
    pub in_flight: bool,
    pub last_outcome: Option<SyncOutcomeDto>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncOutcomeDto {
    AlreadyInSync,
    Pushed {
        is_first_seed: bool,
    },
    FastReplaced,
    Merged {
        entries_added: usize,
        entries_modified: usize,
        entries_removed: usize,
    },
    Unknown,
}

#[derive(Clone, Debug)]
pub enum SyncEvent {
    Started,
    Activity,
    Done(SyncOutcomeDto),
    Failed(FalachApiError),
}

// ---------------------------------------------------------------------------
// Lock / lifecycle / events
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum LockEvent {
    Locked,
    Unlocked,
}

#[derive(Clone, Debug)]
pub struct ClipboardEvent {
    pub remaining_secs: u32,
    pub cleared: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum LifecycleStateDto {
    Resumed,
    Inactive,
    Hidden,
    Paused,
    Detached,
}

// ---------------------------------------------------------------------------
// Init / keyfile / prefs
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct AppInitConfig {
    pub state_dir: Option<String>,
    pub config_dir: Option<String>,
}

#[derive(Clone)]
pub enum KeyfileRef {
    Path(String),
    Bytes(Vec<u8>),
}

impl Zeroize for KeyfileRef {
    fn zeroize(&mut self) {
        if let Self::Bytes(bytes) = self {
            bytes.zeroize();
        }
    }
}

impl Drop for KeyfileRef {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for KeyfileRef {}

impl fmt::Debug for KeyfileRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(_) => f.write_str("KeyfileRef::Path(***)"),
            Self::Bytes(_) => f.write_str("KeyfileRef::Bytes(***)"),
        }
    }
}

#[derive(Clone, Debug)]
pub enum RevealField {
    Password,
    CustomField(String),
    TotpUri,
}

#[derive(Clone, Debug)]
pub enum CopyField {
    Username,
    Password,
    TotpCode,
    CustomField(String),
}

#[derive(Clone, Debug, Default)]
pub struct UiPrefs {
    pub theme_mode: Option<String>,
    pub window_x: Option<i32>,
    pub window_y: Option<i32>,
    pub window_width: Option<i32>,
    pub window_height: Option<i32>,
    pub last_vault: Option<String>,
}

// ===========================================================================
// Mapping functions from core types
// ===========================================================================

impl From<falach_core::EntryKind> for EntryKindDto {
    fn from(kind: falach_core::EntryKind) -> Self {
        match kind {
            falach_core::EntryKind::Credential => Self::Credential,
            falach_core::EntryKind::SecureNote => Self::SecureNote,
            falach_core::EntryKind::Totp => Self::Totp,
        }
    }
}

impl From<falach_core::MatchedField> for MatchedFieldDto {
    fn from(field: falach_core::MatchedField) -> Self {
        match field {
            falach_core::MatchedField::Title => Self::Title,
            falach_core::MatchedField::Username => Self::Username,
            falach_core::MatchedField::Url => Self::Url,
            falach_core::MatchedField::Notes => Self::Notes,
            falach_core::MatchedField::Tags => Self::Tags,
        }
    }
}

// These adapters are intentionally crate-private: the public UI boundary must
// never expose core or sync crate types. The application service added in T1.2
// consumes them; until then, the unit tests below are their only callers.
#[allow(dead_code)]
fn datetime_to_epoch(dt: chrono::DateTime<chrono::Utc>) -> i64 {
    dt.timestamp()
}

#[allow(dead_code)]
pub(crate) fn entry_summary_from_view(
    view: &falach_core::EntryView<'_>,
    group_uuid: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> EntrySummary {
    EntrySummary {
        uuid: view.uuid().hyphenated().to_string(),
        title: view.title().to_string(),
        username: view.username().to_string(),
        url: view.url().to_string(),
        kind: view.kind().into(),
        has_totp: view.kind() == falach_core::EntryKind::Totp,
        has_attachments: !view.attachments().is_empty(),
        is_expired: view.expires().is_some_and(|exp| exp <= now),
        group_uuid: group_uuid.to_string(),
        tags: view.tags().iter().map(|t| t.as_str().to_string()).collect(),
    }
}

#[allow(dead_code)]
pub(crate) fn entry_detail_from_view(view: &falach_core::EntryView<'_>) -> EntryDetail {
    EntryDetail {
        uuid: view.uuid().hyphenated().to_string(),
        title: view.title().to_string(),
        username: view.username().to_string(),
        has_password: !view.password().is_empty(),
        url: view.url().to_string(),
        notes: view.notes().to_string(),
        kind: view.kind().into(),
        tags: view.tags().iter().map(|t| t.as_str().to_string()).collect(),
        custom_fields: view
            .custom_field_names()
            .into_iter()
            .map(|name| CustomFieldDto {
                name: name.to_string(),
                is_protected: view.custom_field_is_protected(name).unwrap_or(false),
            })
            .collect(),
        attachments: view
            .attachments()
            .into_iter()
            .map(|a| AttachmentMeta {
                name: a.name,
                size_bytes: a.size_bytes,
            })
            .collect(),
        creation_time: view.creation_time().map(datetime_to_epoch),
        last_modification_time: view.last_modification_time().map(datetime_to_epoch),
        expiry_time: view.expires().map(datetime_to_epoch),
    }
}

#[allow(dead_code)]
pub(crate) fn history_summaries_from_view(
    view: &falach_core::EntryView<'_>,
) -> Vec<HistorySummary> {
    view.history()
        .into_iter()
        .map(|h| HistorySummary {
            title: h.title().to_string(),
            username: h.username().to_string(),
            last_modification_time: h.last_modification_time().map(datetime_to_epoch),
        })
        .collect()
}

#[allow(dead_code)]
pub(crate) fn sync_outcome_from_core(outcome: &falach_sync::SyncOutcome) -> SyncOutcomeDto {
    match outcome {
        falach_sync::SyncOutcome::AlreadyInSync => SyncOutcomeDto::AlreadyInSync,
        falach_sync::SyncOutcome::Pushed { is_first_seed } => SyncOutcomeDto::Pushed {
            is_first_seed: *is_first_seed,
        },
        falach_sync::SyncOutcome::FastReplaced => SyncOutcomeDto::FastReplaced,
        falach_sync::SyncOutcome::Merged { delta, .. } => SyncOutcomeDto::Merged {
            entries_added: delta.added.len(),
            entries_modified: delta.modified.len(),
            entries_removed: delta.removed.len(),
        },
        _ => SyncOutcomeDto::Unknown,
    }
}

/// Convert a core database into the UI tree and flattened entry list.
///
/// The recycle-bin subtree is deliberately excluded from both views. Recycled
/// entries are available only through explicit search options so callers do
/// not accidentally present deleted data as live vault contents.
#[allow(dead_code)]
pub(crate) fn vault_tree_from_database(
    database: &falach_core::Database,
    now: chrono::DateTime<chrono::Utc>,
) -> VaultTree {
    let recycle_bin_uuid = database.recycle_bin().map(|group| group.id().uuid());
    let mut entries = Vec::new();
    let root_ref = database.root();
    let root = group_node_from_ref(&root_ref, recycle_bin_uuid, now, &mut entries);
    VaultTree { root, entries }
}

#[allow(dead_code)]
fn group_node_from_ref(
    group: &falach_core::GroupRef<'_>,
    recycle_bin_uuid: Option<falach_core::Uuid>,
    now: chrono::DateTime<chrono::Utc>,
    flattened_entries: &mut Vec<EntrySummary>,
) -> GroupNode {
    let group_uuid = group.id().uuid();
    let group_uuid_string = group_uuid.hyphenated().to_string();
    let entry_count = group.entries().count();
    flattened_entries.extend(group.entries().map(|entry| {
        entry_summary_from_view(&falach_core::EntryView::new(entry), &group_uuid_string, now)
    }));

    let children = group
        .groups()
        .filter(|child| Some(child.id().uuid()) != recycle_bin_uuid)
        .map(|child| group_node_from_ref(&child, recycle_bin_uuid, now, flattened_entries))
        .collect();

    GroupNode {
        uuid: group_uuid_string,
        name: group.name.clone(),
        children,
        entry_count,
    }
}

/// Convert one core search result while keeping every highlight range paired
/// with the field whose text it indexes.
#[allow(dead_code)]
pub(crate) fn search_hit_from_core(
    result: &falach_core::SearchResult,
    view: &falach_core::EntryView<'_>,
    group_uuid: &str,
    mode: SearchModeDto,
    query: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> SearchHit {
    let matches = match mode {
        SearchModeDto::Fuzzy => result
            .match_indices
            .iter()
            .map(|(field, indices)| SearchFieldMatchDto {
                field: (*field).into(),
                ranges: char_indices_to_utf16_ranges(&field_value(view, *field), indices),
            })
            .collect(),
        SearchModeDto::Substring => result
            .matched_fields
            .iter()
            .map(|field| SearchFieldMatchDto {
                field: (*field).into(),
                ranges: substring_match_utf16_ranges(&field_value(view, *field), query),
            })
            .collect(),
        SearchModeDto::Wildcard => result
            .matched_fields
            .iter()
            .map(|field| SearchFieldMatchDto {
                field: (*field).into(),
                ranges: Vec::new(),
            })
            .collect(),
    };

    SearchHit {
        entry: entry_summary_from_view(view, group_uuid, now),
        matches,
    }
}

#[allow(dead_code)]
fn field_value(view: &falach_core::EntryView<'_>, field: falach_core::MatchedField) -> String {
    match field {
        falach_core::MatchedField::Title => view.title().to_string(),
        falach_core::MatchedField::Username => view.username().to_string(),
        falach_core::MatchedField::Url => view.url().to_string(),
        falach_core::MatchedField::Notes => view.notes().to_string(),
        falach_core::MatchedField::Tags => view
            .tags()
            .iter()
            .map(falach_core::Tag::as_str)
            .collect::<Vec<_>>()
            .join(";"),
    }
}

/// Convert core char-index-based match positions to UTF-16 code unit ranges.
///
/// Core's fuzzy matcher yields character indices into `haystack.chars()`.
/// Dart's `TextSpan` works in UTF-16 code units. This function converts char
/// indices to UTF-16 offsets, returning `(start, end)` pairs suitable for
/// slicing Dart `String`s. Each matched char produces one range spanning
/// that char's UTF-16 code units.
#[allow(clippy::cast_possible_truncation)]
#[allow(dead_code)]
pub(crate) fn char_indices_to_utf16_ranges(
    haystack: &str,
    char_indices: &[u32],
) -> Vec<(u32, u32)> {
    if char_indices.is_empty() {
        return Vec::new();
    }

    let mut ranges = Vec::with_capacity(char_indices.len());
    let mut utf16_offset: u32 = 0;
    let mut idx_cursor = 0;

    for (char_pos, ch) in (0_u32..).zip(haystack.chars()) {
        if idx_cursor >= char_indices.len() {
            break;
        }
        let ch_utf16_len = ch.len_utf16() as u32;
        if char_pos == char_indices[idx_cursor] {
            ranges.push((utf16_offset, utf16_offset + ch_utf16_len));
            idx_cursor += 1;
        }
        utf16_offset += ch_utf16_len;
    }

    ranges
}

/// Compute UTF-16 ranges for a substring match (case-insensitive).
///
/// Core's substring search yields no position data — only which fields matched.
/// We re-locate the match here purely for highlighting.
struct FoldedSegment {
    folded_start: usize,
    folded_end: usize,
    utf16_start: u32,
    utf16_end: u32,
}

#[allow(clippy::cast_possible_truncation)]
#[allow(dead_code)]
pub(crate) fn substring_match_utf16_ranges(haystack: &str, needle: &str) -> Vec<(u32, u32)> {
    if needle.is_empty() {
        return Vec::new();
    }

    let mut hay_lower = String::new();
    let mut segments = Vec::with_capacity(haystack.chars().count());
    let mut utf16_offset = 0_u32;
    for ch in haystack.chars() {
        let folded_start = hay_lower.len();
        hay_lower.extend(ch.to_lowercase());
        let folded_end = hay_lower.len();
        let utf16_end = utf16_offset + ch.len_utf16() as u32;
        segments.push(FoldedSegment {
            folded_start,
            folded_end,
            utf16_start: utf16_offset,
            utf16_end,
        });
        utf16_offset = utf16_end;
    }
    let needle_lower = needle.to_lowercase();

    if needle_lower.is_empty() {
        return Vec::new();
    }

    let Some(byte_start) = hay_lower.find(&needle_lower) else {
        return Vec::new();
    };
    let byte_end = byte_start + needle_lower.len();

    let Some(first) = segments
        .iter()
        .find(|segment| segment.folded_end > byte_start)
    else {
        return Vec::new();
    };
    let Some(last) = segments
        .iter()
        .rev()
        .find(|segment| segment.folded_start < byte_end)
    else {
        return Vec::new();
    };

    vec![(first.utf16_start, last.utf16_end)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn char_indices_to_utf16_ranges_ascii() {
        let ranges = char_indices_to_utf16_ranges("GitHub", &[0, 1, 2]);
        assert_eq!(ranges, vec![(0, 1), (1, 2), (2, 3)]);
    }

    #[test]
    fn char_indices_to_utf16_ranges_bmp_multibyte() {
        // "café" — 'é' is U+00E9 (BMP, 1 UTF-16 code unit, but 2 UTF-8 bytes)
        let ranges = char_indices_to_utf16_ranges("café", &[3]);
        assert_eq!(ranges, vec![(3, 4)]);
    }

    #[test]
    fn char_indices_to_utf16_ranges_astral() {
        // "a🔑b" — '🔑' is U+1F511 (astral, 2 UTF-16 code units)
        let ranges = char_indices_to_utf16_ranges("a\u{1F511}b", &[0, 1, 2]);
        // 'a' = offset 0, width 1 → (0,1)
        // '🔑' = offset 1, width 2 → (1,3)
        // 'b' = offset 3, width 1 → (3,4)
        assert_eq!(ranges, vec![(0, 1), (1, 3), (3, 4)]);
    }

    #[test]
    fn char_indices_to_utf16_ranges_empty() {
        let ranges = char_indices_to_utf16_ranges("hello", &[]);
        assert!(ranges.is_empty());
    }

    #[test]
    fn char_indices_to_utf16_mixed_bmp_and_astral() {
        // "日本🗾語" — 日(BMP,1), 本(BMP,1), 🗾(astral,2), 語(BMP,1)
        let ranges = char_indices_to_utf16_ranges("日本\u{1F5FE}語", &[0, 2, 3]);
        // '日' offset 0, width 1 → (0,1)
        // '🗾' offset 2, width 2 → (2,4)
        // '語' offset 4, width 1 → (4,5)
        assert_eq!(ranges, vec![(0, 1), (2, 4), (4, 5)]);
    }

    #[test]
    fn substring_match_utf16_ranges_ascii() {
        let ranges = substring_match_utf16_ranges("Hello World", "world");
        assert_eq!(ranges, vec![(6, 11)]);
    }

    #[test]
    fn substring_match_utf16_ranges_no_match() {
        let ranges = substring_match_utf16_ranges("Hello", "xyz");
        assert!(ranges.is_empty());
    }

    #[test]
    fn substring_match_utf16_ranges_empty_needle() {
        let ranges = substring_match_utf16_ranges("Hello", "");
        assert!(ranges.is_empty());
    }

    #[test]
    fn substring_match_preserves_original_offsets_when_case_fold_expands() {
        // U+0130 lowercases to two Unicode scalars (`i` + combining dot).
        // The following ASCII x is still at UTF-16 offset 1 in the original.
        assert_eq!(substring_match_utf16_ranges("İx", "x"), vec![(1, 2)]);
        assert_eq!(substring_match_utf16_ranges("İx", "i\u{307}"), vec![(0, 1)]);
    }

    #[test]
    fn vault_tree_uses_production_mapper_and_excludes_recycle_bin() {
        use falach_core::fields;

        let mut database = falach_core::Database::new();
        database
            .root_mut()
            .edit(|root| root.name = "Root".to_string());
        database.root_mut().add_entry().edit(|entry| {
            entry.set_unprotected(fields::TITLE, "Root entry");
        });
        database
            .root_mut()
            .add_group()
            .edit(|group| group.name = "Banking".to_string())
            .add_entry()
            .edit(|entry| entry.set_unprotected(fields::TITLE, "Bank entry"));
        let recycle_bin_id = database
            .root_mut()
            .add_group()
            .edit(|group| group.name = "Recycle Bin".to_string())
            .id();
        database
            .group_mut(recycle_bin_id)
            .expect("recycle bin group should exist")
            .add_entry()
            .edit(|entry| entry.set_unprotected(fields::TITLE, "Deleted entry"));
        database.meta.recyclebin_enabled = Some(true);
        database.meta.recyclebin_uuid = Some(recycle_bin_id.uuid());

        let tree = vault_tree_from_database(&database, chrono::Utc::now());

        assert_eq!(tree.root.name, "Root");
        assert_eq!(tree.root.entry_count, 1);
        assert_eq!(tree.root.children.len(), 1);
        assert_eq!(tree.root.children[0].name, "Banking");
        assert_eq!(tree.root.children[0].entry_count, 1);
        assert_eq!(tree.entries.len(), 2);
        assert!(tree
            .entries
            .iter()
            .all(|entry| entry.title != "Deleted entry"));
    }

    #[test]
    fn expiration_at_the_current_instant_is_expired() {
        use falach_core::fields;

        let now = chrono::Utc::now();
        let mut database = falach_core::Database::new();
        let entry_id = database
            .root_mut()
            .add_entry()
            .edit(|entry| {
                entry.set_unprotected(fields::TITLE, "Boundary");
                entry.times.expires = Some(true);
                entry.times.expiry = Some(now.naive_utc());
            })
            .id();
        let view = falach_core::EntryView::new(
            database
                .entry(entry_id)
                .expect("boundary entry should exist"),
        );

        assert!(entry_summary_from_view(&view, "root", now).is_expired);
    }

    #[test]
    fn search_ranges_remain_associated_with_their_fields() {
        use falach_core::{fields, MatchedField, SearchResult};

        let mut database = falach_core::Database::new();
        let entry_id = database
            .root_mut()
            .add_entry()
            .edit(|entry| {
                entry.set_unprotected(fields::TITLE, "GitHub");
                entry.set_unprotected(fields::USERNAME, "octocat");
            })
            .id();
        let view = falach_core::EntryView::new(
            database.entry(entry_id).expect("search entry should exist"),
        );
        let title_match = falach_core::fuzzy_match("gh", view.title()).expect("title should match");
        let username_match =
            falach_core::fuzzy_match("oct", view.username()).expect("username should match");
        let result = SearchResult {
            uuid: view.uuid(),
            score: 1,
            matched_fields: vec![MatchedField::Title, MatchedField::Username],
            match_indices: vec![
                (MatchedField::Title, title_match.indices.clone()),
                (MatchedField::Username, username_match.indices.clone()),
            ],
        };

        let hit = search_hit_from_core(
            &result,
            &view,
            "root",
            SearchModeDto::Fuzzy,
            "unused-in-fuzzy-mode",
            chrono::Utc::now(),
        );

        assert_eq!(hit.matches.len(), 2);
        assert_eq!(hit.matches[0].field, MatchedFieldDto::Title);
        assert_eq!(
            hit.matches[0].ranges,
            char_indices_to_utf16_ranges(view.title(), &title_match.indices)
        );
        assert_eq!(hit.matches[1].field, MatchedFieldDto::Username);
        assert_eq!(
            hit.matches[1].ranges,
            char_indices_to_utf16_ranges(view.username(), &username_match.indices)
        );
    }

    #[test]
    fn substring_and_wildcard_search_mapping_have_mode_correct_ranges() {
        use falach_core::{fields, MatchedField, SearchResult};

        let mut database = falach_core::Database::new();
        let entry_id = database
            .root_mut()
            .add_entry()
            .edit(|entry| entry.set_unprotected(fields::TITLE, "İx"))
            .id();
        let view = falach_core::EntryView::new(
            database.entry(entry_id).expect("search entry should exist"),
        );
        let result = SearchResult {
            uuid: view.uuid(),
            score: 1,
            matched_fields: vec![MatchedField::Title],
            match_indices: Vec::new(),
        };

        let substring = search_hit_from_core(
            &result,
            &view,
            "root",
            SearchModeDto::Substring,
            "x",
            chrono::Utc::now(),
        );
        assert_eq!(substring.matches[0].ranges, vec![(1, 2)]);

        let wildcard = search_hit_from_core(
            &result,
            &view,
            "root",
            SearchModeDto::Wildcard,
            "*x",
            chrono::Utc::now(),
        );
        assert!(wildcard.matches[0].ranges.is_empty());
    }

    #[test]
    fn fuzzy_browse_result_still_maps_to_one_entry_hit() {
        use falach_core::{fields, SearchResult};

        let mut database = falach_core::Database::new();
        let entry_id = database
            .root_mut()
            .add_entry()
            .edit(|entry| entry.set_unprotected(fields::TITLE, "Browse entry"))
            .id();
        let view = falach_core::EntryView::new(
            database.entry(entry_id).expect("browse entry should exist"),
        );
        let result = SearchResult {
            uuid: view.uuid(),
            score: 0,
            matched_fields: Vec::new(),
            match_indices: Vec::new(),
        };

        let hit = search_hit_from_core(
            &result,
            &view,
            "root",
            SearchModeDto::Fuzzy,
            "",
            chrono::Utc::now(),
        );

        assert_eq!(hit.entry.uuid, view.uuid().hyphenated().to_string());
        assert!(hit.matches.is_empty());
    }

    #[test]
    fn sync_outcome_mapping_is_exact_for_every_current_variant() {
        use falach_core::Uuid;
        use falach_sync::{EntryDelta, SyncOutcome};

        assert_eq!(
            sync_outcome_from_core(&SyncOutcome::AlreadyInSync),
            SyncOutcomeDto::AlreadyInSync
        );
        assert_eq!(
            sync_outcome_from_core(&SyncOutcome::Pushed {
                is_first_seed: true,
            }),
            SyncOutcomeDto::Pushed {
                is_first_seed: true,
            }
        );
        assert_eq!(
            sync_outcome_from_core(&SyncOutcome::FastReplaced),
            SyncOutcomeDto::FastReplaced
        );
        assert_eq!(
            sync_outcome_from_core(&SyncOutcome::Merged {
                delta: EntryDelta {
                    added: vec![Uuid::nil()],
                    modified: vec![Uuid::nil(), Uuid::nil()],
                    removed: Vec::new(),
                },
                attempts: 2,
            }),
            SyncOutcomeDto::Merged {
                entries_added: 1,
                entries_modified: 2,
                entries_removed: 0,
            }
        );
    }

    #[test]
    fn entry_detail_maps_kinds_fields_and_password_presence_without_password_value() {
        use falach_core::{fields, Value};

        let mut database = falach_core::Database::new();
        let credential_id = database
            .root_mut()
            .add_entry()
            .edit(|entry| {
                entry.set_unprotected(fields::TITLE, "Credential");
                entry.set_unprotected(fields::USERNAME, "user");
                entry.set_protected(fields::PASSWORD, "marker-password");
                entry.set_protected("pin", "1234");
                entry.set_unprotected("label", "home");
                entry
                    .tags
                    .extend(["work".to_string(), "finance".to_string()]);
                entry.add_attachment("document.pdf", Value::unprotected(vec![1, 2, 3]));
            })
            .id();
        let note_id = database
            .root_mut()
            .add_entry()
            .edit(|entry| {
                entry.set_unprotected(fields::TITLE, "Note");
                entry.set_unprotected(fields::NOTES, "note contents");
            })
            .id();
        let totp_id = database
            .root_mut()
            .add_entry()
            .edit(|entry| {
                entry.set_unprotected(fields::TITLE, "TOTP");
                entry.set_protected(fields::OTP, "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP");
            })
            .id();

        let credential_view = falach_core::EntryView::new(
            database
                .entry(credential_id)
                .expect("credential should exist"),
        );
        let credential = entry_detail_from_view(&credential_view);
        assert_eq!(credential.kind, EntryKindDto::Credential);
        assert!(credential.has_password);
        assert_eq!(credential.tags, vec!["work", "finance"]);
        assert_eq!(credential.attachments[0].name, "document.pdf");
        assert_eq!(credential.attachments[0].size_bytes, 3);
        assert!(credential
            .custom_fields
            .iter()
            .any(|field| field.name == "pin" && field.is_protected));
        assert!(credential
            .custom_fields
            .iter()
            .any(|field| field.name == "label" && !field.is_protected));
        assert!(!format!("{credential:?}").contains("marker-password"));

        let note = entry_detail_from_view(&falach_core::EntryView::new(
            database.entry(note_id).expect("note should exist"),
        ));
        assert_eq!(note.kind, EntryKindDto::SecureNote);
        assert!(!note.has_password);

        let totp = entry_detail_from_view(&falach_core::EntryView::new(
            database.entry(totp_id).expect("TOTP entry should exist"),
        ));
        assert_eq!(totp.kind, EntryKindDto::Totp);
        assert!(!totp.has_password);
    }

    #[test]
    fn history_summary_preserves_newest_first_order_and_timestamps() {
        use falach_core::fields;

        fn instant(value: &str) -> chrono::NaiveDateTime {
            chrono::DateTime::parse_from_rfc3339(value)
                .expect("test timestamp should parse")
                .naive_utc()
        }

        let mut database = falach_core::Database::new();
        let entry_id = database
            .root_mut()
            .add_entry()
            .edit(|entry| {
                entry.set_unprotected(fields::TITLE, "v1");
                entry.set_unprotected(fields::USERNAME, "user-v1");
                entry.times.last_modification = Some(instant("2024-01-01T00:00:00Z"));
            })
            .id();
        for (title, username, timestamp) in [
            ("v2", "user-v2", "2024-01-02T00:00:00Z"),
            ("v3", "user-v3", "2024-01-03T00:00:00Z"),
            ("v4", "user-v4", "2024-01-04T00:00:00Z"),
        ] {
            database
                .entry_mut(entry_id)
                .expect("history entry should exist")
                .edit_tracking(|entry| {
                    entry.set_unprotected(fields::TITLE, title);
                    entry.set_unprotected(fields::USERNAME, username);
                    entry.times.last_modification = Some(instant(timestamp));
                });
        }

        let view = falach_core::EntryView::new(
            database
                .entry(entry_id)
                .expect("history entry should exist"),
        );
        let history = history_summaries_from_view(&view);

        assert_eq!(history.len(), 3);
        assert_eq!(
            history
                .iter()
                .map(|item| item.title.as_str())
                .collect::<Vec<_>>(),
            vec!["v3", "v2", "v1"]
        );
        assert_eq!(
            history
                .iter()
                .map(|item| item.username.as_str())
                .collect::<Vec<_>>(),
            vec!["user-v3", "user-v2", "user-v1"]
        );
        assert_eq!(
            history
                .iter()
                .map(|item| item.last_modification_time)
                .collect::<Vec<_>>(),
            vec![
                Some(1_704_240_000),
                Some(1_704_153_600),
                Some(1_704_067_200)
            ]
        );
    }

    #[test]
    fn entry_kind_dto_from_core() {
        assert_eq!(
            EntryKindDto::from(falach_core::EntryKind::Credential),
            EntryKindDto::Credential
        );
        assert_eq!(
            EntryKindDto::from(falach_core::EntryKind::SecureNote),
            EntryKindDto::SecureNote
        );
        assert_eq!(
            EntryKindDto::from(falach_core::EntryKind::Totp),
            EntryKindDto::Totp
        );
    }

    #[test]
    fn matched_field_dto_from_core() {
        assert_eq!(
            MatchedFieldDto::from(falach_core::MatchedField::Title),
            MatchedFieldDto::Title
        );
        assert_eq!(
            MatchedFieldDto::from(falach_core::MatchedField::Username),
            MatchedFieldDto::Username
        );
    }
}
