//! Entry search over an unlocked KDBX database.
//!
//! Two modes per FR-014:
//!
//! - [`SearchMode::Substring`] (default): case-insensitive substring match.
//! - [`SearchMode::Wildcard`] (opt-in): case-insensitive whole-field match
//!   with `*` (any sequence, including empty) and `?` (exactly one
//!   character). To express "field contains FOO" use `*FOO*`. Literal
//!   `*` and `?` are not supported as search terms — see PRD §6.2 FR-014.
//!
//! The wildcard matcher is a small in-tree iterative two-pointer
//! implementation (`wildcard_match` below) — deliberately a few dozen
//! lines so we don't pull a regex/PCRE crate for an opt-in feature.

use keepass::db::{fields, EntryRef};
use keepass::Database;

use crate::entry::crud::is_entry_in_recycle_bin;
use crate::entry::fuzzy::fuzzy_match;
use crate::{Vault, VaultError, VaultReadOnly};

/// Ranking weight for title matches.
pub const RANK_TITLE: u32 = 8;
/// Ranking weight for username matches.
pub const RANK_USERNAME: u32 = 4;
/// Ranking weight for URL matches.
pub const RANK_URL: u32 = 2;
/// Ranking weight for notes matches.
pub const RANK_NOTES: u32 = 1;
/// Ranking weight for tag matches.
pub const RANK_TAGS: u32 = 4;

/// Search configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchOptions {
    query: String,
    mode: SearchMode,
    include_recycled: bool,
    scope: SearchScope,
    boost: Vec<uuid::Uuid>,
}

/// Search matching mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchMode {
    /// Case-insensitive substring match.
    Substring,
    /// Case-insensitive wildcard match anchored to the whole field. `*`
    /// matches any sequence of characters (including empty); `?` matches
    /// exactly one character. Every other character is matched literally.
    Wildcard,
    /// fzf-style fuzzy subsequence match with per-field ranking and match
    /// highlighting (see [`crate::fuzzy_match`]). Space-separated query terms
    /// are combined with a logical AND: a term may match any field, and the
    /// entry matches only when every term matches at least one field.
    Fuzzy,
}

/// Restricts a search to a subset of the vault.
///
/// Scope composes with (does not replace) the Recycle Bin exclusion and applies
/// to every [`SearchMode`], not just [`SearchMode::Fuzzy`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum SearchScope {
    /// Search every entry in the vault (the default).
    #[default]
    All,
    /// Search only entries whose group is the given group or one of its
    /// descendants.
    GroupSubtree(uuid::Uuid),
    /// Search only entries carrying the given tag (case-insensitive, exact).
    Tag(String),
}

/// One entry search hit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchResult {
    /// Entry UUID.
    pub uuid: uuid::Uuid,
    /// Field-weighted score. Higher scores sort first.
    pub score: u32,
    /// Fields that matched the query.
    pub matched_fields: Vec<MatchedField>,
    /// Matched character positions per field, for highlighting. Populated only
    /// in [`SearchMode::Fuzzy`]; empty for substring/wildcard modes and for
    /// browse-mode (empty-query) fuzzy results. Positions are into the field
    /// value's `chars()`, strictly increasing (see [`crate::FuzzyMatch`]).
    pub match_indices: Vec<(MatchedField, Vec<u32>)>,
}

/// Entry field that matched a search query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchedField {
    /// KDBX `Title` field.
    Title,
    /// KDBX `UserName` field.
    Username,
    /// KDBX `URL` field.
    Url,
    /// KDBX `Notes` field.
    Notes,
    /// Entry tags.
    Tags,
}

impl SearchOptions {
    /// Construct default substring search options for `query`.
    ///
    /// Defaults to case-insensitive substring matching and excludes entries in
    /// the Recycle Bin.
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            mode: SearchMode::Substring,
            include_recycled: false,
            scope: SearchScope::All,
            boost: Vec::new(),
        }
    }

    /// Construct fuzzy-mode search options for `query`.
    ///
    /// Equivalent to `SearchOptions::new(query).with_mode(SearchMode::Fuzzy)`.
    /// An empty (or whitespace-only) query is browse mode: every in-scope entry
    /// is returned, boost-listed entries first (see [`Self::with_boost`]) then
    /// alphabetically by title.
    pub fn fuzzy(query: impl Into<String>) -> Self {
        Self::new(query).with_mode(SearchMode::Fuzzy)
    }

    /// Enable or disable wildcard mode.
    ///
    /// Wildcards (`*`, `?`) match the whole value — pad with `*` to express
    /// "contains."
    #[must_use]
    pub fn wildcard(mut self, on: bool) -> Self {
        self.mode = if on {
            SearchMode::Wildcard
        } else {
            SearchMode::Substring
        };
        self
    }

    /// Set the matching mode explicitly.
    #[must_use]
    pub fn with_mode(mut self, mode: SearchMode) -> Self {
        self.mode = mode;
        self
    }

    /// Restrict the search to a group subtree or a tag. Defaults to
    /// [`SearchScope::All`].
    #[must_use]
    pub fn with_scope(mut self, scope: SearchScope) -> Self {
        self.scope = scope;
        self
    }

    /// Provide a recency-boost list: at equal score bands these UUIDs rank
    /// above non-boosted entries (and, in browse mode, appear first in the
    /// given order). Boost never outranks a strictly higher score.
    #[must_use]
    pub fn with_boost(mut self, boost: Vec<uuid::Uuid>) -> Self {
        self.boost = boost;
        self
    }

    /// Include or exclude Recycle Bin entries.
    #[must_use]
    pub fn include_recycled(mut self, on: bool) -> Self {
        self.include_recycled = on;
        self
    }

    /// Return the configured query.
    pub fn query(&self) -> &str {
        &self.query
    }

    /// Return the configured search mode.
    pub fn mode(&self) -> SearchMode {
        self.mode
    }

    /// Return whether recycled entries are included.
    pub fn includes_recycled(&self) -> bool {
        self.include_recycled
    }
}

impl Vault {
    /// Search entries in this writable vault.
    pub fn search(&self, opts: SearchOptions) -> Result<Vec<SearchResult>, VaultError> {
        Ok(search_database(self.database(), opts))
    }
}

impl VaultReadOnly {
    /// Search entries in this read-only vault.
    pub fn search(&self, opts: SearchOptions) -> Result<Vec<SearchResult>, VaultError> {
        Ok(search_database(self.database(), opts))
    }
}

fn search_database(db: &Database, opts: SearchOptions) -> Vec<SearchResult> {
    let SearchOptions {
        query,
        mode,
        include_recycled,
        scope,
        boost,
    } = opts;

    // Scope membership is computed once per search (never per entry). Subtree
    // scope expands to the descendant-group UUID set; tag scope folds the
    // needle to lowercase for a case-insensitive exact match.
    let subtree_groups = match &scope {
        SearchScope::GroupSubtree(target) => Some(collect_subtree_group_ids(db, *target)),
        _ => None,
    };
    let tag_needle = match &scope {
        SearchScope::Tag(tag) => Some(tag.to_lowercase()),
        _ => None,
    };
    let in_scope = |entry: &EntryRef<'_>| -> bool {
        if let Some(groups) = &subtree_groups {
            if !groups.contains(&entry.parent().id().uuid()) {
                return false;
            }
        }
        if let Some(tag) = &tag_needle {
            if !entry.tags.iter().any(|t| t.to_lowercase() == *tag) {
                return false;
            }
        }
        true
    };

    // Fuzzy browse mode: an empty query lists every in-scope entry, boosted
    // first, then alphabetically — the search overlay opens useful (design
    // §2.2.6). Substring/wildcard keep their historical empty-query = no-op.
    if mode == SearchMode::Fuzzy && query.trim().is_empty() {
        return browse_results(db, include_recycled, &in_scope, &boost);
    }
    if query.is_empty() {
        return Vec::new();
    }

    let mut results = Vec::new();
    match mode {
        SearchMode::Fuzzy => {
            let terms: Vec<&str> = query.split_whitespace().collect();
            for entry in db.iter_all_entries() {
                if !include_recycled && is_entry_in_recycle_bin(db, entry.id()) {
                    continue;
                }
                if !in_scope(&entry) {
                    continue;
                }
                if let Some(result) = score_entry_fuzzy(&entry, &terms) {
                    results.push(result);
                }
            }
        }
        SearchMode::Substring | SearchMode::Wildcard => {
            let matcher = Matcher::new(&query, mode);
            for entry in db.iter_all_entries() {
                if !include_recycled && is_entry_in_recycle_bin(db, entry.id()) {
                    continue;
                }
                if !in_scope(&entry) {
                    continue;
                }
                if let Some(result) = score_entry(&entry, &matcher) {
                    results.push(result);
                }
            }
        }
    }

    // Primary sort key is score (descending) — boost NEVER outranks a strictly
    // higher score. Within an equal-score band, boosted entries sort first;
    // UUID order is the final deterministic tie-break.
    let boost_set: std::collections::HashSet<uuid::Uuid> = boost.iter().copied().collect();
    results.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| {
                let left_boost = boost_set.contains(&left.uuid);
                let right_boost = boost_set.contains(&right.uuid);
                right_boost.cmp(&left_boost)
            })
            .then_with(|| left.uuid.as_bytes().cmp(right.uuid.as_bytes()))
    });

    results
}

/// Browse-mode (empty fuzzy query) ordering: boosted entries first in the
/// boost-list order, then remaining in-scope entries alphabetically by title.
fn browse_results(
    db: &Database,
    include_recycled: bool,
    in_scope: &impl Fn(&EntryRef<'_>) -> bool,
    boost: &[uuid::Uuid],
) -> Vec<SearchResult> {
    let mut entries: Vec<(uuid::Uuid, String)> = Vec::new();
    for entry in db.iter_all_entries() {
        if !include_recycled && is_entry_in_recycle_bin(db, entry.id()) {
            continue;
        }
        if !in_scope(&entry) {
            continue;
        }
        let title = entry.get(fields::TITLE).unwrap_or("").to_string();
        entries.push((entry.id().uuid(), title));
    }

    let present: std::collections::HashSet<uuid::Uuid> =
        entries.iter().map(|(uuid, _)| *uuid).collect();
    let mut used: std::collections::HashSet<uuid::Uuid> = std::collections::HashSet::new();
    let mut out: Vec<SearchResult> = Vec::new();

    for uuid in boost {
        if present.contains(uuid) && used.insert(*uuid) {
            out.push(browse_hit(*uuid));
        }
    }

    let mut rest: Vec<&(uuid::Uuid, String)> = entries
        .iter()
        .filter(|(uuid, _)| !used.contains(uuid))
        .collect();
    rest.sort_by(|left, right| {
        left.1
            .to_lowercase()
            .cmp(&right.1.to_lowercase())
            .then_with(|| left.0.as_bytes().cmp(right.0.as_bytes()))
    });
    for (uuid, _) in rest {
        out.push(browse_hit(*uuid));
    }

    out
}

fn browse_hit(uuid: uuid::Uuid) -> SearchResult {
    SearchResult {
        uuid,
        score: 0,
        matched_fields: Vec::new(),
        match_indices: Vec::new(),
    }
}

/// Collect the target group UUID plus every descendant group UUID.
fn collect_subtree_group_ids(
    db: &Database,
    target: uuid::Uuid,
) -> std::collections::HashSet<uuid::Uuid> {
    let mut set = std::collections::HashSet::new();
    if let Some(group) = db.iter_all_groups().find(|g| g.id().uuid() == target) {
        collect_group_ids(&group, &mut set);
    }
    set
}

fn collect_group_ids(
    group: &keepass::db::GroupRef<'_>,
    set: &mut std::collections::HashSet<uuid::Uuid>,
) {
    set.insert(group.id().uuid());
    for child in group.groups() {
        collect_group_ids(&child, set);
    }
}

enum Matcher {
    Substring { needle: String },
    Wildcard { pattern: Vec<char> },
}

impl Matcher {
    fn new(query: &str, mode: SearchMode) -> Self {
        match mode {
            SearchMode::Substring | SearchMode::Fuzzy => Self::Substring {
                needle: query.to_lowercase(),
            },
            SearchMode::Wildcard => Self::Wildcard {
                pattern: query.to_lowercase().chars().collect(),
            },
        }
    }

    fn is_match(&self, value: &str) -> bool {
        match self {
            Self::Substring { needle } => value.to_lowercase().contains(needle.as_str()),
            Self::Wildcard { pattern } => {
                let value: Vec<char> = value.to_lowercase().chars().collect();
                wildcard_match(pattern, &value)
            }
        }
    }
}

/// Whole-string wildcard match: `*` matches any sequence (including empty),
/// `?` matches exactly one character, all other characters match literally.
///
/// Iterative two-pointer algorithm with backtrack on `*` — O(n+m) for
/// typical inputs and O(n*m) worst case, well within budget for the
/// 5,000-entry / ≤200-char field workload search is benchmarked against.
fn wildcard_match(pattern: &[char], value: &[char]) -> bool {
    let mut p = 0;
    let mut v = 0;
    let mut star_p: Option<usize> = None;
    let mut star_v: usize = 0;

    while v < value.len() {
        if p < pattern.len() && pattern[p] == '*' {
            star_p = Some(p);
            star_v = v;
            p += 1;
        } else if p < pattern.len() && (pattern[p] == '?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if let Some(saved) = star_p {
            p = saved + 1;
            star_v += 1;
            v = star_v;
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

fn score_entry(entry: &EntryRef<'_>, matcher: &Matcher) -> Option<SearchResult> {
    let mut score = 0;
    let mut matched_fields = Vec::new();

    score_field(
        entry.get(fields::TITLE).unwrap_or(""),
        matcher,
        RANK_TITLE,
        MatchedField::Title,
        &mut score,
        &mut matched_fields,
    );
    score_field(
        entry.get(fields::USERNAME).unwrap_or(""),
        matcher,
        RANK_USERNAME,
        MatchedField::Username,
        &mut score,
        &mut matched_fields,
    );
    score_field(
        entry.get(fields::URL).unwrap_or(""),
        matcher,
        RANK_URL,
        MatchedField::Url,
        &mut score,
        &mut matched_fields,
    );
    score_field(
        entry.get(fields::NOTES).unwrap_or(""),
        matcher,
        RANK_NOTES,
        MatchedField::Notes,
        &mut score,
        &mut matched_fields,
    );

    let tags = entry.tags.join(";");
    score_field(
        &tags,
        matcher,
        RANK_TAGS,
        MatchedField::Tags,
        &mut score,
        &mut matched_fields,
    );

    (score > 0).then(|| SearchResult {
        uuid: entry.id().uuid(),
        score,
        matched_fields,
        match_indices: Vec::new(),
    })
}

fn score_field(
    value: &str,
    matcher: &Matcher,
    weight: u32,
    field: MatchedField,
    score: &mut u32,
    matched_fields: &mut Vec<MatchedField>,
) {
    if matcher.is_match(value) {
        *score += weight;
        matched_fields.push(field);
    }
}

/// The searchable fields of an entry, in ranking-weight order, as
/// `(value, field, weight)` tuples. The joined tag string is owned by the
/// caller so it outlives the returned borrows.
fn scored_fields<'a>(entry: &'a EntryRef<'a>, tags: &'a str) -> [(&'a str, MatchedField, u32); 5] {
    [
        (
            entry.get(fields::TITLE).unwrap_or(""),
            MatchedField::Title,
            RANK_TITLE,
        ),
        (
            entry.get(fields::USERNAME).unwrap_or(""),
            MatchedField::Username,
            RANK_USERNAME,
        ),
        (
            entry.get(fields::URL).unwrap_or(""),
            MatchedField::Url,
            RANK_URL,
        ),
        (
            entry.get(fields::NOTES).unwrap_or(""),
            MatchedField::Notes,
            RANK_NOTES,
        ),
        (tags, MatchedField::Tags, RANK_TAGS),
    ]
}

/// Fuzzy-score an entry against the query's AND-combined terms.
///
/// Each term is matched independently against every field; the entry matches
/// only when **every** term matches at least one field (a term may hit any
/// field — `"git jason"` can match a git-titled, jason-usernamed entry). Each
/// term contributes its best `fuzzy score × field weight`; the contributing
/// field's matched character positions are recorded for highlighting.
fn score_entry_fuzzy(entry: &EntryRef<'_>, terms: &[&str]) -> Option<SearchResult> {
    let tags = entry.tags.join(";");
    let scored = scored_fields(entry, &tags);

    let mut total: i32 = 0;
    let mut field_indices: Vec<(MatchedField, Vec<u32>)> = Vec::new();

    for term in terms {
        // The single best (highest weighted-score) field for this term.
        let mut best: Option<(i32, MatchedField, Vec<u32>)> = None;
        for (value, field, weight) in scored {
            if let Some(m) = fuzzy_match(term, value) {
                let weighted = m.score.saturating_mul(weight.cast_signed());
                if best
                    .as_ref()
                    .is_none_or(|(best_score, _, _)| weighted > *best_score)
                {
                    best = Some((weighted, field, m.indices));
                }
            }
        }

        // A term that matches no field excludes the entry.
        let (weighted, field, indices) = best?;
        total = total.saturating_add(weighted);
        match field_indices.iter_mut().find(|(f, _)| *f == field) {
            Some(slot) => slot.1.extend(indices),
            None => field_indices.push((field, indices)),
        }
    }

    for (_, indices) in &mut field_indices {
        indices.sort_unstable();
        indices.dedup();
    }
    let matched_fields = field_indices.iter().map(|(field, _)| *field).collect();

    Some(SearchResult {
        uuid: entry.id().uuid(),
        // Heavily-gapped subsequence matches can score negative; browse/sort
        // treat those as the low-value tail, so clamp to the u32 floor.
        score: total.max(0).cast_unsigned(),
        matched_fields,
        match_indices: field_indices,
    })
}

#[cfg(test)]
mod tests {
    use keepass::db::Value;

    use super::*;

    fn search_db() -> (Database, uuid::Uuid, uuid::Uuid) {
        let mut db = Database::new();
        let title = db
            .root_mut()
            .add_entry()
            .edit(|entry| {
                entry.set_unprotected(fields::TITLE, "Example");
                entry.set_unprotected(fields::USERNAME, "alice");
                entry.set_unprotected(fields::URL, "https://title.test");
                entry.set_unprotected(fields::NOTES, "no keyword here");
                entry.tags.push("primary".to_string());
            })
            .id()
            .uuid();
        let notes = db
            .root_mut()
            .add_entry()
            .edit(|entry| {
                entry.set_unprotected(fields::TITLE, "Secondary");
                entry.set_unprotected(fields::USERNAME, "bob");
                entry.set_unprotected(fields::URL, "https://notes.test");
                entry.set_unprotected(fields::NOTES, "example appears only here");
                entry.tags.push("archive".to_string());
                entry.add_attachment("ignored.txt", Value::unprotected(b"example".to_vec()));
            })
            .id()
            .uuid();
        (db, title, notes)
    }

    #[test]
    fn substring_search_matches_standard_fields_and_tags() {
        let (mut db, _, _) = search_db();
        db.root_mut().add_entry().edit(|entry| {
            entry.set_unprotected(fields::TITLE, "Tagged");
            entry.tags.push("ExampleTag".to_string());
        });

        let results = search_database(&db, SearchOptions::new("example"));

        assert_eq!(results.len(), 3);
        assert!(results
            .iter()
            .any(|result| result.matched_fields.contains(&MatchedField::Tags)));
    }

    #[test]
    fn substring_search_is_case_insensitive() {
        let (db, _, _) = search_db();

        let lower = search_database(&db, SearchOptions::new("example"));
        let upper = search_database(&db, SearchOptions::new("EXAMPLE"));

        assert_eq!(lower, upper);
    }

    #[test]
    fn title_match_ranks_above_notes_match() {
        let (db, title_uuid, notes_uuid) = search_db();

        let results = search_database(&db, SearchOptions::new("example"));

        assert_eq!(results[0].uuid, title_uuid);
        assert_eq!(results[1].uuid, notes_uuid);
        assert!(results[0].score > results[1].score);
    }

    #[test]
    fn wildcard_mode_anchors_to_whole_field() {
        let (db, title_uuid, _) = search_db();

        // Anchored: "Example" matches only the entry whose title is exactly
        // "Example" (and no other field on any other entry contains it
        // standalone).
        let results = search_database(&db, SearchOptions::new("example").wildcard(true));

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].uuid, title_uuid);
    }

    #[test]
    fn wildcard_star_matches_any_substring() {
        let (db, title_uuid, notes_uuid) = search_db();

        let results = search_database(&db, SearchOptions::new("*example*").wildcard(true));

        // Both the title and the notes entry should match, since *example*
        // matches anywhere in a field.
        let uuids: Vec<_> = results.iter().map(|result| result.uuid).collect();
        assert!(uuids.contains(&title_uuid));
        assert!(uuids.contains(&notes_uuid));
    }

    #[test]
    fn wildcard_question_mark_matches_single_character() {
        let mut db = Database::new();
        let one = db
            .root_mut()
            .add_entry()
            .edit(|entry| entry.set_unprotected(fields::TITLE, "cat"))
            .id()
            .uuid();
        db.root_mut().add_entry().edit(|entry| {
            entry.set_unprotected(fields::TITLE, "cart");
        });

        let results = search_database(&db, SearchOptions::new("c?t").wildcard(true));

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].uuid, one);
    }

    #[test]
    fn empty_query_returns_no_results() {
        let (db, _, _) = search_db();

        let results = search_database(&db, SearchOptions::new(""));

        assert!(results.is_empty());
    }

    #[test]
    fn wildcard_match_basics() {
        // Direct unit tests on the matcher to lock in the contract.
        let cases: &[(&str, &str, bool)] = &[
            ("", "", true),
            ("*", "", true),
            ("*", "anything", true),
            ("?", "", false),
            ("?", "a", true),
            ("?", "ab", false),
            ("a*b", "ab", true),
            ("a*b", "axxb", true),
            ("a*b", "axxc", false),
            ("foo*", "foobar", true),
            ("*bar", "foobar", true),
            ("*foo*", "xfoox", true),
            ("a?c", "abc", true),
            ("a?c", "ac", false),
            ("**", "abc", true),
        ];
        for (pattern, value, want) in cases {
            let pattern: Vec<char> = pattern.chars().collect();
            let value: Vec<char> = value.chars().collect();
            let got = wildcard_match(&pattern, &value);
            assert_eq!(
                got, *want,
                "pattern={pattern:?} value={value:?} want={want}"
            );
        }
    }

    // ---------------------------------------------------------------------
    // T4.1: fuzzy mode, scope, boost
    // ---------------------------------------------------------------------

    fn uuids(results: &[SearchResult]) -> Vec<uuid::Uuid> {
        results.iter().map(|r| r.uuid).collect()
    }

    #[test]
    fn fuzzy_mode_matches_and_ranks() {
        // "git" hits both a title ("GitHub") and a notes field ("git repo");
        // the title weight (8) must rank the title match first.
        let mut db = Database::new();
        let title_hit = db
            .root_mut()
            .add_entry()
            .edit(|entry| {
                entry.set_unprotected(fields::TITLE, "GitHub");
                entry.set_unprotected(fields::USERNAME, "octocat");
            })
            .id()
            .uuid();
        let notes_hit = db
            .root_mut()
            .add_entry()
            .edit(|entry| {
                entry.set_unprotected(fields::TITLE, "Wiki");
                entry.set_unprotected(fields::NOTES, "git repository notes");
            })
            .id()
            .uuid();

        let results = search_database(&db, SearchOptions::fuzzy("git"));

        assert_eq!(uuids(&results), vec![title_hit, notes_hit]);
        assert!(results[0].score > results[1].score);
    }

    #[test]
    fn terms_hit_across_fields() {
        // "git jason": each term may match a *different* field. The match has
        // git in the title and jason in the username; the miss has git but no
        // jason anywhere and is excluded.
        let mut db = Database::new();
        let hit = db
            .root_mut()
            .add_entry()
            .edit(|entry| {
                entry.set_unprotected(fields::TITLE, "GitHub");
                entry.set_unprotected(fields::USERNAME, "jason");
            })
            .id()
            .uuid();
        db.root_mut().add_entry().edit(|entry| {
            entry.set_unprotected(fields::TITLE, "GitLab");
            entry.set_unprotected(fields::USERNAME, "bob");
        });

        let results = search_database(&db, SearchOptions::fuzzy("git jason"));

        assert_eq!(uuids(&results), vec![hit]);
    }

    struct ScopedDb {
        db: Database,
        bank: uuid::Uuid,
        card1: uuid::Uuid,
        bank1: uuid::Uuid,
        other1: uuid::Uuid,
        root1: uuid::Uuid,
    }

    /// root ─ Banking ─ Cards ─ [card1 (tag "Primary")]
    ///      │         └ [bank1]
    ///      ├ Other ─ [other1]
    ///      ├ [root1]
    ///      └ Recycle Bin ─ [recycled]   (all titles contain "acct")
    fn scoped_db() -> ScopedDb {
        let mut db = Database::new();
        let banking_group = db
            .root_mut()
            .add_group()
            .edit(|g| g.name = "Banking".to_string())
            .id();
        let cards_group = db
            .group_mut(banking_group)
            .unwrap()
            .add_group()
            .edit(|g| g.name = "Cards".to_string())
            .id();
        let other_group = db
            .root_mut()
            .add_group()
            .edit(|g| g.name = "Other".to_string())
            .id();

        let card1 = db
            .group_mut(cards_group)
            .unwrap()
            .add_entry()
            .edit(|entry| {
                entry.set_unprotected(fields::TITLE, "Acct Card");
                entry.tags.push("Primary".to_string());
            })
            .id()
            .uuid();
        let bank1 = db
            .group_mut(banking_group)
            .unwrap()
            .add_entry()
            .edit(|entry| entry.set_unprotected(fields::TITLE, "Acct Bank"))
            .id()
            .uuid();
        let other1 = db
            .group_mut(other_group)
            .unwrap()
            .add_entry()
            .edit(|entry| entry.set_unprotected(fields::TITLE, "Acct Other"))
            .id()
            .uuid();
        let root1 = db
            .root_mut()
            .add_entry()
            .edit(|entry| entry.set_unprotected(fields::TITLE, "Acct Root"))
            .id()
            .uuid();

        // A recycled entry that scope + recycle exclusion must both drop.
        let bin = db
            .root_mut()
            .add_group()
            .edit(|g| g.name = "Recycle Bin".to_string())
            .id();
        db.meta.recyclebin_uuid = Some(bin.uuid());
        db.meta.recyclebin_enabled = Some(true);
        db.group_mut(bin)
            .unwrap()
            .add_entry()
            .edit(|entry| entry.set_unprotected(fields::TITLE, "Acct Old"));

        ScopedDb {
            db,
            bank: banking_group.uuid(),
            card1,
            bank1,
            other1,
            root1,
        }
    }

    #[test]
    fn scope_group_subtree_and_tag_filter() {
        let fx = scoped_db();

        let all = search_database(&fx.db, SearchOptions::fuzzy("acct"));
        let mut all_set: Vec<_> = uuids(&all);
        all_set.sort();
        let mut expected = vec![fx.card1, fx.bank1, fx.other1, fx.root1];
        expected.sort();
        assert_eq!(all_set, expected, "recycled excluded, siblings included");

        let subtree = search_database(
            &fx.db,
            SearchOptions::fuzzy("acct").with_scope(SearchScope::GroupSubtree(fx.bank)),
        );
        let mut subtree_set = uuids(&subtree);
        subtree_set.sort();
        let mut want = vec![fx.card1, fx.bank1];
        want.sort();
        assert_eq!(
            subtree_set, want,
            "subtree includes descendant, drops siblings"
        );

        let tagged = search_database(
            &fx.db,
            SearchOptions::fuzzy("acct").with_scope(SearchScope::Tag("primary".to_string())),
        );
        assert_eq!(
            uuids(&tagged),
            vec![fx.card1],
            "tag is case-insensitive exact"
        );
    }

    #[test]
    fn scope_applies_to_substring_mode_too() {
        let fx = scoped_db();
        let subtree = search_database(
            &fx.db,
            SearchOptions::new("acct").with_scope(SearchScope::GroupSubtree(fx.bank)),
        );
        let mut got = uuids(&subtree);
        got.sort();
        let mut want = vec![fx.card1, fx.bank1];
        want.sort();
        assert_eq!(got, want);
    }

    #[test]
    fn boost_list_ranks_above_equal_scores_only() {
        // best: leading match (start-of-string boundary bonus) → strictly
        // highest. a/b: identical mid-word matches → equal score.
        let mut db = Database::new();
        let best = db
            .root_mut()
            .add_entry()
            .edit(|entry| entry.set_unprotected(fields::TITLE, "Sam"))
            .id()
            .uuid();
        let a = db
            .root_mut()
            .add_entry()
            .edit(|entry| entry.set_unprotected(fields::TITLE, "Insam"))
            .id()
            .uuid();
        let b = db
            .root_mut()
            .add_entry()
            .edit(|entry| entry.set_unprotected(fields::TITLE, "Insam"))
            .id()
            .uuid();

        let results = search_database(&db, SearchOptions::fuzzy("sam").with_boost(vec![b]));

        // best (strictly higher score) stays first despite b being boosted;
        // among the equal-score pair the boosted b outranks a.
        assert_eq!(uuids(&results), vec![best, b, a]);
    }

    #[test]
    fn empty_query_returns_boost_then_alpha() {
        let mut db = Database::new();
        let zebra = db
            .root_mut()
            .add_entry()
            .edit(|entry| entry.set_unprotected(fields::TITLE, "Zebra"))
            .id()
            .uuid();
        let apple = db
            .root_mut()
            .add_entry()
            .edit(|entry| entry.set_unprotected(fields::TITLE, "apple"))
            .id()
            .uuid();
        let mango = db
            .root_mut()
            .add_entry()
            .edit(|entry| entry.set_unprotected(fields::TITLE, "Mango"))
            .id()
            .uuid();

        let results = search_database(&db, SearchOptions::fuzzy("").with_boost(vec![mango]));

        // Boosted mango first, then the rest case-insensitively alphabetical.
        assert_eq!(uuids(&results), vec![mango, apple, zebra]);
    }

    #[test]
    fn match_indices_surface_per_field() {
        let mut db = Database::new();
        db.root_mut().add_entry().edit(|entry| {
            entry.set_unprotected(fields::TITLE, "GitHub");
        });

        let fuzzy = search_database(&db, SearchOptions::fuzzy("git"));
        assert_eq!(fuzzy.len(), 1);
        assert_eq!(
            fuzzy[0].match_indices,
            vec![(MatchedField::Title, vec![0, 1, 2])]
        );

        let substring = search_database(&db, SearchOptions::new("git"));
        assert_eq!(substring.len(), 1);
        assert!(
            substring[0].match_indices.is_empty(),
            "non-fuzzy modes carry no highlight indices"
        );
    }
}
