//! `entry_tree` — the Secrets-tab group/entry tree (T3.1 / T3.2 / ADR-T6).
//!
//! The tree is the left pane of the Secrets tab: a depth-first flattening of the
//! vault's group hierarchy with entries nested under their group. The Recycle
//! Bin group is skipped. Selection is tracked by **UUID** (not row index) so it
//! survives content changes, expand/collapse, and re-sorts (ADR-T4a:
//! "selection re-resolved from UUIDs each frame").
//!
//! ## Pure core vs. render adapter
//!
//! [`build_rows`] is a clock-free pure function: it flattens the visible tree
//! into [`TreeRow`]s given the expansion set + [`SortOrder`]. Navigation lives
//! on [`TreeState`] and operates over a precomputed `&[TreeRow]`, so both are
//! unit-testable without a terminal. [`render_tree`] is the thin adapter that
//! draws the rows (and computes the per-entry expired affordance, which needs a
//! clock) into a `ratatui` `List` — the `List` gives auto-scroll-to-selection
//! for free.

use std::cmp::Ordering;
use std::collections::HashSet;

use chrono::{DateTime, Utc};
use falach_core::Vault;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};
use ratatui::Frame;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::recents::Recents;
use crate::theme::Theme;

/// Tree sort order (design U.2). Applies to **entries within each group**;
/// groups always sort by name. `RecentlyUsed` is the redesign default (D-2):
/// it orders entries by their position in the per-vault [`Recents`] list, with
/// entries not in the list falling back to title order (see [`sort_entries`]).
///
/// The explicit `#[serde(rename)]`s pin the `tui.toml` wire form so a future
/// variant rename can't silently invalidate persisted configs (ADR-T3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum SortOrder {
    #[serde(rename = "recently-used")]
    RecentlyUsed,
    #[serde(rename = "title")]
    Title,
    #[serde(rename = "last-modified")]
    LastModified,
    #[serde(rename = "group")]
    Group,
}

impl SortOrder {
    /// Human-readable name for the status bar.
    pub(crate) fn label(self) -> &'static str {
        match self {
            SortOrder::RecentlyUsed => "Recently used",
            SortOrder::Title => "Title",
            SortOrder::LastModified => "Last modified",
            SortOrder::Group => "Group",
        }
    }

    /// The next order in the cycle (`o` key).
    pub(crate) fn next(self) -> Self {
        match self {
            SortOrder::RecentlyUsed => SortOrder::Title,
            SortOrder::Title => SortOrder::LastModified,
            SortOrder::LastModified => SortOrder::Group,
            SortOrder::Group => SortOrder::RecentlyUsed,
        }
    }
}

/// What a flattened row represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RowKind {
    Group { expanded: bool, has_children: bool },
    Entry,
}

/// One visible row in the flattened tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TreeRow {
    pub(crate) uuid: Uuid,
    pub(crate) depth: usize,
    pub(crate) kind: RowKind,
}

impl TreeRow {
    fn is_group(self) -> bool {
        matches!(self.kind, RowKind::Group { .. })
    }
}

/// Persistent tree state: which groups are expanded, the selected node (by
/// UUID), and the active sort order. Lives on `App` (design U.2).
pub(crate) struct TreeState {
    expanded: HashSet<Uuid>,
    selected: Option<Uuid>,
    sort: SortOrder,
}

impl TreeState {
    pub(crate) fn new() -> Self {
        Self::with_sort(SortOrder::RecentlyUsed)
    }

    /// A fresh tree state with a caller-chosen sort order. `App` uses this on
    /// unlock to honour the persisted global default (`config.toml`); [`Self::new`]
    /// applies the redesign default (`RecentlyUsed`, D-2 / T4.3).
    pub(crate) fn with_sort(sort: SortOrder) -> Self {
        Self {
            expanded: HashSet::new(),
            selected: None,
            sort,
        }
    }

    pub(crate) fn sort(&self) -> SortOrder {
        self.sort
    }

    pub(crate) fn selected(&self) -> Option<Uuid> {
        self.selected
    }

    /// Advance the sort order (the `o` key). Selection is UUID-based so it
    /// survives the re-sort untouched.
    pub(crate) fn cycle_sort(&mut self) {
        self.sort = self.sort.next();
    }

    /// Index of the selected UUID within `rows`, if it is currently visible.
    pub(crate) fn selected_index(&self, rows: &[TreeRow]) -> Option<usize> {
        let selected = self.selected?;
        rows.iter().position(|r| r.uuid == selected)
    }

    /// Whether the selected node is an entry (vs. a group / nothing).
    pub(crate) fn selected_is_entry(&self, rows: &[TreeRow]) -> bool {
        self.selected_index(rows)
            .is_some_and(|i| !rows[i].is_group())
    }

    /// Select the first visible row (called on unlock).
    pub(crate) fn select_first(&mut self, rows: &[TreeRow]) {
        self.selected = rows.first().map(|r| r.uuid);
    }

    /// Programmatically select `uuid` (search jump, post-add). Visibility is the
    /// caller's concern — the detail pane resolves the selection by UUID even
    /// when the row is inside a collapsed group.
    pub(crate) fn select(&mut self, uuid: Uuid) {
        self.selected = Some(uuid);
    }

    /// Mark `group` expanded so a freshly added/searched entry under it becomes
    /// visible in the flattened rows.
    pub(crate) fn expand(&mut self, group: Uuid) {
        self.expanded.insert(group);
    }

    /// `j` / Down — move selection down one visible row. Returns whether the
    /// selected node changed (so the caller can reset reveal/scroll).
    pub(crate) fn move_next(&mut self, rows: &[TreeRow]) -> bool {
        if rows.is_empty() {
            return self.clear_selection();
        }
        let idx = self.selected_index(rows).unwrap_or(0);
        let next = (idx + 1).min(rows.len() - 1);
        self.set_selected(rows[next].uuid)
    }

    /// `k` / Up — move selection up one visible row.
    pub(crate) fn move_prev(&mut self, rows: &[TreeRow]) -> bool {
        if rows.is_empty() {
            return self.clear_selection();
        }
        let idx = self.selected_index(rows).unwrap_or(0);
        let prev = idx.saturating_sub(1);
        self.set_selected(rows[prev].uuid)
    }

    /// `h` / Left — collapse the selected group, or (on an entry / collapsed
    /// group) move selection up to the parent group.
    pub(crate) fn collapse_or_parent(&mut self, rows: &[TreeRow]) -> bool {
        let Some(idx) = self.selected_index(rows) else {
            return false;
        };
        let row = rows[idx];
        if let RowKind::Group { expanded: true, .. } = row.kind {
            // Collapse in place; selection stays on the (still-visible) group.
            self.expanded.remove(&row.uuid);
            return false;
        }
        if row.depth == 0 {
            return false; // top-level node has no parent
        }
        // Nearest preceding row at a shallower depth is the parent group.
        for i in (0..idx).rev() {
            if rows[i].depth < row.depth {
                return self.set_selected(rows[i].uuid);
            }
        }
        false
    }

    /// `l` / Right — expand a collapsed group, or step into the first child of
    /// an already-expanded group. No-op on an entry or an empty group.
    pub(crate) fn expand_or_child(&mut self, rows: &[TreeRow]) -> bool {
        let Some(idx) = self.selected_index(rows) else {
            return false;
        };
        match rows[idx].kind {
            RowKind::Group {
                expanded: false,
                has_children: true,
            } => {
                self.expanded.insert(rows[idx].uuid);
                false // expansion changes the tree, not the selected node
            }
            RowKind::Group { expanded: true, .. }
                if idx + 1 < rows.len() && rows[idx + 1].depth > rows[idx].depth =>
            {
                self.set_selected(rows[idx + 1].uuid)
            }
            _ => false,
        }
    }

    /// `Enter` on a group toggles its expansion. Returns whether the selected
    /// node was a group (so the caller knows it was handled).
    pub(crate) fn toggle_expand(&mut self, rows: &[TreeRow]) -> bool {
        let Some(idx) = self.selected_index(rows) else {
            return false;
        };
        if rows[idx].is_group() {
            let uuid = rows[idx].uuid;
            if !self.expanded.remove(&uuid) {
                self.expanded.insert(uuid);
            }
            true
        } else {
            false
        }
    }

    fn set_selected(&mut self, uuid: Uuid) -> bool {
        let changed = self.selected != Some(uuid);
        self.selected = Some(uuid);
        changed
    }

    fn clear_selection(&mut self) -> bool {
        let changed = self.selected.is_some();
        self.selected = None;
        changed
    }
}

/// Flatten the visible tree into rows (depth-first; Recycle Bin skipped).
/// Pure and clock-free — the expired affordance is computed at render time.
/// `recents` supplies the per-vault MRU ordering for the `RecentlyUsed` sort
/// (ignored by the other orders).
pub(crate) fn build_rows(vault: &Vault, state: &TreeState, recents: &Recents) -> Vec<TreeRow> {
    let recycle = vault.database().recycle_bin().map(|g| g.id().uuid());
    let mut rows = Vec::new();
    walk(
        vault,
        vault.root_group_uuid(),
        0,
        &state.expanded,
        state.sort,
        recents,
        recycle,
        &mut rows,
    );
    rows
}

/// Emit the child groups (then entries) of `group_uuid` at `depth`, recursing
/// into expanded groups.
#[allow(clippy::too_many_arguments)]
fn walk(
    vault: &Vault,
    group_uuid: Uuid,
    depth: usize,
    expanded: &HashSet<Uuid>,
    sort: SortOrder,
    recents: &Recents,
    recycle: Option<Uuid>,
    rows: &mut Vec<TreeRow>,
) {
    let Ok(group) = vault.group_view(group_uuid) else {
        return;
    };

    // Child groups, sorted by name, with the Recycle Bin filtered out.
    let mut child_groups: Vec<(String, Uuid)> = group
        .child_group_uuids()
        .into_iter()
        .filter(|uuid| Some(*uuid) != recycle)
        .filter_map(|uuid| {
            vault
                .group_view(uuid)
                .ok()
                .map(|g| (g.name().to_lowercase(), uuid))
        })
        .collect();
    child_groups.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    for (_, child) in child_groups {
        let child_view = vault.group_view(child);
        let has_children = child_view.as_ref().is_ok_and(|g| !g.is_empty());
        let is_expanded = expanded.contains(&child);
        rows.push(TreeRow {
            uuid: child,
            depth,
            kind: RowKind::Group {
                expanded: is_expanded,
                has_children,
            },
        });
        if is_expanded {
            walk(
                vault,
                child,
                depth + 1,
                expanded,
                sort,
                recents,
                recycle,
                rows,
            );
        }
    }

    // Entries of this group, sorted per the active order.
    let mut entries = group.entry_uuids();
    sort_entries(vault, &mut entries, sort, recents);
    for entry in entries {
        rows.push(TreeRow {
            uuid: entry,
            depth,
            kind: RowKind::Entry,
        });
    }
}

/// Sort entry UUIDs in place per `sort`. `RecentlyUsed` orders by position in
/// `recents` (most-recent first); entries absent from the list fall back to
/// title order, so an empty recents list degenerates to a plain title sort.
fn sort_entries(vault: &Vault, entries: &mut [Uuid], sort: SortOrder, recents: &Recents) {
    match sort {
        // Native order from `entry_uuids()` (UUID order); a stable grouping.
        SortOrder::Group => {}
        SortOrder::Title => {
            entries.sort_by(|a, b| title_cmp(vault, *a, *b));
        }
        SortOrder::RecentlyUsed => {
            entries.sort_by(|a, b| match (recents.rank(*a), recents.rank(*b)) {
                (Some(ra), Some(rb)) => ra.cmp(&rb),
                // A used entry sorts before an unused one.
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                // Neither used: stable title order.
                (None, None) => title_cmp(vault, *a, *b),
            });
        }
        SortOrder::LastModified => {
            entries.sort_by(|a, b| {
                let ma = vault
                    .get_entry(*a)
                    .ok()
                    .and_then(|e| e.last_modification_time());
                let mb = vault
                    .get_entry(*b)
                    .ok()
                    .and_then(|e| e.last_modification_time());
                // Newest first; `None` (unknown) sorts last.
                mb.cmp(&ma).then(a.cmp(b))
            });
        }
    }
}

fn title_key(vault: &Vault, uuid: Uuid) -> String {
    vault
        .get_entry(uuid)
        .map(|e| e.title().to_lowercase())
        .unwrap_or_default()
}

/// Compare two entries by title (case-insensitive), tie-breaking on UUID for a
/// stable total order.
fn title_cmp(vault: &Vault, a: Uuid, b: Uuid) -> Ordering {
    title_key(vault, a)
        .cmp(&title_key(vault, b))
        .then(a.cmp(&b))
}

/// Build the per-row `ListItem`s. `now` drives the expired affordance; kept
/// separate from [`render_tree`] so the draw call stays under the argument cap
/// and so callers can reuse the items.
pub(crate) fn tree_items(
    rows: &[TreeRow],
    vault: &Vault,
    now: DateTime<Utc>,
    marks: &HashSet<Uuid>,
    theme: &Theme,
) -> Vec<ListItem<'static>> {
    rows.iter()
        .map(|row| list_item(*row, vault, now, marks, theme))
        .collect()
}

/// Draw prepared tree `items` into `area` as a selectable `List`. `focused`
/// styles the pane border with a text affordance (NFR-015, not colour alone).
pub(crate) fn render_tree(
    items: Vec<ListItem<'static>>,
    selected_index: Option<usize>,
    focused: bool,
    frame: &mut Frame,
    area: Rect,
    theme: &Theme,
) -> usize {
    let title = if focused {
        "Entries [focus]"
    } else {
        "Entries"
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(if focused {
            theme.border_focused()
        } else {
            theme.border()
        })
        .title(title)
        .title_style(if focused {
            theme.header()
        } else {
            Style::default()
        });

    let mut list_state = ListState::default();
    list_state.select(selected_index);

    let list = List::new(items)
        .block(block)
        .highlight_style(theme.selected());
    frame.render_stateful_widget(list, area, &mut list_state);
    list_state.offset()
}

fn list_item(
    row: TreeRow,
    vault: &Vault,
    now: DateTime<Utc>,
    marks: &HashSet<Uuid>,
    theme: &Theme,
) -> ListItem<'static> {
    let indent = "  ".repeat(row.depth);
    match row.kind {
        RowKind::Group {
            expanded,
            has_children,
        } => {
            let marker = if !has_children {
                "  "
            } else if expanded {
                "▼ "
            } else {
                "▶ "
            };
            let name = vault
                .group_view(row.uuid)
                .map_or_else(|_| "(group)".to_string(), |g| g.name().to_string());
            ListItem::new(Line::from(vec![
                Span::raw(format!("{indent}{marker}")),
                Span::styled(name, theme.header()),
            ]))
        }
        RowKind::Entry => {
            let title = vault.get_entry(row.uuid).map_or_else(
                |_| "(missing)".to_string(),
                |e| {
                    let t = e.title();
                    if t.is_empty() {
                        "(untitled)".to_string()
                    } else {
                        t.to_string()
                    }
                },
            );
            let expired = vault.is_expired(row.uuid, now).unwrap_or(false);
            // Entries are indented two extra columns so their titles line up
            // under sibling group names (which carry a 2-col marker). A marked
            // entry (T4.5 visual multi-select) replaces that lead with a glyph +
            // BOLD modifier — a text carrier, never colour alone (NFR-015).
            let lead = if marks.contains(&row.uuid) {
                Span::styled(
                    format!("{indent}▸ "),
                    Style::default().add_modifier(Modifier::BOLD),
                )
            } else {
                Span::raw(format!("{indent}  "))
            };
            if expired {
                ListItem::new(Line::from(vec![
                    lead,
                    Span::styled(format!("{title} (expired)"), theme.expired()),
                ]))
            } else {
                ListItem::new(Line::from(vec![lead, Span::raw(title)]))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use falach_core::{EntryBuilder, KdfParams, MasterPassword, NoRecoveryConfirmed, Vault};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use super::*;
    use crate::theme::{ThemeDef, Tier};

    fn fast_kdf() -> KdfParams {
        KdfParams {
            memory_kib: 1_024,
            iterations: 1,
            parallelism: 1,
        }
    }

    /// A vault with: Personal/{GitHub, Mail, BankCard(expired)}, Work(empty),
    /// and a loose root-level entry `Loose`. Returns the vault + the UUIDs of
    /// Personal, Work, and the three Personal entries.
    struct Fixture {
        _dir: tempfile::TempDir,
        vault: Vault,
        personal: Uuid,
        work: Uuid,
        github: Uuid,
        mail: Uuid,
        bankcard: Uuid,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tree.kdbx");
        let mut vault = Vault::create(
            &path,
            &MasterPassword::new("pw".to_string()),
            None,
            fast_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create");
        let root = vault.root_group_uuid();
        let personal = vault.create_group(root, "Personal").expect("personal");
        let work = vault.create_group(root, "Work").expect("work");
        let github = vault
            .add_entry(personal, EntryBuilder::credential("GitHub").build())
            .expect("github");
        let mail = vault
            .add_entry(personal, EntryBuilder::credential("Mail").build())
            .expect("mail");
        let bankcard = vault
            .add_entry(personal, EntryBuilder::credential("BankCard").build())
            .expect("bankcard");
        vault
            .add_entry(root, EntryBuilder::credential("Loose").build())
            .expect("loose");
        // BankCard expired in the past — `is_expired` is then stable forever.
        vault
            .set_expiration(bankcard, Utc.timestamp_opt(1_000_000, 0).unwrap())
            .expect("expire");
        Fixture {
            _dir: dir,
            vault,
            personal,
            work,
            github,
            mail,
            bankcard,
        }
    }

    #[test]
    fn collapsed_tree_shows_only_top_level() {
        let f = fixture();
        let state = TreeState::new();
        let rows = build_rows(&f.vault, &state, &Recents::new());
        // Personal, Work (groups, sorted by name), then Loose (root entry).
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].uuid, f.personal);
        assert!(matches!(
            rows[0].kind,
            RowKind::Group {
                expanded: false,
                has_children: true
            }
        ));
        assert_eq!(rows[1].uuid, f.work);
        assert!(matches!(
            rows[1].kind,
            RowKind::Group {
                has_children: false,
                ..
            }
        ));
        assert!(matches!(rows[2].kind, RowKind::Entry)); // Loose
    }

    #[test]
    fn tree_renderer_adopts_focused_and_unfocused_border_slots() {
        let theme = ThemeDef::builtin("default-dark")
            .unwrap()
            .theme_for_tier(Tier::TrueColor);
        for (focused, expected) in [(true, theme.border_focused()), (false, theme.border())] {
            let mut terminal = Terminal::new(TestBackend::new(20, 5)).unwrap();
            terminal
                .draw(|frame| {
                    render_tree(Vec::new(), None, focused, frame, frame.area(), &theme);
                })
                .unwrap();
            let style = terminal.backend().buffer().cell((0, 0)).unwrap().style();
            assert_eq!(style.fg, expected.fg);
            assert_eq!(style.add_modifier, expected.add_modifier);
        }
    }

    #[test]
    fn expanding_personal_reveals_its_entries_sorted_by_title() {
        // Explicitly exercise the `Title` sort path (rather than relying on the
        // RecentlyUsed default degenerating to title order on empty recents).
        let mut state = TreeState::with_sort(SortOrder::Title);
        let f = fixture();
        state.expanded.insert(f.personal);
        let rows = build_rows(&f.vault, &state, &Recents::new());
        // Personal, BankCard, GitHub, Mail (title order), Work, Loose.
        let titles: Vec<Uuid> = rows.iter().map(|r| r.uuid).collect();
        assert_eq!(rows[0].uuid, f.personal);
        assert_eq!(rows[1].uuid, f.bankcard, "BankCard sorts first by title");
        assert_eq!(rows[2].uuid, f.github);
        assert_eq!(rows[1].depth, 1, "entries nest one level under the group");
        assert!(titles.contains(&f.work));
    }

    #[test]
    fn move_next_advances_by_one_in_flattened_view() {
        let f = fixture();
        let mut state = TreeState::new();
        let rows = build_rows(&f.vault, &state, &Recents::new());
        state.select_first(&rows);
        assert_eq!(state.selected(), Some(f.personal));
        assert!(state.move_next(&rows));
        assert_eq!(state.selected(), Some(f.work));
    }

    #[test]
    fn move_next_clamps_at_the_bottom() {
        let f = fixture();
        let mut state = TreeState::new();
        let rows = build_rows(&f.vault, &state, &Recents::new());
        state.selected = Some(rows.last().unwrap().uuid);
        assert!(!state.move_next(&rows), "already at bottom — no change");
        assert_eq!(state.selected(), Some(rows.last().unwrap().uuid));
    }

    #[test]
    fn expand_then_collapse_round_trips_the_group() {
        let f = fixture();
        let mut state = TreeState::new();
        let rows = build_rows(&f.vault, &state, &Recents::new());
        state.selected = Some(f.personal);
        // `l` expands.
        state.expand_or_child(&rows);
        let rows = build_rows(&f.vault, &state, &Recents::new());
        assert!(rows.len() > 3, "Personal's entries are now visible");
        // `h` collapses (selection stays on Personal).
        state.collapse_or_parent(&rows);
        let rows = build_rows(&f.vault, &state, &Recents::new());
        assert_eq!(rows.len(), 3);
        assert_eq!(state.selected(), Some(f.personal));
    }

    #[test]
    fn collapse_from_child_moves_selection_to_parent() {
        let f = fixture();
        let mut state = TreeState::new();
        state.expanded.insert(f.personal);
        let rows = build_rows(&f.vault, &state, &Recents::new());
        // Select GitHub (a child of Personal), then press `h`.
        state.selected = Some(f.github);
        assert!(state.collapse_or_parent(&rows));
        assert_eq!(
            state.selected(),
            Some(f.personal),
            "h on a child selects its parent group"
        );
    }

    #[test]
    fn sort_cycle_round_trips_through_all_orders() {
        let mut state = TreeState::new();
        // The redesign default (D-2 / T4.3) is RecentlyUsed.
        assert_eq!(state.sort(), SortOrder::RecentlyUsed);
        state.cycle_sort();
        assert_eq!(state.sort(), SortOrder::Title);
        state.cycle_sort();
        assert_eq!(state.sort(), SortOrder::LastModified);
        state.cycle_sort();
        assert_eq!(state.sort(), SortOrder::Group);
        state.cycle_sort();
        assert_eq!(state.sort(), SortOrder::RecentlyUsed);
    }

    #[test]
    fn recently_used_sort_orders_by_recents_then_title() {
        let f = fixture();
        let mut state = TreeState::with_sort(SortOrder::RecentlyUsed);
        state.expanded.insert(f.personal);

        // Mark GitHub (would sort 2nd by title, after BankCard) as most-recently
        // used, then Mail. BankCard is never used.
        let mut recents = Recents::new();
        recents.bump(f.github);
        recents.bump(f.mail);
        // MRU order is now [Mail, GitHub]; BankCard falls back to title order
        // *after* the two used entries.
        let rows = build_rows(&f.vault, &state, &recents);
        let entries: Vec<Uuid> = rows
            .iter()
            .filter(|r| matches!(r.kind, RowKind::Entry) && r.depth == 1)
            .map(|r| r.uuid)
            .collect();
        assert_eq!(
            entries,
            vec![f.mail, f.github, f.bankcard],
            "used entries lead in MRU order; the unused one trails by title"
        );
    }

    #[test]
    fn selected_is_entry_distinguishes_groups_from_entries() {
        let f = fixture();
        let mut state = TreeState::new();
        let rows = build_rows(&f.vault, &state, &Recents::new());
        state.selected = Some(f.personal);
        assert!(!state.selected_is_entry(&rows), "Personal is a group");
        state.expanded.insert(f.personal);
        let rows = build_rows(&f.vault, &state, &Recents::new());
        state.selected = Some(f.github);
        assert!(state.selected_is_entry(&rows), "GitHub is an entry");
    }
}
