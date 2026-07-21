//! `Overlay::Search` — scoped fuzzy search across the unlocked vault (T4.2).
//!
//! An enlarged centred modal (~80%×70%, design D-5) with an input-first query, a
//! ranked result list (quick-select indices, match highlighting), and a
//! **non-secret** preview pane (dropped below 70 cols). The query runs in
//! [`falach_core::SearchMode::Fuzzy`] with the current [`SearchScope`] and the
//! recents boost list; `Enter`/`Tab` split copy-vs-open per config; `Esc`
//! restores the exact pre-search view (AC-6).
//!
//! **Security (T-SEC-PREVIEW-1):** [`build_preview`] renders only non-secret
//! fields — never the password, TOTP code/secret, protected fields, or notes
//! *content*. This is a hard regression gate (`preview_never_contains_secret_fields`).

use std::cell::Cell;

use falach_core::{EntryKind, EntryView, SearchScope, Uuid};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;
use tui_input::Input;

use super::clear;
use crate::app::{App, Focus, MouseTarget};
use crate::theme::Theme;

/// Minimum terminal geometry the search modal will open in. Below this the
/// overlay refuses to open with a status note (design D-5 floor).
pub(crate) const SEARCH_MIN_WIDTH: u16 = 60;
pub(crate) const SEARCH_MIN_HEIGHT: u16 = 16;
/// At or above this modal width the preview pane is shown; below it the results
/// list takes the full body width.
const PREVIEW_MIN_WIDTH: u16 = 70;

/// The exact pre-search view, captured on open and restored verbatim on cancel
/// (AC-6). Discarded when the user opens an entry on purpose (`Tab`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SavedView {
    pub(crate) selected: Option<Uuid>,
    pub(crate) focus: Focus,
    pub(crate) detail_scroll: u16,
}

/// State for the search overlay.
pub(crate) struct SearchState {
    pub(crate) input: Input,
    pub(crate) results: Vec<SearchRow>,
    pub(crate) selected: usize,
    /// First visible result row. Interior mutability lets render record the
    /// exact viewport offset while retaining ratatui's `&App` render model.
    pub(crate) scroll: Cell<usize>,
    pub(crate) scope: SearchScope,
    pub(crate) saved: SavedView,
}

/// A single rendered search hit. All display strings are resolved up front so
/// rendering holds no vault borrow; `title_indices` drives match highlighting.
pub(crate) struct SearchRow {
    pub(crate) uuid: Uuid,
    pub(crate) title: String,
    pub(crate) username: String,
    pub(crate) url_host: String,
    pub(crate) tags: String,
    pub(crate) title_indices: Vec<u32>,
}

impl SearchState {
    pub(crate) fn new(scope: SearchScope, saved: SavedView) -> Self {
        Self {
            input: Input::default(),
            results: Vec::new(),
            selected: 0,
            scroll: Cell::new(0),
            scope,
            saved,
        }
    }

    pub(crate) fn set_results(&mut self, results: Vec<SearchRow>) {
        self.results = results;
        self.clamp_selection();
    }

    pub(crate) fn select_next(&mut self) {
        if !self.results.is_empty() {
            self.selected = (self.selected + 1).min(self.results.len() - 1);
        }
    }

    pub(crate) fn select_prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub(crate) fn ensure_selected_visible(&self, viewport: usize) -> usize {
        let mut offset = self.scroll.get();
        if self.selected < offset {
            offset = self.selected;
        } else if viewport > 0 && self.selected >= offset.saturating_add(viewport) {
            offset = self.selected + 1 - viewport;
        }
        self.scroll.set(offset);
        offset
    }

    pub(crate) fn selected_uuid(&self) -> Option<Uuid> {
        self.results.get(self.selected).map(|r| r.uuid)
    }

    /// The UUID at 1-based visible row `n` (`Alt+n` quick-select). Visible rows
    /// are the first nine from the current scroll offset; out-of-range → `None`.
    pub(crate) fn quick_select_uuid(&self, n: usize) -> Option<Uuid> {
        if n == 0 {
            return None;
        }
        self.results.get(self.scroll.get() + n - 1).map(|r| r.uuid)
    }

    fn clamp_selection(&mut self) {
        if self.results.is_empty() {
            self.selected = 0;
            self.scroll.set(0);
        } else {
            self.selected = self.selected.min(self.results.len() - 1);
            self.scroll.set(self.scroll.get().min(self.selected));
        }
    }
}

/// The computed geometry of the search modal for a given terminal `Rect`.
pub(crate) struct SearchLayout {
    pub(crate) modal: Rect,
    pub(crate) input: Rect,
    pub(crate) results: Rect,
    pub(crate) preview: Option<Rect>,
}

/// Lay out the search modal, or `None` if the terminal is below the floor.
pub(crate) fn search_layout(term: Rect) -> Option<SearchLayout> {
    if term.width < SEARCH_MIN_WIDTH || term.height < SEARCH_MIN_HEIGHT {
        return None;
    }
    // ~80%×70% of the terminal, clamped up to the floor and down to the term.
    let modal_w = (term.width * 4 / 5).max(SEARCH_MIN_WIDTH).min(term.width);
    let modal_h = (term.height * 7 / 10)
        .max(SEARCH_MIN_HEIGHT)
        .min(term.height);
    let x = term.x + (term.width - modal_w) / 2;
    let y = term.y + (term.height - modal_h) / 2;
    let modal = Rect::new(x, y, modal_w, modal_h);

    let [input, body] = Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).areas(modal);

    if modal_w >= PREVIEW_MIN_WIDTH {
        let [results, preview] =
            Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)])
                .areas(body);
        Some(SearchLayout {
            modal,
            input,
            results,
            preview: Some(preview),
        })
    } else {
        Some(SearchLayout {
            modal,
            input,
            results: body,
            preview: None,
        })
    }
}

/// The scope indicator shown in the query header (`[ALL]` / `[GROUP:name]` /
/// `[TAG:tag]`), with `name`/`tag` middle-truncated to 16 columns.
pub(crate) fn scope_label(scope: &SearchScope, group_name: impl Fn(Uuid) -> String) -> String {
    match scope {
        SearchScope::All => "[ALL]".to_string(),
        SearchScope::GroupSubtree(uuid) => format!("[GROUP:{}]", truncate16(&group_name(*uuid))),
        SearchScope::Tag(tag) => format!("[TAG:{}]", truncate16(tag)),
    }
}

fn truncate16(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 16 {
        return s.to_string();
    }
    let head: String = chars[..7].iter().collect();
    let tail: String = chars[chars.len() - 8..].iter().collect();
    format!("{head}…{tail}")
}

/// Build the non-secret preview lines for `entry` (**T-SEC-PREVIEW-1**).
///
/// Renders ONLY: title, username, URL, tags, modified time, attachment count,
/// a literal "configured" marker for TOTP, and a *line count* for notes.
/// **Never** the password, the TOTP code or secret, protected custom fields, or
/// any notes content — those могут carry secrets. The permanent regression gate
/// `preview_never_contains_secret_fields` feeds an entry whose every secret is a
/// sentinel and asserts no sentinel reaches this output.
pub(crate) fn build_preview(entry: &EntryView<'_>) -> Vec<(&'static str, String)> {
    let mut out: Vec<(&'static str, String)> = Vec::new();
    out.push(("Title", entry.title().to_string()));
    if !entry.username().is_empty() {
        out.push(("Username", entry.username().to_string()));
    }
    if !entry.url().is_empty() {
        out.push(("URL", entry.url().to_string()));
    }
    let tags = entry.tags();
    if !tags.is_empty() {
        out.push((
            "Tags",
            tags.iter()
                .map(falach_core::Tag::as_str)
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }
    if let Some(modified) = entry.last_modification_time() {
        out.push(("Modified", crate::util::format_ts(modified)));
    }
    let attachments = entry.attachments();
    if !attachments.is_empty() {
        out.push(("Attachments", attachments.len().to_string()));
    }
    if matches!(entry.kind(), EntryKind::Totp) {
        // The WORD only — never the generated code or the shared secret.
        out.push(("TOTP", "configured".to_string()));
    }
    let notes = entry.notes();
    if !notes.is_empty() {
        // A count only — notes may contain secrets, so content never renders.
        out.push(("Notes", format!("{} line(s)", notes.lines().count())));
    }
    out
}

/// Extract a compact host from a URL for the result row (scheme + path removed).
pub(crate) fn url_host(url: &str) -> String {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    after_scheme
        .split('/')
        .next()
        .unwrap_or(after_scheme)
        .to_string()
}

/// Render the search overlay. Holds an `&App` (like the palette) so the preview
/// pane can resolve the selected entry's non-secret fields from the vault.
pub(crate) fn render(app: &App, state: &SearchState, frame: &mut Frame) {
    let theme = &app.theme;
    let Some(layout) = search_layout(frame.area()) else {
        // Too small to open usefully — a bordered note (the overlay refuses).
        let area = super::centered(frame, 40, 3);
        clear(frame, area);
        frame.render_widget(
            Paragraph::new("Terminal too small for search")
                .style(theme.warning())
                .block(Block::default().borders(Borders::ALL)),
            area,
        );
        return;
    };

    clear(frame, layout.modal);

    // Query header: `[SCOPE] › <input> — N results`.
    let scope = scope_label(&state.scope, |uuid| app.group_name_for(uuid));
    let header = format!("Search  {scope} — {} results", state.results.len());
    let query_block = Block::default().borders(Borders::ALL).title(header);
    frame.render_widget(
        Paragraph::new(state.input.value().to_string())
            .style(theme.header())
            .block(query_block),
        layout.input,
    );

    render_results(app, state, frame, layout.results, theme);

    if let Some(preview_area) = layout.preview {
        render_preview(app, state, frame, preview_area);
    }
}

fn render_results(app: &App, state: &SearchState, frame: &mut Frame, area: Rect, theme: &Theme) {
    let block = Block::default().borders(Borders::ALL).title("Results");
    if state.results.is_empty() {
        let msg = if state.input.value().is_empty() {
            "No entries."
        } else {
            "No matches."
        };
        frame.render_widget(Paragraph::new(msg).style(theme.muted()).block(block), area);
        return;
    }

    let viewport = usize::from(area.height.saturating_sub(2));
    let offset = state.ensure_selected_visible(viewport);

    // Keep enough of the row for metadata while allowing the title to consume
    // most of narrow layouts. Matching text is retained by truncating around
    // the highlighted range instead of blindly clipping from the right.
    let title_width = usize::from(area.width.saturating_sub(10)).max(8) * 2 / 3;
    let items: Vec<ListItem> = state
        .results
        .iter()
        .enumerate()
        .map(|(i, row)| result_line(i, offset, row, title_width, theme))
        .collect();
    let list = List::new(items)
        .block(block)
        .highlight_style(theme.selected())
        .highlight_symbol("> ");
    let mut list_state = ListState::default();
    list_state.select(Some(state.selected));
    *list_state.offset_mut() = offset;
    frame.render_stateful_widget(list, area, &mut list_state);
    state.scroll.set(list_state.offset());
    for (visible, absolute) in (list_state.offset()..state.results.len())
        .take(viewport)
        .enumerate()
    {
        app.register_mouse_target(
            Rect::new(
                area.x.saturating_add(1),
                area.y
                    .saturating_add(1 + u16::try_from(visible).unwrap_or(u16::MAX)),
                area.width.saturating_sub(2),
                1,
            ),
            MouseTarget::SearchRow(absolute),
        );
    }
}

/// One result row: `[n] title  username  url-host  tags`, matched title chars
/// highlighted with the `match_hl` slot (+bold carrier). The first nine rows
/// carry a `[1]..[9]` quick-select index.
fn result_line(
    index: usize,
    offset: usize,
    row: &SearchRow,
    title_width: usize,
    theme: &Theme,
) -> ListItem<'static> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    let visible_index = index.checked_sub(offset);
    if visible_index.is_some_and(|i| i < 9) {
        let n = visible_index.expect("checked above") + 1;
        spans.push(Span::styled(
            format!("[{n}] "),
            Style::default().add_modifier(Modifier::DIM),
        ));
    } else {
        spans.push(Span::raw("    "));
    }
    let title = if row.title.is_empty() {
        "(untitled)".to_string()
    } else {
        row.title.clone()
    };
    let (title, title_indices) = truncate_around_match(&title, &row.title_indices, title_width);
    spans.extend(highlight(&title, &title_indices, theme));
    if !row.username.is_empty() {
        spans.push(Span::styled(format!("  {}", row.username), theme.muted()));
    }
    if !row.url_host.is_empty() {
        spans.push(Span::styled(format!("  {}", row.url_host), theme.muted()));
    }
    if !row.tags.is_empty() {
        spans.push(Span::styled(format!("  #{}", row.tags), theme.muted()));
    }
    ListItem::new(Line::from(spans))
}

/// Truncate a title to `max_chars`, retaining the matched region and adjusting
/// highlight indices to the returned string. Ellipses are counted as chars.
fn truncate_around_match(text: &str, indices: &[u32], max_chars: usize) -> (String, Vec<u32>) {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max_chars || max_chars < 3 {
        return (text.to_string(), indices.to_vec());
    }
    let matched_start = indices
        .iter()
        .filter_map(|&i| usize::try_from(i).ok())
        .min()
        .unwrap_or(0)
        .min(chars.len() - 1);
    let matched_end = indices
        .iter()
        .filter_map(|&i| usize::try_from(i).ok())
        .max()
        .unwrap_or(matched_start)
        .min(chars.len() - 1);
    let content = max_chars.saturating_sub(2);
    let window = content.min(chars.len());
    let match_midpoint = matched_start + (matched_end - matched_start) / 2;
    let mut start = match_midpoint.saturating_sub(window / 2);
    start = start.min(chars.len() - window);
    let end = start + window;
    let leading = start > 0;
    let trailing = end < chars.len();
    let mut shown = String::new();
    if leading {
        shown.push('…');
    }
    shown.extend(chars[start..end].iter());
    if trailing {
        shown.push('…');
    }
    let prefix = usize::from(leading);
    let adjusted = indices
        .iter()
        .filter_map(|&i| usize::try_from(i).ok())
        .filter(|&i| i >= start && i < end)
        .filter_map(|i| u32::try_from(i - start + prefix).ok())
        .collect();
    (shown, adjusted)
}

/// Split `text` into styled spans, applying the match-highlight style to the
/// character positions in `indices` (bold carrier, not colour alone).
fn highlight(text: &str, indices: &[u32], theme: &Theme) -> Vec<Span<'static>> {
    if indices.is_empty() {
        return vec![Span::raw(text.to_string())];
    }
    let hl: std::collections::HashSet<u32> = indices.iter().copied().collect();
    let mut spans = Vec::new();
    let mut buf = String::new();
    let mut buf_hl = false;
    for (i, ch) in text.chars().enumerate() {
        let pos = u32::try_from(i).unwrap_or(u32::MAX);
        let is_hl = hl.contains(&pos);
        if is_hl != buf_hl && !buf.is_empty() {
            spans.push(styled_span(&buf, buf_hl, theme));
            buf.clear();
        }
        buf_hl = is_hl;
        buf.push(ch);
    }
    if !buf.is_empty() {
        spans.push(styled_span(&buf, buf_hl, theme));
    }
    spans
}

fn styled_span(text: &str, highlighted: bool, theme: &Theme) -> Span<'static> {
    if highlighted {
        Span::styled(text.to_string(), theme.match_hl())
    } else {
        Span::raw(text.to_string())
    }
}

fn render_preview(app: &App, state: &SearchState, frame: &mut Frame, area: Rect) {
    let theme = &app.theme;
    let block = Block::default().borders(Borders::ALL).title("Preview");
    let Some(uuid) = state.selected_uuid() else {
        frame.render_widget(block, area);
        return;
    };
    let Some(vault) = app.vault.as_ref() else {
        frame.render_widget(block, area);
        return;
    };
    let Ok(entry) = vault.get_entry(uuid) else {
        frame.render_widget(block, area);
        return;
    };
    let mut lines: Vec<Line> = Vec::new();
    // Group path is non-secret; render it above the entry fields.
    if let Some(path) = crate::screens::secrets::node_path(vault, vault.root_group_uuid(), uuid) {
        let groups: Vec<String> = path[..path.len().saturating_sub(1)]
            .iter()
            .filter_map(|g| vault.group_view(*g).ok().map(|v| v.name().to_string()))
            .collect();
        if !groups.is_empty() {
            lines.push(Line::from(Span::styled(groups.join(" › "), theme.muted())));
        }
    }
    for (label, value) in build_preview(&entry) {
        lines.push(Line::from(vec![
            Span::styled(format!("{label}: "), theme.muted()),
            Span::raw(value),
        ]));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use falach_core::{EntryBuilder, MasterPassword, NoRecoveryConfirmed};

    fn saved() -> SavedView {
        SavedView {
            selected: None,
            focus: Focus::Tree,
            detail_scroll: 0,
        }
    }

    #[test]
    fn search_layout_floors() {
        // Wide terminal → preview present.
        let big = search_layout(Rect::new(0, 0, 100, 30)).expect("opens at 100x30");
        assert!(big.preview.is_some(), "preview shown on a wide terminal");
        // Narrow-but-openable → no preview.
        let narrow = search_layout(Rect::new(0, 0, 69, 30)).expect("opens at 69x30");
        assert!(narrow.preview.is_none(), "preview dropped below 70 cols");
        // Exact floor → opens, no preview.
        let floor = search_layout(Rect::new(0, 0, 60, 16)).expect("opens at the 60x16 floor");
        assert!(floor.preview.is_none());
        // Below the floor → refuses.
        assert!(
            search_layout(Rect::new(0, 0, 59, 16)).is_none(),
            "refuses below 60 wide"
        );
        assert!(
            search_layout(Rect::new(0, 0, 60, 15)).is_none(),
            "refuses below 16 tall"
        );
    }

    #[test]
    fn scope_label_renders_and_truncates() {
        let u = Uuid::new_v4();
        assert_eq!(scope_label(&SearchScope::All, |_| String::new()), "[ALL]");
        assert_eq!(
            scope_label(&SearchScope::GroupSubtree(u), |_| "Banking".to_string()),
            "[GROUP:Banking]"
        );
        assert_eq!(
            scope_label(&SearchScope::Tag("dev".to_string()), |_| String::new()),
            "[TAG:dev]"
        );
        // Long names middle-truncate to 16 columns.
        let long = scope_label(
            &SearchScope::Tag("a-very-long-tag-name-here".to_string()),
            |_| String::new(),
        );
        assert!(long.contains('…'), "long tag is truncated: {long}");
    }

    #[test]
    fn quick_select_indexes_visible_rows() {
        let mut state = SearchState::new(SearchScope::All, saved());
        let rows: Vec<SearchRow> = (0..5)
            .map(|_| SearchRow {
                uuid: Uuid::new_v4(),
                title: "x".to_string(),
                username: String::new(),
                url_host: String::new(),
                tags: String::new(),
                title_indices: Vec::new(),
            })
            .collect();
        let third = rows[2].uuid;
        state.set_results(rows);
        assert_eq!(
            state.quick_select_uuid(3),
            Some(third),
            "Alt+3 → visible row 3"
        );
        assert_eq!(
            state.quick_select_uuid(9),
            None,
            "Alt+9 with 5 rows → no-op"
        );
        assert_eq!(state.quick_select_uuid(0), None);
    }

    #[test]
    fn quick_select_tracks_scrolled_visible_rows() {
        let mut state = SearchState::new(SearchScope::All, saved());
        let rows: Vec<SearchRow> = (0..20).map(|_| row(Uuid::new_v4())).collect();
        let expected = rows[8].uuid;
        state.set_results(rows);
        state.selected = 10;
        assert_eq!(state.ensure_selected_visible(3), 8);
        assert_eq!(state.quick_select_uuid(1), Some(expected));
    }

    fn row(uuid: Uuid) -> SearchRow {
        SearchRow {
            uuid,
            title: "x".to_string(),
            username: String::new(),
            url_host: String::new(),
            tags: String::new(),
            title_indices: Vec::new(),
        }
    }

    // Successor to the pre-T4.2 `selection_clamps_when_results_shrink`.
    #[test]
    fn selection_clamps_when_results_shrink() {
        let mut state = SearchState::new(SearchScope::All, saved());
        let u = Uuid::new_v4();
        state.set_results(vec![row(u), row(u), row(u)]);
        state.select_next();
        state.select_next();
        assert_eq!(state.selected, 2);
        state.set_results(vec![row(u)]);
        assert_eq!(state.selected, 0, "selection clamps when results shrink");
    }

    // Successor to `select_prev_saturates_at_zero` + `empty_results_have_no_selected_uuid`.
    #[test]
    fn selection_edges() {
        let mut state = SearchState::new(SearchScope::All, saved());
        assert!(
            state.selected_uuid().is_none(),
            "empty results → no selection"
        );
        let u = Uuid::new_v4();
        state.set_results(vec![row(u)]);
        state.select_prev();
        assert_eq!(state.selected, 0, "select_prev saturates at zero");
        assert_eq!(state.selected_uuid(), Some(u));
    }

    #[test]
    fn long_title_truncates_around_match_and_rebases_highlights() {
        let text = "prefix-prefix-important-match-suffix-suffix";
        let match_start = text.find("match").unwrap();
        let indices: Vec<u32> = (match_start..match_start + 5)
            .map(|i| u32::try_from(i).unwrap())
            .collect();
        let (shown, adjusted) = truncate_around_match(text, &indices, 18);
        assert!(
            shown.contains("match"),
            "matched text remains visible: {shown}"
        );
        assert!(shown.starts_with('…') && shown.ends_with('…'));
        let highlighted: String = adjusted
            .iter()
            .filter_map(|&i| shown.chars().nth(i as usize))
            .collect();
        assert_eq!(highlighted, "match");
    }

    #[test]
    fn highlight_splits_on_match_indices() {
        let theme = Theme::auto();
        let spans = highlight("GitHub", &[0, 1, 2], &theme);
        // "Git" highlighted, "Hub" plain → two spans; the whole text is preserved.
        let joined: String = spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(joined, "GitHub");
        assert!(spans.len() >= 2, "matched prefix splits into its own span");
    }

    #[test]
    fn url_host_strips_scheme_and_path() {
        assert_eq!(url_host("https://github.com/user/repo"), "github.com");
        assert_eq!(url_host("example.org"), "example.org");
        assert_eq!(url_host(""), "");
    }

    /// **T-SEC-PREVIEW-1** — the permanent regression gate. An entry whose every
    /// secret is a unique sentinel must never leak any sentinel into the preview.
    #[test]
    fn preview_never_contains_secret_fields() {
        const PW: &str = "SENTINEL_PASSWORD_9f3a";
        const TOTP_SECRET: &str = "SENTINELTOTPSECRETJBSWY3DPEHPK3PXP";
        const NOTES: &str = "SENTINEL_NOTES_body_c71e";
        const PROTECTED: &str = "SENTINEL_PROTECTED_custom_ab12";

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sec.kdbx");
        let mut vault = falach_core::Vault::create(
            &path,
            &MasterPassword::new("pw".to_string()),
            None,
            falach_core::KdfParams {
                memory_kib: 1_024,
                iterations: 1,
                parallelism: 1,
            },
            NoRecoveryConfirmed::yes(),
        )
        .unwrap();
        let root = vault.root_group_uuid();
        let draft = EntryBuilder::totp(
            "Bank",
            &format!("otpauth://totp/Bank?secret={TOTP_SECRET}&issuer=Bank"),
        )
        .expect("totp draft")
        .username("alice")
        .password(PW)
        .url("https://bank.example")
        .notes(NOTES)
        .custom_field("apikey", PROTECTED, true)
        .build();
        let uuid = vault.add_entry(root, draft).expect("add entry");

        let entry = vault.get_entry(uuid).unwrap();
        // Positive controls: the sentinels ARE stored on the entry, so the
        // negative assertions below can never pass vacuously (a fixture that
        // silently dropped a secret would make "no leak" trivially true).
        assert_eq!(entry.password(), PW, "password sentinel is stored");
        assert!(entry.notes().contains(NOTES), "notes sentinel is stored");
        assert_eq!(
            entry.custom_field("apikey"),
            Some(PROTECTED),
            "protected custom-field sentinel is stored"
        );

        let rendered = build_preview(&entry)
            .iter()
            .map(|(l, v)| format!("{l}: {v}"))
            .collect::<Vec<_>>()
            .join("\n");
        for sentinel in [PW, TOTP_SECRET, NOTES, PROTECTED] {
            assert!(
                !rendered.contains(sentinel),
                "preview leaked a secret ({sentinel}): {rendered}"
            );
        }
        // It still shows the non-secret fields.
        assert!(
            rendered.contains("Bank") && rendered.contains("alice"),
            "preview shows non-secret fields: {rendered}"
        );
    }
}
