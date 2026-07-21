//! `Overlay::History` — a read-only viewer for an entry's KDBX history (T5.4).
//!
//! When opened, the App snapshots the selected entry's `history()` into owned
//! [`HistorySnapshot`]s (so the overlay holds no `Vault` borrow). Passwords are
//! **not** stored in the clear — only a "set / empty" indicator — keeping the
//! viewer secret-free (history is read-only; reveal/copy live on the live entry
//! in the detail pane). `↑`/`↓` browse versions; `Esc` closes.

use falach_core::HistoryView;
use ratatui::layout::{Constraint, Layout};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use super::{centered, clear};
use crate::theme::Theme;

/// One historical version of an entry, snapshotted to owned, secret-free data.
pub(crate) struct HistorySnapshot {
    pub(crate) modified: String,
    pub(crate) title: String,
    pub(crate) username: String,
    pub(crate) url: String,
    pub(crate) notes: String,
    pub(crate) has_password: bool,
}

/// History-overlay state: the live entry's title, its version snapshots
/// (newest first), and the highlighted version.
pub(crate) struct HistoryState {
    pub(crate) entry_title: String,
    pub(crate) snapshots: Vec<HistorySnapshot>,
    pub(crate) selected: usize,
}

impl HistoryState {
    /// Snapshot the history views into owned rows. `views` are oldest-first (the
    /// KDBX append order); we reverse so the most recent version sorts first.
    pub(crate) fn from_views(entry_title: String, views: &[HistoryView<'_>]) -> Self {
        let mut snapshots: Vec<HistorySnapshot> = views
            .iter()
            .map(|v| HistorySnapshot {
                modified: v
                    .last_modification_time()
                    .map_or_else(|| "(unknown)".to_string(), crate::util::format_ts),
                title: v.title().to_string(),
                username: v.username().to_string(),
                url: v.url().to_string(),
                notes: v.notes().to_string(),
                has_password: !v.password().is_empty(),
            })
            .collect();
        snapshots.reverse();
        Self {
            entry_title,
            snapshots,
            selected: 0,
        }
    }

    pub(crate) fn select_next(&mut self) {
        if !self.snapshots.is_empty() {
            self.selected = (self.selected + 1).min(self.snapshots.len() - 1);
        }
    }

    pub(crate) fn select_prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }
}

pub(crate) fn render(state: &HistoryState, frame: &mut Frame, theme: &Theme) {
    let area = centered(frame, 70, 18);
    clear(frame, area);

    let title = if state.entry_title.is_empty() {
        "History".to_string()
    } else {
        format!("History — {}", state.entry_title)
    };
    let outer = Block::default().borders(Borders::ALL).title(title);
    let inner = outer.inner(area);
    frame.render_widget(outer, area);

    if state.snapshots.is_empty() {
        frame.render_widget(
            Paragraph::new("No prior versions.").style(theme.muted()),
            inner,
        );
        return;
    }

    let [list_area, detail_area] =
        Layout::horizontal([Constraint::Percentage(40), Constraint::Min(1)]).areas(inner);

    let items: Vec<ListItem> = state
        .snapshots
        .iter()
        .map(|s| ListItem::new(Line::from(s.modified.clone())))
        .collect();
    let list = List::new(items)
        .block(Block::default().borders(Borders::RIGHT).title("Versions"))
        .highlight_style(theme.selected())
        .highlight_symbol("> ");
    let mut list_state = ListState::default();
    list_state.select(Some(state.selected));
    frame.render_stateful_widget(list, list_area, &mut list_state);

    let snap = &state.snapshots[state.selected];
    let mut lines: Vec<Line> = vec![
        Line::from(format!("Modified: {}", snap.modified)),
        Line::from(format!("Title: {}", snap.title)),
    ];
    if !snap.username.is_empty() {
        lines.push(Line::from(format!("Username: {}", snap.username)));
    }
    if snap.has_password {
        lines.push(Line::from("Password: •••••••• (set)".to_string()));
    }
    if !snap.url.is_empty() {
        lines.push(Line::from(format!("URL: {}", snap.url)));
    }
    if !snap.notes.is_empty() {
        lines.push(Line::from("Notes:".to_string()));
        for nl in snap.notes.lines() {
            lines.push(Line::from(format!("  {nl}")));
        }
    }
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }),
        detail_area,
    );
}
