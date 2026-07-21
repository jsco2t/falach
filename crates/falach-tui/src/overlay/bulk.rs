//! `Overlay::GroupPicker` and `Overlay::TagInput` — the modal inputs for the
//! visual-mode bulk operations (T4.5).
//!
//! Neither overlay holds secret material: a group picker lists group names, a
//! tag input edits a plain tag string. Both act on the App's marked-entry set
//! and apply through a single [`crate::app::App::persist_vault`] call so a bulk
//! operation is one atomic write (OQ-1).

use falach_core::Uuid;
use ratatui::layout::{Constraint, Layout};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::Frame;
use tui_input::Input;

use super::{centered, clear};
use crate::theme::Theme;

/// Whether a [`TagInputState`] adds or removes the entered tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TagAction {
    Add,
    Remove,
}

/// One selectable destination group, pre-formatted with a nesting indent.
pub(crate) struct GroupChoice {
    pub(crate) uuid: Uuid,
    pub(crate) label: String,
}

/// Group-picker state: the flat (indented) group list and the highlighted row.
/// The Recycle Bin is excluded by the builder in `App` (never a move target).
pub(crate) struct GroupPickerState {
    pub(crate) groups: Vec<GroupChoice>,
    pub(crate) selected: usize,
    /// How many entries the move will affect (for the title).
    pub(crate) count: usize,
}

impl GroupPickerState {
    pub(crate) fn new(groups: Vec<GroupChoice>, count: usize) -> Self {
        Self {
            groups,
            selected: 0,
            count,
        }
    }

    pub(crate) fn select_next(&mut self) {
        if !self.groups.is_empty() {
            self.selected = (self.selected + 1).min(self.groups.len() - 1);
        }
    }

    pub(crate) fn select_prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    /// The highlighted destination group UUID, if any.
    pub(crate) fn selected_uuid(&self) -> Option<Uuid> {
        self.groups.get(self.selected).map(|g| g.uuid)
    }
}

/// Tag-input state: a single-line editor plus whether it adds or removes.
pub(crate) struct TagInputState {
    pub(crate) input: Input,
    pub(crate) action: TagAction,
    /// How many entries the tag change will affect (for the title).
    pub(crate) count: usize,
}

impl TagInputState {
    pub(crate) fn new(action: TagAction, count: usize) -> Self {
        Self {
            input: Input::default(),
            action,
            count,
        }
    }
}

pub(crate) fn render_group_picker(state: &GroupPickerState, frame: &mut Frame, theme: &Theme) {
    let area = centered(frame, 50, 16);
    clear(frame, area);
    let title = format!("Move {} entr{} to…", state.count, plural(state.count));
    let outer = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .title_style(theme.header());
    let inner = outer.inner(area);
    frame.render_widget(outer, area);
    if inner.height == 0 {
        return;
    }

    let [list_area, hint_area] =
        Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(inner);

    let items: Vec<ListItem> = state
        .groups
        .iter()
        .map(|g| ListItem::new(Line::from(g.label.clone())))
        .collect();
    let list = List::new(items)
        .highlight_style(theme.selected())
        .highlight_symbol("> ");
    let mut list_state = ListState::default();
    list_state.select(Some(state.selected));
    frame.render_stateful_widget(list, list_area, &mut list_state);

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "↑/↓ select   Enter move   Esc cancel",
            theme.muted(),
        ))),
        hint_area,
    );
}

pub(crate) fn render_tag_input(state: &TagInputState, frame: &mut Frame, theme: &Theme) {
    let verb = match state.action {
        TagAction::Add => "Add tag to",
        TagAction::Remove => "Remove tag from",
    };
    let area = centered(frame, 52, 7);
    clear(frame, area);
    let title = format!("{verb} {} entr{}", state.count, plural(state.count));
    let outer = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .title_style(theme.header());
    let inner = outer.inner(area);
    frame.render_widget(outer, area);
    if inner.height == 0 {
        return;
    }

    let [field_area, hint_area] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(inner);
    frame.render_widget(Paragraph::new(state.input.value()), field_area);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "Enter apply   Esc cancel",
            theme.muted(),
        ))),
        hint_area,
    );
}

/// `"y"` for one, `"ies"` for many — used in the modal titles.
fn plural(count: usize) -> &'static str {
    if count == 1 {
        "y"
    } else {
        "ies"
    }
}
