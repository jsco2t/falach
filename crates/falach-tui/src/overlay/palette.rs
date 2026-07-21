//! `Overlay::Palette` — the filterable, executable command palette (T2.3).
//!
//! D-3 RESOLVED: **`?` is the palette.** It replaces the read-only Help overlay
//! with one grouped, filterable surface where `Enter` runs the selected
//! command. Every non-`Hidden` command is listed (so the palette doubles as the
//! keybinding reference — US-070); a command whose context does not include the
//! *underlying* context the palette was opened over is listed **disabled**
//! (dimmed, non-executing) — the palette teaches the whole surface. Filtering
//! uses the shared core matcher (`fuzzy_match_terms`) so ranking and match
//! highlighting match the search overlay.
//!
//! Reachable throughout the workspace and from the unlock list / lock screen
//! (T2.4). The master-password prompt deliberately keeps `?` as text input.
//! The palette keeps a `Zeroizing`-free surface — command metadata is non-secret.
//!
//! Pure row-building (`build_palette_rows`) + thin render, per the crate
//! convention; key handling lives on `App` (`on_palette_key`) so it can execute
//! commands through the shared `App::execute_command` path.

use falach_core::fuzzy_match_terms;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;
use tui_input::Input;

use super::{centered, clear};
use crate::app::{App, MouseTarget};
use crate::command::registry::{CmdState, CommandSpec, Contexts, COMMANDS};
use crate::theme::Theme;

/// Minimum palette geometry — at this floor the filter row + ≥6 command rows
/// still render without overlap (D-8 subsumption: the palette replaces the old
/// sub-60×20 help concern). Snapshotted at exactly this size.
pub(crate) const FLOOR_W: u16 = 40;
pub(crate) const FLOOR_H: u16 = 12;

/// The palette overlay's live state: the filter query, the selected **command
/// row** index (headers are visual only and never selectable), and the
/// underlying context it was opened over (for enablement).
pub(crate) struct PaletteState {
    pub input: Input,
    pub selected: usize,
    /// The context the palette was opened *over* — commands available there are
    /// executable; the rest are listed disabled.
    pub underlying: Contexts,
}

impl PaletteState {
    pub(crate) fn new(underlying: Contexts) -> Self {
        Self {
            input: Input::default(),
            selected: 0,
            underlying,
        }
    }

    /// The current filter text.
    pub(crate) fn filter(&self) -> &str {
        self.input.value()
    }
}

/// One command row in the palette.
pub(crate) struct PaletteRow {
    pub spec: &'static CommandSpec,
    pub state: CmdState,
    /// Pretty key string (`j / ↓`), or empty when the command is unbound in the
    /// active keymap.
    pub keys: String,
    /// Character positions (into `spec.desc`) of the filter match, for
    /// highlighting. Empty when unfiltered or matched only via `name`.
    pub match_indices: Vec<u32>,
}

/// The command rows for the palette (no header rows — those are a render
/// concern). Unfiltered: every non-`Hidden` command, ordered by group rank then
/// registry `order`. Filtered: `fuzzy_match_terms` over `desc` (falling back to
/// `name` for inclusion), best score first. Enablement: a command outside the
/// `underlying` context is `Disabled`; otherwise `app.command_state`.
pub(crate) fn build_palette_rows(app: &App, underlying: Contexts, filter: &str) -> Vec<PaletteRow> {
    let filter = filter.trim();
    let mut scored: Vec<(Option<i32>, &'static CommandSpec, Vec<u32>)> = COMMANDS
        .iter()
        .filter(|spec| row_state(app, underlying, spec) != CmdState::Hidden)
        .filter_map(|spec| {
            if filter.is_empty() {
                return Some((None, spec, Vec::new()));
            }
            let (score, indices) = score_row(filter, spec)?;
            Some((Some(score), spec, indices))
        })
        .collect();

    if filter.is_empty() {
        // Group rank, then registry order (which is the declaration order).
        scored.sort_by_key(|(_, spec, _)| (spec.group.rank(), spec.order));
    } else {
        // Best score first; ties keep the group/order arrangement for stability.
        scored.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| (a.1.group.rank(), a.1.order).cmp(&(b.1.group.rank(), b.1.order)))
        });
    }

    scored
        .into_iter()
        .map(|(_, spec, match_indices)| PaletteRow {
            spec,
            state: row_state(app, underlying, spec),
            keys: app.keys.rendered_keys(spec.id).unwrap_or_default(),
            match_indices,
        })
        .collect()
}

/// Score a command against the filter: `desc` first (its indices highlight),
/// then `name` as an inclusion fallback (no highlight). `None` if neither
/// matches.
fn score_row(filter: &str, spec: &CommandSpec) -> Option<(i32, Vec<u32>)> {
    if let Some(m) = fuzzy_match_terms(filter, spec.desc) {
        return Some((m.score, m.indices));
    }
    fuzzy_match_terms(filter, spec.name).map(|m| (m.score, Vec::new()))
}

/// The row's enablement: `Disabled` when the command is not available in the
/// underlying context (listed-but-teaching), otherwise the live
/// `App::command_state` (which itself may disable it — e.g. copy on a group row).
fn row_state(app: &App, underlying: Contexts, spec: &CommandSpec) -> CmdState {
    if !spec.contexts.contains(underlying) {
        return CmdState::Disabled;
    }
    app.command_state(spec.id)
}

/// Render the palette centred over the workspace. Filter input on top, then the
/// grouped/ordered command rows with the selection highlighted, match
/// characters emphasised, and disabled rows dimmed. Scrolls to keep the
/// selected row visible.
pub(crate) fn render(app: &App, state: &PaletteState, frame: &mut Frame) {
    let area = frame.area();
    // Generous but floored: never smaller than the 40×12 floor when the frame
    // allows it. Divide before multiplying so the intermediate can't overflow
    // `u16` on an (absurdly) wide terminal.
    let width = (area.width / 5 * 4).max(FLOOR_W).min(area.width);
    let height = (area.height / 5 * 4).max(FLOOR_H).min(area.height);
    let modal = centered(frame, width, height);
    clear(frame, modal);

    let block = Block::default()
        .borders(Borders::ALL)
        .title("Commands — type to filter, Enter to run")
        .title_style(app.theme.header());
    let inner = block.inner(modal);
    frame.render_widget(block, modal);
    if inner.height < 2 || inner.width == 0 {
        return;
    }

    let [filter_area, list_area] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(inner);

    // Filter row: `> query`.
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("> ", app.theme.muted()),
            Span::raw(state.filter().to_string()),
        ])),
        filter_area,
    );

    let rows = build_palette_rows(app, state.underlying, state.filter());
    let unfiltered = state.filter().trim().is_empty();
    let lines = build_lines(&rows, state.selected, unfiltered, &app.theme);

    // Scroll so the selected command's line stays visible. `selected` indexes
    // command rows; map it to its display line (which counts inserted headers).
    let selected_line = selected_display_line(&rows, state.selected, unfiltered);
    let viewport = list_area.height as usize;
    let offset = selected_line.saturating_sub(viewport.saturating_sub(1));
    let scroll = u16::try_from(offset).unwrap_or(u16::MAX);
    frame.render_widget(Paragraph::new(lines).scroll((scroll, 0)), list_area);
    for (row_index, display_line) in command_display_lines(&rows, unfiltered) {
        if let Some(visible_line) = display_line
            .checked_sub(offset)
            .filter(|line| *line < viewport)
        {
            app.register_mouse_target(
                ratatui::layout::Rect::new(
                    list_area.x,
                    list_area
                        .y
                        .saturating_add(u16::try_from(visible_line).unwrap_or(u16::MAX)),
                    list_area.width,
                    1,
                ),
                MouseTarget::PaletteRow(row_index),
            );
        }
    }
}

fn command_display_lines(rows: &[PaletteRow], unfiltered: bool) -> Vec<(usize, usize)> {
    let mut out = Vec::with_capacity(rows.len());
    let mut line = 0usize;
    let mut last_group = None;
    for (index, row) in rows.iter().enumerate() {
        if unfiltered && Some(row.spec.group) != last_group {
            line += 1;
            last_group = Some(row.spec.group);
        }
        out.push((index, line));
        line += 1;
    }
    out
}

/// The display-line index (counting inserted group headers) of the `selected`
/// command row.
fn selected_display_line(rows: &[PaletteRow], selected: usize, unfiltered: bool) -> usize {
    if !unfiltered {
        return selected;
    }
    let mut line = 0usize;
    let mut last_group = None;
    for (i, row) in rows.iter().enumerate() {
        if Some(row.spec.group) != last_group {
            line += 1; // header
            last_group = Some(row.spec.group);
        }
        if i == selected {
            return line;
        }
        line += 1;
    }
    line
}

/// The palette body lines: group headers (unfiltered only) + one `desc … keys`
/// line per command row, selection reversed, disabled dimmed, match chars bold.
fn build_lines(
    rows: &[PaletteRow],
    selected: usize,
    unfiltered: bool,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::with_capacity(rows.len() + 8);
    let mut last_group = None;
    for (i, row) in rows.iter().enumerate() {
        if unfiltered && Some(row.spec.group) != last_group {
            lines.push(Line::from(Span::styled(
                row.spec.group.label().to_string(),
                theme.header(),
            )));
            last_group = Some(row.spec.group);
        }
        lines.push(row_line(row, i == selected, theme));
    }
    lines
}

/// One command line: `  desc` (match chars bold) padded, then the key string.
fn row_line(row: &PaletteRow, selected: bool, theme: &Theme) -> Line<'static> {
    let disabled = row.state == CmdState::Disabled;
    let base = if disabled {
        theme.muted()
    } else {
        Style::default()
    };
    // Description with matched characters emphasised via the `match_hl` slot
    // (bold carrier + color where available). Built char-by-char so the
    // highlight indices line up. Disabled rows stay muted even where matched.
    let mut spans: Vec<Span<'static>> = vec![Span::raw("  ")];
    for (idx, ch) in row.spec.desc.chars().enumerate() {
        let matched = u32::try_from(idx).is_ok_and(|i| row.match_indices.contains(&i));
        let style = if matched && !disabled {
            theme.match_hl()
        } else {
            base
        };
        spans.push(Span::styled(ch.to_string(), style));
    }
    if !row.keys.is_empty() {
        spans.push(Span::styled(format!("  [{}]", row.keys), theme.muted()));
    }
    let mut line = Line::from(spans);
    if selected {
        line = line.style(theme.selected());
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::registry::Command;
    use ratatui::style::Modifier;

    // The palette's row-building and execution are exercised against a real
    // unlocked `App` in `app.rs`'s test module (where `populated_app()` lives):
    // `rows_grouped_and_ordered`, `filter_ranks_via_core_matcher`,
    // `every_visible_command_listed_unfiltered`, `disabled_rows_listed_but_...`,
    // `enter_executes_selected_command_via_dispatch`, `palette_esc_closes_...`,
    // and the `palette_floor_geometry_40x12` render-smoke. The styling (which a
    // text snapshot cannot capture) is pinned here.

    fn row(state: CmdState, match_indices: Vec<u32>) -> PaletteRow {
        let spec = COMMANDS
            .iter()
            .find(|s| s.id == Command::CopyPassword)
            .expect("copy-password registered");
        PaletteRow {
            spec,
            state,
            keys: "c".to_string(),
            match_indices,
        }
    }

    #[test]
    fn row_line_dims_disabled_bolds_matches_and_reverses_selection() {
        // Accessible (monochrome) theme so the carriers are pure modifiers.
        let theme = Theme::accessible();

        // Disabled → the description spans carry DIM (muted), never dropped.
        let line = row_line(&row(CmdState::Disabled, Vec::new()), false, &theme);
        assert!(
            line.spans
                .iter()
                .any(|s| s.style.add_modifier.contains(Modifier::DIM)),
            "a disabled row renders dimmed"
        );

        // Matched characters (indices 0,1 of \"copy password\") render BOLD.
        let line = row_line(&row(CmdState::Enabled, vec![0, 1]), false, &theme);
        let bold = line
            .spans
            .iter()
            .filter(|s| s.style.add_modifier.contains(Modifier::BOLD))
            .count();
        assert_eq!(bold, 2, "exactly the two matched chars are bold");

        // Selected → the whole line carries the selection style (REVERSED).
        let line = row_line(&row(CmdState::Enabled, Vec::new()), true, &theme);
        assert!(
            line.style.add_modifier.contains(Modifier::REVERSED),
            "the selected row is reverse-video"
        );
    }
}
