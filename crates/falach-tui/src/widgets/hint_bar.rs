//! `hint_bar` — the always-visible, context-derived bottom hint line (T2.1).
//!
//! Replaces every hand-maintained hint string (the former `*_HINTS` consts in
//! `screens/workspace.rs` and the pre-unlock footers) with one widget derived
//! from the command registry each frame. For the current [`Contexts`],
//! [`build_hint_bar`] projects the `quick_bar`-eligible commands (via
//! [`commands_for`]), renders each command's first trigger through the T1.3
//! grammar, and greedily fits whole cells into the available width — so a hint
//! can never drift from dispatch, and a rebinding shows up here automatically
//! (AC-3).
//!
//! **Disabled hints teach** (gitui): a command that is available in the context
//! but not currently actionable (e.g. `copy password` on a group row) still
//! renders, dimmed, rather than vanishing.
//!
//! **The palette cell is reserved first.** The last cell describes the live Help
//! binding (design §3.9: the palette is the overflow). If Help is unavailable in
//! the context or explicitly unbound, the cell is honestly disabled rather than
//! advertising a key that dispatch cannot execute.
//!
//! Pure-build + thin-render split (crate convention): [`build_hint_bar`] returns
//! plain [`HintCell`]s (unit-tested headlessly); [`render_hint_bar`] /
//! [`hint_line`] are the ratatui adapters. Styles always carry a `Modifier`
//! (never colour alone — FR-074/NFR-015).

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use unicode_width::UnicodeWidthStr;

use crate::app::App;
use crate::command::keymap::render_grammar;
use crate::command::registry::{commands_for, CmdState, Command, Contexts};
use crate::theme::Theme;

/// Columns between two rendered cells.
const SEP: &str = "  ";

/// The description shown on the palette-affordance cell.
const MORE_DESC: &str = "more";

/// Description used when the palette has no executable binding here.
const PALETTE_UNAVAILABLE_DESC: &str = "palette";

/// One rendered hint: a command's key(s) + its description, plus the live
/// enablement that drives its styling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HintCell {
    /// Human description from the registry (`copy password`).
    pub desc: &'static str,
    /// The command's first trigger in the current context, rendered via the
    /// T1.3 grammar (`c`, `ctrl+f`, `g t`). Owned because grammar rendering
    /// allocates.
    pub keys: String,
    /// `Enabled` renders normally; `Disabled` renders dimmed (teaching, not
    /// dropped). `Hidden` never reaches a cell (filtered in [`build_hint_bar`]).
    pub state: CmdState,
}

impl HintCell {
    /// Display width in terminal columns of `"{keys} {desc}"`.
    fn width(&self) -> usize {
        self.keys.width() + 1 + self.desc.width()
    }
}

/// Rectangle occupied by the final (`more`) cell in a rendered hint line.
pub(crate) fn more_cell_rect(cells: &[HintCell], area: Rect) -> Option<Rect> {
    let last = cells.last()?;
    let preceding = cells[..cells.len() - 1]
        .iter()
        .map(HintCell::width)
        .sum::<usize>()
        + SEP.width() * cells.len().saturating_sub(1);
    let x = area
        .x
        .saturating_add(u16::try_from(preceding).unwrap_or(u16::MAX));
    let width = u16::try_from(last.width()).unwrap_or(u16::MAX);
    Some(Rect::new(
        x,
        area.y,
        width.min(area.right().saturating_sub(x)),
        area.height.min(1),
    ))
}

/// The palette-affordance cell (`? more`) for `ctx`. Its `keys` is the `Help`
/// command's first trigger in `ctx` (so it tracks the active preset / rebind).
/// When Help is unavailable or unbound, the reserved cell remains as disabled
/// documentation without inventing a non-functional fallback key.
fn more_cell(ctx: Contexts, app: &App) -> HintCell {
    let trigger = app
        .keys
        .triggers_for(ctx, Command::Help)
        .first()
        .map(|trigger| render_grammar(trigger));
    let state = if trigger.is_some() {
        CmdState::Enabled
    } else {
        CmdState::Disabled
    };
    HintCell {
        desc: if state == CmdState::Enabled {
            MORE_DESC
        } else {
            PALETTE_UNAVAILABLE_DESC
        },
        keys: trigger.unwrap_or_else(|| "—".to_string()),
        state,
    }
}

/// Build the hint cells for `ctx`, fitted to `width` columns.
///
/// Order: `quick_bar` commands available in `ctx` (sorted by registry `order`),
/// then the reserved `? more` affordance last. `Hidden` commands are dropped;
/// `Disabled` ones are kept (dimmed at render). Cells are whole — never
/// truncated mid-cell; the affordance's width is budgeted first so it survives
/// any overflow. `Help` itself is not emitted as an ordinary cell (it *is* the
/// affordance).
pub(crate) fn build_hint_bar(ctx: Contexts, app: &App, width: u16) -> Vec<HintCell> {
    let more = more_cell(ctx, app);
    let budget = width as usize;

    // Candidate cells: quick_bar-eligible, non-hidden, bound in this context,
    // excluding Help (reserved as the affordance).
    let candidates: Vec<HintCell> = commands_for(ctx, app)
        .into_iter()
        .filter(|(spec, state)| {
            spec.quick_bar && spec.id != Command::Help && *state != CmdState::Hidden
        })
        .filter_map(|(spec, state)| {
            let keys = app
                .keys
                .triggers_for(ctx, spec.id)
                .first()
                .map(|t| render_grammar(t))?;
            Some(HintCell {
                desc: spec.desc,
                keys,
                state,
            })
        })
        .collect();

    // Greedy fit: reserve the affordance first, then add whole cells (each with
    // a preceding separator) until the next one would not fit.
    let sep_w = SEP.width();
    let mut used = more.width();
    let mut cells: Vec<HintCell> = Vec::with_capacity(candidates.len() + 1);
    for cell in candidates {
        let needed = sep_w + cell.width();
        if used + needed > budget {
            break;
        }
        used += needed;
        cells.push(cell);
    }
    cells.push(more);
    cells
}

/// Style the key portion of a cell.
fn key_style(state: CmdState, theme: &Theme) -> ratatui::style::Style {
    match state {
        // Disabled: the whole cell is muted+dim ("disabled hints teach").
        CmdState::Disabled => theme.muted(),
        // Enabled: the key stands out — the `hint_key` slot (bold carrier + color
        // where available); the description carries no signal of its own.
        CmdState::Enabled | CmdState::Hidden => theme.hint_key(),
    }
}

/// Style the description portion of a cell.
fn desc_style(state: CmdState, theme: &Theme) -> ratatui::style::Style {
    match state {
        CmdState::Disabled => theme.muted(),
        CmdState::Enabled | CmdState::Hidden => theme.hint_desc(),
    }
}

/// What the status bar shows on the left when no transient message is up:
/// either a bespoke string (text-entry / action overlays supply their own,
/// where a derived bar would be just `? more` over a typed `?`) or the derived
/// hint cells (tab bodies, pre-unlock screens, the palette). `Copy` (it holds
/// only shared references) so it passes by value cheaply.
#[derive(Clone, Copy)]
pub(crate) enum HintContent<'a> {
    /// A hand-supplied hint string (`Overlay::hints()`).
    Text(&'a str),
    /// Derived hint cells from [`build_hint_bar`].
    Cells(&'a [HintCell]),
}

/// Build the styled hint line from pre-fitted cells (pure adapter over the
/// build output; the render fn wraps this in a `Paragraph`).
pub(crate) fn hint_line(cells: &[HintCell], theme: &Theme) -> Line<'static> {
    let mut spans: Vec<Span<'static>> = Vec::with_capacity(cells.len() * 4);
    for (i, cell) in cells.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(SEP));
        }
        spans.push(Span::styled(
            cell.keys.clone(),
            key_style(cell.state, theme),
        ));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            cell.desc.to_string(),
            desc_style(cell.state, theme),
        ));
    }
    Line::from(spans)
}

/// Render pre-fitted `cells` into `area` (a single line). Used directly by the
/// pre-unlock screens; the workspace routes through the status bar so the
/// idle-lock countdown shares the row.
pub(crate) fn render_hint_bar(frame: &mut Frame, area: Rect, cells: &[HintCell], theme: &Theme) {
    frame.render_widget(Paragraph::new(hint_line(cells, theme)), area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::keymap::KeymapPatch;
    use crate::command::Keymap;

    // The App-dependent hint-bar tests (`build_reflects_context_and_rebinds`,
    // `disabled_commands_render_dimmed_not_dropped`, `every_context_has_...`)
    // live in `app.rs`'s test module, where the `populated_app()` vault fixture
    // is in scope. The width-fitting tests below are pure and live here.

    /// A cell of a fixed width for the fitting tests.
    fn cell(keys: &str, desc: &'static str) -> HintCell {
        HintCell {
            desc,
            keys: keys.to_string(),
            state: CmdState::Enabled,
        }
    }

    #[test]
    fn cell_width_counts_keys_space_desc() {
        assert_eq!(cell("c", "copy").width(), 1 + 1 + 4);
        assert_eq!(cell("ctrl+f", "search").width(), 6 + 1 + 6);
    }

    #[test]
    fn hint_line_alternates_key_and_desc_spans() {
        let theme = Theme::accessible();
        let line = hint_line(&[cell("c", "copy"), cell("/", "search")], &theme);
        // key, space, desc, SEP, key, space, desc.
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(text, "c copy  / search");
    }

    #[test]
    fn from_patch_helper_builds_a_keymap() {
        // Guard that the test helper compiles against the real patch API (used
        // by the app-side rebind test).
        let (_km, warnings): (Keymap, _) = Keymap::from_patch(&KeymapPatch::default());
        assert!(warnings.is_empty());
    }
}
