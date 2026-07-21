//! `overlay` — modal surfaces layered over the active workspace tab (ADR-T1).
//!
//! Phase 5 re-homes the action screens as [`Overlay`]s rather than top-level
//! `Phase`s: search, add/edit, generate (nested in edit), history, and the
//! delete confirmation. Dispatch (`App::on_overlay_key`) checks the overlay
//! before the active tab; rendering ([`render`]) draws the overlay on top of
//! the already-drawn workspace.
//!
//! **Memory hygiene:** overlays that hold secret material (the [`edit`] password
//! field, the [`generate`] preview) keep it in `Zeroizing`/`PasswordInput`
//! buffers, so dropping the overlay (cancel, lock, save) zeroizes them. The
//! canonical lock path (`App::lock_app`) clears `App::overlay` for exactly this
//! reason.

pub(crate) mod bulk;
pub(crate) mod edit;
pub(crate) mod generate;
pub(crate) mod history;
pub(crate) mod palette;
pub(crate) mod search;
pub(crate) mod sync_config;

use falach_core::Uuid;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::widgets::Clear;
use ratatui::Frame;

use crate::app::App;
use crate::sync_runtime::SyncTrigger;
use crate::theme::Theme;
use crate::widgets::password_input::PasswordInput;

pub(crate) use bulk::{GroupPickerState, TagAction, TagInputState};
pub(crate) use edit::EditState;
pub(crate) use history::HistoryState;
pub(crate) use palette::PaletteState;
pub(crate) use search::SearchState;
pub(crate) use sync_config::SyncConfigState;

/// A modal overlay layered over the active tab.
pub(crate) enum Overlay {
    /// Search-as-you-type across the unlocked vault (T5.1).
    Search(SearchState),
    /// Add or edit an entry, with an optional nested generate panel (T5.2/T5.3).
    /// Boxed — `EditState` is much larger than the other variants.
    Edit(Box<EditState>),
    /// Read-only history viewer for the selected entry (T5.4).
    History(HistoryState),
    /// Confirm a destructive delete (`y`/`n`). `title` is non-secret (shown in
    /// the tree) and only used for the prompt text.
    ConfirmDelete { entry_uuid: Uuid, title: String },
    /// Confirm a bulk delete of the marked entries (`y`/`n`). `titles` is used
    /// only for the pluralized prompt; `uuids` is the exact set to delete (T4.5).
    ConfirmBulkDelete {
        uuids: Vec<Uuid>,
        titles: Vec<String>,
    },
    /// Confirm quitting the app (`y`/`n`) when `behavior.confirm-quit` is on
    /// (T4.8). Carries no state — the answer drives the existing quit path.
    ConfirmQuit,
    /// Pick a destination group for a bulk move (T4.5).
    GroupPicker(GroupPickerState),
    /// Enter a tag to add to / remove from the marked entries (T4.5).
    TagInput(TagInputState),
    /// Re-prompt the master password to drive a sync (T6.2 / ADR-T4). The TUI
    /// retains no `MasterPassword`, so every manual / on-lock/quit sync collects
    /// it here. The buffer zeroizes when the overlay drops.
    SyncUnlock {
        input: PasswordInput,
        pending: SyncTrigger,
    },
    /// Configure the S3 sync target + credentials (T6.4). Boxed — the state
    /// carries several input fields and two `PasswordInput`s.
    SyncConfig(Box<SyncConfigState>),
    /// The filterable, executable command palette (T2.3) — `?` opens it in the
    /// workspace, unlock list, and lock screen. The password prompt is excluded
    /// so `?` remains valid master-password input. Replaces the read-only Help
    /// overlay (D-3: `?` *is* the palette).
    /// Rendered fresh from the command registry each frame, so it can never drift
    /// from dispatch.
    Palette(PaletteState),
}

impl Overlay {
    /// A short label for the contextual status-bar hint while the overlay is up.
    pub(crate) fn hints(&self) -> &'static str {
        match self {
            Overlay::Search(_) => {
                "type to search   Enter/Tab: copy/open   ↑/↓: select   Esc: cancel"
            }
            Overlay::Edit(state) => state.hints(),
            Overlay::History(_) => "↑/↓: browse versions   Esc: close",
            Overlay::ConfirmDelete { .. } => "y: delete   n / Esc: cancel",
            Overlay::ConfirmBulkDelete { .. } => "y: delete all   n / Esc: cancel",
            Overlay::ConfirmQuit => "y: quit   n / Esc: cancel",
            Overlay::GroupPicker(_) => "↑/↓: select   Enter: move   Esc: cancel",
            Overlay::TagInput(_) => "type a tag   Enter: apply   Esc: cancel",
            Overlay::SyncUnlock { .. } => "Enter: sync   Esc: cancel",
            Overlay::SyncConfig(_) => sync_config::HINTS,
            Overlay::Palette(_) => "type to filter   ↑/↓ select   Enter run   Esc close",
        }
    }
}

/// Draw the active overlay over the workspace. No-op when there is no overlay.
pub(crate) fn render(app: &App, frame: &mut Frame) {
    let Some(overlay) = app.overlay.as_ref() else {
        return;
    };
    match overlay {
        Overlay::Search(state) => search::render(app, state, frame),
        Overlay::Edit(state) => edit::render(state, frame, &app.theme),
        Overlay::History(state) => history::render(state, frame, &app.theme),
        Overlay::ConfirmDelete { title, .. } => render_confirm_delete(title, frame, &app.theme),
        Overlay::ConfirmBulkDelete { titles, .. } => {
            render_confirm_bulk_delete(titles, frame, &app.theme);
        }
        Overlay::ConfirmQuit => render_confirm_quit(frame, &app.theme),
        Overlay::GroupPicker(state) => bulk::render_group_picker(state, frame, &app.theme),
        Overlay::TagInput(state) => bulk::render_tag_input(state, frame, &app.theme),
        Overlay::SyncUnlock { input, pending } => {
            render_sync_unlock(input, *pending, frame, &app.theme);
        }
        Overlay::SyncConfig(state) => sync_config::render(state, frame, &app.theme),
        Overlay::Palette(state) => palette::render(app, state, frame),
    }
}

/// Master-password re-prompt for a sync (T6.2). Renders a masked field and a
/// trigger-specific subtitle so the user knows why they are being asked.
fn render_sync_unlock(
    input: &PasswordInput,
    pending: SyncTrigger,
    frame: &mut Frame,
    theme: &Theme,
) {
    use ratatui::layout::{Constraint, Layout};
    use ratatui::text::{Line, Span};
    use ratatui::widgets::{Block, Borders, Paragraph};

    let subtitle = match pending {
        SyncTrigger::Manual => "Sync now — enter your master password.",
        SyncTrigger::OnUnlock => "Sync — enter your master password.",
        SyncTrigger::OnLock => "Sync before locking — enter your master password.",
        SyncTrigger::OnQuit => "Sync before quitting — enter your master password.",
    };

    let area = centered(frame, 54, 7);
    clear(frame, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Sync")
        .title_style(theme.header());
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height == 0 {
        return;
    }

    let [subtitle_area, field_area, hint_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(1),
    ])
    .areas(inner);

    frame.render_widget(Paragraph::new(subtitle).style(theme.muted()), subtitle_area);
    input.render(frame, field_area, theme);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "Enter: sync    Esc: cancel",
            theme.muted(),
        ))),
        hint_area,
    );
}

/// A centred rectangle `width`×`height` (clamped to the frame), used by the
/// modal overlays. Clears the cells underneath so the overlay is opaque.
pub(crate) fn centered(frame: &Frame, width: u16, height: u16) -> Rect {
    let area = frame.area();
    let [row] = Layout::vertical([Constraint::Length(height.min(area.height))])
        .flex(Flex::Center)
        .areas(area);
    let [col] = Layout::horizontal([Constraint::Length(width.min(area.width))])
        .flex(Flex::Center)
        .areas(row);
    col
}

/// Clear `area` then return it, so a modal renders opaquely over the workspace.
pub(crate) fn clear(frame: &mut Frame, area: Rect) {
    frame.render_widget(Clear, area);
}

/// Confirm a bulk delete: pluralized count with up to five titles listed, then
/// `…` for the remainder (T4.5).
fn render_confirm_bulk_delete(titles: &[String], frame: &mut Frame, theme: &Theme) {
    use ratatui::text::{Line, Span};
    use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

    let area = centered(frame, 54, 11);
    clear(frame, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Delete entries")
        .title_style(theme.warning());
    let n = titles.len();
    let mut body = vec![
        Line::from(vec![
            Span::raw("Delete "),
            Span::styled(
                format!("{n} entr{}", if n == 1 { "y" } else { "ies" }),
                theme.header(),
            ),
            Span::raw("?"),
        ]),
        Line::from(""),
    ];
    for title in titles.iter().take(5) {
        body.push(Line::from(format!("  • {title}")));
    }
    if n > 5 {
        body.push(Line::from(format!("  … and {} more", n - 5)));
    }
    body.push(Line::from(""));
    body.push(Line::from(Span::styled(
        "y: delete all    n / Esc: cancel",
        theme.muted(),
    )));
    frame.render_widget(
        Paragraph::new(body).block(block).wrap(Wrap { trim: false }),
        area,
    );
}

/// The quit confirmation dialog (T4.8).
fn render_confirm_quit(frame: &mut Frame, theme: &Theme) {
    use ratatui::text::{Line, Span};
    use ratatui::widgets::{Block, Borders, Paragraph};

    let area = centered(frame, 40, 5);
    clear(frame, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Quit")
        .title_style(theme.header());
    let body = vec![
        Line::from("Quit Falach?"),
        Line::from(""),
        Line::from(Span::styled("y: quit    n / Esc: cancel", theme.muted())),
    ];
    frame.render_widget(Paragraph::new(body).block(block), area);
}

fn render_confirm_delete(title: &str, frame: &mut Frame, theme: &Theme) {
    use ratatui::text::{Line, Span};
    use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

    let area = centered(frame, 54, 7);
    clear(frame, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Delete entry")
        .title_style(theme.warning());
    let body = vec![
        Line::from(vec![
            Span::raw("Delete \""),
            Span::styled(title.to_string(), theme.header()),
            Span::raw("\"?"),
        ]),
        Line::from(""),
        Line::from(Span::styled("y: delete    n / Esc: cancel", theme.muted())),
    ];
    frame.render_widget(
        Paragraph::new(body).block(block).wrap(Wrap { trim: false }),
        area,
    );
}
