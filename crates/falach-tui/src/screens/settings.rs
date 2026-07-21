//! `settings` — the Settings/Sync tab body (T6.3 / T6.4).
//!
//! Two regions: (a) a settings editor — a `List` of non-secret rows the user
//! cycles/toggles inline (default sort, the two sync-trigger toggles, and a row
//! that launches the secure credential overlay); and (b) a **secret-free**
//! sync-status sub-view (the configured target + the last outcome/error).
//!
//! Key handling lives on `App` (`on_settings_key`); this module only renders.
//! Per ADR-T3 nothing here is secret: `config.toml` holds preferences,
//! `tui.toml` holds pins/recents, and the S3
//! credential is collected in [`crate::overlay::sync_config`] and written to
//! `vaults.toml` as ciphertext.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::App;

/// The editable settings rows, in display order. `App::SETTINGS_ROW_COUNT` must
/// match this slice's length (asserted in `app.rs` tests).
pub(crate) const ROW_LABELS: &[&str] = &[
    "Default sort",
    "Theme",
    "Auto-lock",
    "Auto-sync on unlock",
    "Auto-sync on lock/quit",
    "Configure sync target…",
];

/// Render the Settings tab into `area`: the editable rows on top, and a
/// secret-free "Status" sub-view below that also acknowledges the two settings
/// configured *outside* this editor (the env-detected theme and per-vault
/// auto-lock) so a user who looks here for them isn't met with a void.
pub(crate) fn render(app: &App, frame: &mut Frame, area: Rect) {
    let [editor_area, status_area] =
        Layout::vertical([Constraint::Min(1), Constraint::Length(8)]).areas(area);

    render_editor(app, frame, editor_area);
    render_status(app, frame, status_area);
}

fn render_editor(app: &App, frame: &mut Frame, area: Rect) {
    let values = [
        app.user_config.default_sort().label().to_string(),
        app.current_theme_name().to_string(),
        format!("{} min", app.current_auto_lock_seconds() / 60),
        on_off(app.user_config.sync_on_unlock()),
        on_off(app.user_config.sync_on_lock_quit()),
        String::new(), // the action row has no value
    ];

    let items: Vec<ListItem> = ROW_LABELS
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let selected = i == app.settings_index;
            let marker = if selected { "> " } else { "  " };
            let value = &values[i];
            let text = if value.is_empty() {
                format!("{marker}{label}")
            } else {
                format!("{marker}{label}: {value}")
            };
            let style = if selected {
                app.theme.selected()
            } else {
                app.theme.header()
            };
            ListItem::new(Line::from(text)).style(style)
        })
        .collect();

    frame.render_widget(
        List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(app.theme.border_focused())
                .title("Settings")
                .title_style(app.theme.header()),
        ),
        area,
    );
}

fn render_status(app: &App, frame: &mut Frame, area: Rect) {
    let target = app
        .sync_target_summary()
        .unwrap_or_else(|| "(no sync target configured)".to_string());
    let last = app.sync_status_line().unwrap_or("Last sync: —").to_string();

    let body = vec![
        // App settings that live outside this editor — surfaced read-only with a
        // pointer to where they're changed.
        Line::from(vec![
            Span::styled("Keymap preset: ", app.theme.muted()),
            Span::styled(app.keymap_preset_label(), app.theme.header()),
            Span::styled("  (config.toml [keymap])", app.theme.muted()),
        ]),
        Line::from(vec![
            Span::styled("Config file: ", app.theme.muted()),
            Span::styled(app.config_file_display(), app.theme.header()),
        ]),
        Line::from(""),
        // Sync target + last outcome (secret-free).
        Line::from(vec![
            Span::styled("Target: ", app.theme.muted()),
            Span::styled(target, app.theme.header()),
        ]),
        Line::from(Span::styled(last, app.theme.muted())),
    ];

    frame.render_widget(
        Paragraph::new(body).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(app.theme.border())
                .title("Status")
                .title_style(app.theme.header()),
        ),
        area,
    );
}

fn on_off(on: bool) -> String {
    if on {
        "[x] on".to_string()
    } else {
        "[ ] off".to_string()
    }
}
