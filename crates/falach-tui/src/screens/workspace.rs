//! `Workspace` — the unlocked UI shell: tab bar (top) + active-tab body +
//! status bar (bottom). **Phase 4:** the Secrets tab (tree + scrollable detail,
//! via [`crate::screens::secrets`]) and pinned tabs (each renders one entry's
//! detail) are real; the Settings editor (Phase 6) is still a placeholder.

use std::time::Instant;

use chrono::Utc;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::{App, MouseTarget};
use crate::screens::{secrets, settings};
use crate::tabs::Tab;
use crate::widgets::entry_detail;
use crate::widgets::hint_bar::{self, HintContent};
use crate::widgets::which_key;

pub(crate) fn render(app: &App, frame: &mut Frame, now: Instant) {
    let [tab_area, body_area, status_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    // Tab bar with the pinned entries' titles (T4.4).
    let pin_titles = app.pin_titles();
    app.tabs.render(&pin_titles, frame, tab_area, &app.theme);
    for (area, index) in app.tabs.hit_regions(&pin_titles, tab_area) {
        app.register_mouse_target(area, MouseTarget::Tab(index));
    }

    // Active-tab body. While a background sync owns the vault (ADR-T4a), the
    // vault is temporarily unavailable; show a "Syncing…" body for every tab.
    let active = app.tabs.active_tab();
    if app.is_syncing() {
        frame.render_widget(
            placeholder("Syncing… (vault temporarily unavailable)"),
            body_area,
        );
    } else {
        match active {
            Tab::Secrets => secrets::render(app, frame, body_area, now),
            Tab::Pinned(uuid) => match app.vault.as_ref() {
                Some(vault) => {
                    entry_detail::render_pinned(
                        vault,
                        uuid,
                        app.reveal_password,
                        app.detail_scroll,
                        &app.theme,
                        frame,
                        body_area,
                        Utc::now(),
                    );
                    app.register_mouse_target(body_area, MouseTarget::DetailPane);
                }
                None => frame.render_widget(placeholder("No vault open."), body_area),
            },
            Tab::Settings => settings::render(app, frame, body_area),
        }
    }

    // Status bar: transient message / contextual hints + idle-lock countdown.
    // An open overlay (Phase 5) supplies its own bespoke hint string; a bare tab
    // body derives its hint bar from the registry (T2.1) for the current context.
    // An overlay supplies its own bespoke hint string (including the palette,
    // whose nav is hardcoded ↑/↓ — a derived bar would misleadingly show the
    // registry's j/k). A bare tab body derives its hint bar from the registry
    // (T2.1) for the current context.
    let cells = if app.overlay.is_none() {
        // Build for the left region (status width minus the countdown column) so
        // every cell fits without being clipped mid-cell on the right edge.
        let badge_width = if app.read_only { 3 } else { 0 };
        let hint_width = status_area
            .width
            .saturating_sub(crate::widgets::status_bar::COUNTDOWN_COLS)
            .saturating_sub(badge_width);
        hint_bar::build_hint_bar(app.current_context(), app, hint_width)
    } else {
        Vec::new()
    };
    let hints = if let Some(overlay) = app.overlay.as_ref() {
        HintContent::Text(overlay.hints())
    } else {
        HintContent::Cells(&cells)
    };
    let mode_badge = app.read_only.then_some("RO");
    app.status_bar.render(
        hints,
        &app.controller,
        mode_badge,
        now,
        frame,
        status_area,
        &app.theme,
    );
    if app.overlay.is_none() && !app.status_bar.has_transient() {
        let badge_width = if app.read_only { 3 } else { 0 };
        let left = Rect::new(
            status_area.x,
            status_area.y,
            status_area
                .width
                .saturating_sub(crate::widgets::status_bar::COUNTDOWN_COLS)
                .saturating_sub(badge_width),
            status_area.height,
        );
        if let Some(area) = hint_bar::more_cell_rect(&cells, left) {
            app.register_mouse_target(area, MouseTarget::HintMore);
        }
    }

    // Which-key candidate menu (T2.2): when a chord prefix has been pending past
    // the render delay and has >1 continuation, draw it anchored bottom-right of
    // the body, above the hint bar. Never over an open overlay (a prefix can only
    // be pending in a bare workspace).
    if app.overlay.is_none() {
        if let Some(rows) =
            which_key::which_key_menu(app.pending_seq(), &app.keys, app.current_context(), now)
        {
            which_key::render_which_key(frame, body_area, &rows, &app.theme);
        }
    }
}

fn placeholder(message: &str) -> Paragraph<'static> {
    Paragraph::new(Line::from(message.to_string()))
}
