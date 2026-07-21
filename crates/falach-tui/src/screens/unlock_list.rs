//! `UnlockList` — pick a registered vault.

use ratatui::layout::{Constraint, Layout};
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::widgets::hint_bar;

pub(crate) fn render(app: &App, frame: &mut Frame) {
    let [title_area, list_area, status_area, hint_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    frame.render_widget(
        Paragraph::new("Falach — select a vault").style(app.theme.header()),
        title_area,
    );

    let items: Vec<ListItem> = app
        .registry()
        .list()
        .enumerate()
        .map(|(i, vault)| {
            let selected = i == app.list_index;
            let marker = if selected { "> " } else { "  " };
            let style = if selected {
                app.theme.selected()
            } else {
                Style::default()
            };
            ListItem::new(Line::from(format!("{marker}{}. {}", i + 1, vault.name))).style(style)
        })
        .collect();

    frame.render_widget(
        List::new(items).block(Block::default().borders(Borders::ALL).title("Vaults")),
        list_area,
    );

    if let Some(status) = &app.status {
        frame.render_widget(
            Paragraph::new(status.as_str()).style(app.theme.warning()),
            status_area,
        );
    }

    // Derived hint bar (T2.1) — the former static footer.
    let cells = hint_bar::build_hint_bar(app.current_context(), app, hint_area.width);
    hint_bar::render_hint_bar(frame, hint_area, &cells, &app.theme);
}
