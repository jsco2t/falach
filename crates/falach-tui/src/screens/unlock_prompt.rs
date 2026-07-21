//! `UnlockPrompt` — enter the master password for the chosen vault.

use ratatui::layout::{Constraint, Layout};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::{App, Phase, MAX_UNLOCK_ATTEMPTS};
use crate::widgets::hint_bar;

pub(crate) fn render(app: &App, frame: &mut Frame) {
    let Phase::UnlockPrompt {
        vault_name,
        input,
        attempts,
    } = &app.phase
    else {
        return;
    };

    let [title_area, field_area, msg_area, hint_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    frame.render_widget(
        Paragraph::new(format!("Unlock {vault_name}")).style(app.theme.header()),
        title_area,
    );

    let block = Block::default()
        .borders(Borders::ALL)
        .title("Master password");
    let inner = block.inner(field_area);
    frame.render_widget(block, field_area);
    input.render(frame, inner, &app.theme);

    if *attempts > 0 {
        frame.render_widget(
            Paragraph::new(format!(
                "Authentication failed ({attempts}/{MAX_UNLOCK_ATTEMPTS})"
            ))
            .style(app.theme.error()),
            msg_area,
        );
    }

    // Derived hint bar (T2.1) — the former static footer.
    let cells = hint_bar::build_hint_bar(app.current_context(), app, hint_area.width);
    hint_bar::render_hint_bar(frame, hint_area, &cells, &app.theme);
}
