//! `LockScreen` — shown after an idle or manual lock; any key returns to the
//! vault list. The vault is already dropped (zeroized) before this renders.

use ratatui::layout::{Constraint, Flex, Layout};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::App;
use crate::theme::Theme;

pub(crate) fn render(app: &App, frame: &mut Frame) {
    let name = app.selected_vault.as_deref().unwrap_or("The vault");
    let lines = lock_lines(name, app.status.as_deref(), &app.theme);

    let height = u16::try_from(lines.len()).unwrap_or(u16::MAX);
    let [area] = Layout::vertical([Constraint::Length(height)])
        .flex(Flex::Center)
        .areas(frame.area());

    frame.render_widget(Paragraph::new(lines).centered(), area);
}

/// Build the centered lock-screen body. Pure (no `Frame`) so the content —
/// including the conditional status line — is unit-testable.
fn lock_lines(name: &str, status: Option<&str>, theme: &Theme) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(Span::styled("Vault locked", theme.warning())),
        Line::from(""),
        Line::from(format!("{name} is locked.")),
    ];

    // Surface any pending status (e.g. a `SyncError → LockScreen` message such
    // as the `.kdbx.bak` / Unresolvable pointer) *on the lock frame itself*,
    // not one keypress later on the unlock list (ADR-T4a). Mirrors the
    // unlock-list styling so the message reads identically across both frames.
    if let Some(status) = status {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            status.to_string(),
            theme.warning(),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Press any key to return to the vault list.",
        theme.muted(),
    )));

    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Flatten a rendered `Line` to its plain text.
    fn line_text(line: &Line<'static>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn status_message_is_rendered_on_the_lock_frame_when_set() {
        // PMF-4 / T4.1: a `SyncError → LockScreen` message (e.g. the
        // `.kdbx.bak` pointer) must appear on the lock frame itself, not one
        // keypress later on the unlock list.
        let theme = Theme::auto();
        let status = "Sync conflict — local copy saved to personal.kdbx.bak";
        let lines = lock_lines("personal", Some(status), &theme);
        let rendered: Vec<String> = lines.iter().map(line_text).collect();
        assert!(
            rendered.iter().any(|l| l == status),
            "lock screen must render the status message; got {rendered:?}"
        );
    }

    #[test]
    fn no_status_line_when_status_is_none() {
        let theme = Theme::auto();
        let lines = lock_lines("personal", None, &theme);
        let rendered: Vec<String> = lines.iter().map(line_text).collect();
        // Only the fixed body: "Vault locked", "", "personal is locked.", "",
        // "Press any key…" — no extra status row.
        assert_eq!(rendered.len(), 5);
        assert!(rendered.iter().any(|l| l == "personal is locked."));
    }
}
