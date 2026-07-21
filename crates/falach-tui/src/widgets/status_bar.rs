//! `StatusBar` — the unlocked workspace's bottom line (U.3 / T2.5).
//!
//! Shows a transient message (with a TTL) when one is set, otherwise the
//! active context's keybinding hints; the idle-lock countdown is right-aligned
//! here (it no longer needs a separate corner gauge). The countdown's numeric
//! value is always present, so the signal never relies on colour alone
//! (NFR-015).

use std::time::{Duration, Instant};

use falach_security::AutoLockController;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::theme::Theme;
use crate::widgets::hint_bar::{self, HintContent};
use crate::widgets::lock_countdown;

/// Default lifetime of a transient status message.
const DEFAULT_TTL: Duration = Duration::from_secs(3);
/// Columns reserved at the right for the countdown (`Locks in mm:ss`). Callers
/// building the derived hint bar subtract this from the status-line width so
/// their cells fit the left region exactly (whole-cell guarantee).
pub(crate) const COUNTDOWN_COLS: u16 = 16;

/// The kind of a transient message — drives its styling so a failure never
/// reads as a confirmation (NFR-015: severity carried by style **and** wording).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Severity {
    /// A completed action ("Entry added", "Password copied").
    Success,
    /// Neutral progress / status ("Syncing…", "Will lock when the sync finishes.").
    Info,
    /// A non-fatal guard or advisory ("Select an entry first.", "No sync target…").
    Warning,
    /// A failure ("Copy failed", "Sync failed", "Could not save tui.toml").
    Error,
}

struct Transient {
    message: String,
    severity: Severity,
    expires_at: Instant,
}

/// The workspace status line.
pub(crate) struct StatusBar {
    transient: Option<Transient>,
}

impl StatusBar {
    pub(crate) fn new() -> Self {
        Self { transient: None }
    }

    pub(crate) fn has_transient(&self) -> bool {
        self.transient.is_some()
    }

    /// Show a **success** `message` for the default TTL (the common confirmation
    /// path: copied, saved, synced). For other severities use [`Self::set_info`]
    /// / [`Self::set_warning`] / [`Self::set_error`].
    pub(crate) fn set(&mut self, message: impl Into<String>, now: Instant) {
        self.set_with(message, Severity::Success, now);
    }

    /// Show a neutral **info** message (progress / status; no success or failure
    /// connotation).
    pub(crate) fn set_info(&mut self, message: impl Into<String>, now: Instant) {
        self.set_with(message, Severity::Info, now);
    }

    /// Show a **warning** (a non-fatal guard or advisory).
    pub(crate) fn set_warning(&mut self, message: impl Into<String>, now: Instant) {
        self.set_with(message, Severity::Warning, now);
    }

    /// Show an **error** — a failure the user should notice. Styled distinctly
    /// from a success so a failure never reads as a confirmation.
    pub(crate) fn set_error(&mut self, message: impl Into<String>, now: Instant) {
        self.set_with(message, Severity::Error, now);
    }

    fn set_with(&mut self, message: impl Into<String>, severity: Severity, now: Instant) {
        self.transient = Some(Transient {
            message: message.into(),
            severity,
            expires_at: now + DEFAULT_TTL,
        });
    }

    /// Drop the transient message once it has expired. Call from `App::tick`.
    pub(crate) fn tick(&mut self, now: Instant) {
        if self.transient.as_ref().is_some_and(|t| now >= t.expires_at) {
            self.transient = None;
        }
    }

    #[cfg(test)]
    pub(crate) fn current(&self) -> Option<&str> {
        self.transient.as_ref().map(|t| t.message.as_str())
    }

    #[cfg(test)]
    pub(crate) fn current_severity(&self) -> Option<Severity> {
        self.transient.as_ref().map(|t| t.severity)
    }

    /// Render the status line: a transient message (when one is live), else the
    /// contextual `hints`, on the left; the lock countdown right-aligned. `hints`
    /// is either a bespoke string (overlays) or the registry-derived hint cells
    /// (tab bodies) — see [`HintContent`].
    #[allow(clippy::too_many_arguments)] // a status bar legitimately composes several inputs
    pub(crate) fn render(
        &self,
        hints: HintContent<'_>,
        controller: &AutoLockController,
        mode_badge: Option<&str>,
        now: Instant,
        frame: &mut Frame,
        area: Rect,
        theme: &Theme,
    ) {
        // A persistent mode badge (e.g. `RO` for a read-only session, T4.7) sits
        // just left of the idle-lock countdown. It is a text carrier styled with
        // `REVERSED` — never colour alone (NFR-015).
        let badge_cols =
            mode_badge.map_or(0, |b| u16::try_from(b.len()).unwrap_or(0).saturating_add(1));
        let [left, badge_area, right] = Layout::horizontal([
            Constraint::Min(1),
            Constraint::Length(badge_cols),
            Constraint::Length(COUNTDOWN_COLS),
        ])
        .areas(area);
        if let Some(badge) = mode_badge {
            use ratatui::style::{Modifier, Style};
            frame.render_widget(
                Paragraph::new(badge).style(Style::default().add_modifier(Modifier::REVERSED)),
                badge_area,
            );
        }

        match self.transient.as_ref() {
            // A severity prefix (`✗`/`⚠`) is the text carrier so a failure is
            // distinguishable from a confirmation even on the monochrome
            // `accessible` theme, where good/warning/error all render as bold.
            Some(t) => {
                let text = format!("{}{}", severity_prefix(t.severity), t.message);
                frame.render_widget(
                    Paragraph::new(text).style(severity_style(t.severity, theme)),
                    left,
                );
            }
            None => match hints {
                HintContent::Text(s) => {
                    frame.render_widget(Paragraph::new(s.to_string()).style(theme.muted()), left);
                }
                HintContent::Cells(cells) => {
                    frame.render_widget(Paragraph::new(hint_bar::hint_line(cells, theme)), left);
                }
            },
        }
        lock_countdown::render(controller, now, frame, right, theme);
    }
}

/// Map a [`Severity`] to its style (colour where the palette has it).
fn severity_style(severity: Severity, theme: &Theme) -> ratatui::style::Style {
    match severity {
        Severity::Success => theme.good(),
        Severity::Info => theme.muted(),
        Severity::Warning => theme.warning(),
        Severity::Error => theme.error(),
    }
}

/// A short text marker prepended to warning/error messages. This is the
/// **text carrier** (NFR-015): on the monochrome `accessible` theme the styles
/// for good/warning/error all collapse to bold, so the glyph is what tells a
/// failure apart from a confirmation. Success/info carry no prefix (clean).
fn severity_prefix(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "✗ ",
        Severity::Warning => "⚠ ",
        Severity::Success | Severity::Info => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_message_expires_after_ttl() {
        let mut bar = StatusBar::new();
        let t0 = Instant::now();
        bar.set("Saved", t0);
        assert_eq!(bar.current(), Some("Saved"));

        // Still live just before the TTL.
        bar.tick(t0 + DEFAULT_TTL.saturating_sub(Duration::from_millis(1)));
        assert_eq!(bar.current(), Some("Saved"));

        // Cleared at/after the TTL.
        bar.tick(t0 + DEFAULT_TTL);
        assert_eq!(bar.current(), None);
    }

    #[test]
    fn no_message_by_default() {
        let bar = StatusBar::new();
        assert_eq!(bar.current(), None);
    }

    #[test]
    fn setting_a_new_message_replaces_the_old() {
        let mut bar = StatusBar::new();
        let t0 = Instant::now();
        bar.set("first", t0);
        bar.set("second", t0 + Duration::from_millis(10));
        assert_eq!(bar.current(), Some("second"));
    }

    // The fix for the "errors look like success" finding. On a colour theme,
    // an error and a success differ by style; on the monochrome `accessible`
    // theme (where good/warning/error all collapse to bold) the text-carrier
    // prefix is what keeps a failure from reading as a confirmation.
    #[test]
    fn errors_are_distinguishable_from_successes() {
        // Colour theme: distinct styles.
        let colour = Theme::from_env_parts(None, false, None, Some("truecolor"));
        assert_ne!(
            severity_style(Severity::Success, &colour),
            severity_style(Severity::Error, &colour),
            "error and success must differ in style on a colour theme"
        );
        // Monochrome: the text carrier distinguishes them.
        assert_eq!(severity_prefix(Severity::Success), "");
        assert_eq!(severity_prefix(Severity::Info), "");
        assert_ne!(
            severity_prefix(Severity::Error),
            severity_prefix(Severity::Success),
            "an error carries a text marker a success does not"
        );
        assert!(!severity_prefix(Severity::Warning).is_empty());
    }
}
