//! `LockCountdown` — renders the idle auto-lock countdown (FR-073 / US-073).
//!
//! Stateless: it reads `AutoLockController::time_until_lock(now)` each frame and
//! renders `Locks in mm:ss`, right-aligned. The colour escalates to `warn`
//! under a minute; the numeric value is always present, so the signal never
//! relies on colour alone (FR-074 / NFR-015).

use std::time::{Duration, Instant};

use falach_security::AutoLockController;
use ratatui::layout::Rect;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::theme::Theme;

/// Render the countdown into `area`.
pub(crate) fn render(
    controller: &AutoLockController,
    now: Instant,
    frame: &mut Frame,
    area: Rect,
    theme: &Theme,
) {
    let remaining = controller.time_until_lock(now);
    let label = match remaining {
        Some(r) if r.as_secs() == 0 => "Locking…".to_string(),
        Some(r) => format!("Locks in {}", format_mm_ss(r)),
        None => "Locked".to_string(),
    };
    let style = match remaining {
        Some(r) if r.as_secs() < 60 => theme.warning(),
        Some(_) => theme.muted(),
        None => theme.error(),
    };
    frame.render_widget(Paragraph::new(label).style(style).right_aligned(), area);
}

/// Format a duration as `m:ss` (minutes uncapped, seconds zero-padded).
fn format_mm_ss(d: Duration) -> String {
    let total = d.as_secs();
    format!("{}:{:02}", total / 60, total % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_mm_ss_table() {
        let cases = [
            (0, "0:00"),
            (1, "0:01"),
            (9, "0:09"),
            (10, "0:10"),
            (59, "0:59"),
            (60, "1:00"),
            (61, "1:01"),
            (125, "2:05"),
            (600, "10:00"),
        ];
        for (secs, expected) in cases {
            assert_eq!(
                format_mm_ss(Duration::from_secs(secs)),
                expected,
                "format_mm_ss({secs}s)"
            );
        }
    }

    #[test]
    fn format_mm_ss_truncates_subsecond() {
        // Sub-second remainder is dropped (we show whole seconds).
        assert_eq!(format_mm_ss(Duration::from_millis(1_900)), "0:01");
    }
}
