//! Event-loop driver: tick → draw → poll-with-deadline → dispatch (~20 FPS).
//!
//! The poll deadline is `min(FRAME_BUDGET, time_until_lock)` while unlocked, so
//! idle auto-lock (FR-073) fires within one syscall-wakeup of its deadline
//! rather than up to a frame late. `register_activity` fires on every key
//! *press* (not repeat/release, not resize) at the loop level, so it counts
//! even for keys the active phase ignores.

use std::io::Stdout;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyEventKind};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use crate::app::App;
use crate::error::TuiError;

/// Maximum idle interval between redraws (~20 FPS) so the lock countdown stays
/// live without busy-spinning.
pub(crate) const FRAME_BUDGET: Duration = Duration::from_millis(50);

pub(crate) fn run_event_loop(
    mut app: App,
    mut terminal: Terminal<CrosstermBackend<Stdout>>,
) -> Result<(), TuiError> {
    loop {
        let now = Instant::now();
        app.tick(now);
        terminal.draw(|frame| app.render(frame, now))?;

        if app.should_quit {
            return Ok(());
        }

        // Tighten the poll deadline to the lock countdown only while unlocked;
        // otherwise a fresh/locked controller could yield a 0-length poll.
        let poll_for = if app.vault.is_some() {
            app.controller
                .time_until_lock(now)
                .map_or(FRAME_BUDGET, |d| d.min(FRAME_BUDGET))
        } else {
            FRAME_BUDGET
        };

        if event::poll(poll_for)? {
            let ev = event::read()?;
            match &ev {
                // A key *press* and any mouse event both count as user activity
                // for idle auto-lock (T4.6: mouse registers activity like keys).
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    app.controller.register_activity(Instant::now());
                }
                Event::Mouse(mouse) => {
                    app.controller.register_activity(Instant::now());
                    app.handle_mouse_event(*mouse);
                    continue;
                }
                _ => {}
            }
            app.handle_event(&ev);
        }
        // No event → loop; the next tick brings the deadline closer and locks
        // when it passes.
    }
}
