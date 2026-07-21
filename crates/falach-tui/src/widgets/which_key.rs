//! `which_key` — the chord-continuation menu (T2.2, design §2.2.3 / §3.8).
//!
//! When a multi-key sequence prefix is pending (today only `g` in the Vim
//! preset), a small panel lists the possible next keys and the command each
//! reaches — derived from the same [`Keymap`] continuations dispatch uses, so
//! it can never drift. It appears only after a short delay
//! ([`WHICH_KEY_DELAY`]) so a fast typist completing `gt` never sees it, and
//! only when the prefix has **more than one** continuation (an unambiguous
//! prefix fires silently). A count-only pending state (bare digits) shows no
//! menu — the count feedback stays in the status bar.
//!
//! Pure decision + build (`which_key_visible` / `build_which_key`, clock
//! injected as a parameter) + thin render adapter, per the crate convention.
//! Styles carry a `Modifier` (never colour alone — FR-074/NFR-015).

use std::time::{Duration, Instant};

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;
use unicode_width::UnicodeWidthStr;

use crate::command::keymap::{render_grammar, KeyTrigger};
use crate::command::registry::Contexts;
use crate::command::{Keymap, PendingSeq};
use crate::theme::Theme;

/// How long a chord prefix must stay pending before the menu appears. A named
/// const, not a config knob (RESOLVED A-4): fast `gt` never flashes the menu.
pub(crate) const WHICH_KEY_DELAY: Duration = Duration::from_millis(150);

/// Most continuation rows to render before eliding the rest with a `…` row.
/// Only `g` exists today (2 rows), so this is future-proofing, not speculation.
const MAX_ROWS: usize = 8;

/// The delay+prefix gate: a chord prefix is pending and the render delay has
/// elapsed. Pure over `(pending, now)` — takes the injected `now` so tests are
/// deterministic (no `Instant::now()` inside). Does not itself count
/// continuations (that is [`build_which_key`]); a caller shows the menu only
/// when this is true *and* there is more than one continuation.
pub(crate) fn which_key_visible(pending: &PendingSeq, now: Instant) -> bool {
    match pending.since {
        Some(since) if !pending.prefix.is_empty() => {
            now.saturating_duration_since(since) >= WHICH_KEY_DELAY
        }
        _ => false,
    }
}

/// The continuation rows for the pending prefix: `(key string, description)`,
/// one per distinct next key, from the keymap's live continuations (the same
/// source dispatch uses). Empty when no prefix is pending.
pub(crate) fn build_which_key(
    pending: &PendingSeq,
    keymap: &Keymap,
    ctx: Contexts,
) -> Vec<(String, &'static str)> {
    if pending.prefix.is_empty() {
        return Vec::new();
    }
    keymap
        .continuations_for(ctx, &pending.prefix)
        .into_iter()
        .map(|(key, spec)| (render_grammar(&KeyTrigger::Key(key)), spec.desc))
        .collect()
}

/// The menu to render, or `None` when it should not appear: shown iff the
/// delay has elapsed **and** the prefix has more than one continuation (a lone
/// continuation dispatches silently). The single decision the render path uses.
pub(crate) fn which_key_menu(
    pending: &PendingSeq,
    keymap: &Keymap,
    ctx: Contexts,
    now: Instant,
) -> Option<Vec<(String, &'static str)>> {
    if !which_key_visible(pending, now) {
        return None;
    }
    let rows = build_which_key(pending, keymap, ctx);
    (rows.len() >= 2).then_some(rows)
}

/// Render the which-key panel anchored bottom-right of `area`, sized to its
/// content (capped at [`MAX_ROWS`] + a `…` row). Cleared underneath so it is
/// opaque over the workspace.
pub(crate) fn render_which_key(
    frame: &mut Frame,
    area: Rect,
    rows: &[(String, &'static str)],
    theme: &Theme,
) {
    let lines = build_lines(rows, theme);
    let inner_w = lines
        .iter()
        .map(|l| l.spans.iter().map(|s| s.content.width()).sum::<usize>())
        .max()
        .unwrap_or(0);
    // +2 for the left/right borders; +2 for one column of inner padding.
    let width = u16::try_from(inner_w + 4)
        .unwrap_or(u16::MAX)
        .min(area.width);
    let height = u16::try_from(lines.len() + 2)
        .unwrap_or(u16::MAX)
        .min(area.height);
    if width == 0 || height == 0 {
        return;
    }
    // Anchor bottom-right of the body area (just above the hint bar row).
    let panel = Rect {
        x: area.x + area.width - width,
        y: area.y + area.height - height,
        width,
        height,
    };
    frame.render_widget(Clear, panel);
    let block = Block::default()
        .borders(Borders::ALL)
        .title("keys")
        .title_style(theme.header());
    frame.render_widget(Paragraph::new(lines).block(block), panel);
}

/// The panel body: one `key  desc` line per continuation, capped at
/// [`MAX_ROWS`] with a trailing `…` line when there are more.
fn build_lines(rows: &[(String, &'static str)], theme: &Theme) -> Vec<Line<'static>> {
    let key_col = rows
        .iter()
        .take(MAX_ROWS)
        .map(|(k, _)| k.width())
        .max()
        .unwrap_or(0);
    let mut lines: Vec<Line<'static>> = rows
        .iter()
        .take(MAX_ROWS)
        .map(|(key, desc)| {
            Line::from(vec![
                Span::styled(format!("{key:<key_col$}"), theme.header()),
                Span::raw("  "),
                Span::raw((*desc).to_string()),
            ])
        })
        .collect();
    if rows.len() > MAX_ROWS {
        lines.push(Line::from(Span::styled("…", theme.muted())));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::keymap::KeymapPatch;
    use crate::command::{Preset, Resolution};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn ch(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }

    /// Drive the Vim keymap to a pending `g` prefix and return the pending state.
    fn pending_g() -> (Keymap, PendingSeq) {
        let keymap = Keymap::preset(Preset::Vim);
        let mut pending = PendingSeq::default();
        match keymap.resolve(Contexts::WORKSPACE, &ch('g'), &mut pending) {
            Resolution::Pending(_) => {}
            _ => panic!("g must be pending"),
        }
        // The App stamps `since` on the empty→pending transition; do the same.
        pending.since = Some(Instant::now());
        (keymap, pending)
    }

    #[test]
    fn build_lists_all_continuations_with_desc() {
        let (keymap, pending) = pending_g();
        let mut rows = build_which_key(&pending, &keymap, Contexts::WORKSPACE);
        rows.sort();
        assert_eq!(
            rows,
            vec![
                ("T".to_string(), "previous tab"),
                ("t".to_string(), "next tab"),
            ],
            "g offers t→next tab and T→previous tab, from the registry descs"
        );
    }

    #[test]
    fn delay_gate_is_pure() {
        // A table of (since→now offsets) around the 150ms boundary — no
        // `Instant::now()` inside `which_key_visible`.
        let base = Instant::now();
        let mut pending = PendingSeq {
            prefix: vec![ch('g')],
            count: None,
            since: Some(base),
        };
        assert!(
            !which_key_visible(&pending, base),
            "0ms elapsed: below the delay"
        );
        assert!(
            !which_key_visible(&pending, base + Duration::from_millis(149)),
            "149ms: still below the delay"
        );
        assert!(
            which_key_visible(&pending, base + WHICH_KEY_DELAY),
            "exactly the delay: visible"
        );
        assert!(
            which_key_visible(&pending, base + Duration::from_millis(300)),
            "past the delay: visible"
        );
        // No prefix → never visible regardless of elapsed time.
        pending.prefix.clear();
        assert!(!which_key_visible(&pending, base + Duration::from_secs(10)));
    }

    #[test]
    fn single_continuation_prefix_produces_no_menu() {
        // Unbind `prev-tab` (its `g T`), leaving `g t` (next-tab, and the jump
        // count-variant which shares `t`) as the *only* continuation after `g`.
        // A lone continuation dispatches silently — the menu never shows, even
        // past the delay.
        let patch: KeymapPatch = toml::from_str(
            r#"
            [bindings]
            "prev-tab" = false
            "#,
        )
        .expect("patch parses");
        let (keymap, warnings) = Keymap::from_patch(&patch);
        assert!(warnings.is_empty());

        // `since = base`, query at `base + delay` so the delay has elapsed
        // without subtracting from an `Instant`.
        let base = Instant::now();
        let past_delay = base + WHICH_KEY_DELAY;
        let pending = PendingSeq {
            prefix: vec![ch('g')],
            count: None,
            since: Some(base),
        };
        assert_eq!(
            build_which_key(&pending, &keymap, Contexts::WORKSPACE).len(),
            1,
            "only `g t` remains after unbinding prev-tab"
        );
        assert!(
            which_key_menu(&pending, &keymap, Contexts::WORKSPACE, past_delay).is_none(),
            "a single continuation shows no menu, even past the delay"
        );

        // Sanity: the two-continuation default `g` *does* show a menu past the
        // delay (so the None above is the single-continuation rule, not a bug).
        let vim = Keymap::preset(Preset::Vim);
        assert!(which_key_menu(&pending, &vim, Contexts::WORKSPACE, past_delay).is_some());
    }

    #[test]
    fn count_pending_shows_no_menu() {
        // Bare digits pending (a `{count}` with no chord prefix): no menu.
        let keymap = Keymap::preset(Preset::Vim);
        let pending = PendingSeq {
            prefix: Vec::new(),
            count: Some(2),
            since: None,
        };
        assert!(!which_key_visible(&pending, Instant::now()));
        assert!(which_key_menu(&pending, &keymap, Contexts::WORKSPACE, Instant::now()).is_none());
    }
}
