//! `entry_detail` — the scrollable multi-type detail pane (T3.3 / T3.4 / ADR-T6).
//!
//! The right pane of the Secrets tab renders every field type of the selected
//! entry: title, kind, username, URL, password (masked + reveal), TOTP (live
//! code + window), notes, tags, attachments, custom fields, timestamps, and a
//! history affordance. Every value carries a **text label** and reveal/expired
//! states use text + style, never colour alone (NFR-015).
//!
//! ## Pure core vs. render adapter
//!
//! [`detail_lines`] is a pure, clock-free function over a plain [`DetailData`]
//! snapshot — no `Vault`, no `SystemTime`, no fixture-timestamp flakiness — so
//! it is fully unit-testable (covers all field types, the reveal toggle, the
//! expired affordance, and the TOTP format). [`build_detail_data`] is the thin
//! adapter that snapshots the selected `EntryView` (resolving the live TOTP and
//! expiry against the clock); [`render_detail`] composes the two, applies the
//! scroll offset (clamped to content height), and draws the bordered pane.

use chrono::{DateTime, Utc};
use falach_core::{EntryKind, Vault, Zeroizing};
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;
use uuid::Uuid;

use crate::app::{App, Focus};
use crate::theme::Theme;

/// Fixed-width password mask. A constant width (not `password.len()`) so the
/// rendered field never leaks the secret's length.
const MASK: &str = "••••••••";

/// A plain, clock-free snapshot of one entry's displayable fields. Built from
/// an `EntryView` by [`build_detail_data`]; consumed by [`detail_lines`].
///
/// **No `Debug` derive:** `password` is the live entry secret. It is held in a
/// [`Zeroizing`] so the per-frame copy is wiped on drop (CLAUDE.md zeroize-on-
/// drop), and `Debug` is omitted so the secret can never be formatted/logged.
#[derive(Clone, Default)]
pub(crate) struct DetailData {
    pub(crate) title: String,
    pub(crate) kind: &'static str,
    pub(crate) username: String,
    pub(crate) url: String,
    pub(crate) password: Zeroizing<String>,
    pub(crate) notes: String,
    /// Preformatted `YYYY-MM-DD HH:MM UTC` strings.
    pub(crate) created: Option<String>,
    pub(crate) modified: Option<String>,
    pub(crate) expired: bool,
    /// `(code, seconds_remaining)` when the entry carries a TOTP secret.
    pub(crate) totp: Option<(String, u64)>,
    /// `(name, size_bytes)` per attachment.
    pub(crate) attachments: Vec<(String, u64)>,
    pub(crate) tags: Vec<String>,
    /// Per non-standard custom field. Protected values are masked unless the
    /// `reveal` toggle is on (PMF-1).
    pub(crate) custom_fields: Vec<CustomFieldData>,
    pub(crate) history_count: usize,
}

/// One displayable custom field. The `value` is held in a [`Zeroizing`] (wiped
/// when this per-frame snapshot drops) and `protected` carries KDBX's protected
/// flag so the renderer can mask it — mirroring the password field's discipline.
///
/// **No `Debug` derive** (like [`DetailData`]): a protected value is secret.
#[derive(Clone)]
pub(crate) struct CustomFieldData {
    pub(crate) name: String,
    pub(crate) value: Zeroizing<String>,
    pub(crate) protected: bool,
}

/// Render `DetailData` into styled lines. Pure: identical input → identical
/// output, regardless of clock or terminal.
pub(crate) fn detail_lines(data: &DetailData, reveal: bool, theme: &Theme) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();

    // Title (always shown). Expired entries get the bold + " (expired)" dual
    // affordance (FR-074).
    if data.expired {
        lines.push(Line::from(vec![
            Span::raw("Title: "),
            Span::styled(format!("{} (expired)", data.title), theme.expired()),
        ]));
    } else {
        lines.push(Line::from(vec![
            Span::raw("Title: "),
            Span::styled(data.title.clone(), theme.header()),
        ]));
    }
    lines.push(field_line("Kind", data.kind));

    if !data.username.is_empty() {
        lines.push(field_line("Username", &data.username));
    }
    if !data.url.is_empty() {
        lines.push(field_line("URL", &data.url));
    }
    if !data.password.is_empty() {
        // Only materialise the plaintext when actually revealing; the masked
        // path never copies the secret out of the `Zeroizing` buffer.
        let (value, hint) = if reveal {
            (data.password.as_str().to_string(), " (Space: hide)")
        } else {
            (MASK.to_string(), " (Space: reveal)")
        };
        lines.push(Line::from(vec![
            Span::raw("Password: "),
            Span::raw(value),
            Span::styled(hint.to_string(), theme.muted()),
        ]));
    }
    if let Some((code, remaining)) = &data.totp {
        lines.push(Line::from(vec![
            Span::raw("TOTP: "),
            Span::styled(code.clone(), theme.good()),
            Span::styled(format!("  (valid {remaining}s)"), theme.muted()),
        ]));
    }

    if !data.notes.is_empty() {
        lines.push(section("Notes:", theme));
        for line in data.notes.lines() {
            lines.push(Line::from(format!("  {line}")));
        }
    }

    if !data.tags.is_empty() {
        let rendered = data
            .tags
            .iter()
            .map(|t| format!("[{t}]"))
            .collect::<Vec<_>>()
            .join(" ");
        lines.push(field_line("Tags", &rendered));
    }

    if !data.attachments.is_empty() {
        lines.push(section("Attachments:", theme));
        for (name, size) in &data.attachments {
            lines.push(Line::from(format!("  {name} ({})", human_size(*size))));
        }
    }

    if !data.custom_fields.is_empty() {
        lines.push(section("Custom fields:", theme));
        for field in &data.custom_fields {
            // Protected values are masked unless revealed; the masked path never
            // copies the plaintext out of the `Zeroizing` buffer (mirrors the
            // password field above).
            if field.protected && !reveal {
                lines.push(Line::from(vec![
                    Span::raw(format!("  {}: {MASK}", field.name)),
                    Span::styled(" (Space: reveal)".to_string(), theme.muted()),
                ]));
            } else {
                lines.push(Line::from(format!(
                    "  {}: {}",
                    field.name,
                    field.value.as_str()
                )));
            }
        }
    }

    if let Some(created) = &data.created {
        lines.push(field_line("Created", created));
    }
    if let Some(modified) = &data.modified {
        lines.push(field_line("Modified", modified));
    }

    // History affordance only — the read-only viewer is the Phase-5 `Shift+H`
    // overlay (T5.4); the key is a no-op this phase.
    let plural = if data.history_count == 1 {
        "entry"
    } else {
        "entries"
    };
    lines.push(Line::from(vec![
        Span::raw(format!("History: {} {plural}", data.history_count)),
        Span::styled(" (Shift+H to view)".to_string(), theme.muted()),
    ]));

    lines
}

fn field_line(label: &str, value: &str) -> Line<'static> {
    Line::from(format!("{label}: {value}"))
}

fn section(label: &str, theme: &Theme) -> Line<'static> {
    Line::from(Span::styled(label.to_string(), theme.header()))
}

/// Human-readable byte size for attachment metadata. Integer math (one decimal
/// place) — avoids `u64 as f64` precision loss and is exact for display.
fn human_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    if bytes >= MIB {
        format!("{}.{} MiB", bytes / MIB, (bytes % MIB) * 10 / MIB)
    } else if bytes >= KIB {
        format!("{}.{} KiB", bytes / KIB, (bytes % KIB) * 10 / KIB)
    } else {
        format!("{bytes} B")
    }
}

/// Snapshot the selected entry's fields into a [`DetailData`]. Returns `None`
/// when nothing (or a group) is selected, or no vault is open. `now` resolves
/// the live expiry check.
pub(crate) fn build_detail_data(app: &App, now: DateTime<Utc>) -> Option<DetailData> {
    let vault = app.vault.as_ref()?;
    let uuid = app.tree.selected()?;
    detail_data_for(vault, uuid, now)
}

/// Snapshot a specific entry's fields into a [`DetailData`]. Returns `None` if
/// `uuid` is not an entry (e.g. a group UUID, or a stale pinned UUID whose
/// entry was deleted). Shared by the Secrets-tab selection and pinned tabs.
pub(crate) fn detail_data_for(vault: &Vault, uuid: Uuid, now: DateTime<Utc>) -> Option<DetailData> {
    // `get_entry` errors on a group UUID, which is exactly the "not an entry"
    // signal we want.
    let entry = vault.get_entry(uuid).ok()?;

    let kind = match entry.kind() {
        EntryKind::Credential => "Credential",
        EntryKind::SecureNote => "Secure Note",
        EntryKind::Totp => "TOTP",
    };

    let totp = matches!(entry.kind(), EntryKind::Totp)
        .then(|| vault.totp(uuid).ok())
        .flatten();

    // Custom fields, excluding any OTP-bearing field (surfaced as TOTP above)
    // so the secret seed is never rendered in plaintext.
    let custom_fields = entry
        .custom_field_names()
        .into_iter()
        .filter(|name| !crate::util::is_otp_field(name))
        .filter_map(|name| {
            entry.custom_field(name).map(|value| CustomFieldData {
                name: name.to_string(),
                value: Zeroizing::new(value.to_string()),
                protected: entry.custom_field_is_protected(name).unwrap_or(false),
            })
        })
        .collect();

    Some(DetailData {
        title: non_empty(entry.title(), "(untitled)"),
        kind,
        username: entry.username().to_string(),
        url: entry.url().to_string(),
        password: Zeroizing::new(entry.password().to_string()),
        notes: entry.notes().to_string(),
        created: entry.creation_time().map(crate::util::format_ts),
        modified: entry.last_modification_time().map(crate::util::format_ts),
        expired: vault.is_expired(uuid, now).unwrap_or(false),
        totp,
        attachments: entry
            .attachments()
            .into_iter()
            .map(|a| (a.name, a.size_bytes))
            .collect(),
        tags: entry
            .tags()
            .into_iter()
            .map(|t| t.as_str().to_string())
            .collect(),
        custom_fields,
        history_count: entry.history().len(),
    })
}

fn non_empty(value: &str, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}

/// Draw the detail pane for the Secrets-tab selection into `area`. Reads `App`
/// immutably; the stored scroll offset is clamped to the content height at
/// render time (the offset can't be written back from `&self`, so over-scroll
/// renders blank rather than garbage).
pub(crate) fn render_detail(app: &App, frame: &mut Frame, area: Rect, now: DateTime<Utc>) {
    let focused = app.focus == Focus::Detail;
    let title = if focused { "Detail [focus]" } else { "Detail" };
    let data = build_detail_data(app, now);
    render_detail_data(
        data.as_ref(),
        app.reveal_password,
        app.detail_scroll,
        focused,
        title,
        &app.theme,
        frame,
        area,
    );
}

/// Draw a pinned tab's body: the pinned entry's detail filling `area` (T4.4).
/// Shares the App's `reveal`/`scroll` state (reset on tab switch). A stale pin
/// (entry deleted) renders the "not found" placeholder rather than panicking.
#[allow(clippy::too_many_arguments)]
pub(crate) fn render_pinned(
    vault: &Vault,
    uuid: Uuid,
    reveal: bool,
    scroll: u16,
    theme: &Theme,
    frame: &mut Frame,
    area: Rect,
    now: DateTime<Utc>,
) {
    let data = detail_data_for(vault, uuid, now);
    render_detail_data(
        data.as_ref(),
        reveal,
        scroll,
        false,
        "Pinned entry",
        theme,
        frame,
        area,
    );
}

/// Shared detail draw: a bordered, scrollable `Paragraph` of `data`'s lines, or
/// a placeholder when `data` is `None`. Keeps the Secrets-tab and pinned-tab
/// paths byte-identical.
#[allow(clippy::too_many_arguments)]
fn render_detail_data(
    data: Option<&DetailData>,
    reveal: bool,
    scroll: u16,
    focused: bool,
    title: &str,
    theme: &Theme,
    frame: &mut Frame,
    area: Rect,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(if focused {
            theme.border_focused()
        } else {
            theme.border()
        })
        .title(title.to_string())
        .title_style(if focused {
            theme.header()
        } else {
            Style::default()
        });

    let Some(data) = data else {
        let placeholder = Paragraph::new("No entry selected.")
            .block(block)
            .style(theme.muted());
        frame.render_widget(placeholder, area);
        return;
    };

    let lines = detail_lines(data, reveal, theme);
    let viewport = block.inner(area).height as usize;
    let max_scroll = u16::try_from(lines.len().saturating_sub(viewport)).unwrap_or(u16::MAX);
    let scroll = scroll.min(max_scroll);

    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));
    frame.render_widget(paragraph, area);
}

#[cfg(test)]
mod tests {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use super::*;
    use crate::theme::{ThemeDef, Tier};

    fn theme() -> Theme {
        Theme::auto()
    }

    #[test]
    fn detail_renderer_adopts_focused_and_unfocused_border_slots() {
        let theme = ThemeDef::builtin("default-dark")
            .unwrap()
            .theme_for_tier(Tier::TrueColor);
        for (focused, expected) in [(true, theme.border_focused()), (false, theme.border())] {
            let mut terminal = Terminal::new(TestBackend::new(20, 5)).unwrap();
            terminal
                .draw(|frame| {
                    render_detail_data(
                        None,
                        false,
                        0,
                        focused,
                        "Details",
                        &theme,
                        frame,
                        frame.area(),
                    );
                })
                .unwrap();
            let style = terminal.backend().buffer().cell((0, 0)).unwrap().style();
            if let Some(expected_fg) = expected.fg {
                assert_eq!(style.fg, Some(expected_fg));
            }
            assert!(style.add_modifier.contains(expected.add_modifier));
        }
    }

    /// Concatenate a line's span contents into a plain string for assertions.
    fn text(line: &Line) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    fn full_credential() -> DetailData {
        DetailData {
            title: "GitHub".to_string(),
            kind: "Credential",
            username: "octocat".to_string(),
            url: "https://github.com".to_string(),
            password: Zeroizing::new("hunter2".to_string()),
            notes: "first line\nsecond line".to_string(),
            created: Some("2026-01-02 03:04 UTC".to_string()),
            modified: Some("2026-05-06 07:08 UTC".to_string()),
            expired: false,
            totp: None,
            attachments: vec![("recovery.txt".to_string(), 2048)],
            tags: vec!["work".to_string(), "dev".to_string()],
            custom_fields: vec![
                CustomFieldData {
                    name: "API Key".to_string(),
                    value: Zeroizing::new("abc123".to_string()),
                    protected: false,
                },
                CustomFieldData {
                    name: "Recovery PIN".to_string(),
                    value: Zeroizing::new("9999".to_string()),
                    protected: true,
                },
            ],
            history_count: 3,
        }
    }

    // T-DETAIL-1: every field type renders with a text label.
    #[test]
    fn renders_all_field_types_with_labels() {
        let lines = detail_lines(&full_credential(), false, &theme());
        let joined: Vec<String> = lines.iter().map(text).collect();
        let blob = joined.join("\n");
        assert!(blob.contains("Title: GitHub"));
        assert!(blob.contains("Kind: Credential"));
        assert!(blob.contains("Username: octocat"));
        assert!(blob.contains("URL: https://github.com"));
        assert!(blob.contains("Notes:"));
        assert!(blob.contains("  first line"));
        assert!(blob.contains("  second line"));
        assert!(blob.contains("Tags: [work] [dev]"));
        assert!(blob.contains("Attachments:"));
        assert!(blob.contains("recovery.txt (2.0 KiB)"));
        assert!(blob.contains("Custom fields:"));
        assert!(blob.contains("  API Key: abc123"));
        assert!(blob.contains("Created: 2026-01-02 03:04 UTC"));
        assert!(blob.contains("Modified: 2026-05-06 07:08 UTC"));
        assert!(blob.contains("History: 3 entries"));
        assert!(blob.contains("Shift+H"));
    }

    // T-DETAIL-1: the password is masked by default and revealed on toggle, and
    // the mask never leaks the password length.
    #[test]
    fn password_masks_by_default_and_reveals_on_toggle() {
        let data = full_credential();
        let masked = detail_lines(&data, false, &theme());
        let masked_blob = masked.iter().map(text).collect::<Vec<_>>().join("\n");
        assert!(masked_blob.contains(MASK), "default render is masked");
        assert!(
            !masked_blob.contains("hunter2"),
            "plaintext never shown when masked"
        );
        assert!(masked_blob.contains("(Space: reveal)"));

        let revealed = detail_lines(&data, true, &theme());
        let revealed_blob = revealed.iter().map(text).collect::<Vec<_>>().join("\n");
        assert!(revealed_blob.contains("Password: hunter2"));
        assert!(revealed_blob.contains("(Space: hide)"));
    }

    // PMF-1 (T1.5): a protected custom field is masked by default and revealed
    // on the same `reveal` toggle as the password; the plaintext never appears
    // in the masked render. The unprotected custom field stays visible.
    #[test]
    fn protected_custom_field_masks_until_revealed() {
        let data = full_credential(); // carries protected "Recovery PIN" = 9999

        let masked = detail_lines(&data, false, &theme())
            .iter()
            .map(text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            masked.contains(&format!("Recovery PIN: {MASK}")),
            "protected custom value is masked by default"
        );
        assert!(
            !masked.contains("9999"),
            "plaintext never appears in the masked render"
        );
        assert!(
            masked.contains("API Key: abc123"),
            "unprotected custom value stays visible"
        );

        let revealed = detail_lines(&data, true, &theme())
            .iter()
            .map(text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            revealed.contains("Recovery PIN: 9999"),
            "protected custom value is shown when revealed"
        );
    }

    // T-DETAIL-1: expired entries carry the " (expired)" text suffix.
    #[test]
    fn expired_entry_carries_text_suffix() {
        let mut data = full_credential();
        data.expired = true;
        let blob = detail_lines(&data, false, &theme())
            .iter()
            .map(text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(blob.contains("Title: GitHub (expired)"));
    }

    // T-DETAIL-1: the TOTP line shows the code and remaining window.
    #[test]
    fn totp_line_shows_code_and_window() {
        let mut data = full_credential();
        data.kind = "TOTP";
        data.totp = Some(("123456".to_string(), 23));
        let blob = detail_lines(&data, false, &theme())
            .iter()
            .map(text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(blob.contains("TOTP: 123456"));
        assert!(blob.contains("(valid 23s)"));
    }

    // Empty optional fields are omitted (no "Username: " for a bare note).
    #[test]
    fn empty_fields_are_omitted() {
        let data = DetailData {
            title: "Note".to_string(),
            kind: "Secure Note",
            notes: "secret".to_string(),
            history_count: 0,
            ..DetailData::default()
        };
        let blob = detail_lines(&data, false, &theme())
            .iter()
            .map(text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!blob.contains("Username:"));
        assert!(!blob.contains("URL:"));
        assert!(!blob.contains("Password:"));
        assert!(blob.contains("History: 0 entries"));
    }

    #[test]
    fn human_size_formats_units() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(2048), "2.0 KiB");
        assert_eq!(human_size(3 * 1024 * 1024), "3.0 MiB");
    }
}
