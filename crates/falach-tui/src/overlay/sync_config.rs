//! `Overlay::SyncConfig` — the secure S3-credential entry surface (T6.4 /
//! ADR-T2), reachable only while unlocked.
//!
//! This overlay collects an S3 sync target plus the **two** secrets the
//! RST-CRED-1 two-call flow needs:
//!
//! 1. the **S3 secret access key** (the thing being encrypted), and
//! 2. the **master password** (the key `encrypt_credential` derives from — it
//!    is keyed off the pre-KDF master password, *not* `Vault.key`, which is why
//!    the App, holding no `MasterPassword`, must re-collect it here).
//!
//! Both live in echo-suppressed [`PasswordInput`] buffers (`Zeroizing`), so
//! dropping the overlay (cancel, save, lock) zeroizes them. `access_key_id`,
//! bucket, key, region, and endpoint are **not** secret and use plain
//! `tui_input::Input`s.
//!
//! This module owns *state, focus, and rendering only*. The two-call persistence
//! (`encrypt_credential` → `Sync::configure_remote`) lives on `App`
//! (`perform_configure_sync`), keeping the secret-bearing call path on the type
//! that owns the registry.

use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;
use tui_input::Input;

use super::{centered, clear};
use crate::theme::Theme;
use crate::widgets::password_input::PasswordInput;

/// A focusable field in the credential form, in `Tab` order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncField {
    Endpoint,
    Region,
    Bucket,
    Key,
    PathStyle,
    AccessKeyId,
    Secret,
    Master,
}

/// The fields in focus order. `Tab`/`Shift+Tab` walk this slice.
const FIELDS: &[SyncField] = &[
    SyncField::Endpoint,
    SyncField::Region,
    SyncField::Bucket,
    SyncField::Key,
    SyncField::PathStyle,
    SyncField::AccessKeyId,
    SyncField::Secret,
    SyncField::Master,
];

/// Credential-overlay state.
pub(crate) struct SyncConfigState {
    /// Custom endpoint URL (blank → AWS default for the region). Non-secret.
    pub(crate) endpoint: Input,
    /// AWS region (required for `SigV4`). Non-secret.
    pub(crate) region: Input,
    /// Bucket name. Non-secret.
    pub(crate) bucket: Input,
    /// Object key. Non-secret.
    pub(crate) key: Input,
    /// Path-style addressing (`MinIO` and some S3-compatible backends need it).
    pub(crate) path_style: bool,
    /// Public AWS access-key identifier. Non-secret (appears in CloudTrail/IAM).
    pub(crate) access_key_id: Input,
    /// The S3 **secret** access key (the value RST-CRED-1 encrypts).
    pub(crate) secret: PasswordInput,
    /// The master password (re-collected to drive `encrypt_credential`).
    pub(crate) master: PasswordInput,
    /// Index into [`FIELDS`].
    pub(crate) focus: usize,
    /// A non-secret validation / persistence error to surface.
    pub(crate) error: Option<String>,
}

impl SyncConfigState {
    /// A blank credential form.
    pub(crate) fn new() -> Self {
        Self {
            endpoint: Input::default(),
            region: Input::default(),
            bucket: Input::default(),
            key: Input::default(),
            path_style: false,
            access_key_id: Input::default(),
            secret: PasswordInput::new(),
            master: PasswordInput::new(),
            focus: 0,
            error: None,
        }
    }

    /// The currently-focused field.
    pub(crate) fn focused(&self) -> SyncField {
        FIELDS[self.focus.min(FIELDS.len() - 1)]
    }

    /// Move focus to the next field (wraps).
    pub(crate) fn focus_next(&mut self) {
        self.focus = (self.focus + 1) % FIELDS.len();
    }

    /// Move focus to the previous field (wraps).
    pub(crate) fn focus_prev(&mut self) {
        self.focus = (self.focus + FIELDS.len() - 1) % FIELDS.len();
    }
}

/// The status-bar hint while this overlay is up.
pub(crate) const HINTS: &str =
    "Tab/Shift+Tab: field   Space: toggle path-style   Ctrl+S: save   Esc: cancel";

/// Render the credential overlay over the workspace.
pub(crate) fn render(state: &SyncConfigState, frame: &mut Frame, theme: &Theme) {
    let area = centered(frame, 64, 18);
    clear(frame, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title("Configure sync target (S3)")
        .title_style(theme.header());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.height == 0 || inner.width == 0 {
        return;
    }

    // One line per field + a spacer + the (optional) error line.
    let mut lines: Vec<Line> = Vec::new();
    lines.push(field_line(
        "Endpoint",
        display_value(state.endpoint.value(), "(AWS default)"),
        state.focused() == SyncField::Endpoint,
        theme,
    ));
    lines.push(field_line(
        "Region",
        state.region.value(),
        state.focused() == SyncField::Region,
        theme,
    ));
    lines.push(field_line(
        "Bucket",
        state.bucket.value(),
        state.focused() == SyncField::Bucket,
        theme,
    ));
    lines.push(field_line(
        "Object key",
        state.key.value(),
        state.focused() == SyncField::Key,
        theme,
    ));
    lines.push(field_line(
        "Path-style",
        if state.path_style {
            "[x] on"
        } else {
            "[ ] off"
        },
        state.focused() == SyncField::PathStyle,
        theme,
    ));
    lines.push(field_line(
        "Access key ID",
        state.access_key_id.value(),
        state.focused() == SyncField::AccessKeyId,
        theme,
    ));
    let secret_mask = mask(state.secret.len_chars());
    lines.push(field_line(
        "Secret key",
        &secret_mask,
        state.focused() == SyncField::Secret,
        theme,
    ));
    let master_mask = mask(state.master.len_chars());
    lines.push(field_line(
        "Master pass",
        &master_mask,
        state.focused() == SyncField::Master,
        theme,
    ));
    lines.push(Line::from(""));
    if let Some(err) = &state.error {
        lines.push(Line::from(Span::styled(err.clone(), theme.error())));
    } else {
        lines.push(Line::from(Span::styled(
            "Only the encrypted credential reaches vaults.toml.",
            theme.muted(),
        )));
    }

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

/// `value` if non-empty, else a muted placeholder string (for the endpoint).
fn display_value<'a>(value: &'a str, placeholder: &'a str) -> &'a str {
    if value.is_empty() {
        placeholder
    } else {
        value
    }
}

/// One labelled field row. The focused row gets a `> ` text affordance
/// (NFR-015: never colour alone) plus the accent style.
fn field_line<'a>(label: &'a str, value: &'a str, focused: bool, theme: &Theme) -> Line<'a> {
    let marker = if focused { "> " } else { "  " };
    let label_span = Span::styled(format!("{marker}{label:>13}: "), theme.muted());
    let value_style = if focused {
        theme.selected()
    } else {
        theme.header()
    };
    Line::from(vec![
        label_span,
        Span::styled(value.to_string(), value_style),
    ])
}

/// A masked rendering of an `n`-character secret (never the bytes).
fn mask(n: usize) -> String {
    "•".repeat(n)
}
