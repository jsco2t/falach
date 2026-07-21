//! `Overlay::Edit` — add or edit an entry's full field set (T5.2), with the
//! nested generate panel (T5.3).
//!
//! The overlay holds one editable field per entry attribute: title, username,
//! password (masked, revealable, over `Zeroizing` via [`PasswordInput`]), URL,
//! a TOTP otpauth URI (add-only), multi-line notes, tags, and a dynamic list of
//! custom fields. Focus moves with `Tab`/`Shift+Tab`; `Ctrl+S` commits;
//! `Esc` cancels (dropping the overlay zeroizes the password buffer);
//! `Ctrl+G` opens the [`generate`](super::generate) panel for the password.
//!
//! This module owns the *state, focus model, validation, and rendering*. The
//! vault mutation (`add_entry` / `update_entry` + `save`) lives on `App`, which
//! reads an [`EditValues`] snapshot — keeping the secret-bearing apply path on
//! the type that owns the `Vault`.

use falach_core::{EntryKind, EntryView, Tag, Uuid, Zeroizing};
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;
use tui_input::Input;

use super::generate::GenState;
use super::{centered, clear};
use crate::theme::Theme;
use crate::widgets::password_input::PasswordInput;
use crate::widgets::text_area::TextArea;

/// Which column of a custom-field row is addressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Col {
    Name,
    Value,
}

/// A focusable field within the edit form. Recomputed (not stored) from the
/// kind + custom-row count via [`EditState::fields`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EditField {
    Kind,
    Title,
    Username,
    Password,
    Url,
    TotpUri,
    Notes,
    Tags,
    Custom(usize, Col),
    CustomAdd,
}

/// One editable custom-field row. The value is held in a [`PasswordInput`]
/// (`Zeroizing`-backed) so a custom value that may carry key material wipes on
/// drop (cancel/save/lock); the name stays a plain [`Input`] (PMF-1).
pub(crate) struct CustomRow {
    pub(crate) name: Input,
    pub(crate) value: PasswordInput,
    /// Whether this field is KDBX-protected. Seeded from the loaded entry so an
    /// existing protected field is written back protected (PMF-5 write-fidelity);
    /// new rows default to `false`. Carried through to the write APIs unchanged.
    pub(crate) protected: bool,
}

/// Edit-overlay state.
pub(crate) struct EditState {
    /// `true` for add, `false` for edit-in-place.
    pub(crate) is_new: bool,
    /// The entry being edited (`None` for add).
    pub(crate) target: Option<Uuid>,
    /// The group a new entry is added to (add only).
    pub(crate) group: Uuid,
    pub(crate) kind: EntryKind,
    pub(crate) title: Input,
    pub(crate) username: Input,
    pub(crate) password: PasswordInput,
    pub(crate) reveal_password: bool,
    pub(crate) url: Input,
    /// The otpauth URI embeds the `secret=` seed (key material), so it is held
    /// in a [`PasswordInput`] (`Zeroizing`-backed) and wipes on drop (PMF-1).
    /// Add-only; rendered visibly (not masked) so the user can verify a paste.
    pub(crate) totp_uri: PasswordInput,
    pub(crate) notes: TextArea,
    pub(crate) tags: Input,
    pub(crate) custom: Vec<CustomRow>,
    /// Custom-field names present when an *existing* entry was loaded — used to
    /// compute which fields the user removed (edit only). OTP fields are
    /// excluded so the TOTP seed is preserved untouched.
    original_custom: Vec<String>,
    /// Index into [`Self::fields`].
    pub(crate) focus: usize,
    /// The nested generate panel (T5.3); `Some` while generating.
    pub(crate) generating: Option<GenState>,
    /// A non-secret validation error to surface (e.g. empty title, bad URI).
    pub(crate) error: Option<String>,
}

/// A plain snapshot of the form's committed values, consumed by `App` to drive
/// `add_entry` / `update_entry`. The password is kept in `Zeroizing` so the
/// snapshot wipes it on drop.
pub(crate) struct EditValues {
    pub(crate) kind: EntryKind,
    pub(crate) title: String,
    pub(crate) username: String,
    pub(crate) password: Zeroizing<String>,
    pub(crate) url: String,
    /// otpauth URI (carries the seed) — `Zeroizing` so the snapshot wipes it.
    pub(crate) totp_uri: Zeroizing<String>,
    pub(crate) notes: String,
    pub(crate) tags: Vec<Tag>,
    /// `(name, value, protected)`; the value is `Zeroizing` since a custom field
    /// may hold key material (PMF-1). `protected` preserves the loaded field's
    /// KDBX protectedness so an edit doesn't silently demote it (PMF-5).
    pub(crate) custom: Vec<(String, Zeroizing<String>, bool)>,
    /// Original custom-field names the user removed (edit only).
    pub(crate) removed_custom: Vec<String>,
}

impl EditState {
    /// A blank add form for `group`, defaulting to a credential.
    pub(crate) fn new_add(group: Uuid) -> Self {
        Self {
            is_new: true,
            target: None,
            group,
            kind: EntryKind::Credential,
            title: Input::default(),
            username: Input::default(),
            password: PasswordInput::new(),
            reveal_password: false,
            url: Input::default(),
            totp_uri: PasswordInput::new(),
            notes: TextArea::new(),
            tags: Input::default(),
            custom: Vec::new(),
            original_custom: Vec::new(),
            focus: 0,
            generating: None,
            error: None,
        }
    }

    /// An edit form pre-filled from an existing entry. OTP-bearing custom fields
    /// are filtered out of the editable list and preserved untouched on save.
    pub(crate) fn from_entry(uuid: Uuid, view: &EntryView<'_>) -> Self {
        let tags = view
            .tags()
            .iter()
            .map(|t| t.as_str().to_string())
            .collect::<Vec<_>>()
            .join(" ");
        let mut custom = Vec::new();
        let mut original_custom = Vec::new();
        for name in view.custom_field_names() {
            if crate::util::is_otp_field(name) {
                continue;
            }
            let value = view.custom_field(name).unwrap_or("");
            let protected = view.custom_field_is_protected(name).unwrap_or(false);
            original_custom.push(name.to_string());
            custom.push(CustomRow {
                name: Input::new(name.to_string()),
                value: PasswordInput::with_value(value),
                protected,
            });
        }
        Self {
            is_new: false,
            target: Some(uuid),
            group: Uuid::nil(),
            kind: view.kind(),
            title: Input::new(view.title().to_string()),
            username: Input::new(view.username().to_string()),
            password: PasswordInput::with_value(view.password()),
            reveal_password: false,
            url: Input::new(view.url().to_string()),
            totp_uri: PasswordInput::new(),
            notes: TextArea::from_str(view.notes()),
            tags: Input::new(tags),
            custom,
            original_custom,
            focus: 0,
            generating: None,
            error: None,
        }
    }

    /// The ordered focusable fields for the current kind + custom rows.
    pub(crate) fn fields(&self) -> Vec<EditField> {
        let mut f = Vec::new();
        if self.is_new {
            f.push(EditField::Kind);
        }
        f.push(EditField::Title);
        match self.kind {
            EntryKind::Credential => {
                f.push(EditField::Username);
                f.push(EditField::Password);
                f.push(EditField::Url);
            }
            EntryKind::Totp => {
                if self.is_new {
                    f.push(EditField::TotpUri);
                }
                f.push(EditField::Username);
                f.push(EditField::Url);
            }
            EntryKind::SecureNote => {}
        }
        f.push(EditField::Notes);
        f.push(EditField::Tags);
        for i in 0..self.custom.len() {
            f.push(EditField::Custom(i, Col::Name));
            f.push(EditField::Custom(i, Col::Value));
        }
        f.push(EditField::CustomAdd);
        f
    }

    /// The currently-focused field.
    pub(crate) fn focused(&self) -> EditField {
        let fields = self.fields();
        fields[self.focus.min(fields.len() - 1)]
    }

    pub(crate) fn focus_next(&mut self) {
        let len = self.fields().len();
        self.focus = (self.focus + 1) % len;
    }

    pub(crate) fn focus_prev(&mut self) {
        let len = self.fields().len();
        self.focus = (self.focus + len - 1) % len;
    }

    /// Cycle the entry kind (add only). Clamps focus afterwards since the field
    /// set changes shape.
    pub(crate) fn cycle_kind(&mut self) {
        if !self.is_new {
            return;
        }
        self.kind = match self.kind {
            EntryKind::Credential => EntryKind::SecureNote,
            EntryKind::SecureNote => EntryKind::Totp,
            EntryKind::Totp => EntryKind::Credential,
        };
        self.clamp_focus();
    }

    /// Cycle the entry kind backwards (the `Left`/`h` key on the Kind field).
    pub(crate) fn cycle_kind_back(&mut self) {
        if !self.is_new {
            return;
        }
        self.kind = match self.kind {
            EntryKind::Credential => EntryKind::Totp,
            EntryKind::Totp => EntryKind::SecureNote,
            EntryKind::SecureNote => EntryKind::Credential,
        };
        self.clamp_focus();
    }

    /// Append an empty custom-field row and move focus to its name column.
    pub(crate) fn add_custom_row(&mut self) {
        self.custom.push(CustomRow {
            name: Input::default(),
            value: PasswordInput::new(),
            protected: false,
        });
        // Focus the new row's name column.
        let fields = self.fields();
        if let Some(idx) = fields.iter().position(
            |f| matches!(f, EditField::Custom(i, Col::Name) if *i == self.custom.len() - 1),
        ) {
            self.focus = idx;
        }
    }

    /// Remove custom row `i` and clamp focus.
    pub(crate) fn remove_custom_row(&mut self, i: usize) {
        if i < self.custom.len() {
            self.custom.remove(i);
            self.clamp_focus();
        }
    }

    fn clamp_focus(&mut self) {
        let len = self.fields().len();
        self.focus = self.focus.min(len - 1);
    }

    /// Validate and snapshot the form. `Err` carries a non-secret message to
    /// show in the overlay's error line.
    pub(crate) fn snapshot(&self) -> Result<EditValues, String> {
        let title = self.title.value().trim().to_string();
        if title.is_empty() {
            return Err("Title is required.".to_string());
        }

        let tags = parse_tags(self.tags.value())?;

        // Custom rows with a non-empty (trimmed) name; later wins on dup names.
        let mut custom: Vec<(String, Zeroizing<String>, bool)> = Vec::new();
        for row in &self.custom {
            let name = row.name.value().trim().to_string();
            if name.is_empty() {
                continue;
            }
            if crate::util::is_otp_field(&name) {
                return Err("Custom field name 'otp'/'TOTP' is reserved.".to_string());
            }
            custom.retain(|(n, _, _)| n != &name);
            custom.push((
                name,
                Zeroizing::new(row.value.as_str().to_string()),
                row.protected,
            ));
        }

        // Removed = original names no longer present among the current rows.
        let current_names: Vec<&String> = custom.iter().map(|(n, _, _)| n).collect();
        let removed_custom = self
            .original_custom
            .iter()
            .filter(|orig| !current_names.contains(orig))
            .cloned()
            .collect();

        Ok(EditValues {
            kind: self.kind,
            title,
            username: self.username.value().to_string(),
            password: Zeroizing::new(self.password.as_str().to_string()),
            url: self.url.value().to_string(),
            totp_uri: Zeroizing::new(self.totp_uri.as_str().trim().to_string()),
            notes: self.notes.value(),
            tags,
            custom,
            removed_custom,
        })
    }

    /// Status-bar hints, sensitive to the generate panel + focused field.
    pub(crate) fn hints(&self) -> &'static str {
        if self.generating.is_some() {
            return "Tab: kind   +/-: size   l/u/d/s: classes   b: ambiguous   r: re-roll   Enter: use   Esc: back";
        }
        match self.focused() {
            EditField::Kind => "h/l: change type   Tab: next field   Ctrl+S: save   Esc: cancel",
            EditField::Password => {
                "type password   Ctrl+G: generate   Ctrl+R: reveal   Ctrl+S: save   Esc: cancel"
            }
            EditField::Notes => "Enter: newline   Tab: next field   Ctrl+S: save   Esc: cancel",
            EditField::Custom(..) => {
                "edit field   Ctrl+D: delete field   Tab: next   Ctrl+S: save   Esc: cancel"
            }
            EditField::CustomAdd => {
                "Enter: add custom field   Tab: next   Ctrl+S: save   Esc: cancel"
            }
            _ => "Tab/Shift+Tab: move   Ctrl+S: save   Esc: cancel",
        }
    }
}

/// Parse a whitespace/comma-separated tag string into validated [`Tag`]s.
fn parse_tags(raw: &str) -> Result<Vec<Tag>, String> {
    let mut tags = Vec::new();
    for token in raw.split([',', ' ', '\t']).filter(|t| !t.is_empty()) {
        match Tag::from(token.to_string()) {
            Ok(tag) => {
                if !tags.iter().any(|t: &Tag| t.as_str() == tag.as_str()) {
                    tags.push(tag);
                }
            }
            Err(_) => return Err(format!("Invalid tag: {token}")),
        }
    }
    Ok(tags)
}

/// Insert a `▏` caret at character index `col` in `line` (for the focused notes
/// line). `col` is a character count, clamped to the line length.
fn with_caret(line: &str, col: usize) -> String {
    let chars: Vec<char> = line.chars().collect();
    let at = col.min(chars.len());
    let mut out: String = chars[..at].iter().collect();
    out.push('▏');
    out.extend(chars[at..].iter());
    out
}

/// The displayed value of a single-line input: the plain value, plus a `▏`
/// caret at the cursor when the field is focused (mirrors the notes editor, so
/// mid-string editing of a seeded value has a visible insertion point).
fn caret_value(input: &Input, focused: bool) -> String {
    if focused {
        with_caret(input.value(), input.cursor())
    } else {
        input.value().to_string()
    }
}

/// `caret_value` for a [`PasswordInput`]-backed visible field (the otpauth URI):
/// the buffer is `Zeroizing` for memory hygiene, but the field is rendered in
/// the clear (add-only) so a paste can be verified.
fn caret_value_pw(input: &PasswordInput, focused: bool) -> String {
    if focused {
        with_caret(input.as_str(), input.cursor_chars())
    } else {
        input.as_str().to_string()
    }
}

fn kind_label(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::Credential => "Credential",
        EntryKind::SecureNote => "Secure Note",
        EntryKind::Totp => "TOTP",
    }
}

pub(crate) fn render(state: &EditState, frame: &mut Frame, theme: &Theme) {
    // Generate panel takes over the modal while active.
    if let Some(gen) = state.generating.as_ref() {
        render_generate(gen, frame, theme);
        return;
    }

    let area = centered(frame, 72, 22);
    clear(frame, area);

    let title = if state.is_new {
        "Add entry"
    } else {
        "Edit entry"
    };
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let lines = form_lines(state, theme);
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }),
        inner_with_margin(inner),
    );
}

/// A `marker + label: value` line, styled by focus state.
fn field_line(label: &str, value: String, is_focused: bool, theme: &Theme) -> Line<'static> {
    let marker = if is_focused { "> " } else { "  " };
    let label_style = if is_focused {
        theme.header()
    } else {
        theme.muted()
    };
    Line::from(vec![
        Span::styled(format!("{marker}{label}: "), label_style),
        Span::raw(value),
    ])
}

/// Build the full set of form lines for the current state.
fn form_lines(state: &EditState, theme: &Theme) -> Vec<Line<'static>> {
    let focused = state.focused();
    let mut lines: Vec<Line> = Vec::new();
    push_identity_fields(&mut lines, state, theme, focused);
    push_notes(&mut lines, state, theme, focused);
    lines.push(field_line(
        "Tags",
        caret_value(&state.tags, focused == EditField::Tags),
        focused == EditField::Tags,
        theme,
    ));
    push_custom_fields(&mut lines, state, theme, focused);
    if let Some(err) = state.error.as_ref() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(format!("⚠ {err}"), theme.error())));
    }
    lines
}

/// Kind (add only) + title + the kind-specific identity fields.
fn push_identity_fields(
    lines: &mut Vec<Line<'static>>,
    state: &EditState,
    theme: &Theme,
    focused: EditField,
) {
    if state.is_new {
        lines.push(field_line(
            "Type",
            format!("◂ {} ▸", kind_label(state.kind)),
            focused == EditField::Kind,
            theme,
        ));
    }
    lines.push(field_line(
        "Title",
        caret_value(&state.title, focused == EditField::Title),
        focused == EditField::Title,
        theme,
    ));
    match state.kind {
        EntryKind::Credential => {
            lines.push(field_line(
                "Username",
                caret_value(&state.username, focused == EditField::Username),
                focused == EditField::Username,
                theme,
            ));
            lines.push(password_line(state, theme, focused == EditField::Password));
            lines.push(field_line(
                "URL",
                caret_value(&state.url, focused == EditField::Url),
                focused == EditField::Url,
                theme,
            ));
        }
        EntryKind::Totp => {
            if state.is_new {
                lines.push(field_line(
                    "otpauth URI",
                    caret_value_pw(&state.totp_uri, focused == EditField::TotpUri),
                    focused == EditField::TotpUri,
                    theme,
                ));
            }
            lines.push(field_line(
                "Username",
                caret_value(&state.username, focused == EditField::Username),
                focused == EditField::Username,
                theme,
            ));
            lines.push(field_line(
                "URL",
                caret_value(&state.url, focused == EditField::Url),
                focused == EditField::Url,
                theme,
            ));
        }
        EntryKind::SecureNote => {}
    }
}

/// The multi-line notes section, with an inline caret on the focused line.
fn push_notes(
    lines: &mut Vec<Line<'static>>,
    state: &EditState,
    theme: &Theme,
    focused: EditField,
) {
    let notes_focused = focused == EditField::Notes;
    let notes_marker = if notes_focused { "> " } else { "  " };
    lines.push(Line::from(Span::styled(
        format!("{notes_marker}Notes:"),
        if notes_focused {
            theme.header()
        } else {
            theme.muted()
        },
    )));
    let (cursor_row, cursor_col) = state.notes.cursor();
    for (i, nl) in state.notes.lines().iter().enumerate() {
        let rendered = if notes_focused && i == cursor_row {
            with_caret(nl, cursor_col)
        } else {
            nl.clone()
        };
        lines.push(Line::from(format!("    {rendered}")));
    }
}

/// The dynamic custom-field rows + the "add" affordance.
fn push_custom_fields(
    lines: &mut Vec<Line<'static>>,
    state: &EditState,
    theme: &Theme,
    focused: EditField,
) {
    if !state.custom.is_empty() {
        lines.push(Line::from(Span::styled("  Custom fields:", theme.muted())));
    }
    for (i, row) in state.custom.iter().enumerate() {
        let name_focused = focused == EditField::Custom(i, Col::Name);
        let value_focused = focused == EditField::Custom(i, Col::Value);
        let nmarker = if name_focused { "> " } else { "  " };
        let vmarker = if value_focused { "> " } else { "  " };
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {nmarker}name: "),
                if name_focused {
                    theme.header()
                } else {
                    theme.muted()
                },
            ),
            Span::raw(row.name.value().to_string()),
            Span::styled(
                format!("   {vmarker}value: "),
                if value_focused {
                    theme.header()
                } else {
                    theme.muted()
                },
            ),
            Span::raw(row.value.as_str().to_string()),
        ]));
    }

    let add_focused = focused == EditField::CustomAdd;
    lines.push(Line::from(Span::styled(
        format!(
            "{}[+ add custom field]",
            if add_focused { "> " } else { "  " }
        ),
        if add_focused {
            theme.header()
        } else {
            theme.muted()
        },
    )));
}

/// One-cell left margin inside the border so text doesn't hug the frame.
fn inner_with_margin(inner: Rect) -> Rect {
    Rect {
        x: inner.x + 1,
        y: inner.y,
        width: inner.width.saturating_sub(2),
        height: inner.height,
    }
}

/// The password row: masked dots (or plaintext when revealed). Never prints the
/// secret unless `reveal_password` is set.
fn password_line(state: &EditState, theme: &Theme, is_focused: bool) -> Line<'static> {
    let marker = if is_focused { "> " } else { "  " };
    let label_style = if is_focused {
        theme.header()
    } else {
        theme.muted()
    };
    let value = if state.reveal_password {
        state.password.as_str().to_string()
    } else {
        "•".repeat(state.password.len_chars())
    };
    let hint = if state.reveal_password {
        " (Ctrl+R: hide · Ctrl+G: generate)"
    } else {
        " (Ctrl+R: reveal · Ctrl+G: generate)"
    };
    Line::from(vec![
        Span::styled(format!("{marker}Password: "), label_style),
        Span::raw(value),
        Span::styled(hint.to_string(), theme.muted()),
    ])
}

fn render_generate(gen: &GenState, frame: &mut Frame, theme: &Theme) {
    use super::generate::GenKind;

    let area = centered(frame, 60, 14);
    clear(frame, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Generate password");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled("Type: ", theme.muted()),
        Span::styled(
            match gen.kind {
                GenKind::Password => "Password",
                GenKind::Passphrase => "Passphrase",
            },
            theme.header(),
        ),
        Span::styled("  (Tab to switch)", theme.muted()),
    ]));
    match gen.kind {
        GenKind::Password => {
            lines.push(Line::from(format!("Length: {}  (+/-)", gen.length)));
            lines.push(Line::from(format!(
                "Classes: {}{}{}{}  (l/u/d/s)",
                if gen.classes.lowercase { "a-z " } else { "" },
                if gen.classes.uppercase { "A-Z " } else { "" },
                if gen.classes.digits { "0-9 " } else { "" },
                if gen.classes.symbols { "!@# " } else { "" },
            )));
            lines.push(Line::from(format!(
                "Exclude ambiguous: {}  (b)",
                if gen.exclude_ambiguous { "yes" } else { "no" }
            )));
        }
        GenKind::Passphrase => {
            lines.push(Line::from(format!("Words: {}  (+/-)", gen.words)));
        }
    }
    lines.push(Line::from(""));
    if let Some(err) = gen.error.as_ref() {
        lines.push(Line::from(Span::styled(format!("⚠ {err}"), theme.error())));
    } else {
        lines.push(Line::from(vec![
            Span::styled("Preview: ", theme.muted()),
            Span::styled(gen.preview.as_str().to_string(), theme.good()),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Enter: use this  ·  r: re-roll  ·  Esc: back",
        theme.muted(),
    )));

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add_state() -> EditState {
        EditState::new_add(Uuid::nil())
    }

    #[test]
    fn fields_for_credential_add_include_kind_and_password() {
        let state = add_state();
        let fields = state.fields();
        assert_eq!(fields.first(), Some(&EditField::Kind));
        assert!(fields.contains(&EditField::Password));
        assert!(fields.contains(&EditField::Title));
        assert!(fields.contains(&EditField::CustomAdd));
    }

    #[test]
    fn secure_note_has_no_username_or_password_fields() {
        let mut state = add_state();
        state.kind = EntryKind::SecureNote;
        let fields = state.fields();
        assert!(!fields.contains(&EditField::Username));
        assert!(!fields.contains(&EditField::Password));
        assert!(!fields.contains(&EditField::Url));
    }

    #[test]
    fn totp_add_has_uri_but_no_password() {
        let mut state = add_state();
        state.kind = EntryKind::Totp;
        let fields = state.fields();
        assert!(fields.contains(&EditField::TotpUri));
        assert!(!fields.contains(&EditField::Password));
    }

    #[test]
    fn cycle_kind_walks_all_three_and_back() {
        let mut state = add_state();
        assert_eq!(state.kind, EntryKind::Credential);
        state.cycle_kind();
        assert_eq!(state.kind, EntryKind::SecureNote);
        state.cycle_kind();
        assert_eq!(state.kind, EntryKind::Totp);
        state.cycle_kind();
        assert_eq!(state.kind, EntryKind::Credential);
    }

    #[test]
    fn focus_next_prev_wrap() {
        let mut state = add_state();
        let len = state.fields().len();
        state.focus = len - 1;
        state.focus_next();
        assert_eq!(state.focus, 0, "wraps to start");
        state.focus_prev();
        assert_eq!(state.focus, len - 1, "wraps to end");
    }

    #[test]
    fn snapshot_requires_title() {
        let state = add_state();
        assert!(state.snapshot().is_err(), "empty title rejected");
    }

    #[test]
    fn snapshot_collects_fields_and_tags() {
        let mut state = add_state();
        state.title = Input::new("GitHub".to_string());
        state.username = Input::new("octocat".to_string());
        state.password.set_value("hunter2");
        state.url = Input::new("https://github.com".to_string());
        state.tags = Input::new("work, dev work".to_string());
        let values = state.snapshot().expect("valid");
        assert_eq!(values.title, "GitHub");
        assert_eq!(values.username, "octocat");
        assert_eq!(&*values.password, "hunter2");
        // "work" deduped, "dev" kept.
        assert_eq!(values.tags.len(), 2);
    }

    #[test]
    fn add_and_remove_custom_rows() {
        let mut state = add_state();
        state.add_custom_row();
        assert_eq!(state.custom.len(), 1);
        assert!(matches!(state.focused(), EditField::Custom(0, Col::Name)));
        state.remove_custom_row(0);
        assert_eq!(state.custom.len(), 0);
    }

    #[test]
    fn snapshot_skips_empty_named_custom_and_flags_removed() {
        let mut state = add_state();
        state.title = Input::new("X".to_string());
        // Simulate an edit that had an original custom field "API".
        state.original_custom = vec!["API".to_string()];
        // The user cleared its name (empty) → it is removed, not written.
        state.custom.push(CustomRow {
            name: Input::default(),
            value: PasswordInput::with_value("leftover"),
            protected: false,
        });
        let values = state.snapshot().expect("valid");
        assert!(values.custom.is_empty(), "empty-named row dropped");
        assert_eq!(values.removed_custom, vec!["API".to_string()]);
    }

    // PMF-1 (T1.5): the otpauth URI and custom-field value buffers are
    // `Zeroizing`-backed (via `PasswordInput`) and wipe their bytes — mirroring
    // `password_input::buffer_zeroizes_its_bytes` (zeroize-then-volatile-read
    // while still allocated; drop-then-read is flaky on macOS).
    #[cfg(test)]
    #[allow(unsafe_code)] // documented volatile-read zeroize verification
    #[test]
    fn totp_and_custom_value_buffers_zeroize() {
        let mut state = EditState::new_add(Uuid::nil());
        // otpauth URI carries the secret seed.
        for c in "otpauth://totp/X?secret=JBSWY3DPEHPK3PXP".chars() {
            state.totp_uri.on_key(&crossterm::event::KeyEvent::new(
                crossterm::event::KeyCode::Char(c),
                crossterm::event::KeyModifiers::NONE,
            ));
        }
        // A custom-field value (may hold key material).
        state.add_custom_row();
        for c in "super-secret-pin".chars() {
            state.custom[0]
                .value
                .on_key(&crossterm::event::KeyEvent::new(
                    crossterm::event::KeyCode::Char(c),
                    crossterm::event::KeyModifiers::NONE,
                ));
        }

        for buf in [&mut state.totp_uri, &mut state.custom[0].value] {
            let (ptr, len) = buf.zeroize_and_expose();
            assert!(len > 0, "buffer should hold typed bytes before zeroize");
            for i in 0..len {
                // SAFETY: the buffer is still allocated (only zeroized, not
                // dropped); `ptr`/`len` came from the live buffer.
                let byte = unsafe { std::ptr::read_volatile(ptr.add(i)) };
                assert_eq!(byte, 0, "secret byte at offset {i} not zeroed");
            }
        }
    }

    #[test]
    fn snapshot_rejects_reserved_otp_custom_name() {
        let mut state = add_state();
        state.title = Input::new("X".to_string());
        state.custom.push(CustomRow {
            name: Input::new("otp".to_string()),
            value: PasswordInput::with_value("secret"),
            protected: false,
        });
        assert!(state.snapshot().is_err());
    }
}
