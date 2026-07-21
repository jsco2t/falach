//! `secrets` — the Secrets-tab body: a breadcrumb header (T2.4) + the entry tree
//! (left, configured 20–60%) + the scrollable detail pane (right). Composed inside the
//! workspace's body area (the tab bar and status bar are drawn by `workspace`).
//! Key handling lives on `App` (`on_secrets_key`); this module only renders.

use std::time::Instant;

use chrono::Utc;
use falach_core::{Uuid, Vault};
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use unicode_width::UnicodeWidthStr;

use crate::app::{App, MouseTarget};
use crate::user_config::{TREE_RATIO_MAX, TREE_RATIO_MIN};
use crate::widgets::{entry_detail, entry_tree};

/// Separator between breadcrumb components.
const CRUMB_SEP: &str = " › ";

/// Render the Secrets tab into `area`. `_now` (monotonic) is unused here — the
/// expired affordance and TOTP need wall-clock time, taken from `Utc::now()`.
pub(crate) fn render(app: &App, frame: &mut Frame, area: Rect, _now: Instant) {
    let Some(vault) = app.vault.as_ref() else {
        // Unreachable in `Phase::Workspace`, but render defensively rather than
        // panic in a draw closure.
        frame.render_widget(Paragraph::new("No vault open."), area);
        return;
    };

    // Breadcrumb header (T2.4) above the tree/detail split, with the visual-mode
    // selection indicator right-aligned on the same line (T4.5).
    let [crumb_area, body_area] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(area);
    if let Some(indicator) = app.selection_indicator() {
        let ind_cols = u16::try_from(indicator.width()).unwrap_or(u16::MAX);
        let ind_width = ind_cols.saturating_add(1).min(crumb_area.width);
        let [crumb_left, ind_area] =
            Layout::horizontal([Constraint::Min(1), Constraint::Length(ind_width)])
                .areas(crumb_area);
        let crumb = build_breadcrumb(app, crumb_left.width as usize);
        frame.render_widget(Paragraph::new(crumb).style(app.theme.muted()), crumb_left);
        frame.render_widget(
            Paragraph::new(indicator)
                .style(Style::default().add_modifier(Modifier::REVERSED))
                .alignment(Alignment::Right),
            ind_area,
        );
    } else {
        let crumb = build_breadcrumb(app, crumb_area.width as usize);
        frame.render_widget(Paragraph::new(crumb).style(app.theme.muted()), crumb_area);
    }

    let now = Utc::now();
    let rows = entry_tree::build_rows(vault, &app.tree, &app.recents);

    let [tree_area, detail_area] = split_panes(body_area, app.tree_ratio());

    let items = entry_tree::tree_items(&rows, vault, now, &app.marks, &app.theme);
    let selected = app.tree.selected_index(&rows);
    let offset = entry_tree::render_tree(
        items,
        selected,
        app.focus == crate::app::Focus::Tree,
        frame,
        tree_area,
        &app.theme,
    );
    let viewport = usize::from(tree_area.height.saturating_sub(2));
    for (visible, absolute) in (offset..rows.len()).take(viewport).enumerate() {
        app.register_mouse_target(
            Rect::new(
                tree_area.x.saturating_add(1),
                tree_area
                    .y
                    .saturating_add(1 + u16::try_from(visible).unwrap_or(u16::MAX)),
                tree_area.width.saturating_sub(2),
                1,
            ),
            MouseTarget::TreeRow(absolute),
        );
    }
    app.register_mouse_target(detail_area, MouseTarget::DetailPane);
    entry_detail::render_detail(app, frame, detail_area, now);
}

pub(crate) fn split_panes(area: Rect, tree_ratio: u8) -> [Rect; 2] {
    Layout::horizontal([
        Constraint::Percentage(u16::from(tree_ratio.clamp(TREE_RATIO_MIN, TREE_RATIO_MAX))),
        Constraint::Min(1),
    ])
    .areas(area)
}

/// The breadcrumb string for the current selection: `vault › Group › … › Entry`,
/// middle-truncated to `width` columns (keeping the first and last components).
/// Pure over `App` so it is unit-testable. The ancestor chain is resolved from
/// the vault hierarchy rather than the visible flattened rows: search can select
/// an entry inside a collapsed group, and its breadcrumb must remain complete.
pub(crate) fn build_breadcrumb(app: &App, width: usize) -> String {
    let vault_name = app.selected_vault.as_deref().unwrap_or("vault");
    let mut parts: Vec<String> = vec![vault_name.to_string()];

    if let (Some(vault), Some(sel)) = (app.vault.as_ref(), app.tree.selected()) {
        if let Some(path) = node_path(vault, vault.root_group_uuid(), sel) {
            parts.extend(path.into_iter().map(|uuid| node_name(vault, uuid)));
        }
    }

    middle_truncate(&parts, width)
}

/// Find `target` below `group_uuid`, returning its root-relative UUID path. The
/// vault root itself is omitted because the registered vault display name is the
/// breadcrumb's first component.
pub(crate) fn node_path(vault: &Vault, group_uuid: Uuid, target: Uuid) -> Option<Vec<Uuid>> {
    let group = vault.group_view(group_uuid).ok()?;
    if group.entry_uuids().contains(&target) {
        return Some(vec![target]);
    }
    for child in group.child_group_uuids() {
        if child == target {
            return Some(vec![child]);
        }
        if let Some(mut tail) = node_path(vault, child, target) {
            let mut path = Vec::with_capacity(tail.len() + 1);
            path.push(child);
            path.append(&mut tail);
            return Some(path);
        }
    }
    None
}

/// The display name of a tree node: a group's name, else an entry's title.
fn node_name(vault: &Vault, uuid: Uuid) -> String {
    if let Ok(group) = vault.group_view(uuid) {
        return group.name().to_string();
    }
    vault.get_entry(uuid).ok().map_or_else(
        || "(entry)".to_string(),
        |e| {
            let t = e.title();
            if t.is_empty() {
                "(untitled)".to_string()
            } else {
                t.to_string()
            }
        },
    )
}

/// Join `parts` with ` › `, eliding the middle with `…` when necessary. If the
/// elided form is still too wide, split the remaining budget between truncated
/// first and last components so the selected node is never discarded.
fn middle_truncate(parts: &[String], width: usize) -> String {
    if parts.is_empty() || width == 0 {
        return String::new();
    }
    let full = parts.join(CRUMB_SEP);
    if full.width() <= width || parts.len() == 1 {
        return truncate_cols(&full, width);
    }
    let divider = if parts.len() > 2 {
        format!("{CRUMB_SEP}…{CRUMB_SEP}")
    } else {
        CRUMB_SEP.to_string()
    };
    let first = &parts[0];
    let last = &parts[parts.len() - 1];
    let elided = format!("{first}{divider}{last}");
    if elided.width() <= width {
        return elided;
    }
    // Tighten only the separator spacing before truncating either endpoint.
    let divider = if parts.len() > 2 {
        " ›…› ".to_string()
    } else {
        divider
    };
    let divider_width = divider.width();
    if width <= divider_width + 1 {
        return truncate_cols(last, width);
    }
    let component_budget = width - divider_width;
    let first_min = first.chars().next().map_or(0, |c| c.to_string().width());
    let last_min = last
        .chars()
        .next_back()
        .map_or(0, |c| c.to_string().width());
    if first_min + last_min > component_budget {
        return truncate_cols(last, width);
    }
    let flexible = component_budget - first_min - last_min;
    let first_budget = first_min + flexible / 2;
    let last_budget = last_min + flexible - flexible / 2;
    format!(
        "{}{divider}{}",
        truncate_cols(first, first_budget),
        truncate_cols_from_end(last, last_budget)
    )
}

#[cfg(test)]
mod layout_tests {
    use super::*;

    #[test]
    fn configured_tree_ratio_changes_pane_geometry() {
        let area = Rect::new(0, 0, 100, 20);
        assert_eq!(split_panes(area, 20)[0].width, 20);
        assert_eq!(split_panes(area, 60)[0].width, 60);
    }
}

/// The longest prefix of `s` whose display width is ≤ `width` (char-aligned).
fn truncate_cols(s: &str, width: usize) -> String {
    if s.width() <= width {
        return s.to_string();
    }
    let mut out = String::new();
    let mut used = 0usize;
    for c in s.chars() {
        let w = c.to_string().width();
        if used + w > width {
            break;
        }
        out.push(c);
        used += w;
    }
    out
}

/// The longest suffix of `s` whose display width is ≤ `width` (char-aligned).
fn truncate_cols_from_end(s: &str, width: usize) -> String {
    let mut chars = Vec::new();
    let mut used = 0usize;
    for c in s.chars().rev() {
        let w = c.to_string().width();
        if used + w > width {
            break;
        }
        chars.push(c);
        used += w;
    }
    chars.into_iter().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn middle_truncate_root_entry_no_elision() {
        // A top-level entry: `vault › Entry` — nothing to elide.
        let parts = vec!["vault".to_string(), "GitHub".to_string()];
        assert_eq!(middle_truncate(&parts, 80), "vault › GitHub");
    }

    #[test]
    fn middle_truncate_elides_the_middle_when_narrow() {
        // A 3-deep selection, too wide → keep the ends, elide the middle.
        let parts = vec![
            "personal".to_string(),
            "Work".to_string(),
            "Cloud".to_string(),
            "AWS root key".to_string(),
        ];
        // Wide: the full path fits.
        assert_eq!(
            middle_truncate(&parts, 80),
            "personal › Work › Cloud › AWS root key"
        );
        // Narrow: middle elided to `first › … › last`.
        assert_eq!(middle_truncate(&parts, 30), "personal › … › AWS root key");
    }

    #[test]
    fn middle_truncate_never_panics_at_tiny_width() {
        let parts = vec![
            "personal".to_string(),
            "Work".to_string(),
            "AWS root key".to_string(),
        ];
        // Width 10 forces a hard truncation of the elided form; no panic, ≤ width.
        let out = middle_truncate(&parts, 10);
        assert!(out.width() <= 10, "breadcrumb fits width 10: {out:?}");
        assert!(out.starts_with('p'), "retains the vault endpoint: {out:?}");
        assert!(
            out.ends_with("key"),
            "retains the selected endpoint: {out:?}"
        );
    }

    #[test]
    fn two_component_overflow_retains_both_endpoints() {
        let parts = vec!["personal".to_string(), "AWS root key".to_string()];
        let out = middle_truncate(&parts, 10);
        assert!(out.width() <= 10);
        assert!(out.starts_with("per"), "vault remains visible: {out:?}");
        assert!(
            out.ends_with("key"),
            "selected entry remains visible: {out:?}"
        );
    }

    #[test]
    fn tight_unicode_breadcrumb_retains_wide_endpoints_when_they_fit() {
        let parts = vec!["個人".to_string(), "秘密🔑".to_string()];
        let out = middle_truncate(&parts, 9);
        assert!(out.width() <= 9, "wide breadcrumb fits: {out:?}");
        assert!(
            out.starts_with('個'),
            "wide vault endpoint remains: {out:?}"
        );
        assert!(
            out.ends_with('🔑'),
            "wide selected endpoint remains: {out:?}"
        );
    }
}
