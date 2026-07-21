//! `TabBar` — the persistent tabbed-workspace navigation (ADR-T1 / U.2).
//!
//! Tab 0 is **Secrets**, the last tab is **Settings**, and any tabs in between
//! are **pinned secrets** (≤5; populated in Phase 4 — `pinned` is empty until
//! then). Navigation is the OQ-N1 portable scheme: `gt`/`gT`/`{count}gt` vim
//! motions + `Alt+1..9` direct jumps (the sequence dispatch lives on `App`).
//!
//! Rendering (OQ-N6): Secrets + Settings are fixed anchors (never truncated);
//! pinned labels shrink first via width-correct middle-ellipsis; when even
//! floored labels won't fit, the strip falls back to bare ordinals and the
//! active tab's full title moves to the status bar. The active tab carries a
//! **text** affordance (brackets), never colour alone (NFR-015).

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use unicode_width::UnicodeWidthStr;
use uuid::Uuid;

use crate::theme::Theme;

/// The fixed labels for the two anchor tabs.
const SECRETS_LABEL: &str = "Secrets";
const SETTINGS_LABEL: &str = "Settings";
/// Separator drawn between tab labels.
const SEP: &str = " │ ";
/// Minimum display width a pinned label is shrunk to before the strip gives up
/// and falls back to bare ordinals.
const PIN_LABEL_FLOOR: usize = 8;

/// Maximum simultaneously pinned tabs (D-7). A 6th pin evicts the
/// least-recently-activated existing pin.
pub(crate) const MAX_PINS: usize = 5;

/// A resolved tab (computed from an ordinal, never stored).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tab {
    Secrets,
    Pinned(Uuid),
    Settings,
}

/// The outcome of a [`TabBar::toggle_pin`] call, so the caller can post the
/// right status note (D-7) and persist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinChange {
    /// The entry was pinned; no eviction was needed.
    Pinned,
    /// The entry was pinned, evicting the carried (least-recently-activated)
    /// pin to stay within [`MAX_PINS`].
    PinnedEvicting(Uuid),
    /// The entry was already pinned and is now unpinned.
    Unpinned,
}

/// Ordered tabs + the active index. `pinned` holds the pinned entries' UUIDs in
/// display (left-to-right) order; `activation` tracks pin-tab activation recency
/// (front = most-recently-activated) so eviction can drop the least-recently-
/// activated pin (ADR-T7 / D-7).
pub(crate) struct TabBar {
    /// 0 = Secrets; `1..=pinned.len()` = pinned; `pinned.len()+1` = Settings.
    active: usize,
    pinned: Vec<Uuid>,
    /// Pinned UUIDs by activation recency, most-recent first. Always the same
    /// set as `pinned`; only the ordering differs.
    activation: Vec<Uuid>,
}

impl TabBar {
    pub(crate) fn new() -> Self {
        Self {
            active: 0,
            pinned: Vec::new(),
            activation: Vec::new(),
        }
    }

    /// Hydrate from a persisted pin list (T4.4; `tui.toml`). The activation MRU
    /// is seeded so the leftmost (oldest) pin is the first eviction victim until
    /// the user activates a pin tab. De-duplicated (first occurrence wins) and
    /// truncated to [`MAX_PINS`] defensively, in case a hand-edited config
    /// repeats a UUID or exceeds the cap — mirroring `Recents::from_persisted`.
    pub(crate) fn with_pins(pinned: Vec<Uuid>) -> Self {
        let mut deduped: Vec<Uuid> = Vec::with_capacity(pinned.len().min(MAX_PINS));
        for uuid in pinned {
            if !deduped.contains(&uuid) {
                deduped.push(uuid);
                if deduped.len() == MAX_PINS {
                    break;
                }
            }
        }
        let pinned = deduped;
        // Front = most-recent; seed so `pinned[0]` is least-recent (back).
        let activation = pinned.iter().rev().copied().collect();
        Self {
            active: 0,
            pinned,
            activation,
        }
    }

    /// Total tab count: Secrets + pins + Settings.
    pub(crate) fn count(&self) -> usize {
        self.pinned.len() + 2
    }

    /// The active ordinal index. Test-only observation for now; production
    /// reads [`TabBar::active_tab`]. (Phase 4 surfaces the active title in the
    /// status bar under the bare-ordinal fallback and will promote this.)
    #[cfg(test)]
    pub(crate) fn active_index(&self) -> usize {
        self.active
    }

    /// Resolve an ordinal index to a [`Tab`]. `None` if out of range.
    pub(crate) fn resolve(&self, index: usize) -> Option<Tab> {
        if index == 0 {
            Some(Tab::Secrets)
        } else if index <= self.pinned.len() {
            Some(Tab::Pinned(self.pinned[index - 1]))
        } else if index == self.pinned.len() + 1 {
            Some(Tab::Settings)
        } else {
            None
        }
    }

    pub(crate) fn active_tab(&self) -> Tab {
        self.resolve(self.active)
            .expect("active index is always in range")
    }

    /// `gt` — next tab, wrapping.
    pub(crate) fn next(&mut self) {
        self.active = (self.active + 1) % self.count();
        self.record_activation();
    }

    /// `gT` — previous tab, wrapping.
    pub(crate) fn prev(&mut self) {
        let count = self.count();
        self.active = (self.active + count - 1) % count;
        self.record_activation();
    }

    /// `{count}gt` / `Alt+N` — jump to 1-based ordinal `n`. Out-of-range is a
    /// no-op (the user can't reach a tab that isn't there).
    pub(crate) fn jump_to(&mut self, n: usize) {
        if (1..=self.count()).contains(&n) {
            self.active = n - 1;
            self.record_activation();
        }
    }

    /// The pinned entries' UUIDs in display order (for label computation).
    pub(crate) fn pins(&self) -> &[Uuid] {
        &self.pinned
    }

    /// Whether `uuid` is currently pinned. Used by the delete path to unpin a
    /// removed entry's tab.
    pub(crate) fn is_pinned(&self, uuid: Uuid) -> bool {
        self.pinned.contains(&uuid)
    }

    /// Toggle the pin on `uuid` (the `p` key; D-7). Pinning a 6th entry evicts
    /// the least-recently-activated existing pin. Returns what happened so the
    /// caller can post a status note and persist. A freshly pinned entry counts
    /// as activated (seeded at the front of the MRU) so it is never its own
    /// immediate eviction victim.
    pub(crate) fn toggle_pin(&mut self, uuid: Uuid) -> PinChange {
        if self.pinned.contains(&uuid) {
            self.pinned.retain(|&u| u != uuid);
            self.activation.retain(|&u| u != uuid);
            self.clamp_active();
            return PinChange::Unpinned;
        }

        let evicted = if self.pinned.len() >= MAX_PINS {
            // Least-recently-activated = back of the MRU.
            let victim = self.activation.last().copied();
            if let Some(v) = victim {
                self.pinned.retain(|&u| u != v);
                self.activation.retain(|&u| u != v);
            }
            victim
        } else {
            None
        };

        self.pinned.push(uuid);
        self.activation.insert(0, uuid);
        self.clamp_active();

        match evicted {
            Some(v) => PinChange::PinnedEvicting(v),
            None => PinChange::Pinned,
        }
    }

    /// If the active tab is a pinned tab, mark its entry most-recently-activated.
    fn record_activation(&mut self) {
        if let Tab::Pinned(uuid) = self.active_tab() {
            self.activation.retain(|&u| u != uuid);
            self.activation.insert(0, uuid);
        }
    }

    /// Keep `active` in range after the tab set shrinks or grows.
    fn clamp_active(&mut self) {
        let max = self.count() - 1; // count() ≥ 2 (Secrets + Settings)
        if self.active > max {
            self.active = max;
        }
    }

    /// Render the tab strip into `area`. `pin_titles` supplies the display
    /// title for each pinned tab (same order as `pinned`); empty in Phase 2.
    pub(crate) fn render(
        &self,
        pin_titles: &[String],
        frame: &mut Frame,
        area: Rect,
        theme: &Theme,
    ) {
        let labels = self.styled_labels(pin_titles, area.width as usize, theme);
        frame.render_widget(Paragraph::new(Line::from(labels)), area);
    }

    /// Exact rectangles occupied by each rendered tab label. Separators are
    /// intentionally not clickable, preventing a click in blank/tab-divider
    /// space from selecting an unrelated tab.
    pub(crate) fn hit_regions(&self, pin_titles: &[String], area: Rect) -> Vec<(Rect, usize)> {
        let (labels, separator) = self.layout_parts(pin_titles, area.width as usize);
        let separator_width = u16::try_from(separator.width()).unwrap_or(u16::MAX);
        let mut x = area.x;
        labels
            .into_iter()
            .enumerate()
            .map(|(index, (label, _))| {
                if index > 0 {
                    x = x.saturating_add(separator_width);
                }
                let width = u16::try_from(label.width()).unwrap_or(u16::MAX);
                let rect = Rect::new(x, area.y, width.min(area.right().saturating_sub(x)), 1);
                x = x.saturating_add(width);
                (rect, index)
            })
            .collect()
    }

    fn styled_labels(
        &self,
        pin_titles: &[String],
        avail: usize,
        theme: &Theme,
    ) -> Vec<Span<'static>> {
        let (labels, separator) = self.layout_parts(pin_titles, avail);
        labels
            .into_iter()
            .enumerate()
            .flat_map(|(i, (label, active))| {
                let mut spans = Vec::with_capacity(2);
                if i > 0 {
                    spans.push(Span::styled(separator.to_string(), theme.muted()));
                }
                let style = if active {
                    theme.tab_active()
                } else {
                    theme.tab_inactive()
                };
                spans.push(Span::styled(label, style));
                spans
            })
            .collect()
    }

    /// Build the tab-strip text for a given available width (pure, testable).
    #[cfg(test)]
    fn lay_out(&self, pin_titles: &[String], avail: usize) -> String {
        let (labels, separator) = self.layout_parts(pin_titles, avail);
        labels
            .into_iter()
            .map(|(label, _active)| label)
            .collect::<Vec<_>>()
            .join(separator)
    }

    fn layout_parts(
        &self,
        pin_titles: &[String],
        avail: usize,
    ) -> (Vec<(String, bool)>, &'static str) {
        // Full labels, with the active one bracketed (the text affordance).
        let labels = self.labels(pin_titles, str::to_string);
        if width_of(&labels) <= avail {
            return (self.with_active(labels), SEP);
        }

        // Overflow: shrink pinned labels to the floor (anchors never shrink).
        let shrunk = self.labels(pin_titles, |title| middle_ellipsis(title, PIN_LABEL_FLOOR));
        if width_of(&shrunk) <= avail {
            return (self.with_active(shrunk), SEP);
        }

        // Still won't fit: bare ordinals. The active title is surfaced by the
        // status bar (see `App` / status_bar); here every tab stays addressable.
        let labels = (0..self.count())
            .map(|i| {
                let n = i + 1;
                if i == self.active {
                    format!("[{n}]")
                } else {
                    n.to_string()
                }
            })
            .collect::<Vec<_>>();
        (self.with_active(labels), " ")
    }

    fn with_active(&self, labels: Vec<String>) -> Vec<(String, bool)> {
        labels
            .into_iter()
            .enumerate()
            .map(|(index, label)| (label, index == self.active))
            .collect()
    }

    /// The ordered labels (Secrets, pins…, Settings), each prefixed with its
    /// 1-based jump ordinal (`1:Secrets`, `2:…`; the number `Alt+N` / `{count}gt`
    /// jumps to — T2.4 self-hinting tabs) and the active tab bracketed.
    /// `pin_label` maps a raw pin title to its (possibly shrunk) display form.
    fn labels(&self, pin_titles: &[String], pin_label: impl Fn(&str) -> String) -> Vec<String> {
        let mut out = Vec::with_capacity(self.count());
        out.push(SECRETS_LABEL.to_string());
        for (i, _uuid) in self.pinned.iter().enumerate() {
            let title = pin_titles.get(i).map_or("(pinned)", String::as_str);
            out.push(pin_label(title));
        }
        out.push(SETTINGS_LABEL.to_string());
        // Ordinal prefix first, then bracket the active tab → `[1:Secrets]`.
        for (i, label) in out.iter_mut().enumerate() {
            *label = format!("{}:{label}", i + 1);
            if i == self.active {
                *label = format!("[{label}]");
            }
        }
        out
    }

    #[cfg(test)]
    pub(crate) fn set_pins_for_test(&mut self, pins: Vec<Uuid>) {
        self.activation = pins.iter().rev().copied().collect();
        self.pinned = pins;
    }
}

/// Total display width of `labels` joined by [`SEP`].
fn width_of(labels: &[String]) -> usize {
    let content: usize = labels.iter().map(|s| s.width()).sum();
    let separators = labels.len().saturating_sub(1) * SEP.width();
    content + separators
}

/// Truncate `s` to at most `max_width` display columns, keeping the head and
/// tail with a `…` in the middle. Width-correct (CJK/emoji count as their real
/// column width) and never splits a character.
fn middle_ellipsis(s: &str, max_width: usize) -> String {
    if s.width() <= max_width {
        return s.to_string();
    }
    if max_width <= 1 {
        return "…".to_string();
    }
    // Budget one column for the ellipsis; split the rest head/tail.
    let budget = max_width - 1;
    let head_budget = budget.div_ceil(2);
    let tail_budget = budget - head_budget;

    let head = take_width_prefix(s, head_budget);
    let tail = take_width_suffix(s, tail_budget);
    format!("{head}…{tail}")
}

/// Longest prefix of `s` whose display width is ≤ `budget`.
fn take_width_prefix(s: &str, budget: usize) -> String {
    let mut out = String::new();
    let mut used = 0;
    for c in s.chars() {
        let w = c.to_string().width();
        if used + w > budget {
            break;
        }
        out.push(c);
        used += w;
    }
    out
}

/// Longest suffix of `s` whose display width is ≤ `budget`.
fn take_width_suffix(s: &str, budget: usize) -> String {
    let mut chars: Vec<char> = Vec::new();
    let mut used = 0;
    for c in s.chars().rev() {
        let w = c.to_string().width();
        if used + w > budget {
            break;
        }
        chars.push(c);
        used += w;
    }
    chars.iter().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::{ThemeDef, Tier};

    fn uuids(n: usize) -> Vec<Uuid> {
        (0..n).map(|_| Uuid::new_v4()).collect()
    }

    #[test]
    fn resolution_maps_ordinals_to_tabs() {
        let mut bar = TabBar::new();
        let pins = uuids(2);
        bar.set_pins_for_test(pins.clone());
        assert_eq!(bar.count(), 4); // Secrets + 2 pins + Settings
        assert_eq!(bar.resolve(0), Some(Tab::Secrets));
        assert_eq!(bar.resolve(1), Some(Tab::Pinned(pins[0])));
        assert_eq!(bar.resolve(2), Some(Tab::Pinned(pins[1])));
        assert_eq!(bar.resolve(3), Some(Tab::Settings));
        assert_eq!(bar.resolve(4), None);
    }

    #[test]
    fn phase2_has_only_secrets_and_settings() {
        let bar = TabBar::new();
        assert_eq!(bar.count(), 2);
        assert_eq!(bar.resolve(0), Some(Tab::Secrets));
        assert_eq!(bar.resolve(1), Some(Tab::Settings));
        assert_eq!(bar.active_tab(), Tab::Secrets);
    }

    #[test]
    fn next_and_prev_wrap() {
        let mut bar = TabBar::new(); // 2 tabs
        assert_eq!(bar.active_index(), 0);
        bar.next();
        assert_eq!(bar.active_index(), 1);
        bar.next(); // wraps
        assert_eq!(bar.active_index(), 0);
        bar.prev(); // wraps backwards
        assert_eq!(bar.active_index(), 1);
    }

    #[test]
    fn jump_to_is_one_based_and_clamps() {
        let mut bar = TabBar::new();
        bar.set_pins_for_test(uuids(2)); // 4 tabs
        bar.jump_to(1);
        assert_eq!(bar.active_index(), 0); // Secrets
        bar.jump_to(4);
        assert_eq!(bar.active_index(), 3); // Settings
        bar.jump_to(0); // out of range — no-op
        assert_eq!(bar.active_index(), 3);
        bar.jump_to(99); // out of range — no-op
        assert_eq!(bar.active_index(), 3);
    }

    #[test]
    fn strip_renders_anchors_with_active_bracketed() {
        let bar = TabBar::new();
        let strip = bar.lay_out(&[], 80);
        // Ordinal-prefixed (T2.4), active tab bracketed.
        assert_eq!(strip, "[1:Secrets] │ 2:Settings");
    }

    #[test]
    fn labels_carry_jump_ordinals() {
        // Each label is prefixed with the 1-based ordinal `Alt+N`/`{count}gt`
        // jumps to (self-hinting tabs — T2.4).
        let mut bar = TabBar::new();
        bar.set_pins_for_test(uuids(2)); // 4 tabs: Secrets, 2 pins, Settings
        let titles = vec!["one".to_string(), "two".to_string()];
        let strip = bar.lay_out(&titles, 80);
        for (i, name) in ["Secrets", "one", "two", "Settings"].iter().enumerate() {
            assert!(
                strip.contains(&format!("{}:{name}", i + 1)),
                "tab {name} carries ordinal {}: {strip}",
                i + 1
            );
        }
    }

    #[test]
    fn separator_inside_pinned_title_does_not_create_a_pseudo_tab() {
        let mut tabs = TabBar::new();
        tabs.set_pins_for_test(vec![Uuid::new_v4()]);
        let (labels, separator) = tabs.layout_parts(&[format!("left{SEP}right")], 200);
        assert_eq!(separator, SEP);
        assert_eq!(labels.len(), tabs.count());
        assert!(labels[1].0.contains(SEP));
    }

    #[test]
    fn tab_renderer_adopts_active_and_inactive_slots() {
        let theme = ThemeDef::builtin("default-dark")
            .unwrap()
            .theme_for_tier(Tier::TrueColor);
        let tabs = TabBar::new();
        let spans = tabs.styled_labels(&[], 100, &theme);
        let label_spans = spans
            .iter()
            .filter(|span| span.content.as_ref() != SEP)
            .collect::<Vec<_>>();
        assert_eq!(label_spans[0].style, theme.tab_active());
        assert_eq!(label_spans[1].style, theme.tab_inactive());
    }

    #[test]
    fn strip_shrinks_pins_before_anchors() {
        let mut bar = TabBar::new();
        bar.set_pins_for_test(uuids(1));
        let titles = vec!["a-very-long-pinned-entry-title".to_string()];
        // Width 40: the full strip (~53 cols) doesn't fit, but the shrunk one
        // (~31 cols) does — so the pin is ellipsized rather than dropped to a
        // bare ordinal.
        let strip = bar.lay_out(&titles, 40);
        assert!(strip.contains("Secrets"), "anchor never truncated: {strip}");
        assert!(
            strip.contains("Settings"),
            "anchor never truncated: {strip}"
        );
        assert!(
            strip.contains('…'),
            "long pin label is middle-ellipsized: {strip}"
        );
    }

    #[test]
    fn strip_falls_back_to_bare_ordinals_when_too_narrow() {
        let mut bar = TabBar::new();
        bar.set_pins_for_test(uuids(3));
        let titles = vec![
            "alpha-entry".to_string(),
            "beta-entry".to_string(),
            "gamma-entry".to_string(),
        ];
        bar.jump_to(2); // active = ordinal 2 (index 1)
        let strip = bar.lay_out(&titles, 10);
        assert_eq!(
            strip, "1 [2] 3 4 5",
            "narrow strip → bare ordinals, active bracketed"
        );
    }

    #[test]
    fn toggle_pin_adds_and_removes() {
        let mut bar = TabBar::new();
        let ids = uuids(2);
        assert_eq!(bar.toggle_pin(ids[0]), PinChange::Pinned);
        assert!(bar.is_pinned(ids[0]));
        assert_eq!(bar.pins(), &[ids[0]]);
        assert_eq!(bar.count(), 3); // Secrets + 1 pin + Settings
                                    // Toggling the same entry unpins it.
        assert_eq!(bar.toggle_pin(ids[0]), PinChange::Unpinned);
        assert!(!bar.is_pinned(ids[0]));
        assert_eq!(bar.count(), 2);
    }

    #[test]
    fn sixth_pin_evicts_least_recently_activated() {
        let mut bar = TabBar::new();
        let ids = uuids(MAX_PINS + 1);
        for &id in &ids[..MAX_PINS] {
            assert_eq!(bar.toggle_pin(id), PinChange::Pinned);
        }
        assert_eq!(bar.pins().len(), MAX_PINS);
        // No pin tab was ever activated, so the leftmost (oldest) pin — ids[0] —
        // is the least-recently-activated and gets evicted (point-D degenerate
        // case).
        assert_eq!(
            bar.toggle_pin(ids[MAX_PINS]),
            PinChange::PinnedEvicting(ids[0])
        );
        assert!(!bar.is_pinned(ids[0]), "oldest pin evicted");
        assert!(bar.is_pinned(ids[MAX_PINS]), "new pin present");
        assert_eq!(bar.pins().len(), MAX_PINS);
    }

    #[test]
    fn sequential_evictions_keep_activation_and_pins_in_sync() {
        let mut bar = TabBar::new();
        let ids = uuids(MAX_PINS + 2);
        for &id in &ids[..MAX_PINS] {
            bar.toggle_pin(id);
        }
        // 6th pin (no activations yet): evicts the oldest, ids[0].
        assert_eq!(
            bar.toggle_pin(ids[MAX_PINS]),
            PinChange::PinnedEvicting(ids[0])
        );
        // 7th pin immediately, still no manual activation: the just-pinned 6th
        // was seeded at the MRU front, so it is NOT its own next victim — the
        // next-oldest survivor (ids[1]) is evicted instead. This only holds if
        // `toggle_pin` kept `activation` and `pinned` in sync across the first
        // eviction's mutation of both vectors.
        assert_eq!(
            bar.toggle_pin(ids[MAX_PINS + 1]),
            PinChange::PinnedEvicting(ids[1])
        );
        assert!(
            bar.is_pinned(ids[MAX_PINS]),
            "freshly pinned entry survives the next eviction"
        );
        assert!(bar.is_pinned(ids[MAX_PINS + 1]));
        assert_eq!(bar.pins().len(), MAX_PINS);
    }

    #[test]
    fn activating_a_pin_protects_it_from_eviction() {
        let mut bar = TabBar::new();
        let ids = uuids(MAX_PINS + 1);
        for &id in &ids[..MAX_PINS] {
            bar.toggle_pin(id);
        }
        // Activate the leftmost pin (ordinal 2 = first pin) — it is now the
        // most-recently-activated, so the *second*-oldest (ids[1]) is evicted.
        bar.jump_to(2);
        assert_eq!(
            bar.toggle_pin(ids[MAX_PINS]),
            PinChange::PinnedEvicting(ids[1])
        );
        assert!(bar.is_pinned(ids[0]), "recently-activated pin survived");
        assert!(!bar.is_pinned(ids[1]), "second-oldest evicted instead");
    }

    #[test]
    fn with_pins_hydrates_and_caps() {
        let ids = uuids(MAX_PINS + 2);
        let bar = TabBar::with_pins(ids.clone());
        assert_eq!(bar.pins().len(), MAX_PINS, "hydration caps at MAX_PINS");
        assert_eq!(bar.pins(), &ids[..MAX_PINS]);
    }

    #[test]
    fn with_pins_dedups_a_hand_edited_config() {
        let ids = uuids(2);
        // A hand-edited config repeating a UUID must not produce two tabs for
        // one entry.
        let bar = TabBar::with_pins(vec![ids[0], ids[1], ids[0]]);
        assert_eq!(bar.pins(), &[ids[0], ids[1]], "duplicate pin collapsed");
    }

    #[test]
    fn unpinning_clamps_active_into_range() {
        let mut bar = TabBar::new();
        let ids = uuids(2);
        bar.toggle_pin(ids[0]);
        bar.toggle_pin(ids[1]); // tabs: Secrets, p0, p1, Settings (count 4)
        bar.jump_to(4); // active = Settings (index 3)
        bar.toggle_pin(ids[0]); // unpin → count 3; active must clamp into range
        assert!(bar.active_index() < bar.count());
        // active_tab must still resolve (no panic).
        let _ = bar.active_tab();
    }

    #[test]
    fn middle_ellipsis_preserves_width_and_boundaries() {
        assert_eq!(middle_ellipsis("short", 10), "short");
        let e = middle_ellipsis("abcdefghijklmnop", 7);
        assert!(
            e.width() <= 7,
            "result within budget: {e:?} ({}w)",
            e.width()
        );
        assert!(e.contains('…'));
        // Wide chars are not split: a string of CJK chars stays char-aligned.
        let cjk = middle_ellipsis("一二三四五六七八", 5);
        assert!(
            cjk.width() <= 5,
            "CJK within budget: {cjk:?} ({}w)",
            cjk.width()
        );
        assert!(cjk
            .chars()
            .all(|c| c == '…' || "一二三四五六七八".contains(c)));
    }
}
