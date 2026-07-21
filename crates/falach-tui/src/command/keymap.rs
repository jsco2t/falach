//! Trigger → [`Command`] resolution: the keymap, presets, and the tab-motion
//! sequence/count state machine (design §2.2.2).
//!
//! [`Keymap`] maps `(context, trigger) → command`. It is built once from a
//! [`Preset`] (and, in T1.3, a user TOML patch over it). Three consumers read it:
//!
//! - **Per-context single-key dispatch** ([`Keymap::matches`]) — the workspace
//!   tab bodies ask "does this key fire command X here?" exactly as before.
//! - **The tab-motion resolver** ([`Keymap::resolve`]) — owns the `g`-prefix /
//!   `{count}` / `Alt+N` chord machine that used to live inline in `app.rs`.
//!   Returns the resolved motion, a pending-prefix continuation set (which-key,
//!   T2.2), or `None` (the key is not a tab motion — the caller dispatches it to
//!   the active tab body).
//! - **Key rendering** ([`Keymap::rendered_keys`], [`Keymap::triggers_for`]) —
//!   the command palette and (T2.1) the hint bar.
//!
//! Command *descriptions* live once in [`super::registry::COMMANDS`]; this module
//! carries triggers only.
//!
//! ## Trigger kinds
//!
//! - [`KeyTrigger::Key`] — a single key event (`j`, `Ctrl+Q`, `Alt+3`).
//! - [`KeyTrigger::Seq`] — a fixed multi-key motion (`g t`, `g T`). Max two keys
//!   (the grammar cap, T1.3).
//! - [`KeyTrigger::CountSeq`] — a sequence a `{count}` prefix applies to
//!   (`{count}g t` → jump to tab N). Shares its keys with a `Seq` command
//!   (`g t` is `NextTab` without a count, `JumpToTab` with one); the two are
//!   distinguished by trigger kind, never conflicting.
//!
//! Sequences own `Vec<KeyEvent>` rather than the `&'static [KeyEvent]` first
//! sketched in design §2.2.2 — `KeyEvent::new` is not a `const fn`, so a static
//! slice is not constructible; the map is built at runtime anyway.

use std::collections::BTreeMap;
use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde::{Deserialize, Serialize};

use super::registry::{spec_for, Command, CommandSpec, Contexts, COMMANDS};

/// How a command is triggered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeyTrigger {
    /// A single key event — resolvable by [`Keymap::matches`].
    Key(KeyEvent),
    /// A fixed multi-key motion (`g t`). Resolved by [`Keymap::resolve`].
    Seq(Vec<KeyEvent>),
    /// A `{count}`-prefixed sequence (`{count}g t`). Resolved by
    /// [`Keymap::resolve`] when a count prefix is pending.
    CountSeq(Vec<KeyEvent>),
}

/// A shipped keymap preset selected before any user patch (T3.1 wires the
/// config key). Vim is the default. Deserialized from `keymap.preset` as a
/// lowercase string (`"vim"` / `"plain"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Preset {
    Vim,
    /// Selected via the config key by T3.1; exercised by the preset tests now.
    #[cfg_attr(not(test), allow(dead_code))]
    Plain,
}

/// The outcome of feeding one key event to [`Keymap::resolve`].
pub(crate) enum Resolution {
    /// A tab motion fired: cycle (`NextTab`/`PrevTab`) or jump (`JumpToTab` with
    /// the 1-based ordinal).
    Command(Command, Option<u16>),
    /// A chord prefix is pending; the pairs are the possible next keys and the
    /// commands they would reach (which-key data, first rendered by T2.2 — the
    /// preset tests read it now). Empty while only a `{count}` digit run is
    /// pending (no menu — the count shows in the status bar).
    #[cfg_attr(not(test), allow(dead_code))]
    Pending(Vec<(KeyEvent, &'static CommandSpec)>),
    /// The key is not a tab motion; the caller dispatches it to the active tab.
    None,
}

/// Mutable chord state the caller (`App`) owns and threads through
/// [`Keymap::resolve`]. `resolve` is a pure transition function over
/// `(self, ctx, ev, this)` — no hidden state.
///
/// `since` records when the current chord prefix began; the caller stamps it on
/// the transition into a pending prefix so the which-key render delay (T2.2) is
/// a pure function of `(pending, now)`. `resolve` never reads it (`resolve`
/// stays clock-free).
#[derive(Debug, Default)]
pub(crate) struct PendingSeq {
    /// Keys typed so far in an in-progress sequence (e.g. `[g]` after `g`).
    pub prefix: Vec<KeyEvent>,
    /// Accumulated `{count}` prefix (e.g. `Some(12)` after `1`,`2`).
    pub count: Option<u16>,
    /// When the current prefix began (set by the caller on the empty→pending
    /// transition; the which-key delay measures against it). `None` when no
    /// prefix is pending.
    pub since: Option<Instant>,
}

impl PendingSeq {
    /// Clear all pending chord state.
    pub(crate) fn reset(&mut self) {
        self.prefix.clear();
        self.count = None;
        self.since = None;
    }
}

/// Is `cmd` one of the tab-navigation motions the resolver owns?
fn is_tab_command(cmd: Command) -> bool {
    matches!(
        cmd,
        Command::NextTab | Command::PrevTab | Command::JumpToTab
    )
}

/// The keymap: `(context, trigger, command)` rows, built from a preset.
#[derive(Debug, Clone)]
pub(crate) struct Keymap {
    map: Vec<(Contexts, KeyTrigger, Command)>,
}

/// Convenience: a `KeyEvent` for a plain character with no modifiers.
fn ch_ev(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}

/// Convenience: a `KeyTrigger::Key` for a plain character.
fn ch(c: char) -> KeyTrigger {
    KeyTrigger::Key(ch_ev(c))
}

/// Convenience: a `KeyTrigger::Key` for `Ctrl+<c>`.
fn ctrl(c: char) -> KeyTrigger {
    KeyTrigger::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL))
}

/// Convenience: a `KeyTrigger::Key` for `Alt+<c>`.
fn alt(c: char) -> KeyTrigger {
    KeyTrigger::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::ALT))
}

/// Convenience: a `KeyTrigger::Key` for a non-character key.
fn code(code: KeyCode) -> KeyTrigger {
    KeyTrigger::Key(KeyEvent::new(code, KeyModifiers::NONE))
}

/// Convenience: a `KeyTrigger::Key` for `Alt+<non-character key>` (the portable
/// jump-history aliases, `Alt+←`/`Alt+→`).
fn alt_code(code: KeyCode) -> KeyTrigger {
    KeyTrigger::Key(KeyEvent::new(code, KeyModifiers::ALT))
}

/// The `Alt+1..9` direct-jump bindings shared by both presets, expanded into
/// nine `Key` triggers so they render (collapsed) and rebind individually.
fn alt_digit_jumps() -> Vec<(Command, KeyTrigger)> {
    ('1'..='9').map(|d| (Command::JumpToTab, alt(d))).collect()
}

impl Keymap {
    /// Build a preset keymap. Each `(command, trigger)` pair is stored with the
    /// command's declared [`Contexts`] (from the registry), so a command is
    /// resolvable exactly where it is available.
    pub(crate) fn preset(preset: Preset) -> Self {
        let mut pairs: Vec<(Command, KeyTrigger)> = vec![
            // Global
            (Command::Quit, ctrl('q')),
            (Command::LockNow, ctrl('l')),
            (Command::Help, ch('?')),
            (Command::Cancel, code(KeyCode::Esc)),
            (Command::Confirm, code(KeyCode::Enter)),
            // Navigation — vim + arrows
            (Command::Next, ch('j')),
            (Command::Next, code(KeyCode::Down)),
            (Command::Prev, ch('k')),
            (Command::Prev, code(KeyCode::Up)),
            (Command::Parent, ch('h')),
            (Command::Parent, code(KeyCode::Left)),
            (Command::Child, ch('l')),
            (Command::Child, code(KeyCode::Right)),
            // Jump history — Ctrl+O/Ctrl+I (vim muscle memory) plus portable
            // Alt+←/Alt+→ aliases in both presets (D-8).
            (Command::JumpBack, ctrl('o')),
            (Command::JumpBack, alt_code(KeyCode::Left)),
            (Command::JumpForward, ctrl('i')),
            (Command::JumpForward, alt_code(KeyCode::Right)),
            // Search overlay (T4.2)
            (Command::CycleScope, ctrl('s')),
            (Command::OpenEntry, code(KeyCode::Tab)),
            (Command::QuickSelect, alt('1')),
            (Command::QuickSelect, alt('2')),
            (Command::QuickSelect, alt('3')),
            (Command::QuickSelect, alt('4')),
            (Command::QuickSelect, alt('5')),
            (Command::QuickSelect, alt('6')),
            (Command::QuickSelect, alt('7')),
            (Command::QuickSelect, alt('8')),
            (Command::QuickSelect, alt('9')),
            // Secrets-tab operations
            (Command::FocusPane, code(KeyCode::Tab)),
            (Command::Search, ch('/')),
            (Command::AddEntry, ch('a')),
            (Command::EditEntry, ch('e')),
            (Command::DeleteEntry, ch('d')),
            (Command::CopyPassword, ch('c')),
            (Command::CopyUsername, ch('C')),
            (Command::RevealPassword, ch(' ')),
            (Command::History, ch('H')),
            (Command::PinToggle, ch('p')),
            (Command::SortCycle, ch('o')),
            // Visual mode / bulk operations (T4.5)
            (Command::VisualMode, ch('v')),
            (Command::MoveToGroup, ch('m')),
            (Command::AddTag, ch('t')),
            (Command::RemoveTag, ch('T')),
            // Sync / generation
            (Command::Sync, ch('s')),
            (Command::Generate, ctrl('g')),
        ];

        // Tab navigation is the only preset-divergent block.
        match preset {
            Preset::Vim => {
                pairs.push((
                    Command::NextTab,
                    KeyTrigger::Seq(vec![ch_ev('g'), ch_ev('t')]),
                ));
                pairs.push((
                    Command::PrevTab,
                    KeyTrigger::Seq(vec![ch_ev('g'), ch_ev('T')]),
                ));
                pairs.push((
                    Command::JumpToTab,
                    KeyTrigger::CountSeq(vec![ch_ev('g'), ch_ev('t')]),
                ));
            }
            Preset::Plain => {
                // No chord sequences, no `{count}`: `]`/`[` cycle tabs directly.
                pairs.push((Command::NextTab, ch(']')));
                pairs.push((Command::PrevTab, ch('[')));
                // `F1` joins `?` for the palette/help.
                pairs.push((Command::Help, code(KeyCode::F(1))));
            }
        }
        // `Alt+1..9` direct jumps in both presets.
        pairs.extend(alt_digit_jumps());

        let map = pairs
            .into_iter()
            .map(|(cmd, trigger)| {
                let contexts = spec_for(cmd)
                    .expect("every bound command is registered")
                    .contexts;
                (contexts, trigger, cmd)
            })
            .collect();
        Self { map }
    }

    /// Does `ev` trigger `command` (context-free)? Only [`KeyTrigger::Key`] rows
    /// can match — `Seq`/`CountSeq` are resolved by [`Keymap::resolve`]. This is
    /// the per-tab dispatch entry the workspace bodies use.
    pub(crate) fn matches(&self, command: Command, ev: &KeyEvent) -> bool {
        self.map.iter().any(|(_, trigger, cmd)| {
            *cmd == command && matches!(trigger, KeyTrigger::Key(k) if key_event_eq(k, ev))
        })
    }

    /// The first single-key trigger bound to `command`, if any (test/inspection
    /// helper; sequence-only commands return `None`).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn binding_for(&self, command: Command) -> Option<&KeyEvent> {
        self.map.iter().find_map(|(_, trigger, cmd)| match trigger {
            KeyTrigger::Key(k) if *cmd == command => Some(k),
            _ => None,
        })
    }

    /// Every trigger bound to `command` that is available in `ctx`. Read by the
    /// T2.1 hint bar (first trigger → cell key) and the preset tests.
    pub(crate) fn triggers_for(&self, ctx: Contexts, command: Command) -> Vec<&KeyTrigger> {
        self.map
            .iter()
            .filter(|(c, _, cmd)| *cmd == command && c.contains(ctx))
            .map(|(_, trigger, _)| trigger)
            .collect()
    }

    /// The human-readable key string for `command` (context-free): every trigger
    /// bound to it, in table order, joined with `" / "` (e.g. `Next` → `"j / ↓"`).
    /// A run of `Alt+1`…`Alt+9` collapses to `"Alt+1..9"`. `None` if unbound.
    pub(crate) fn rendered_keys(&self, command: Command) -> Option<String> {
        let parts = self.rendered_key_parts(command);
        if parts.is_empty() {
            return None;
        }
        Some(parts.join(" / "))
    }

    /// The individual rendered key strings for `command` (context-free), in
    /// table order, with `Alt+1`…`Alt+9` runs collapsed to `"Alt+1..9"`. Empty
    /// if unbound. Backs [`Self::rendered_keys`] and the `--dump-keys` JSON
    /// output (which needs the keys as a list, not a joined string).
    pub(crate) fn rendered_key_parts(&self, command: Command) -> Vec<String> {
        let parts: Vec<String> = self
            .map
            .iter()
            .filter(|(_, _, cmd)| *cmd == command)
            .map(|(_, trigger, _)| render_trigger(trigger))
            .collect();
        collapse_alt_digits(parts)
    }

    /// Resolve one key event against the tab-motion layer (design §2.2.2). Owns
    /// the `g`-prefix / `{count}` / `Alt+N` chord machine that used to live in
    /// `app.rs`. Only the tab-navigation commands are resolved here; every other
    /// key yields [`Resolution::None`] so the caller dispatches it to the active
    /// tab body.
    pub(crate) fn resolve(
        &self,
        ctx: Contexts,
        ev: &KeyEvent,
        pending: &mut PendingSeq,
    ) -> Resolution {
        // 0. `Alt+N` direct jump takes precedence over any pending chord — the old
        // inline machine checked `Alt+digit` before the `g`-prefix state, so `g`
        // then `Alt+3` still jumps to tab 3. Rebind-aware via the shared scan.
        if alt_digit(ev).is_some() {
            if let Some(res) = self.direct_tab_key(ctx, ev, pending) {
                return res;
            }
        }

        // 1. Continue an in-progress sequence (after `g`).
        if !pending.prefix.is_empty() {
            return self.continue_sequence(ctx, ev, pending);
        }

        // 2. Accumulate a `{count}` prefix (only where a count sequence exists).
        if self.ctx_has_count_seq(ctx) {
            if let Some(d) = plain_digit(ev) {
                let acc = pending
                    .count
                    .unwrap_or(0)
                    .saturating_mul(10)
                    .saturating_add(d);
                pending.count = Some(acc);
                return Resolution::Pending(Vec::new());
            }
        }

        // 3. A direct single-key tab command (`[`/`]` in Plain; `Alt+N` already
        // handled in step 0).
        if let Some(res) = self.direct_tab_key(ctx, ev, pending) {
            return res;
        }

        // 4. Start a sequence whose first key is `ev`.
        if self
            .sequence_triggers(ctx)
            .any(|keys| key_event_eq(&keys[0], ev))
        {
            pending.prefix.push(*ev);
            let conts = self.continuations(ctx, &pending.prefix);
            return Resolution::Pending(conts);
        }

        // 5. Not a tab motion: drop any pending count and let the caller dispatch.
        pending.reset();
        Resolution::None
    }

    /// Resolve a direct single-key tab command (`Alt+N` jump, or `[`/`]` in the
    /// Plain preset). `Alt+N` carries its digit as the jump count; a rebound
    /// plain-key jump falls back to any pending `{count}`. Returns `None` if `ev`
    /// is not a single-key tab command in `ctx`.
    fn direct_tab_key(
        &self,
        ctx: Contexts,
        ev: &KeyEvent,
        pending: &mut PendingSeq,
    ) -> Option<Resolution> {
        for (c, trigger, cmd) in &self.map {
            if !is_tab_command(*cmd) || !c.contains(ctx) {
                continue;
            }
            if let KeyTrigger::Key(k) = trigger {
                if key_event_eq(k, ev) {
                    let count = if *cmd == Command::JumpToTab {
                        alt_digit(ev).or(pending.count)
                    } else {
                        None
                    };
                    pending.reset();
                    return Some(Resolution::Command(*cmd, count));
                }
            }
        }
        None
    }

    /// Handle a key while `pending.prefix` is non-empty (mid-sequence).
    fn continue_sequence(
        &self,
        ctx: Contexts,
        ev: &KeyEvent,
        pending: &mut PendingSeq,
    ) -> Resolution {
        let depth = pending.prefix.len();
        // Does `ev` extend the current prefix toward some sequence?
        let extends = self.sequence_triggers(ctx).any(|keys| {
            keys.len() > depth
                && prefix_matches(keys, &pending.prefix)
                && key_event_eq(&keys[depth], ev)
        });
        if !extends {
            // Stray key: reset and let the caller dispatch it fresh.
            pending.reset();
            return Resolution::None;
        }
        pending.prefix.push(*ev);
        // Complete?
        if let Some(cmd) = self.completed_command(ctx, &pending.prefix, pending.count) {
            let count = pending.count.take();
            pending.reset();
            let count = if cmd == Command::JumpToTab {
                count
            } else {
                None
            };
            return Resolution::Command(cmd, count);
        }
        // Still partial (no ≥3-key sequences exist today, but stay general).
        let conts = self.continuations(ctx, &pending.prefix);
        Resolution::Pending(conts)
    }

    /// The command whose full sequence equals `keys`, disambiguating a shared
    /// `Seq`/`CountSeq` by whether a `{count}` is pending.
    fn completed_command(
        &self,
        ctx: Contexts,
        keys: &[KeyEvent],
        count: Option<u16>,
    ) -> Option<Command> {
        let mut seq_cmd = None;
        let mut count_cmd = None;
        for (c, trigger, cmd) in &self.map {
            if !is_tab_command(*cmd) || !c.contains(ctx) {
                continue;
            }
            match trigger {
                KeyTrigger::Seq(s) if seq_eq(s, keys) => seq_cmd = Some(*cmd),
                KeyTrigger::CountSeq(s) if seq_eq(s, keys) => count_cmd = Some(*cmd),
                _ => {}
            }
        }
        // A pending count selects the count variant; otherwise the plain motion.
        if count.is_some() {
            count_cmd.or(seq_cmd)
        } else {
            seq_cmd.or(count_cmd)
        }
    }

    /// The which-key continuations for a *pending* `prefix` in `ctx`, without
    /// advancing any state (unlike [`Keymap::resolve`]). One row per distinct
    /// next key, paired with the command it would reach — the same data
    /// `resolve` returns in [`Resolution::Pending`], exposed for the which-key
    /// menu (T2.2) to peek the live pending prefix.
    pub(crate) fn continuations_for(
        &self,
        ctx: Contexts,
        prefix: &[KeyEvent],
    ) -> Vec<(KeyEvent, &'static CommandSpec)> {
        self.continuations(ctx, prefix)
    }

    /// The which-key continuations after `prefix`: one row per distinct next key,
    /// paired with the command it would reach.
    fn continuations(
        &self,
        ctx: Contexts,
        prefix: &[KeyEvent],
    ) -> Vec<(KeyEvent, &'static CommandSpec)> {
        let depth = prefix.len();
        let mut out: Vec<(KeyEvent, &'static CommandSpec)> = Vec::new();
        for (c, trigger, cmd) in &self.map {
            if !is_tab_command(*cmd) || !c.contains(ctx) {
                continue;
            }
            let keys = match trigger {
                KeyTrigger::Seq(s) | KeyTrigger::CountSeq(s) => s,
                KeyTrigger::Key(_) => continue,
            };
            if keys.len() > depth && prefix_matches(keys, prefix) {
                let next = keys[depth];
                // One row per distinct next key (a shared `g t` shows once).
                if !out.iter().any(|(k, _)| key_event_eq(k, &next)) {
                    if let Some(spec) = spec_for(*cmd) {
                        out.push((next, spec));
                    }
                }
            }
        }
        out
    }

    /// Iterator over the tab-motion sequence key-slices available in `ctx`.
    fn sequence_triggers(&self, ctx: Contexts) -> impl Iterator<Item = &[KeyEvent]> {
        self.map.iter().filter_map(move |(c, trigger, cmd)| {
            if !is_tab_command(*cmd) || !c.contains(ctx) {
                return None;
            }
            match trigger {
                KeyTrigger::Seq(s) | KeyTrigger::CountSeq(s) => Some(s.as_slice()),
                KeyTrigger::Key(_) => None,
            }
        })
    }

    /// Does `ctx` have any `{count}`-taking sequence (so digit keys accumulate)?
    fn ctx_has_count_seq(&self, ctx: Contexts) -> bool {
        self.map.iter().any(|(c, trigger, cmd)| {
            is_tab_command(*cmd) && c.contains(ctx) && matches!(trigger, KeyTrigger::CountSeq(_))
        })
    }
}

/// Does `seq` start with `prefix`?
fn prefix_matches(seq: &[KeyEvent], prefix: &[KeyEvent]) -> bool {
    seq.len() >= prefix.len() && seq.iter().zip(prefix).all(|(a, b)| key_event_eq(a, b))
}

/// Sequence equality via [`key_event_eq`].
fn seq_eq(a: &[KeyEvent], b: &[KeyEvent]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| key_event_eq(x, y))
}

/// The digit of an `Alt+<digit>` event (`1..=9`), else `None`.
fn alt_digit(ev: &KeyEvent) -> Option<u16> {
    if ev.modifiers.contains(KeyModifiers::ALT) {
        if let KeyCode::Char(c) = ev.code {
            let d = u16::try_from(c.to_digit(10)?).ok()?;
            return (d != 0).then_some(d);
        }
    }
    None
}

/// The digit of a plain (no Ctrl/Alt) `<digit>` event, else `None`.
fn plain_digit(ev: &KeyEvent) -> Option<u16> {
    if ev
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
    {
        return None;
    }
    if let KeyCode::Char(c) = ev.code {
        return u16::try_from(c.to_digit(10)?).ok();
    }
    None
}

/// Collapse a `["…", "Alt+1", "Alt+2", … "Alt+9"]` run into `["…", "Alt+1..9"]`,
/// preserving the order of the non-collapsed parts. Keeps the palette row for
/// `JumpToTab` reading `"{count}gt / Alt+1..9"` rather than nine cells.
fn collapse_alt_digits(parts: Vec<String>) -> Vec<String> {
    let has_full_run = ('1'..='9').all(|d| parts.iter().any(|p| *p == format!("Alt+{d}")));
    if !has_full_run {
        return parts;
    }
    let mut out: Vec<String> = parts
        .into_iter()
        .filter(|p| !is_alt_digit_label(p))
        .collect();
    out.push("Alt+1..9".to_string());
    out
}

/// Is `s` an `Alt+<digit>` render label?
fn is_alt_digit_label(s: &str) -> bool {
    s.strip_prefix("Alt+")
        .and_then(|rest| rest.parse::<u8>().ok())
        .is_some_and(|d| (1..=9).contains(&d))
}

/// Compare two key events for dispatch.
///
/// For character keys the uppercase form already encodes Shift (`Shift+c` →
/// `Char('C')`), and terminals disagree on whether they *also* set `SHIFT` — so
/// for `Char(_)` we compare only `CONTROL`/`ALT` and ignore `SHIFT`. For non-char
/// keys (arrows, Enter, …) all of `CONTROL`/`ALT`/`SHIFT` are compared.
fn key_event_eq(bound: &KeyEvent, ev: &KeyEvent) -> bool {
    if bound.code != ev.code {
        return false;
    }
    let mut mask = KeyModifiers::CONTROL | KeyModifiers::ALT;
    if !matches!(bound.code, KeyCode::Char(_)) {
        mask |= KeyModifiers::SHIFT;
    }
    (bound.modifiers & mask) == (ev.modifiers & mask)
}

/// Render a trigger for discoverability chrome (pretty form: `Ctrl+`, Unicode arrows,
/// `g t` sequences shown as `gt`/`{count}gt`).
fn render_trigger(trigger: &KeyTrigger) -> String {
    match trigger {
        KeyTrigger::Key(k) => render_key(k),
        KeyTrigger::Seq(keys) => keys.iter().map(render_key).collect(),
        KeyTrigger::CountSeq(keys) => {
            format!(
                "{{count}}{}",
                keys.iter().map(render_key).collect::<String>()
            )
        }
    }
}

fn render_key(k: &KeyEvent) -> String {
    let mut out = String::new();
    if k.modifiers.contains(KeyModifiers::CONTROL) {
        out.push_str("Ctrl+");
    }
    if k.modifiers.contains(KeyModifiers::ALT) {
        out.push_str("Alt+");
    }
    let key = match k.code {
        KeyCode::Char(' ') => "Space".to_string(),
        KeyCode::Char(c) => c.to_string(),
        KeyCode::Enter => "Enter".to_string(),
        KeyCode::Esc => "Esc".to_string(),
        KeyCode::Up => "↑".to_string(),
        KeyCode::Down => "↓".to_string(),
        KeyCode::Left => "←".to_string(),
        KeyCode::Right => "→".to_string(),
        KeyCode::Tab => "Tab".to_string(),
        KeyCode::BackTab => "Shift+Tab".to_string(),
        KeyCode::F(n) => format!("F{n}"),
        other => format!("{other:?}"),
    };
    out.push_str(&key);
    out
}

// ===================== T1.3: key-string grammar =====================
//
// The grammar is what a user types in `[keymap.bindings]` TOML. It is a separate
// rendering from the help display (`render_trigger`, which keeps `Ctrl+`, Unicode
// arrows, and `gt`): the grammar is lowercase/ASCII (`ctrl+`, `down`, `g t`) so
// `parse_grammar(render_grammar(t)) == t` round-trips. `CountSeq` has no distinct
// grammar form (the `{count}` is a property of the command, not a user-typed key),
// so it is excluded from the round-trip — users rebind the `g t` keys, not the
// count-ness.

/// Why a key string failed to parse. Precise variants so a caller can report the
/// specific problem without echoing the (arbitrary) input.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum KeyParseError {
    /// The whole string (or a token) was empty.
    Empty,
    /// A sequence had more than two keys (the grammar cap).
    SequenceTooLong,
    /// A `mod+` segment was not `ctrl` or `alt`.
    UnknownModifier,
    /// The key name was not a recognised single char or named key.
    UnknownKey,
}

impl std::fmt::Display for KeyParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            KeyParseError::Empty => "empty key",
            KeyParseError::SequenceTooLong => "sequences may have at most two keys",
            KeyParseError::UnknownModifier => "unknown modifier (use ctrl+/alt+)",
            KeyParseError::UnknownKey => "unknown key name",
        };
        f.write_str(s)
    }
}

/// Parse a key string (grammar above) into a [`KeyTrigger`]. A single space
/// separates the (≤2) keys of a sequence; every other form is a single key.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn parse_key(s: &str) -> Result<KeyTrigger, KeyParseError> {
    if s.is_empty() {
        return Err(KeyParseError::Empty);
    }
    if s.contains(' ') {
        let tokens: Vec<&str> = s.split(' ').collect();
        if tokens.len() > 2 {
            return Err(KeyParseError::SequenceTooLong);
        }
        let mut keys = Vec::with_capacity(tokens.len());
        for t in tokens {
            keys.push(parse_single(t)?);
        }
        return Ok(KeyTrigger::Seq(keys));
    }
    Ok(KeyTrigger::Key(parse_single(s)?))
}

/// Parse one modifier-prefixed key token (`ctrl+alt+x`, `down`, `C`).
fn parse_single(token: &str) -> Result<KeyEvent, KeyParseError> {
    if token.is_empty() {
        return Err(KeyParseError::Empty);
    }
    if token == "+" {
        return Ok(KeyEvent::new(KeyCode::Char('+'), KeyModifiers::NONE));
    }
    // `+` is both punctuation and the modifier separator. A doubled final
    // separator therefore denotes a modified plus key, as in `ctrl++`.
    if let Some(modifier_src) = token.strip_suffix("++") {
        if modifier_src.is_empty() {
            return Err(KeyParseError::UnknownModifier);
        }
        let mut modifiers = KeyModifiers::NONE;
        for seg in modifier_src.split('+') {
            match seg.to_ascii_lowercase().as_str() {
                "ctrl" => modifiers |= KeyModifiers::CONTROL,
                "alt" => modifiers |= KeyModifiers::ALT,
                _ => return Err(KeyParseError::UnknownModifier),
            }
        }
        return Ok(KeyEvent::new(KeyCode::Char('+'), modifiers));
    }
    let mut segments: Vec<&str> = token.split('+').collect();
    // The last segment is the key; the rest are modifiers.
    let key_str = segments.pop().unwrap_or("");
    let mut modifiers = KeyModifiers::NONE;
    for seg in segments {
        match seg.to_ascii_lowercase().as_str() {
            "ctrl" => modifiers |= KeyModifiers::CONTROL,
            "alt" => modifiers |= KeyModifiers::ALT,
            _ => return Err(KeyParseError::UnknownModifier),
        }
    }
    let code = parse_keycode(key_str)?;
    Ok(KeyEvent::new(code, modifiers))
}

/// Parse a bare key name into a [`KeyCode`]. Single characters keep their case
/// (`C` = Shift+c); named keys are case-insensitive.
fn parse_keycode(s: &str) -> Result<KeyCode, KeyParseError> {
    if s.is_empty() {
        return Err(KeyParseError::Empty);
    }
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    if chars.next().is_none() {
        // The user-facing grammar is deliberately closed and portable: one
        // printable ASCII character, with space available only as `space`.
        if first.is_ascii_graphic() {
            return Ok(KeyCode::Char(first));
        }
        return Err(KeyParseError::UnknownKey);
    }
    let lower = s.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix('f') {
        if let Ok(n) = rest.parse::<u8>() {
            if (1..=12).contains(&n) {
                return Ok(KeyCode::F(n));
            }
        }
    }
    Ok(match lower.as_str() {
        "space" => KeyCode::Char(' '),
        "esc" => KeyCode::Esc,
        "enter" => KeyCode::Enter,
        "tab" => KeyCode::Tab,
        "backtab" => KeyCode::BackTab,
        "up" => KeyCode::Up,
        "down" => KeyCode::Down,
        "left" => KeyCode::Left,
        "right" => KeyCode::Right,
        "home" => KeyCode::Home,
        "end" => KeyCode::End,
        "pgup" => KeyCode::PageUp,
        "pgdn" => KeyCode::PageDown,
        _ => return Err(KeyParseError::UnknownKey),
    })
}

/// Render a trigger in the grammar (round-trips through [`parse_key`] for `Key`
/// and `Seq`). Used by the T2.1 hint bar (cell key text) and to name a key in
/// conflict warnings.
pub(crate) fn render_grammar(trigger: &KeyTrigger) -> String {
    match trigger {
        KeyTrigger::Key(k) => render_key_grammar(k),
        KeyTrigger::Seq(keys) | KeyTrigger::CountSeq(keys) => keys
            .iter()
            .map(render_key_grammar)
            .collect::<Vec<_>>()
            .join(" "),
    }
}

fn render_key_grammar(k: &KeyEvent) -> String {
    let mut out = String::new();
    if k.modifiers.contains(KeyModifiers::CONTROL) {
        out.push_str("ctrl+");
    }
    if k.modifiers.contains(KeyModifiers::ALT) {
        out.push_str("alt+");
    }
    let key = match k.code {
        KeyCode::Char(' ') => "space".to_string(),
        KeyCode::Char(c) => c.to_string(),
        KeyCode::Esc => "esc".to_string(),
        KeyCode::Enter => "enter".to_string(),
        KeyCode::Tab => "tab".to_string(),
        KeyCode::BackTab => "backtab".to_string(),
        KeyCode::Up => "up".to_string(),
        KeyCode::Down => "down".to_string(),
        KeyCode::Left => "left".to_string(),
        KeyCode::Right => "right".to_string(),
        KeyCode::Home => "home".to_string(),
        KeyCode::End => "end".to_string(),
        KeyCode::PageUp => "pgup".to_string(),
        KeyCode::PageDown => "pgdn".to_string(),
        KeyCode::F(n) => format!("f{n}"),
        other => format!("{other:?}").to_lowercase(),
    };
    out.push_str(&key);
    out
}

// ===================== T1.3: TOML keymap patch =====================

/// A sparse user override of a preset (`~/.config/falach/config.toml`'s
/// `[keymap]` section). Every field optional; slot names are [`CommandSpec::name`]
/// values.
#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct KeymapPatch {
    /// Base preset selected before the overrides apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<Preset>,
    /// `slot → binding`, where a binding is one key, several keys, or `false`
    /// (unbind).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub bindings: BTreeMap<String, BindValue>,
}

/// A single `[keymap.bindings]` value: `"y"`, `["/", "ctrl+f"]`, or `false`.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum BindValue {
    /// `false` unbinds the slot (`true` is a mistake — reported).
    Unbind(bool),
    /// A single key string.
    One(String),
    /// Several key strings, all bound.
    Many(Vec<String>),
}

/// A non-fatal keymap-load warning surfaced to the status bar (T3.1). Messages
/// name slots and grammar-rendered keys only — never the raw file content, which
/// may contain anything (§2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct KeymapWarning {
    pub message: String,
}

/// The command whose registry `name` is `name`, if any.
fn command_by_name(name: &str) -> Option<Command> {
    COMMANDS.iter().find(|s| s.name == name).map(|s| s.id)
}

/// Do two triggers collide (same kind, same keys)? `Seq(g t)` and `CountSeq(g t)`
/// deliberately do NOT collide — they are the same keys disambiguated by count.
///
/// Per the T1.3 spec, "conflict" is trigger *equality*. A single `Key('g')`
/// rebind that shadows the `g t` sequence *prefix* is therefore not flagged
/// (mixed `Key`/`Seq` kinds return `false`): the rebind is silently captured by
/// the sequence machine. This is an accepted limitation of the equality-based
/// definition, not a detected conflict.
fn triggers_conflict(a: &KeyTrigger, b: &KeyTrigger) -> bool {
    match (a, b) {
        (KeyTrigger::Key(x), KeyTrigger::Key(y)) => key_event_eq(x, y),
        (KeyTrigger::Seq(x), KeyTrigger::Seq(y))
        | (KeyTrigger::CountSeq(x), KeyTrigger::CountSeq(y)) => seq_eq(x, y),
        _ => false,
    }
}

/// Turn a [`BindValue`] into its triggers (empty = unbind), or `Err` on a bad
/// form. Errors are intentionally coarse — the caller emits a slot-named warning
/// that never echoes the raw value.
fn parse_bind_value(value: &BindValue) -> Result<Vec<KeyTrigger>, ()> {
    match value {
        BindValue::Unbind(false) => Ok(Vec::new()),
        BindValue::Unbind(true) => Err(()), // "use false to unbind"
        BindValue::One(s) => Ok(vec![parse_key(s).map_err(|_| ())?]),
        BindValue::Many(list) => {
            let mut out = Vec::with_capacity(list.len());
            for s in list {
                out.push(parse_key(s).map_err(|_| ())?);
            }
            Ok(out)
        }
    }
}

impl Keymap {
    /// Build a keymap from a preset chosen by `patch.preset` (default Vim), then
    /// apply the slot overrides. Returns the keymap plus any non-fatal warnings
    /// (unknown slot, unparseable binding, rejected conflict). Never panics;
    /// never echoes raw file content. Wired to config loading in T3.1; exercised
    /// by the patch tests now.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn from_patch(patch: &KeymapPatch) -> (Self, Vec<KeymapWarning>) {
        let mut km = Keymap::preset(patch.preset.unwrap_or(Preset::Vim));
        let original = km.map.clone();
        let mut warnings = Vec::new();
        let mut rebound: Vec<Command> = Vec::new();

        for (slot, value) in &patch.bindings {
            let Some(cmd) = command_by_name(slot) else {
                warnings.push(KeymapWarning {
                    message: format!("unknown keymap slot `{slot}` (ignored)"),
                });
                continue;
            };
            match parse_bind_value(value) {
                Ok(triggers) => {
                    km.rebind(cmd, triggers);
                    rebound.push(cmd);
                }
                Err(()) => warnings.push(KeymapWarning {
                    message: format!("`{slot}`: invalid key binding (ignored)"),
                }),
            }
        }

        // Reject conflicting rebinds to a fixpoint: restore each conflicting
        // command to its preset default, then re-check. Iterating is required
        // because a restore reintroduces a default trigger that can itself
        // collide with another *kept* rebind (e.g. rebinding `pin-toggle`→`o`
        // while `sort-cycle`→`e` frees `o`; rejecting `sort-cycle` restores it to
        // its default `o`, which then collides with the kept `pin-toggle`). The
        // loop guarantees the final map satisfies the same intra-context trigger
        // uniqueness the presets do. Each iteration removes one command from
        // `active`, so it terminates in ≤ `active.len()` steps.
        let mut active = rebound;
        while let Some(pos) = active
            .iter()
            .position(|&cmd| km.first_conflict(cmd).is_some())
        {
            let cmd = active.remove(pos);
            let (other, key) = km.first_conflict(cmd).expect("position() just found one");
            km.restore(cmd, &original);
            let a = spec_for(cmd).map_or("?", |s| s.name);
            let b = spec_for(other).map_or("?", |s| s.name);
            warnings.push(KeymapWarning {
                message: format!(
                    "`{a}` and `{b}` both bind `{key}` — `{a}` rebind rejected, default kept"
                ),
            });
        }

        (km, warnings)
    }

    /// Replace all of `cmd`'s bindings with `triggers` (stored at `cmd`'s declared
    /// contexts). Empty `triggers` unbinds the command.
    fn rebind(&mut self, cmd: Command, triggers: Vec<KeyTrigger>) {
        self.map.retain(|(_, _, c)| *c != cmd);
        let contexts = spec_for(cmd).map_or(Contexts::ALL, |s| s.contexts);
        for trigger in triggers {
            self.map.push((contexts, trigger, cmd));
        }
    }

    /// Restore `cmd`'s bindings from an original (pre-patch) map snapshot.
    fn restore(&mut self, cmd: Command, original: &[(Contexts, KeyTrigger, Command)]) {
        self.map.retain(|(_, _, c)| *c != cmd);
        for row in original.iter().filter(|(_, _, c)| *c == cmd) {
            self.map.push(row.clone());
        }
    }

    /// The first `(other_command, rendered_key)` that `cmd` conflicts with — a
    /// different command sharing a trigger in an overlapping context.
    fn first_conflict(&self, cmd: Command) -> Option<(Command, String)> {
        for (ci, ti, _) in self.map.iter().filter(|(_, _, c)| *c == cmd) {
            for (cj, tj, other) in &self.map {
                if *other == cmd {
                    continue;
                }
                if ci.contains(*cj) && triggers_conflict(ti, tj) {
                    return Some((*other, render_grammar(ti)));
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::super::registry::COMMANDS;
    use super::*;

    fn vim() -> Keymap {
        Keymap::preset(Preset::Vim)
    }

    // --- Dispatch + rendering (carried over from the T1.1 transitional keymap) ---

    #[test]
    fn preset_binds_every_command_in_some_context() {
        for preset in [Preset::Vim, Preset::Plain] {
            let keys = Keymap::preset(preset);
            for spec in COMMANDS {
                let bound = keys.triggers_for(spec.contexts, spec.id);
                assert!(
                    !bound.is_empty(),
                    "{:?} has no binding in {preset:?}",
                    spec.id
                );
            }
        }
    }

    #[test]
    fn presets_have_no_intra_context_conflicts() {
        for preset in [Preset::Vim, Preset::Plain] {
            let keys = Keymap::preset(preset);
            for (i, (ci, ti, cmi)) in keys.map.iter().enumerate() {
                for (cj, tj, cmj) in keys.map.iter().skip(i + 1) {
                    if cmi == cmj {
                        continue; // same command may have several triggers
                    }
                    // Overlapping contexts sharing an identical trigger is a
                    // shipped ambiguity.
                    assert!(
                        !(ci.contains(*cj) && triggers_equal(ti, tj)),
                        "{preset:?}: {cmi:?} and {cmj:?} share a trigger"
                    );
                }
            }
        }
    }

    /// Two triggers collide only when they are the same kind AND the same keys —
    /// a `Seq(g t)` and a `CountSeq(g t)` deliberately do not conflict.
    fn triggers_equal(a: &KeyTrigger, b: &KeyTrigger) -> bool {
        match (a, b) {
            (KeyTrigger::Key(x), KeyTrigger::Key(y)) => key_event_eq(x, y),
            (KeyTrigger::Seq(x), KeyTrigger::Seq(y))
            | (KeyTrigger::CountSeq(x), KeyTrigger::CountSeq(y)) => seq_eq(x, y),
            _ => false,
        }
    }

    #[test]
    fn quit_and_lock_now_require_ctrl() {
        let keys = vim();
        for command in [Command::Quit, Command::LockNow] {
            let ke = keys
                .binding_for(command)
                .unwrap_or_else(|| panic!("{command:?} should have a single-key binding"));
            assert!(
                ke.modifiers.contains(KeyModifiers::CONTROL),
                "{command:?} must require Ctrl"
            );
        }
    }

    #[test]
    fn matches_resolves_primary_and_secondary_bindings() {
        let keys = vim();
        let j = ch_ev('j');
        let down = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
        assert!(keys.matches(Command::Next, &j));
        assert!(keys.matches(Command::Next, &down));
        let cq = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL);
        assert!(keys.matches(Command::Quit, &cq));
    }

    #[test]
    fn matches_rejects_unbound_and_wrong_modifier_events() {
        let keys = vim();
        let bare_q = ch_ev('q');
        assert!(!keys.matches(Command::Quit, &bare_q));
        assert!(!keys.matches(Command::Prev, &ch_ev('j')));
    }

    #[test]
    fn uppercase_char_binding_ignores_shift_modifier() {
        let keys = vim();
        let c_no_shift = KeyEvent::new(KeyCode::Char('C'), KeyModifiers::NONE);
        let c_with_shift = KeyEvent::new(KeyCode::Char('C'), KeyModifiers::SHIFT);
        assert!(keys.matches(Command::CopyUsername, &c_no_shift));
        assert!(keys.matches(Command::CopyUsername, &c_with_shift));
    }

    #[test]
    fn non_char_key_compares_shift_modifier() {
        let keys = vim();
        let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        let shift_enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::SHIFT);
        assert!(keys.matches(Command::Confirm, &enter));
        assert!(!keys.matches(Command::Confirm, &shift_enter));
    }

    #[test]
    fn rendered_keys_join_and_collapse() {
        let keys = vim();
        assert_eq!(keys.rendered_keys(Command::Next).as_deref(), Some("j / ↓"));
        // Sequences render pretty; the Alt run collapses.
        assert_eq!(
            keys.rendered_keys(Command::JumpToTab).as_deref(),
            Some("{count}gt / Alt+1..9")
        );
        assert_eq!(keys.rendered_keys(Command::NextTab).as_deref(), Some("gt"));
    }

    // --- T1.2 resolver / preset / sequence tests ---

    /// Resolve a whole key run against the workspace context, returning the last
    /// non-pending resolution's command (for terse assertions).
    fn drive(keys: &Keymap, seq: &[KeyEvent]) -> Option<(Command, Option<u16>)> {
        let mut pending = PendingSeq::default();
        let mut last = None;
        for ev in seq {
            match keys.resolve(Contexts::WORKSPACE, ev, &mut pending) {
                Resolution::Command(c, n) => last = Some((c, n)),
                Resolution::Pending(_) | Resolution::None => {}
            }
        }
        last
    }

    #[test]
    fn sequence_resolution_pending_then_command() {
        let keys = vim();
        let mut pending = PendingSeq::default();
        // `g` → pending with {t, T} continuations.
        match keys.resolve(Contexts::WORKSPACE, &ch_ev('g'), &mut pending) {
            Resolution::Pending(conts) => {
                let mut nexts: Vec<char> = conts
                    .iter()
                    .filter_map(|(k, _)| match k.code {
                        KeyCode::Char(c) => Some(c),
                        _ => None,
                    })
                    .collect();
                nexts.sort_unstable();
                assert_eq!(nexts, vec!['T', 't'], "g offers t and T");
            }
            _ => panic!("g must be pending"),
        }
        // `t` completes → NextTab.
        match keys.resolve(Contexts::WORKSPACE, &ch_ev('t'), &mut pending) {
            Resolution::Command(Command::NextTab, None) => {}
            _ => panic!("g,t must resolve NextTab"),
        }
        assert!(pending.prefix.is_empty(), "state resets after completion");

        // Stray key after `g` resets and yields None.
        keys.resolve(Contexts::WORKSPACE, &ch_ev('g'), &mut pending);
        match keys.resolve(Contexts::WORKSPACE, &ch_ev('x'), &mut pending) {
            Resolution::None => {}
            _ => panic!("g,x must be None"),
        }
        assert!(pending.prefix.is_empty(), "stray key resets pending state");
    }

    #[test]
    fn count_prefix_preserved_through_resolution() {
        let keys = vim();
        // 2,g,t → JumpToTab(2).
        assert_eq!(
            drive(&keys, &[ch_ev('2'), ch_ev('g'), ch_ev('t')]),
            Some((Command::JumpToTab, Some(2)))
        );
        // Multi-digit count.
        assert_eq!(
            drive(&keys, &[ch_ev('1'), ch_ev('2'), ch_ev('g'), ch_ev('t')]),
            Some((Command::JumpToTab, Some(12)))
        );
        // Alt+3 jumps directly with count 3.
        let alt3 = KeyEvent::new(KeyCode::Char('3'), KeyModifiers::ALT);
        assert_eq!(drive(&keys, &[alt3]), Some((Command::JumpToTab, Some(3))));
    }

    #[test]
    fn plain_preset_has_no_sequences() {
        let keys = Keymap::preset(Preset::Plain);
        // No trigger is a sequence.
        assert!(
            keys.map
                .iter()
                .all(|(_, t, _)| matches!(t, KeyTrigger::Key(_))),
            "plain preset has only single-key triggers"
        );
        // `g` resolves to None immediately (it is not a tab motion in Plain).
        let mut pending = PendingSeq::default();
        assert!(matches!(
            keys.resolve(Contexts::WORKSPACE, &ch_ev('g'), &mut pending),
            Resolution::None
        ));
        // `]`/`[` cycle directly.
        assert_eq!(drive(&keys, &[ch_ev(']')]), Some((Command::NextTab, None)));
        assert_eq!(drive(&keys, &[ch_ev('[')]), Some((Command::PrevTab, None)));
        // A bare digit is inert in Plain (no count layer).
        assert_eq!(drive(&keys, &[ch_ev('2')]), None);
    }

    #[test]
    fn resolution_is_pure() {
        let keys = vim();
        // Same starting state + event → same outcome and same resulting state.
        let run = || {
            let mut pending = PendingSeq::default();
            let r = keys.resolve(Contexts::WORKSPACE, &ch_ev('g'), &mut pending);
            (matches!(r, Resolution::Pending(_)), pending.prefix.len())
        };
        assert_eq!(run(), run());
        // A stray non-motion key never mutates a fresh pending state.
        let mut pending = PendingSeq::default();
        assert!(matches!(
            keys.resolve(Contexts::WORKSPACE, &ch_ev('z'), &mut pending),
            Resolution::None
        ));
        assert!(pending.prefix.is_empty() && pending.count.is_none());
    }

    // --- T1.3 grammar + patch tests ---

    #[test]
    fn key_string_grammar_round_trips() {
        // Corpus of concrete forms.
        for s in [
            "y", "C", "ctrl+g", "alt+3", "space", "g t", "f1", "pgdn", "+", "ctrl++",
        ] {
            let t = parse_key(s).unwrap_or_else(|_| panic!("{s:?} should parse"));
            assert_eq!(
                parse_key(&render_grammar(&t)),
                Ok(t.clone()),
                "round-trip failed for {s:?}"
            );
        }
        // 100% of both presets' Key/Seq triggers (CountSeq has no grammar form —
        // its `{count}` is a command property, not a typed key).
        for preset in [Preset::Vim, Preset::Plain] {
            let keys = Keymap::preset(preset);
            for (_, trigger, _) in &keys.map {
                if matches!(trigger, KeyTrigger::CountSeq(_)) {
                    continue;
                }
                let rendered = render_grammar(trigger);
                assert_eq!(
                    parse_key(&rendered).as_ref(),
                    Ok(trigger),
                    "round-trip failed for {rendered:?} in {preset:?}"
                );
            }
        }
    }

    #[test]
    fn grammar_rejects_invalid_forms() {
        assert_eq!(parse_key(""), Err(KeyParseError::Empty));
        assert_eq!(parse_key("ctrl+"), Err(KeyParseError::Empty));
        assert_eq!(parse_key("g t t"), Err(KeyParseError::SequenceTooLong));
        assert_eq!(parse_key("meta+x"), Err(KeyParseError::UnknownModifier));
        // "Enter+ctrl": "Enter" parsed as a modifier segment → unknown modifier.
        assert_eq!(parse_key("Enter+ctrl"), Err(KeyParseError::UnknownModifier));
        // A multi-char non-name is an unknown key.
        assert_eq!(parse_key("notakey"), Err(KeyParseError::UnknownKey));
        assert_eq!(parse_key("é"), Err(KeyParseError::UnknownKey));
        assert_eq!(parse_key("\n"), Err(KeyParseError::UnknownKey));
        assert_eq!(parse_key(" "), Err(KeyParseError::Empty));
    }

    /// Build a patch from TOML (exercises the serde `untagged` `BindValue`).
    fn patch(toml_src: &str) -> KeymapPatch {
        toml::from_str(toml_src).expect("patch TOML parses")
    }

    #[test]
    fn patch_overrides_only_named_slots() {
        let (keys, warnings) = Keymap::from_patch(&patch(
            r#"
            [bindings]
            "copy-password" = "y"
            "#,
        ));
        assert!(warnings.is_empty(), "clean rebind has no warnings");
        assert!(
            keys.matches(Command::CopyPassword, &ch_ev('y')),
            "y now copies"
        );
        assert!(
            !keys.matches(Command::CopyPassword, &ch_ev('c')),
            "the old c binding is replaced"
        );
        // Other slots are untouched.
        assert!(keys.matches(Command::Search, &ch_ev('/')));
        assert!(keys.matches(Command::Next, &ch_ev('j')));
        assert!(keys.matches(
            Command::Next,
            &KeyEvent::new(KeyCode::Down, KeyModifiers::NONE)
        ));
    }

    #[test]
    fn patch_unbind_and_multi_trigger() {
        let (keys, warnings) = Keymap::from_patch(&patch(
            r#"
            [bindings]
            "pin-toggle" = false
            "search" = ["/", "ctrl+f"]
            "#,
        ));
        assert!(warnings.is_empty());
        // Unbound: no key resolves it.
        assert!(keys
            .triggers_for(Contexts::SECRETS_TREE, Command::PinToggle)
            .is_empty());
        assert!(!keys.matches(Command::PinToggle, &ch_ev('p')));
        // Multi-trigger: both keys bind Search.
        assert!(keys.matches(Command::Search, &ch_ev('/')));
        assert!(keys.matches(
            Command::Search,
            &KeyEvent::new(KeyCode::Char('f'), KeyModifiers::CONTROL)
        ));
    }

    #[test]
    fn patch_conflict_rejected_with_default_kept() {
        // `e` already belongs to edit-entry; rebinding copy-password to it in the
        // same context is rejected.
        let (keys, warnings) = Keymap::from_patch(&patch(
            r#"
            [bindings]
            "copy-password" = "e"
            "#,
        ));
        let msg = &warnings
            .iter()
            .find(|w| w.message.contains("copy-password"))
            .unwrap()
            .message;
        assert!(msg.contains("copy-password") && msg.contains("edit-entry") && msg.contains('e'));
        assert!(
            keys.matches(Command::CopyPassword, &ch_ev('c')),
            "default c restored"
        );
        assert!(
            keys.matches(Command::EditEntry, &ch_ev('e')),
            "edit-entry default kept"
        );
        assert!(
            !keys.matches(Command::CopyPassword, &ch_ev('e')),
            "rejected rebind not applied"
        );

        // Disjoint contexts sharing a key is NOT a conflict: generate (EDIT) can
        // take `c` while copy-password (tree/detail) also uses `c`.
        let (keys, warnings) = Keymap::from_patch(&patch(
            r#"
            [bindings]
            "generate" = "c"
            "#,
        ));
        assert!(warnings.is_empty(), "disjoint-context reuse is allowed");
        assert!(keys.matches(Command::Generate, &ch_ev('c')));
        assert!(keys.matches(Command::CopyPassword, &ch_ev('c')));
    }

    #[test]
    fn unknown_slot_names_warn_and_ignore() {
        let (keys, warnings) = Keymap::from_patch(&patch(
            r#"
            [bindings]
            "copy-passwrod" = "y"
            "search" = "z"
            "#,
        ));
        assert_eq!(warnings.len(), 1, "one warning for the typo'd slot");
        assert!(warnings[0].message.contains("copy-passwrod"));
        // The valid rebind still applied.
        assert!(keys.matches(Command::Search, &ch_ev('z')));
    }

    #[test]
    fn preset_switch_via_patch() {
        let (keys, warnings) = Keymap::from_patch(&patch(
            r#"
            preset = "plain"

            [bindings]
            "search" = "z"
            "#,
        ));
        assert!(warnings.is_empty());
        // The Plain preset was selected first: `]`/`[` cycle tabs directly.
        assert!(keys.matches(Command::NextTab, &ch_ev(']')));
        assert!(keys.matches(Command::PrevTab, &ch_ev('[')));
        // Then the override applied on top.
        assert!(keys.matches(Command::Search, &ch_ev('z')));
    }

    #[test]
    fn which_key_continuations_pair_keys_with_base_commands() {
        // The which-key rows after `g` must pair each key with the correct
        // command (not merely the right key set): `t`→NextTab (the base motion,
        // not its JumpToTab count-variant which shares the `g t` keys), `T`→PrevTab.
        let keys = vim();
        let mut pending = PendingSeq::default();
        let Resolution::Pending(conts) =
            keys.resolve(Contexts::WORKSPACE, &ch_ev('g'), &mut pending)
        else {
            panic!("g must be pending");
        };
        let row = |c: char| {
            conts
                .iter()
                .find(|(k, _)| matches!(k.code, KeyCode::Char(x) if x == c))
                .map(|(_, spec)| spec.id)
        };
        assert_eq!(row('t'), Some(Command::NextTab), "t → next tab, not jump");
        assert_eq!(row('T'), Some(Command::PrevTab));
    }

    #[test]
    fn count_on_previous_tab_is_discarded() {
        // A `{count}` is meaningless for `gT`; `2gT` resolves PrevTab with no count.
        let keys = vim();
        assert_eq!(
            drive(&keys, &[ch_ev('2'), ch_ev('g'), ch_ev('T')]),
            Some((Command::PrevTab, None))
        );
    }

    #[test]
    fn patch_rebound_tab_motion_resolves_via_sequence_machine() {
        // A tab motion rebound via patch must be honoured by `resolve` (not only
        // `matches`): `next-tab = "]"` fires NextTab on `]`, and the untouched
        // `gT` still cycles to the previous tab.
        let (keys, warnings) = Keymap::from_patch(&patch(
            r#"
            [bindings]
            "next-tab" = "]"
            "#,
        ));
        assert!(warnings.is_empty());
        assert_eq!(drive(&keys, &[ch_ev(']')]), Some((Command::NextTab, None)));
        assert_eq!(
            drive(&keys, &[ch_ev('g'), ch_ev('T')]),
            Some((Command::PrevTab, None))
        );
    }

    /// Count how many of `cmds` resolve on key `c` (the intra-context uniqueness
    /// invariant the conflict resolver must preserve).
    fn hits(keys: &Keymap, cmds: &[Command], c: char) -> usize {
        cmds.iter()
            .filter(|&&cmd| keys.matches(cmd, &ch_ev(c)))
            .count()
    }

    #[test]
    fn mutual_rebind_conflict_resolves_to_conflict_free_map() {
        // Two commands rebound to the same key: the result must be conflict-free
        // (the key binds at most one), with a warning; the rejected command
        // (processed first) is restored to its default.
        let (keys, warnings) = Keymap::from_patch(&patch(
            r#"
            [bindings]
            "add-entry" = "z"
            "edit-entry" = "z"
            "#,
        ));
        assert!(!warnings.is_empty());
        assert_eq!(
            hits(&keys, &[Command::AddEntry, Command::EditEntry], 'z'),
            1,
            "z binds exactly one command — the map is conflict-free"
        );
        assert!(
            keys.matches(Command::AddEntry, &ch_ev('a')),
            "add-entry (processed first) is restored to its default"
        );
    }

    #[test]
    fn restore_induced_conflict_resolved_to_fixpoint() {
        // pin-toggle→o (default p) and sort-cycle→e (default o). Rejecting
        // sort-cycle (collides with edit-entry's e) restores it to o, which then
        // collides with the kept pin-toggle→o — the fixpoint must reject
        // pin-toggle too, leaving a conflict-free map with both on their defaults.
        let (keys, _warnings) = Keymap::from_patch(&patch(
            r#"
            [bindings]
            "pin-toggle" = "o"
            "sort-cycle" = "e"
            "#,
        ));
        assert_eq!(
            hits(&keys, &[Command::PinToggle, Command::SortCycle], 'o'),
            1,
            "o binds exactly one command after the fixpoint"
        );
        assert!(
            keys.matches(Command::PinToggle, &ch_ev('p')),
            "pin-toggle restored to p"
        );
        assert!(
            keys.matches(Command::SortCycle, &ch_ev('o')),
            "sort-cycle restored to o"
        );
    }

    #[test]
    fn alt_digit_jumps_even_mid_sequence() {
        // Alt+N takes precedence over a pending `g` prefix (preserves the old
        // machine's ordering): `g` then `Alt+3` jumps to tab 3.
        let keys = vim();
        let mut pending = PendingSeq::default();
        assert!(matches!(
            keys.resolve(Contexts::WORKSPACE, &ch_ev('g'), &mut pending),
            Resolution::Pending(_)
        ));
        let alt3 = KeyEvent::new(KeyCode::Char('3'), KeyModifiers::ALT);
        assert!(matches!(
            keys.resolve(Contexts::WORKSPACE, &alt3, &mut pending),
            Resolution::Command(Command::JumpToTab, Some(3))
        ));
        assert!(
            pending.prefix.is_empty(),
            "the jump clears the pending prefix"
        );
    }

    #[test]
    fn partial_conflict_restores_whole_slot() {
        // A multi-trigger rebind where one trigger conflicts rejects the WHOLE
        // slot (the harmless trigger is dropped with it — documented behavior).
        let (keys, warnings) = Keymap::from_patch(&patch(
            r#"
            [bindings]
            "search" = ["z", "e"]
            "#,
        ));
        assert_eq!(warnings.len(), 1);
        assert!(
            keys.matches(Command::Search, &ch_ev('/')),
            "search restored to /"
        );
        assert!(
            !keys.matches(Command::Search, &ch_ev('z')),
            "the harmless z is dropped with the rejected slot"
        );
        assert!(keys.matches(Command::EditEntry, &ch_ev('e')));
    }

    #[test]
    fn warnings_never_echo_content() {
        // A binding value that fails to parse must not leak into the warning.
        const SENTINEL: &str = "zzsentinelnotakeyzz";
        let (_keys, warnings) = Keymap::from_patch(&patch(&format!(
            r#"
            [bindings]
            "copy-password" = "{SENTINEL}"
            "#
        )));
        assert_eq!(warnings.len(), 1);
        assert!(
            !warnings[0].message.contains(SENTINEL),
            "the raw (unparseable) value must never appear in a warning: {}",
            warnings[0].message
        );
        // It still names the slot (a grammar-constrained identifier).
        assert!(warnings[0].message.contains("copy-password"));
    }
}
