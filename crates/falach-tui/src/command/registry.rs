//! The command registry — the single source of truth for every user-facing
//! operation (design §2.2.1).
//!
//! One [`Command`] variant per discrete action; the [`COMMANDS`] table carries
//! each command's identity (kebab-case `name`, human `desc`), its display
//! [`Group`], the [`Contexts`] in which it is available, its hint-bar `order`,
//! and whether it is `quick_bar`-eligible. Contextual UI projections consume
//! this metadata, while [`super::Keymap`] owns triggers and `App` owns dispatch.
//!
//! This module was converted from the earlier `keys.rs` `Action` enum in T1.1.
//! The behaviour is unchanged: `desc` strings and command ordering reproduce the
//! former `KeyBindings::describe()` output byte-for-byte. New commands arrive
//! with their features (search/nav/visual-mode in Phase 4); enablement refines
//! in T2.1 (see [`super::super::app::App::command_state`]).

/// One enum variant per discrete user-facing action.
///
/// A closed enum (design decision D-1): type-safe, exhaustiveness-testable, and
/// enumerable for the palette/help without a parser. Parameterised commands (to
/// arrive in Phase 4) carry their argument as enum data; TOML remaps *triggers*,
/// never the command vocabulary.
macro_rules! command_variants {
    ($($variant:ident),+ $(,)?) => {
        #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
        pub(crate) enum Command {
            $($variant),+
        }

        #[cfg(test)]
        const ALL_COMMANDS: &[Command] = &[$(Command::$variant),+];
    };
}

command_variants! {
    // --- Global ---
    Quit,    // Ctrl+Q
    LockNow, // Ctrl+L
    Help,    // ?
    Cancel,  // Esc
    Confirm, // Enter

    // --- Tree / list navigation (vim + arrow parity) ---
    Next,   // j / Down
    Prev,   // k / Up
    Parent, // h / Left
    Child,  // l / Right

    // --- Jump history (T4.4; session-only, cleared on lock) ---
    JumpBack,    // Ctrl+O
    JumpForward, // Ctrl+I (tree focus only — Ctrl+I ≡ Tab on many terminals)

    // --- Tab navigation (workspace; OQ-N1 portable scheme) ---
    NextTab,   // gt
    PrevTab,   // gT
    JumpToTab, // {count}gt / Alt+1..9

    // --- Search overlay (T4.2) ---
    CycleScope,  // Ctrl+S — cycle [ALL] → [GROUP] → [TAG]
    QuickSelect, // Alt+1..9 — act on the numbered visible result
    OpenEntry,   // Tab — secondary search action (opposite configured Enter)

    // --- Secrets-tab operations ---
    FocusPane,      // Tab — toggle focus between the entry tree and detail pane
    Search,         // /
    AddEntry,       // a
    EditEntry,      // e
    DeleteEntry,    // d
    CopyPassword,   // c
    CopyUsername,   // C (Shift+c)
    RevealPassword, // Space
    History,        // H (Shift+h)
    PinToggle,      // p
    SortCycle,      // o

    // --- Visual mode / bulk operations (T4.5) ---
    VisualMode,  // v — enter visual multi-select
    MoveToGroup, // m — move marked entries to a group
    AddTag,      // t — add a tag to marked entries
    RemoveTag,   // T — remove a tag from marked entries

    // --- Sync / generation ---
    Sync,     // s
    Generate // Ctrl+G (inside Edit)
}

/// Display grouping for a command (help sections / palette headers). Distinct
/// from the palette's grouped-row projection.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum Group {
    Global,
    Navigation,
    Tabs,
    Secrets,
    Search,
    Edit,
    Sync,
    /// No command carries the Settings group in T1.1; the editable Settings tab
    /// commands (T3) are the first to use it.
    #[allow(dead_code)]
    Settings,
}

impl Group {
    /// A human-readable section header for the palette (T2.3).
    pub(crate) fn label(self) -> &'static str {
        match self {
            Group::Global => "Global",
            Group::Navigation => "Navigation",
            Group::Tabs => "Tabs",
            Group::Secrets => "Secrets",
            Group::Search => "Search",
            Group::Edit => "Edit",
            Group::Sync => "Sync",
            Group::Settings => "Settings",
        }
    }

    /// Render rank — the order groups appear in the unfiltered palette.
    pub(crate) fn rank(self) -> u8 {
        match self {
            Group::Global => 0,
            Group::Navigation => 1,
            Group::Tabs => 2,
            Group::Secrets => 3,
            Group::Search => 4,
            Group::Edit => 5,
            Group::Sync => 6,
            Group::Settings => 7,
        }
    }
}

/// The set of UI contexts in which a command is available. A hand-rolled bitset
/// (no `bitflags` dependency — supply-chain rule; ~30 lines).
///
/// A "context" is the active phase × tab × overlay the dispatcher is in. A
/// command is offered (hint bar, palette, dispatch) only where its `contexts`
/// intersect the current context.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct Contexts(u16);

impl Contexts {
    pub const UNLOCK_LIST: Contexts = Contexts(1 << 0);
    pub const UNLOCK_PROMPT: Contexts = Contexts(1 << 1);
    /// No command declares this context in T1.1 (the lock screen offers only the
    /// global quit, which uses [`Self::ALL`]); the bit exists for the pre-unlock
    /// palette reachability landing in T2.4.
    #[allow(dead_code)]
    pub const LOCK_SCREEN: Contexts = Contexts(1 << 2);
    pub const SECRETS_TREE: Contexts = Contexts(1 << 3);
    pub const SECRETS_DETAIL: Contexts = Contexts(1 << 4);
    pub const PINNED_TAB: Contexts = Contexts(1 << 5);
    pub const SETTINGS_TAB: Contexts = Contexts(1 << 6);
    pub const SEARCH: Contexts = Contexts(1 << 7);
    pub const EDIT: Contexts = Contexts(1 << 8);
    pub const HISTORY: Contexts = Contexts(1 << 9);
    pub const CONFIRM: Contexts = Contexts(1 << 10);
    /// Palette-only commands (T2.3) declare this; unused in T1.1.
    #[allow(dead_code)]
    pub const PALETTE: Contexts = Contexts(1 << 11);
    pub const SYNC_UNLOCK: Contexts = Contexts(1 << 12);
    pub const SYNC_CONFIG: Contexts = Contexts(1 << 13);

    /// Bit count — every declared context bit above. Used by tests to iterate
    /// over the full context space.
    const BIT_COUNT: u16 = 14;

    /// The four persistent workspace tabs (Secrets tree + detail, a pinned tab,
    /// Settings) — the surfaces where tab motion and workspace-global keys apply.
    pub const WORKSPACE: Contexts = Self::SECRETS_TREE
        .or(Self::SECRETS_DETAIL)
        .or(Self::PINNED_TAB)
        .or(Self::SETTINGS_TAB);

    /// Every context — for globally-available commands (e.g. quit).
    pub const ALL: Contexts = Contexts((1 << Self::BIT_COUNT) - 1);

    /// Union of two context sets (const so it composes in `static` initialisers).
    pub const fn or(self, other: Contexts) -> Contexts {
        Contexts(self.0 | other.0)
    }

    /// Do these two context sets intersect? Used to test "is this command
    /// available in `ctx`?" where `ctx` is a single bit.
    pub const fn contains(self, other: Contexts) -> bool {
        self.0 & other.0 != 0
    }

    /// Is this the empty set (no contexts)? An empty-context command is
    /// unreachable dead weight — the registry tests forbid it. (Consumed by the
    /// `every_command_has_context_and_group` test; a prod caller arrives with the
    /// context-aware dispatch in T1.2.)
    #[cfg_attr(not(test), allow(dead_code))]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Iterate the single-bit contexts (one per declared constant). Test-only;
    /// `pub(crate)` so the App-dependent registry tests in `app.rs` (where the
    /// vault fixtures live) can sweep every context.
    #[cfg(test)]
    pub(crate) fn each_bit() -> impl Iterator<Item = Contexts> {
        (0..Self::BIT_COUNT).map(|i| Contexts(1 << i))
    }

    /// The stable, kebab-case names of the context bits set in this set, in bit
    /// order. Used by `--dump-keys=json` to render a command's `contexts` array
    /// (T3.2). Names are part of the documented JSON contract — keep stable.
    pub(crate) fn names(self) -> Vec<&'static str> {
        const NAMES: [(Contexts, &str); 14] = [
            (Contexts::UNLOCK_LIST, "unlock-list"),
            (Contexts::UNLOCK_PROMPT, "unlock-prompt"),
            (Contexts::LOCK_SCREEN, "lock-screen"),
            (Contexts::SECRETS_TREE, "secrets-tree"),
            (Contexts::SECRETS_DETAIL, "secrets-detail"),
            (Contexts::PINNED_TAB, "pinned-tab"),
            (Contexts::SETTINGS_TAB, "settings-tab"),
            (Contexts::SEARCH, "search"),
            (Contexts::EDIT, "edit"),
            (Contexts::HISTORY, "history"),
            (Contexts::CONFIRM, "confirm"),
            (Contexts::PALETTE, "palette"),
            (Contexts::SYNC_UNLOCK, "sync-unlock"),
            (Contexts::SYNC_CONFIG, "sync-config"),
        ];
        NAMES
            .iter()
            .filter(|(bit, _)| self.contains(*bit))
            .map(|(_, name)| *name)
            .collect()
    }
}

/// Runtime enablement of a command, computed from live `App` state.
///
/// - `Enabled` — offered and dispatchable.
/// - `Disabled` — shown (dimmed) but a no-op if invoked (e.g. copy with no
///   selection). "Disabled hints teach" (gitui).
/// - `Hidden` — not offered at all. Unused in T1.1; the hint-bar refinement in
///   T2.1 is the first consumer.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum CmdState {
    Enabled,
    Disabled,
    #[allow(dead_code)] // first used by the T2.1 hint-bar enablement refinement
    Hidden,
}

/// One row of the command registry: a command's static metadata.
#[derive(Debug)]
pub(crate) struct CommandSpec {
    /// The command this row describes.
    pub id: Command,
    /// Kebab-case identifier — the TOML rebind slot name (`copy-password`).
    /// Validated by tests now; read as a rebind slot in T1.3.
    #[cfg_attr(not(test), allow(dead_code))]
    pub name: &'static str,
    /// Human-readable description for help / hints / palette.
    pub desc: &'static str,
    /// Display group (help section / palette header). Validated by tests now;
    /// rendered as a palette section header in T2.3.
    #[cfg_attr(not(test), allow(dead_code))]
    pub group: Group,
    /// Contexts in which the command is available.
    pub contexts: Contexts,
    /// Hint-bar priority; lower renders further left. Gaps of 10 leave room to
    /// insert between existing commands without renumbering. `i16` (not the
    /// `i8` first sketched in design §2.2.1) because 25 commands at gaps of 10
    /// already exceed the `i8` range.
    pub order: i16,
    /// Eligible for the always-visible bottom hint bar (T2.1). Palette/help list
    /// every command regardless of this flag. First read by the T2.1 hint bar;
    /// the values are pinned by `quick_bar_flags_hint_eligible_commands`.
    #[cfg_attr(not(test), allow(dead_code))]
    pub quick_bar: bool,
}

// Context shorthands used repeatedly below.
const TREE_DETAIL: Contexts = Contexts::SECRETS_TREE.or(Contexts::SECRETS_DETAIL);
const TREE_DETAIL_PINNED: Contexts = TREE_DETAIL.or(Contexts::PINNED_TAB);

/// The command registry. One row per [`Command`] variant, in help-display order
/// (the former `ACTIONS` order — preserved so help output is unchanged).
///
/// `desc` strings reproduce the pre-T1.1 `KeyBindings::describe()` descriptions
/// exactly; `contexts` mirror each command's de-facto reachability in the
/// current dispatcher (verified against `app.rs` handlers, T1.1).
pub(crate) static COMMANDS: &[CommandSpec] = &[
    // --- Global ---
    CommandSpec {
        id: Command::Quit,
        name: "quit",
        desc: "quit",
        group: Group::Global,
        contexts: Contexts::ALL,
        order: 0,
        quick_bar: false,
    },
    CommandSpec {
        id: Command::LockNow,
        name: "lock-now",
        desc: "lock now",
        group: Group::Global,
        contexts: Contexts::WORKSPACE,
        order: 10,
        quick_bar: false,
    },
    CommandSpec {
        id: Command::Help,
        name: "help",
        desc: "help",
        group: Group::Global,
        // The palette is reachable throughout the workspace and from the unlock
        // list / lock screen. UnlockPrompt is deliberately excluded because `?`
        // must remain typeable in a KDBX master password.
        contexts: Contexts::WORKSPACE
            .or(Contexts::UNLOCK_LIST)
            .or(Contexts::LOCK_SCREEN),
        order: 20,
        quick_bar: true,
    },
    CommandSpec {
        id: Command::Cancel,
        name: "cancel",
        desc: "cancel / back",
        group: Group::Global,
        contexts: Contexts::SECRETS_DETAIL
            .or(Contexts::UNLOCK_PROMPT)
            .or(Contexts::SEARCH)
            .or(Contexts::EDIT)
            .or(Contexts::HISTORY)
            .or(Contexts::CONFIRM)
            .or(Contexts::SYNC_UNLOCK)
            .or(Contexts::SYNC_CONFIG),
        order: 30,
        quick_bar: false,
    },
    CommandSpec {
        id: Command::Confirm,
        name: "confirm",
        desc: "confirm / open",
        group: Group::Global,
        contexts: Contexts::SECRETS_TREE
            .or(Contexts::UNLOCK_LIST)
            .or(Contexts::SETTINGS_TAB)
            .or(Contexts::SEARCH)
            .or(Contexts::EDIT)
            .or(Contexts::HISTORY)
            .or(Contexts::CONFIRM)
            .or(Contexts::SYNC_CONFIG),
        order: 40,
        quick_bar: false,
    },
    // --- Navigation ---
    CommandSpec {
        id: Command::Next,
        name: "next",
        desc: "down",
        group: Group::Navigation,
        contexts: TREE_DETAIL_PINNED
            .or(Contexts::UNLOCK_LIST)
            .or(Contexts::SETTINGS_TAB)
            .or(Contexts::HISTORY)
            .or(Contexts::SEARCH),
        order: 50,
        quick_bar: true,
    },
    CommandSpec {
        id: Command::Prev,
        name: "prev",
        desc: "up",
        group: Group::Navigation,
        contexts: TREE_DETAIL_PINNED
            .or(Contexts::UNLOCK_LIST)
            .or(Contexts::SETTINGS_TAB)
            .or(Contexts::HISTORY)
            .or(Contexts::SEARCH),
        order: 60,
        quick_bar: true,
    },
    CommandSpec {
        id: Command::Parent,
        name: "parent",
        desc: "collapse / parent",
        group: Group::Navigation,
        contexts: TREE_DETAIL,
        order: 70,
        quick_bar: false,
    },
    CommandSpec {
        id: Command::Child,
        name: "child",
        desc: "expand / open",
        group: Group::Navigation,
        contexts: TREE_DETAIL,
        order: 80,
        quick_bar: false,
    },
    CommandSpec {
        id: Command::JumpBack,
        name: "jump-back",
        desc: "jump back",
        group: Group::Navigation,
        contexts: TREE_DETAIL.or(Contexts::PINNED_TAB),
        order: 82,
        quick_bar: false,
    },
    CommandSpec {
        id: Command::JumpForward,
        name: "jump-forward",
        desc: "jump forward",
        group: Group::Navigation,
        // Tree focus only: Ctrl+I ≡ Tab on many terminals, and Tab is the
        // pane-toggle in the detail pane (design §2.2.8, risk accepted).
        contexts: Contexts::SECRETS_TREE,
        order: 84,
        quick_bar: false,
    },
    // --- Tabs ---
    CommandSpec {
        id: Command::NextTab,
        name: "next-tab",
        desc: "next tab",
        group: Group::Tabs,
        contexts: Contexts::WORKSPACE,
        order: 90,
        quick_bar: false,
    },
    CommandSpec {
        id: Command::PrevTab,
        name: "prev-tab",
        desc: "previous tab",
        group: Group::Tabs,
        contexts: Contexts::WORKSPACE,
        order: 100,
        quick_bar: false,
    },
    CommandSpec {
        id: Command::JumpToTab,
        name: "jump-to-tab",
        desc: "jump to tab N",
        group: Group::Tabs,
        contexts: Contexts::WORKSPACE,
        order: 110,
        quick_bar: false,
    },
    // --- Search overlay (T4.2) ---
    CommandSpec {
        id: Command::CycleScope,
        name: "cycle-scope",
        desc: "cycle scope",
        group: Group::Search,
        contexts: Contexts::SEARCH,
        order: 132,
        quick_bar: false,
    },
    CommandSpec {
        id: Command::QuickSelect,
        name: "quick-select",
        desc: "quick-select result",
        group: Group::Search,
        contexts: Contexts::SEARCH,
        order: 134,
        quick_bar: false,
    },
    CommandSpec {
        id: Command::OpenEntry,
        name: "open-entry",
        desc: "secondary search action",
        group: Group::Search,
        contexts: Contexts::SEARCH,
        order: 136,
        quick_bar: false,
    },
    // --- Secrets ---
    CommandSpec {
        id: Command::FocusPane,
        name: "focus-pane",
        desc: "focus tree / detail",
        group: Group::Navigation,
        contexts: TREE_DETAIL,
        order: 120,
        quick_bar: false,
    },
    CommandSpec {
        id: Command::Search,
        name: "search",
        desc: "search",
        group: Group::Search,
        contexts: TREE_DETAIL,
        order: 130,
        quick_bar: true,
    },
    CommandSpec {
        id: Command::AddEntry,
        name: "add-entry",
        desc: "add entry",
        group: Group::Secrets,
        contexts: TREE_DETAIL,
        order: 140,
        quick_bar: true,
    },
    CommandSpec {
        id: Command::EditEntry,
        name: "edit-entry",
        desc: "edit entry",
        group: Group::Secrets,
        contexts: TREE_DETAIL,
        order: 150,
        quick_bar: true,
    },
    CommandSpec {
        id: Command::DeleteEntry,
        name: "delete-entry",
        desc: "delete entry",
        group: Group::Secrets,
        contexts: TREE_DETAIL,
        order: 160,
        quick_bar: false,
    },
    CommandSpec {
        id: Command::CopyPassword,
        name: "copy-password",
        desc: "copy password",
        group: Group::Secrets,
        contexts: TREE_DETAIL,
        order: 170,
        quick_bar: true,
    },
    CommandSpec {
        id: Command::CopyUsername,
        name: "copy-username",
        desc: "copy username",
        group: Group::Secrets,
        contexts: TREE_DETAIL,
        order: 180,
        quick_bar: false,
    },
    CommandSpec {
        id: Command::RevealPassword,
        name: "reveal-password",
        desc: "reveal / hide password",
        group: Group::Secrets,
        contexts: TREE_DETAIL_PINNED,
        order: 190,
        quick_bar: false,
    },
    CommandSpec {
        id: Command::History,
        name: "history",
        desc: "history",
        group: Group::Secrets,
        contexts: TREE_DETAIL_PINNED,
        order: 200,
        quick_bar: false,
    },
    CommandSpec {
        id: Command::PinToggle,
        name: "pin-toggle",
        desc: "pin / unpin tab",
        group: Group::Secrets,
        contexts: TREE_DETAIL,
        order: 210,
        quick_bar: false,
    },
    CommandSpec {
        id: Command::SortCycle,
        name: "sort-cycle",
        desc: "cycle sort order",
        group: Group::Secrets,
        contexts: TREE_DETAIL,
        order: 220,
        quick_bar: false,
    },
    // --- Visual mode / bulk operations (T4.5) ---
    CommandSpec {
        id: Command::VisualMode,
        name: "visual-mode",
        desc: "visual select",
        group: Group::Navigation,
        contexts: Contexts::SECRETS_TREE,
        order: 222,
        quick_bar: false,
    },
    CommandSpec {
        id: Command::MoveToGroup,
        name: "move-to-group",
        desc: "move to group",
        group: Group::Secrets,
        contexts: Contexts::SECRETS_TREE,
        order: 224,
        quick_bar: false,
    },
    CommandSpec {
        id: Command::AddTag,
        name: "add-tag",
        desc: "add tag",
        group: Group::Secrets,
        contexts: Contexts::SECRETS_TREE,
        order: 226,
        quick_bar: false,
    },
    CommandSpec {
        id: Command::RemoveTag,
        name: "remove-tag",
        desc: "remove tag",
        group: Group::Secrets,
        contexts: Contexts::SECRETS_TREE,
        order: 228,
        quick_bar: false,
    },
    // --- Sync / generation ---
    CommandSpec {
        id: Command::Sync,
        name: "sync",
        desc: "sync",
        group: Group::Sync,
        contexts: TREE_DETAIL,
        order: 230,
        quick_bar: false,
    },
    CommandSpec {
        id: Command::Generate,
        name: "generate",
        desc: "generate",
        group: Group::Edit,
        contexts: Contexts::EDIT,
        order: 240,
        quick_bar: false,
    },
];

/// The registry row for `id`. Every [`Command`] variant has exactly one row
/// (guaranteed by `commands_table_is_exhaustive_and_unique`), so this never
/// returns `None` in practice; the `Option` keeps the lookup total. Consumed by
/// the keymap (context lookup when building a preset, and which-key continuation
/// specs — T1.2).
pub(crate) fn spec_for(id: Command) -> Option<&'static CommandSpec> {
    COMMANDS.iter().find(|spec| spec.id == id)
}

/// The commands available in `ctx`, paired with their live enablement, sorted by
/// hint-bar `order` (stable — ties keep table position). The projection behind
/// the hint bar (T2.1) and the palette (T2.3). `App` supplies enablement so the
/// same predicate drives both hints and dispatch (the gitui discipline).
#[cfg_attr(not(test), allow(dead_code))] // first consumed by the T2.1 hint bar
pub(crate) fn commands_for_specs<'a>(
    specs: &'a [CommandSpec],
    ctx: Contexts,
    app: &crate::app::App,
) -> Vec<(&'a CommandSpec, CmdState)> {
    let mut out: Vec<(&CommandSpec, CmdState)> = specs
        .iter()
        .filter(|spec| spec.contexts.contains(ctx))
        .map(|spec| (spec, app.command_state(spec.id)))
        .collect();
    // Stable sort by `order`; equal orders keep declaration order (the initial
    // COMMANDS order), so the hint bar never reshuffles on unrelated edits.
    out.sort_by_key(|(spec, _)| spec.order);
    out
}

pub(crate) fn commands_for(
    ctx: Contexts,
    app: &crate::app::App,
) -> Vec<(&'static CommandSpec, CmdState)> {
    commands_for_specs(COMMANDS, ctx, app)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AC-2 drift guarantee: every `Command` variant appears in `COMMANDS`
    /// exactly once. The exhaustive `match` makes adding a variant without
    /// registering it a compile error; the count assertion catches duplicates.
    #[test]
    fn commands_table_is_exhaustive_and_unique() {
        fn assert_registered(c: Command) {
            let count = COMMANDS.iter().filter(|spec| spec.id == c).count();
            assert_eq!(count, 1, "{c:?} must appear exactly once in COMMANDS");
        }
        for &command in ALL_COMMANDS {
            assert_registered(command);
        }
        assert_eq!(COMMANDS.len(), ALL_COMMANDS.len());
    }

    #[test]
    fn every_command_has_context_and_group() {
        for spec in COMMANDS {
            assert!(
                !spec.contexts.is_empty(),
                "{:?} has no contexts — it would be unreachable dead weight",
                spec.id
            );
            // `group` is a closed enum, so it is always declared; assert it is a
            // recognised variant to keep the check honest as the enum grows.
            match spec.group {
                Group::Global
                | Group::Navigation
                | Group::Tabs
                | Group::Secrets
                | Group::Search
                | Group::Edit
                | Group::Sync
                | Group::Settings => {}
            }
        }
    }

    #[test]
    fn command_names_are_unique_kebab_case() {
        let mut seen = std::collections::HashSet::new();
        for spec in COMMANDS {
            assert!(
                seen.insert(spec.name),
                "duplicate command name {:?}",
                spec.name
            );
            assert!(
                !spec.name.is_empty(),
                "empty command name for {:?}",
                spec.id
            );
            for ch in spec.name.chars() {
                assert!(
                    ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-',
                    "command name {:?} is not kebab-case (offending char {ch:?})",
                    spec.name
                );
            }
            assert!(
                !spec.name.starts_with('-') && !spec.name.ends_with('-'),
                "command name {:?} must not start or end with '-'",
                spec.name
            );
        }
    }

    /// The `quick_bar` column is hand-picked data with no prod reader until the
    /// T2.1 hint bar; pin the intended eligibility so the values can't silently
    /// rot before then. The common per-entry operations self-advertise; the
    /// global/rare ones (quit, generate) do not — the palette lists them anyway.
    #[test]
    fn quick_bar_flags_hint_eligible_commands() {
        let flag = |id: Command| COMMANDS.iter().find(|s| s.id == id).unwrap().quick_bar;
        for id in [
            Command::Help,
            Command::Next,
            Command::Prev,
            Command::Search,
            Command::AddEntry,
            Command::EditEntry,
            Command::CopyPassword,
        ] {
            assert!(flag(id), "{id:?} should be hint-bar eligible");
        }
        for id in [Command::Quit, Command::Generate, Command::CopyUsername] {
            assert!(!flag(id), "{id:?} should not be hint-bar eligible");
        }
    }

    // NOTE: the three App-dependent registry tests named in the T1.1 plan —
    // `commands_for_filters_by_context`, `hint_bar_ordering_is_stable`, and
    // `command_state_disabled_matches_dispatch_guard` — live in `app.rs`'s test
    // module, where the `populated_app()` vault fixture is in scope. They
    // exercise `commands_for` / `command_state` against a real unlocked App.
}
